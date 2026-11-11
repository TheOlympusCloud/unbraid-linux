//! The connection: compiles the setup, runs it on the engine, watches its tunnels and statistics. What the window shows
//! and what the speed tests, statistics and checks read of it live here, written only by the connection.
//!
//! Starts, stops and pauses are handled one at a time, in the order asked, by the connection's own task, which owns all
//! it knows ([`Session`]); the engine keeps the tunnels while the app's window is closed. What watches the connection
//! (edits, health checks, the engine's and Tailscale's status, timers) tells that task what it saw.

use crate::compiler::{self, Input, TS_TAG};
use crate::engine::{self, Engine};
use crate::engine_api::daemon::TailscaleEndpointStatus;
use crate::error::{Error, Result};
use crate::health::{self, Streak};
use crate::link_picker::{self, Picked};
use crate::model::{Link, Server, Setup};
use crate::net::NetMonitor;
use crate::providers::{self, AUTO, PORT_OPT, nord::DEDICATED_IP};
use crate::store::Store;
use crate::{APP, app, apps, clock, desktop, linux_pass, log, redact, speed_test, stats, ts_login};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use indexmap::{IndexMap, IndexSet};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, LazyLock, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct TsNode {
    pub name: String,
    pub ip: String,
    pub online: bool,
    pub id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Phase {
    #[default]
    Off,
    Connecting,
    On,
    Paused,
}

/// What the window shows. Lives in-process; the connection is the only writer.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct VpnState {
    pub phase: Phase,
    pub since: i64,
    pub servers: IndexMap<String, Server>,
    pub error: Option<String>,
    pub ts_login_url: Option<String>,
    pub ts_state: Option<String>,
    /// The DNS suffix the tailnet reports (usable form); whether apps may use it is the home's `ts_suffix_allowed`.
    pub ts_suffix: Option<String>,
    /// Tailnet peers that offer themselves as exit nodes.
    pub ts_exit_nodes: Vec<TsNode>,
    /// While paused: when the connection comes back (epoch ms), 0 = only when resumed by hand.
    pub paused_until: i64,
    /// While paused: when the pause began (epoch ms), for the countdown ring.
    pub paused_at: i64,
    /// While paused: it may resume somewhat after `paused_until`. Always false on Linux, where the timer is exact.
    pub paused_about: bool,
    /// Android's "Block connections without VPN"; Linux has none, so apps simply go out directly while paused.
    pub lockdown: bool,
    /// Android's "Always-on VPN"; on Linux the app starts at login instead ([`crate::autostart`]).
    pub always_on: bool,
    /// Providers whose routes have no tunnel right now: provider id → whether it refused the account (sign in again).
    pub stuck: IndexMap<String, bool>,
    /// Routes whose tunnel keeps dropping ([`crate::health`]).
    pub dropping: IndexSet<String>,
    /// Counts engine starts, each of which restarts every tunnel: what was observed of an earlier one no longer holds.
    pub engine: i32,
    /// [`setup_hash`] of the setup the engine runs in full (no route still waiting for a server): a profile switch is done.
    pub applied: u64,
    /// [`setup_hash`] of the last setup the engine refused (the one before it still runs): a profile switch is undone.
    pub refused: u64,
}

/// A start (`on`) or a stop or pause the connection hasn't handled yet, numbered in the order asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    pub n: i32,
    pub on: bool,
}

/// What the connection publishes for the rest of the app.
#[derive(Default)]
pub struct Live {
    pub state: watch::Sender<VpnState>,
    /// Route id → engine tunnel tag of the running setup (speed tests dial through it).
    pub tags: RwLock<IndexMap<String, String>>,
    /// Tunnel tag → the DNS server that tunnel's own lookups use (health checks look their servers up there).
    pub tunnel_dns: RwLock<IndexMap<String, String>>,
    /// The setup the engine runs (not the one being edited): statistics attribute traffic against it.
    pub running: RwLock<Option<Setup>>,
    /// Loopback port and password of the app's own way into each exit ([`crate::compiler::PROBE`]); see [`crate::probe`].
    pub probe: RwLock<Option<(u16, String)>>,
    /// The computer's own network is metered; Linux doesn't say so to the app, so a combined speed test never asks first.
    pub metered: AtomicBool,
    /// Servers ("provider|ip") that failed the last health check: the next connect, even a manual one, avoids them.
    pub failing: RwLock<IndexSet<String>>,
    /// The newest start, stop or pause the connection hasn't handled yet; see [`vpn_on`].
    pub asked: watch::Sender<Option<Ask>>,
    /// One line on what runs, for the tray and the command line.
    pub summary: watch::Sender<String>,
}

static LIVE: LazyLock<Live> = LazyLock::new(Live::default);

pub fn live() -> &'static Live {
    &LIVE
}

impl Live {
    pub fn state(&self) -> VpnState {
        self.state.borrow().clone()
    }
    pub fn tags(&self) -> IndexMap<String, String> {
        self.tags.read().unwrap().clone()
    }
    pub fn tag(&self, route: &str) -> Option<String> {
        self.tags.read().unwrap().get(route).cloned()
    }
    pub fn running(&self) -> Option<Setup> {
        self.running.read().unwrap().clone()
    }
    pub fn probe(&self) -> Option<(u16, String)> {
        self.probe.read().unwrap().clone()
    }
    pub fn set_probe(&self, p: Option<(u16, String)>) {
        *self.probe.write().unwrap() = p;
    }
    pub fn metered(&self) -> bool {
        self.metered.load(Ordering::Relaxed)
    }
    pub fn failing(&self) -> IndexSet<String> {
        self.failing.read().unwrap().clone()
    }
}

/// A setup's identity for following a switch: equal setups hash alike, whatever order their maps were filled in, and a
/// copy read back from disk hashes as the one in memory. The routes up only for a speed test count too.
pub fn setup_hash(s: &Setup) -> u64 {
    // serde_json's own maps are sorted, so the text is the same for equal setups.
    let canonical = serde_json::to_value(s).map(|v| v.to_string()).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut h);
    let mut testing: Vec<&String> = s.testing.iter().collect();
    testing.sort();
    testing.hash(&mut h);
    h.finish()
}

/// For a profile switch to the setup hashed `h`: true once the engine runs it (or runs nothing), false if it refused
/// it, none meanwhile.
pub fn switch_done(v: &VpnState, h: u64) -> Option<bool> {
    if v.phase != Phase::On || v.applied == h {
        Some(true)
    } else if v.refused == h {
        Some(false)
    } else {
        None
    }
}

/// Whether the VPN is on or about to be, for toggles: the newest request the connection hasn't handled yet wins over
/// the phase, so a second quick click undoes the first instead of repeating it, however long the first one takes.
pub fn vpn_on(phase: Phase, ask: Option<Ask>) -> bool {
    ask.map(|a| a.on).unwrap_or(phase == Phase::On || phase == Phase::Connecting)
}

const TAG: &str = "Unbraid";

// ---- what the rest of the app asks of the connection ---------------------------------------------------------------

/// Connects, or resumes a pause.
pub fn start() {
    ask(true, Cmd::Start);
}

pub fn stop() {
    ask(false, Cmd::Stop);
}

/// Drops the tunnel for `minutes` (0 = until resumed); a start while paused resumes.
pub fn pause(minutes: i32) {
    ask(false, |n| Cmd::Pause(n, minutes));
}

static ASKS: AtomicI32 = AtomicI32::new(0);
/// Commands sent and not yet started; see [`while_stopped`].
static WAITING: AtomicI32 = AtomicI32::new(0);

/// Numbers a start (`on`), stop or pause, shows it as asked ([`Live::asked`]) and sends it.
fn ask(on: bool, cmd: impl FnOnce(i32) -> Cmd) {
    let a = Ask { n: ASKS.fetch_add(1, Ordering::SeqCst) + 1, on };
    live().asked.send_replace(Some(a));
    WAITING.fetch_add(1, Ordering::SeqCst);
    if !send(Msg::Cmd(cmd(a.n))) {
        WAITING.fetch_sub(1, Ordering::SeqCst);
        live().asked.send_if_modified(|v| {
            let mine = *v == Some(a);
            if mine {
                *v = None;
            }
            mine
        });
    }
}

/// The connection handled request `n` (or turned it away), and with it every earlier one.
fn handled(live: &Live, n: i32) {
    live.asked.send_if_modified(|a| {
        let done = n != 0 && a.is_some_and(|a| a.n <= n);
        if done {
            *a = None;
        }
        done
    });
}

/// Runs `f` only while the VPN is off with no command waiting, on the connection's task, so none can start meanwhile.
/// None when it didn't run.
pub async fn while_stopped<T: Send + 'static>(f: impl Future<Output = T> + Send + 'static) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    send(Msg::WhileStopped(Box::pin(async move {
        let _ = tx.send(f.await);
    })));
    rx.await.ok()
}

/// Logs this computer out of its tailnet, which needs the engine running. False if it isn't, or the control server
/// didn't confirm.
pub async fn tailscale_logout() -> bool {
    if live().state.borrow().phase != Phase::On {
        return false;
    }
    // On a task of its own: the call goes on after this answer stops waiting for it.
    let call = tokio::spawn(async { engine::get().tailscale_logout(TS_TAG).await.is_ok() });
    matches!(tokio::time::timeout(Duration::from_secs(8), call).await, Ok(Ok(true)))
}

/// Deletes the Tailscale node the engine keeps for this user (its state is the engine's, in its root-only folder);
/// only while stopped ([`while_stopped`]). An engine that never ran for this user has none to delete.
pub async fn forget_tailscale() -> bool {
    let e = engine::get().forget().await.err();
    let gone = e.as_ref().is_none_or(|e| e.code() == tonic::Code::Unknown);
    if gone {
        app::store().set_ts_stored(false);
    } else if let Some(e) = &e {
        log::w(TAG, &format!("tailscale: node not deleted: {}", redact::log(e)));
    }
    gone
}

/// The engine's domain table (fake IP → domain) names every site looked up. The engine keeps it in memory only
/// ([`linux_pass`]): there is nothing to delete, and each engine start is a new table.
pub fn forget_lookups() -> bool {
    true
}

/// Quitting the app ends its connection. Waits for that at most 10 s: call it off the async runtime (from the window's
/// thread, or one of its own), since the connection's task does the work on it.
pub fn quit() {
    let (tx, rx) = std::sync::mpsc::channel();
    if send(Msg::Quit(tx)) {
        let _ = rx.recv_timeout(Duration::from_secs(10));
    }
}

// ---- the connection's task -----------------------------------------------------------------------------------------

/// Starts, stops and pauses, numbered as asked.
enum Cmd {
    Start(i32),
    Stop(i32),
    Pause(i32, i32),
}

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;
type Inbox = mpsc::UnboundedSender<Msg>;

/// What the connection's task does, one at a time, in arrival order.
enum Msg {
    Cmd(Cmd),
    /// [`while_stopped`]'s work: dropped unless the VPN is off with no command waiting.
    WhileStopped(Job),
    Quit(std::sync::mpsc::Sender<()>),
    /// Apply the newest setup without dropping the tunnel ([`Session::reload`]).
    Reload(Reload),
    /// What the providers answered a reload: applied only if nothing changed since it asked.
    Picked(Box<(Pending, Picked)>),
    /// The setup or the accounts changed, and stayed so for 400 ms.
    Edited(Box<(Setup, IndexMap<String, String>)>),
    /// The computer moved to another network.
    NetChanged,
    /// A timed pause is over: it resumes only that pause.
    Resume(i32),
    /// The engine's service stopped while the connection numbered here ran, with what it said.
    Lost(i32, Option<String>),
    /// Tailscale's status while the connection numbered here runs.
    Tailscale(i32, Box<TailscaleEndpointStatus>),
    /// A step of the connection's work done elsewhere ([`locked`]).
    Locked(Box<dyn FnOnce(&mut Session) + Send>),
}

static INBOX: OnceLock<Inbox> = OnceLock::new();

/// To the connection's task, which the first message starts on the app's runtime. False once that task is gone.
fn send(m: Msg) -> bool {
    let inbox = INBOX.get_or_init(|| {
        let (tx, rx) = mpsc::unbounded_channel();
        let me = tx.clone();
        // Made on the runtime: the engine's channel starts a task of its own.
        app::runtime()
            .spawn(async move { Session::new(live(), app::store().clone(), engine::get(), me).run(rx).await });
        tx
    });
    inbox.send(m).is_ok()
}

/// Runs `f` on the connection's task, after what it is doing now, as part of the connection's own work. None once that
/// task is gone.
async fn locked<T: Send + 'static>(me: &Inbox, f: impl FnOnce(&mut Session) -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    me.send(Msg::Locked(Box::new(move |s| {
        let _ = tx.send(f(s));
    })))
    .ok()?;
    rx.await.ok()
}

/// A reload's own start: tunnels to keep while still valid (`keep_from`: the install they were taken at), servers to
/// avoid.
#[derive(Default)]
struct Reload {
    keep: Option<IndexMap<String, Link>>,
    avoid: IndexSet<String>,
    keep_from: i32,
}

/// What a reload asked its providers with.
struct Pending {
    setup: Setup,
    accounts: IndexMap<String, String>,
    generation: i32,
}

/// Tunnels that stopped answering, to replace: the tunnels to keep, servers to avoid, the install they are about,
/// their providers, and whether any route can move (or try another port).
struct Move {
    keep: IndexMap<String, Link>,
    avoid: IndexSet<String>,
    generation: i32,
    providers: IndexSet<String>,
    any_movable: bool,
}

/// What the health checks remember of the running tunnels, by tag.
#[derive(Default)]
struct Checks {
    /// Failed checks in a row; tags that answered have none.
    streaks: HashMap<String, Streak>,
    /// The latest regular checks, for routes that keep dropping.
    history: HashMap<String, Vec<bool>>,
    /// When a dead tunnel there may be handled again; survives restarts.
    holds: HashMap<String, i64>,
    /// How many times longer than usual a round waits: the computer's own network kept failing.
    slow: i64,
}

impl Checks {
    fn hold(&self, tag: &str) -> i64 {
        self.holds.get(tag).copied().unwrap_or(0)
    }

    /// The checks start again (after a sleep, an engine start or a new network): no route is flagged as dropping and no
    /// server as failing until new checks say so. The end of the next grace period, from `now`.
    fn restart(&mut self, live: &Live, now: i64) -> i64 {
        self.streaks.clear();
        self.history.clear();
        let dropping = !live.state.borrow().dropping.is_empty();
        if dropping {
            live.state.send_modify(|v| v.dropping.clear());
        }
        live.failing.write().unwrap().clear();
        now + health::GRACE
    }
}

/// A health round's answers.
struct Round {
    /// The engine start and the network they were made on.
    engine: i32,
    network: Option<String>,
    regular: bool,
    checked: IndexSet<String>,
    /// Tags that didn't answer; none when it was most likely the computer's own network.
    down: Option<IndexSet<String>>,
    now: i64,
    /// Tag → its routes, and tag → its servers as checked ("provider|ip"), before a reload could swap them.
    by_tag: ByTag,
    servers: ByTag,
}

/// Tunnel tag → its routes, or the servers they run on.
type ByTag = IndexMap<String, Vec<String>>;

/// The connection as its task owns it. Watchers and timers come and go with each connection; what they find comes back
/// as messages.
struct Session {
    live: &'static Live,
    store: Arc<Store>,
    engine: &'static Engine,
    /// The task's own inbox, for its watchers and timers.
    me: Inbox,
    net: Arc<NetMonitor>,
    /// This process, as the engine sees it ([`linux_pass`]): its own connections leave directly.
    own: Option<String>,
    watch: Option<JoinHandle<()>>,
    health: Option<JoinHandle<()>>,
    ts: Option<JoinHandle<()>>,
    resume: Option<JoinHandle<()>>,
    engine_watch: Option<JoinHandle<()>>,
    retry: Option<JoinHandle<()>>,
    /// The engine reports its service running; kept by [`Session::watch_engine`].
    engine_up: Arc<AtomicBool>,
    /// Counts engine starts in this process: each restarts every tunnel ([`VpnState::engine`]).
    starts: i32,
    /// Counts connections ended ([`Session::stop_engine`]): a stop from outside applies only to the one it was sent for.
    session: i32,
    /// Pauses in this process: a timed resume for an older one, or after a disconnect, does nothing.
    pauses: i32,
    /// Counts installs and stops: a reload's provider answers apply only if none happened since it asked.
    generation: i32,
    /// The setup and accounts the engine runs right now.
    applied: Option<Setup>,
    applied_accounts: IndexMap<String, String>,
    /// A setup and accounts the engine refused: not retried until either changes, so a sign-out is never skipped.
    rejected: Option<(Setup, IndexMap<String, String>)>,
    /// True between stopping the old engine and the new one running: only then is there something to restore.
    restarting: bool,
    last_good: Option<String>,
    /// What `last_good` was compiled from, so a failed reload can bring exactly that back with a new probe pair.
    last_input: Option<Input>,
    /// An engine runs a domain table: a reload that doesn't restart it keeps its fake-IP block.
    table_open: bool,
    /// The fake-IP block of the open or last table; the store only carries it across restarts of the app.
    last_block: Option<i32>,
    /// Tunnels the engine runs now, per route id.
    links: IndexMap<String, Link>,
    retries: usize,
    /// The running setup's blocked routes, which `retry` tries again.
    retrying: IndexMap<String, Error>,
    /// Pinned servers ("provider|host") their provider's list no longer has, while connected.
    gone: IndexMap<String, Error>,
    /// Providers that refused an account, with that account and why: their routes stay blocked until it changes.
    refusals: IndexMap<String, (Option<String>, Error)>,
    /// Tailscale gave a sign-in link and waits for the user ([`Input::ts_login_pending`]).
    ts_login_pending: bool,
    /// Provider id → how many of its ports Automatic has moved past on this network ([`link_picker::ported`]).
    port_step: IndexMap<String, usize>,
    /// The network `port_step` was learned on.
    port_net: Option<String>,
}

impl Session {
    fn new(live: &'static Live, store: Arc<Store>, engine: &'static Engine, me: Inbox) -> Session {
        // Only a program the engine can tell apart: one that other programs share would take them out of the VPN too.
        let own = std::env::current_exe()
            .ok()
            .filter(|p| apps::unroutable(p).is_none())
            .map(|p| p.to_string_lossy().into_owned());
        Session {
            live,
            store,
            engine,
            me,
            net: Arc::new(NetMonitor::default()),
            own,
            watch: None,
            health: None,
            ts: None,
            resume: None,
            engine_watch: None,
            retry: None,
            engine_up: Arc::new(AtomicBool::new(false)),
            starts: 0,
            session: 0,
            pauses: 0,
            generation: 0,
            applied: None,
            applied_accounts: IndexMap::new(),
            rejected: None,
            restarting: false,
            last_good: None,
            last_input: None,
            table_open: false,
            last_block: None,
            links: IndexMap::new(),
            retries: 0,
            retrying: IndexMap::new(),
            gone: IndexMap::new(),
            refusals: IndexMap::new(),
            ts_login_pending: false,
            port_step: IndexMap::new(),
            port_net: None,
        }
    }

    async fn run(mut self, mut inbox: mpsc::UnboundedReceiver<Msg>) {
        while let Some(m) = inbox.recv().await {
            if let Msg::Cmd(_) = m {
                WAITING.fetch_sub(1, Ordering::SeqCst);
            }
            self.on(m).await;
        }
    }

    async fn on(&mut self, m: Msg) {
        match m {
            Msg::Cmd(c) => {
                let (Cmd::Start(n) | Cmd::Stop(n) | Cmd::Pause(n, _)) = c;
                self.handle(c).await;
                handled(self.live, n);
            }
            Msg::WhileStopped(job) => {
                if self.phase() == Phase::Off && WAITING.load(Ordering::SeqCst) == 0 {
                    job.await;
                }
            }
            Msg::Quit(done) => {
                if self.phase() != Phase::Off {
                    self.teardown(None).await;
                }
                let _ = done.send(());
            }
            Msg::Reload(r) => self.reload(r).await,
            Msg::Picked(p) => {
                let (pending, picked) = *p;
                self.picked(pending, picked).await;
            }
            Msg::Edited(e) => {
                let (setup, accounts) = *e;
                self.edited(setup, accounts).await;
            }
            Msg::NetChanged => {
                cancel(&mut self.retry);
                self.reload(Reload::default()).await;
            }
            Msg::Resume(pause) => {
                if self.phase() == Phase::Paused && self.pauses == pause {
                    self.connect().await;
                }
            }
            Msg::Lost(mine, error) => self.lost(mine, error).await,
            Msg::Tailscale(mine, ep) => {
                if mine == self.session {
                    self.tailscale(&ep).await;
                }
            }
            Msg::Locked(f) => f(self),
        }
    }

    fn phase(&self) -> Phase {
        self.live.state.borrow().phase
    }

    /// One command, in arrival order.
    async fn handle(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Stop(_) => self.teardown(None).await,
            // Nothing to pause (a stale tray menu): nothing to do.
            Cmd::Pause(_, minutes) => {
                if self.phase() != Phase::Off {
                    self.pause_now(minutes).await;
                }
            }
            Cmd::Start(_) => self.connect().await,
        }
    }

    async fn connect(&mut self) {
        // A repeated start (tray, command line).
        if self.phase() == Phase::On {
            return self.notify(&self.store.current());
        }
        cancel(&mut self.resume);
        self.live.state.send_replace(VpnState { phase: Phase::Connecting, ..VpnState::default() });
        if let Err(e) = self.connecting().await {
            log::e(TAG, &format!("connect: {}", redact::log(&e)));
            self.teardown(Some(redact::message(&e, "Could not connect"))).await;
        }
    }

    async fn connecting(&mut self) -> Result<()> {
        self.net.start();
        let setup = self.store.current();
        let accounts = self.store.current_accounts();
        // The app's own tests get a fresh way in with each engine start (see apply); none until it runs.
        self.live.set_probe(None);
        let picked = self.pick_links(&setup, IndexMap::new(), &accounts, IndexSet::new(), false).await;
        self.apply(&setup, &picked, &accounts).await?;
        self.live.state.send_replace(VpnState {
            phase: Phase::On,
            since: now_ms(),
            servers: servers(&picked.links),
            error: blocked_text(&setup, &picked.blocked),
            stuck: stuck(&setup, &picked.blocked),
            engine: self.starts,
            applied: if waits(&picked) { 0 } else { setup_hash(&setup) },
            ..VpnState::default()
        });
        self.notify(&setup);
        self.watch_engine();
        if setup.tailscale() {
            self.watch_tailscale();
        }
        // Anything edited while connecting is picked up here: only the applied setup is skipped. Setup edits and
        // sign-ins and sign-outs both change what the engine must run.
        self.health =
            Some(tokio::spawn(watch_health(self.me.clone(), self.live, self.net.clone(), self.store.clone())));
        self.watch = Some(tokio::spawn(watch_edits(self.store.clone(), self.me.clone())));
        Ok(())
    }

    /// Validates first, so a bad config never replaces a working engine. `accounts` is the snapshot `picked` was made
    /// with: a sign-out after it differs, so the watcher reloads again.
    async fn apply(&mut self, setup: &Setup, picked: &Picked, accounts: &IndexMap<String, String>) -> Result<()> {
        self.generation += 1;
        let links = &picked.links;
        let blocked: IndexSet<String> = picked.blocked.keys().cloned().collect();
        let mut input = self.input(setup, links, &blocked, self.live.probe(), false);
        let mut json = compile(&input, &self.own).await?;
        // A favourite, a rename or a second sign-in changes the setup but not what the engine runs: keep every tunnel up.
        let fresh = self.last_good.as_ref() != Some(&json);
        if fresh {
            // Every engine start gets a new loopback port and password: while an old engine lets go of its port, a local
            // app could take it over and see that engine's password, which no later engine accepts. The app's own tests
            // get the new pair only once the new engine runs.
            let next = new_probe()?;
            // The engine keeps its domain table in memory: a restart is a new table, in the next block.
            input = self.input(setup, links, &blocked, Some(next.clone()), true);
            json = compile(&input, &self.own).await?;
            engine(self.engine.check(&json).await, "The connection engine rejected this setup.")?;
            // The block is spent before the engine can hand out any of it, also if the start fails or the app dies now:
            // a new table that couldn't be noted down doesn't start, or the next process would hand it out again.
            if self.last_block != Some(input.fake_block) {
                let (store, block) = (self.store.clone(), input.fake_block);
                engine(
                    blocking(move || store.set_fake_block(block)).await,
                    &format!("{APP} couldn't save its state. Try again."),
                )?;
            }
            self.last_block = Some(input.fake_block);
            self.restarting = true;
            self.table_open = true;
            // A node is kept in the engine from now on: Settings offers to sign it out even once Tailscale is off.
            if setup.tailscale() && !self.store.ts_stored() {
                self.store.set_ts_stored(true);
            }
            engine(self.engine.start(&json).await, "The connection engine couldn't start.")?;
            self.restarting = false;
            self.starts += 1;
            self.live.set_probe(Some(next));
            self.last_input = Some(input);
        }
        *self.live.tunnel_dns.write().unwrap() = compiler::probe_dns(&json).unwrap_or_default();
        self.last_good = Some(json);
        let mut tags = compiler::shared(setup, &link_picker::ported(setup, links, &self.port_step), &blocked)?;
        tags.extend(
            setup
                .active_routes()
                .into_iter()
                .filter(|r| r.ts_exit.is_some())
                .map(|r| (r.id.clone(), TS_TAG.to_string())),
        );
        *self.live.tags.write().unwrap() = tags;
        let was = self.live.running.write().unwrap().replace(setup.clone());
        // Published after tags and running: whoever sees this engine number also sees the tunnels it runs. The new
        // engine numbers its connections afresh; statistics read the new servers when they first see them.
        if fresh {
            let (servers, starts) = (servers(links), self.starts);
            self.live.state.send_modify(|v| {
                v.servers = servers;
                v.engine = starts;
            });
        }
        // After tags and running, which statistics label new connections by; also when only the setup changed (a city
        // that resolves to the same server is still another place in the history).
        if fresh || was.as_ref() != Some(setup) {
            retime();
        }
        self.applied = Some(setup.clone());
        self.applied_accounts = accounts.clone();
        // A refusal is over once a setup runs again: a retry of the same one is judged afresh.
        let full = (!waits(picked)).then(|| setup_hash(setup));
        self.live.state.send_modify(|v| {
            if let Some(h) = full {
                v.applied = h;
            }
            v.refused = 0;
        });
        self.rejected = None;
        self.links = links.clone();
        self.retry_blocked(&picked.blocked);
        Ok(())
    }

    /// Compiled as under Android's lockdown, where the system leaves no app out (Linux can't), then made a Linux config.
    /// The paths are the engine's own: it keeps them in its root-only folder for this user.
    fn input(
        &self,
        setup: &Setup,
        links: &IndexMap<String, Link>,
        blocked: &IndexSet<String>,
        probe: Option<(u16, String)>,
        new_table: bool,
    ) -> Input {
        Input {
            ts_suffix: self.store.ts_suffix(),
            probe,
            fake_block: self.fake_block(new_table),
            blocked: blocked.clone(),
            ts_login_pending: self.ts_login_pending,
            ..Input::new(
                setup.clone(),
                link_picker::ported(setup, links, &self.port_step),
                "app.unbraid",
                true,
                "tailscale",
                "cache.db",
            )
        }
    }

    /// The running table's fake-IP block, to compare a reload with what runs; a new table (an engine start) takes the
    /// next one.
    fn fake_block(&self, new_table: bool) -> i32 {
        compiler::next_block(self.last_block.unwrap_or_else(|| self.store.fake_block()), self.table_open && !new_table)
    }

    /// Routes blocked for a passing reason (no network, provider unreachable) try again after 5 s, 15 s, 30 s, 1 min,
    /// then every 5 min; signed-out or refused ones wait for a sign-in, which reloads by itself.
    fn retry_blocked(&mut self, blocked: &IndexMap<String, Error>) {
        cancel(&mut self.retry);
        self.retrying = blocked.clone();
        if blocked.values().all(|e| matches!(e, Error::Auth { .. })) {
            self.retries = 0;
            self.net.set_on_change(None);
            return;
        }
        let wait = [5, 15, 30, 60, 300][self.retries.min(4)];
        self.retries += 1;
        let me = self.me.clone();
        self.retry = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let _ = me.send(Msg::Reload(Reload::default()));
        }));
        // A new network is the likeliest fix: try at once, with the backoff kept for what follows.
        let me = self.me.clone();
        self.net.set_on_change(Some(Arc::new(move || {
            let _ = me.send(Msg::NetChanged);
        })));
    }

    /// What ran before a failed reload, back on the engine exactly as it was compiled, with a fresh probe pair; false if
    /// it won't start. Until then the app's own tests have no way in.
    async fn restore_last_good(&mut self) -> bool {
        self.live.set_probe(None);
        let Some(last) = self.last_input.clone() else { return false };
        let Ok(next) = new_probe() else { return false };
        // What ran, but never with tailnet DNS authority or a sign-in way around the exit that was taken back since.
        let mut setup = last.setup.clone();
        setup.home.ts_suffix_allowed = self.store.current().home.ts_suffix_allowed;
        // A restarted engine is a new domain table: the next block after the failed start's (which may have answered
        // lookups before it failed), noted down before the engine can hand any of it out.
        let fake_block = compiler::next_block(self.last_block.unwrap_or(last.fake_block), false);
        let ts_login_pending = last.ts_login_pending && self.ts_login_pending;
        let input = Input {
            setup,
            ts_suffix: self.store.ts_suffix(),
            probe: Some(next.clone()),
            fake_block,
            ts_login_pending,
            ..last
        };
        let Ok(json) = compile(&input, &self.own).await else { return false };
        let store = self.store.clone();
        if blocking(move || store.set_fake_block(fake_block)).await.is_err() || self.engine.start(&json).await.is_err()
        {
            return false;
        }
        self.starts += 1;
        let starts = self.starts;
        self.live.state.send_modify(|v| v.engine = starts);
        self.last_block = Some(fake_block);
        self.live.set_probe(Some(next));
        self.last_good = Some(json);
        self.last_input = Some(input);
        true
    }

    /// Applies the newest setup without dropping the tunnel; routes whose location is unchanged keep their server.
    /// Providers are asked for servers off this task ([`Msg::Picked`]), so a newer change (one that must block an app at
    /// once) never waits for them; what they answer is applied only if nothing changed meanwhile.
    async fn reload(&mut self, r: Reload) {
        if self.phase() != Phase::On {
            return;
        }
        let setup = self.store.current();
        let accounts = self.store.current_accounts();
        // `keep` was taken elsewhere: only valid if nothing was installed since (`keep_from`).
        let keep = r.keep.filter(|_| r.keep_from == self.generation).unwrap_or_else(|| self.links.clone());
        let ready = self.pick_links(&setup, keep, &accounts, r.avoid.clone(), true).await;
        if !waits(&ready) {
            self.install(&setup, &ready, &accounts).await;
            return;
        }
        // While a provider is asked for a server, apps moving off Direct already leave through their new route, or wait
        // blocked if that is the one still waiting: never on their real address for the time it takes. A tunnel whose
        // account was signed out or refused stops now too, not once the others are found.
        let stop_now =
            ready.blocked.iter().any(|(id, e)| matches!(e, Error::Auth { .. }) && self.links.contains_key(id));
        let routes: IndexSet<String> = setup.active_routes().into_iter().map(|r| r.id.clone()).collect();
        if (stop_now || link_picker::leaves_direct(self.applied.as_ref(), &setup, &routes))
            && !self.install(&setup, &ready, &accounts).await
        {
            return;
        }
        let refused = self.refused_for(&setup, &accounts);
        let mut avoid = r.avoid;
        avoid.extend(self.live.failing());
        let pending = Pending { setup: setup.clone(), accounts: accounts.clone(), generation: self.generation };
        let (applied, applied_accounts, store, me) =
            (self.applied.clone(), self.applied_accounts.clone(), self.store.clone(), self.me.clone());
        tokio::spawn(async move {
            // A route without a tunnel (signed out, refused, unreachable) is blocked; the others keep running. Tunnels
            // come from the offline pass, which already dropped any a changed location or account can't keep.
            let picked = blocking(move || {
                link_picker::pick(
                    &setup,
                    &ready.links,
                    applied.as_ref(),
                    &applied_accounts,
                    &accounts,
                    &store.last_links(),
                    &avoid,
                    &refused,
                    false,
                    &providers::get,
                )
            })
            .await;
            let _ = me.send(Msg::Picked(Box::new((pending, picked))));
        });
    }

    /// What the providers answered a reload: stopped, reloaded or edited meanwhile, the newer state wins (the watcher
    /// reloads an edit).
    async fn picked(&mut self, p: Pending, picked: Picked) {
        if self.phase() != Phase::On
            || self.generation != p.generation
            || self.store.current() != p.setup
            || self.store.current_accounts() != p.accounts
        {
            return;
        }
        self.note_refusals(&p.setup, &p.accounts, &picked);
        let (store, remember) = (self.store.clone(), picked.remember.clone());
        blocking(move || store.remember_links(&remember)).await;
        self.install(&p.setup, &picked, &p.accounts).await;
    }

    /// The setup or the accounts changed: reloaded, unless that is what runs or what the engine refused.
    async fn edited(&mut self, setup: Setup, accounts: IndexMap<String, String>) {
        // Moved on from a refused setup (a switch put back): trying that one again later is a fresh attempt.
        if self.rejected.as_ref().is_some_and(|(s, _)| *s != setup) {
            self.rejected = None;
            self.live.state.send_modify(|v| v.refused = 0);
        }
        let now = (setup, accounts);
        if (self.applied.as_ref() != Some(&now.0) || now.1 != self.applied_accounts)
            && self.rejected.as_ref() != Some(&now)
        {
            self.reload(Reload::default()).await;
        }
    }

    /// Runs `picked` on the engine and shows it; on failure brings back what ran. False if it didn't apply.
    async fn install(&mut self, setup: &Setup, picked: &Picked, accounts: &IndexMap<String, String>) -> bool {
        let e = match self.apply(setup, picked, accounts).await {
            Ok(()) => {
                let (servers, error, stuck) =
                    (servers(&picked.links), blocked_text(setup, &picked.blocked), stuck(setup, &picked.blocked));
                self.live.state.send_modify(|v| {
                    v.servers = servers;
                    v.error = error;
                    v.stuck = stuck;
                });
                self.notify(setup);
                if setup.tailscale() && self.ts.is_none() {
                    self.watch_tailscale();
                }
                return true;
            }
            Err(e) => e,
        };
        log::e(TAG, &format!("reload: {}", redact::log(&e)));
        // The same broken pair isn't retried in a loop; `applied` stays what runs.
        self.rejected = Some((setup.clone(), accounts.clone()));
        // The engine stops the old service before starting the new one: only then bring the last good config back. It
        // comes back with a new probe pair too: the old password may have been seen while the old engine's port was free.
        let restarted = self.restarting;
        let restored = !restarted || self.restore_last_good().await;
        self.restarting = false;
        // A retry of the running setup that failed before any engine restart is tried again later; one that restarted
        // every tunnel isn't, so a failing server never takes all apps offline every few minutes (a network change still
        // tries again). A refused edit is never retried this way: it waits for the next edit.
        if restored && restarted {
            cancel(&mut self.retry);
        } else if restored && self.applied.as_ref() == Some(setup) && *accounts == self.applied_accounts {
            let retrying = self.retrying.clone();
            self.retry_blocked(&retrying);
        }
        if restored {
            retime(); // a new engine, numbered afresh
            let (error, refused) = (redact::message(&e, "Change not applied"), setup_hash(setup));
            self.live.state.send_modify(|v| {
                v.error = Some(error);
                v.refused = refused;
            });
        } else {
            self.teardown(Some(redact::message(&e, "Connection lost"))).await;
        }
        false
    }

    /// Tunnels for `setup`'s active routes ([`link_picker::pick`]); providers are asked, off this task, unless `offline`.
    async fn pick_links(
        &mut self,
        setup: &Setup,
        keep: IndexMap<String, Link>,
        accounts: &IndexMap<String, String>,
        mut avoid: IndexSet<String>,
        offline: bool,
    ) -> Picked {
        let refused = self.refused_for(setup, accounts);
        avoid.extend(self.live.failing());
        let (s, a, applied, applied_accounts, store) =
            (setup.clone(), accounts.clone(), self.applied.clone(), self.applied_accounts.clone(), self.store.clone());
        let r = blocking(move || {
            let r = link_picker::pick(
                &s,
                &keep,
                applied.as_ref(),
                &applied_accounts,
                &a,
                &store.last_links(),
                &avoid,
                &refused,
                offline,
                &providers::get,
            );
            // Only a fallback cache: failing to write it never stops a connection.
            if !offline {
                store.remember_links(&r.remember);
            }
            r
        })
        .await;
        self.note_refusals(setup, accounts, &r);
        r
    }

    /// Routes whose provider refused the account it still has, or whose pinned server it no longer offers. A refusal
    /// holds until that account changes (a sign-out or a new sign-in), a server's removal while connected: a later
    /// request that fails never brings the saved server back.
    fn refused_for(&mut self, setup: &Setup, accounts: &IndexMap<String, String>) -> IndexMap<String, Error> {
        self.refusals.retain(|p, (account, _)| account.as_ref() == accounts.get(p));
        let mut out = IndexMap::new();
        for r in setup.active_routes().into_iter().filter(|r| !r.imported()) {
            let gone = || r.loc.pinned.as_ref().and_then(|p| self.gone.get(&format!("{}|{}", r.loc.provider, p.host)));
            if let Some(e) = self.refusals.get(&r.loc.provider).map(|(_, e)| e).or_else(gone) {
                out.insert(r.id.clone(), e.clone());
            }
        }
        out
    }

    fn note_refusals(&mut self, setup: &Setup, accounts: &IndexMap<String, String>, r: &Picked) {
        for (id, e) in &r.blocked {
            let Some(route) = setup.route(Some(id)).filter(|r| !r.imported()) else { continue };
            let p = &route.loc.provider;
            if matches!(e, Error::Auth { .. }) {
                self.refusals.insert(p.clone(), (accounts.get(p).cloned(), e.clone()));
            }
            if let (Error::NoLongerOffered(_), Some(pin)) = (e, &route.loc.pinned) {
                self.gone.insert(format!("{p}|{}", pin.host), e.clone());
            }
        }
    }

    /// Providers that dropped this computer (its device removed on their website): their routes wait blocked for a new
    /// sign-in instead of trying server after server.
    fn dropped(&mut self, dropped: &[String], accounts: &IndexMap<String, String>) {
        for p in dropped {
            let name = providers::get(p).map_or(p.as_str(), |x| x.name());
            let e = Error::Auth {
                message: format!(
                    "{name} no longer has this computer (it was removed from your account). Sign in again"
                ),
                url: None,
            };
            self.refusals.insert(p.clone(), (accounts.get(p).cloned(), e));
        }
    }

    /// Ports Automatic learned on another network don't hold on `network`: true if some were let go (then reload).
    fn new_network(&mut self, network: Option<String>) -> bool {
        if network == self.port_net {
            return false;
        }
        self.port_net = network;
        !std::mem::take(&mut self.port_step).is_empty()
    }

    /// The engine start, and the provider tunnels to check: tag → its routes, and tag → its servers. Pinned and
    /// Dedicated IP routes are checked too (to notice a removed device), but never moved.
    fn checked_tags(&self) -> (i32, ByTag, ByTag) {
        let (mut by_tag, mut servers) = (ByTag::new(), ByTag::new());
        if let Some(s) = self.live.running() {
            let tags = self.live.tags();
            for (id, l) in &self.links {
                let Some(r) = s.route(Some(id)).filter(|r| !r.imported()) else { continue };
                let Some(t) = tags.get(id).filter(|t| *t != TS_TAG) else { continue };
                by_tag.entry(t.clone()).or_default().push(id.clone());
                servers.entry(t.clone()).or_default().push(link_picker::server_key(r, l));
            }
        }
        (self.starts, by_tag, servers)
    }

    /// A health round's answers, judged: tunnels dead long enough to give another server (or, on Automatic, their
    /// provider's next port), if any.
    fn judge(&mut self, c: &mut Checks, r: &Round) -> Option<Move> {
        // Stopped, restarted or moved to another network meanwhile: this round says nothing (the next starts afresh).
        if self.phase() != Phase::On || self.starts != r.engine || self.net.network() != r.network {
            return None;
        }
        let failing = |c: &Checks| -> IndexSet<String> {
            c.streaks.keys().flat_map(|t| r.servers.get(t).into_iter().flatten().cloned()).collect()
        };
        let Some(down) = &r.down else {
            // Most likely the computer's own network: no server is blamed for these checks.
            if r.regular {
                c.streaks.clear();
                c.slow = (c.slow * 2).min(8);
            } else {
                for t in &r.checked {
                    c.streaks.remove(t);
                }
            }
            *self.live.failing.write().unwrap() = failing(c);
            return None;
        };
        if r.regular {
            c.slow = 1;
        }
        for t in &r.checked {
            let ok = !down.contains(t);
            let s = health::next(&c.streaks.get(t).copied().unwrap_or_default(), ok, r.now);
            if s.fails == 0 {
                c.streaks.remove(t);
            } else {
                c.streaks.insert(t.clone(), s);
                log::i(TAG, &format!("health: {t} failed {}x, {} s", s.fails, (r.now - s.since) / 1000));
            }
            // Quick re-checks don't count here: one outage would look like a tunnel that keeps dropping.
            if r.regular {
                let h = health::record(c.history.get(t).map_or(&[][..], Vec::as_slice), ok);
                c.history.insert(t.clone(), h);
            }
        }
        // The next connect, even a manual one, avoids them.
        *self.live.failing.write().unwrap() = failing(c);
        let dropping: IndexSet<String> = r
            .by_tag
            .iter()
            .filter(|(t, _)| health::dropping(c.history.get(*t).map_or(&[][..], Vec::as_slice)))
            .flat_map(|(_, ids)| ids.iter().cloned())
            .collect();
        if dropping != self.live.state.borrow().dropping {
            self.live.state.send_modify(|v| v.dropping = dropping);
        }
        let dead_tags: Vec<&String> =
            r.checked.iter().filter(|t| c.streaks.get(*t).is_some_and(|s| health::dead(s, r.now, c.hold(t)))).collect();
        if dead_tags.is_empty() {
            return None;
        }
        for t in &dead_tags {
            c.holds.insert((*t).clone(), r.now + health::COOLDOWN);
        }
        let dead: Vec<&String> =
            r.by_tag.iter().filter(|(t, _)| dead_tags.contains(t)).flat_map(|(_, ids)| ids).collect();
        let s = self.live.running()?;
        // A dead tunnel on Automatic also tries its provider's next port: a failed check can't tell a blocked port from a
        // dead server.
        let stepped: IndexSet<String> = dead
            .iter()
            .filter_map(|id| {
                let p = &s.route(Some(id))?.loc.provider;
                let ports = matches!(self.links.get(*id), Some(Link::Wg { ports, .. }) if ports.len() > 1);
                (ports && s.opt(p, PORT_OPT).as_deref() == Some(AUTO)).then(|| p.clone())
            })
            .collect();
        for p in &stepped {
            *self.port_step.entry(p.clone()).or_default() += 1;
        }
        let movable: Vec<&String> = dead
            .iter()
            .copied()
            .filter(|id| {
                s.route(Some(id))
                    .is_some_and(|r| r.loc.pinned.is_none() && r.loc.group.as_deref() != Some(DEDICATED_IP))
            })
            .collect();
        log::w(
            TAG,
            &format!("health: {} route(s) stopped answering, {} to move to another server", dead.len(), movable.len()),
        );
        Some(Move {
            keep: self
                .links
                .iter()
                .filter(|(id, _)| !movable.contains(id))
                .map(|(id, l)| (id.clone(), l.clone()))
                .collect(),
            avoid: movable
                .iter()
                .filter_map(|id| Some(link_picker::server_key(s.route(Some(id))?, self.links.get(*id)?)))
                .collect(),
            generation: self.generation,
            providers: dead.iter().filter_map(|id| s.route(Some(id)).map(|r| r.loc.provider.clone())).collect(),
            any_movable: !movable.is_empty() || !stepped.is_empty(),
        })
    }

    /// Tailscale's status: its sign-in link, state, exit nodes and tailnet domain for the window.
    fn watch_tailscale(&mut self) {
        let (mine, e, me) = (self.session, self.engine, self.me.clone());
        self.ts = Some(tokio::spawn(async move {
            // The subscription outlives engine reloads; one the engine drops (it restarted) comes back.
            loop {
                match e.tailscale_status().await {
                    Ok(mut updates) => loop {
                        match updates.message().await {
                            Ok(Some(u)) => {
                                if let Some(ep) = u.endpoints.into_iter().next() {
                                    let _ = me.send(Msg::Tailscale(mine, Box::new(ep)));
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                log::w(TAG, &format!("tailscale status: {}", redact::log(&e)));
                                break;
                            }
                        }
                    },
                    Err(e) => log::w(TAG, &format!("tailscale status: {}", redact::log(&e))),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
    }

    async fn tailscale(&mut self, ep: &TailscaleEndpointStatus) {
        let mut nodes: Vec<TsNode> = ep
            .user_groups
            .iter()
            .flat_map(|g| &g.peers)
            .filter(|p| p.exit_node_option && !p.tailscale_i_ps.is_empty())
            .map(|p| TsNode {
                name: if p.host_name.is_empty() {
                    p.dns_name.split('.').next().unwrap_or_default().into()
                } else {
                    p.host_name.clone()
                },
                ip: p.tailscale_i_ps[0].clone(),
                online: p.online,
                id: p.stable_id.clone(),
            })
            .collect();
        nodes.sort_by_key(|n| n.name.to_lowercase());
        let running = ep.backend_state == "Running";
        let suffix = compiler::ts_suffix(Some(&ep.magic_dns_suffix));
        let stored = self.store.ts_suffix();
        let (url, backend, reported) = (
            Some(ep.auth_url.clone()).filter(|u| !u.is_empty()),
            ep.backend_state.clone(),
            if running { suffix.clone() } else { stored.clone() },
        );
        self.live.state.send_modify(|v| {
            v.ts_login_url = url;
            v.ts_state = Some(backend);
            v.ts_exit_nodes = nodes;
            v.ts_suffix = reported;
        });
        // The sign-in pages' way around the exit opens with a sign-in link and closes only once signed in: a restarted
        // engine reports no link at first, which must not close it (each reload restarts Tailscale). Compared with what
        // the engine runs, so a reload that failed is tried again on the next status.
        self.ts_login_pending = ts_login::pending(&ep.auth_url, Some(&ep.backend_state), self.ts_login_pending);
        let mut reload = self.last_input.as_ref().is_some_and(|i| i.ts_login_pending != self.ts_login_pending);
        // A speed test that was cut off left Tailscale on its test node: put the configured one back.
        if running && self.store.ts_test_from().is_some() && !speed_test::testing() {
            speed_test::restore_node();
        }
        // The tailnet's own domain is only known once signed in: reload once so DNS routes it to Tailscale.
        if running && suffix != stored {
            let store = self.store.clone();
            blocking(move || store.set_ts_suffix(suffix.as_deref())).await;
            reload = true;
        }
        if reload {
            self.reload(Reload::default()).await;
        }
    }

    /// The engine's service: one that stops or fails while it runs ours (the system service restarted, a crash) is said
    /// once it stays stopped, since every reload stops and starts it too.
    fn watch_engine(&mut self) {
        cancel(&mut self.engine_watch);
        let (mine, up, e, me) = (self.session, self.engine_up.clone(), self.engine, self.me.clone());
        up.store(true, Ordering::SeqCst);
        self.engine_watch = Some(tokio::spawn(async move {
            // Looked at again 3 s later, by the connection.
            let lost = |error: Option<String>| {
                let me = me.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let _ = me.send(Msg::Lost(mine, error));
                });
            };
            loop {
                match e.service_status().await {
                    Ok(mut statuses) => loop {
                        match statuses.message().await {
                            Ok(Some(s)) => {
                                let running = engine::running(&s);
                                up.store(running, Ordering::SeqCst);
                                if !running {
                                    lost(Some(s.error_message));
                                }
                            }
                            Ok(None) => break,
                            Err(_) => {
                                up.store(false, Ordering::SeqCst);
                                lost(None);
                                break;
                            }
                        }
                    },
                    Err(_) => {
                        up.store(false, Ordering::SeqCst);
                        lost(None);
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }));
    }

    /// The engine stopped on its own while connection `mine` ran: said, like a failed connect, unless it came back, is
    /// being restarted, or that connection already ended.
    async fn lost(&mut self, mine: i32, error: Option<String>) {
        if self.engine_up.load(Ordering::SeqCst) || self.restarting || self.session != mine || self.phase() != Phase::On
        {
            return;
        }
        let why = match error.filter(|e| !e.trim().is_empty()) {
            Some(e) => format!("The unbraid engine stopped: {}", redact::clean(&e)),
            None => format!("The unbraid engine stopped, so {APP}'s connection ended."),
        };
        self.teardown(Some(why)).await;
    }

    /// Stops the engine and the tunnel; the connection's task stays. When the engine may still run them (its stop
    /// failed) while on, `keep` leaves the connection as it is, says why and returns false: a disconnect or a pause
    /// never shows off or paused while traffic may still go through the tunnel.
    async fn stop_engine(&mut self, keep: bool) -> bool {
        if let Err(e) = self.engine.stop().await {
            log::e(TAG, &format!("stop: {}", redact::log(&e)));
            if keep && self.phase() == Phase::On {
                self.live.state.send_modify(|v| v.error = Some(NOT_STOPPED.into()));
                alert(&format!("{APP} is still on"), NOT_STOPPED);
                return false;
            }
        }
        cancel(&mut self.watch);
        cancel(&mut self.health);
        self.generation += 1;
        self.session += 1;
        cancel(&mut self.retry);
        self.retries = 0;
        self.retrying.clear();
        self.net.set_on_change(None);
        self.refusals.clear();
        self.gone.clear();
        self.live.failing.write().unwrap().clear();
        cancel(&mut self.ts);
        cancel(&mut self.engine_watch);
        self.ts_login_pending = false;
        self.table_open = false;
        self.net.stop();
        self.applied = None;
        self.rejected = None;
        self.last_good = None;
        self.last_input = None;
        self.live.set_probe(None);
        self.links.clear();
        self.applied_accounts.clear();
        *self.live.running.write().unwrap() = None;
        self.live.tags.write().unwrap().clear();
        self.live.tunnel_dns.write().unwrap().clear();
        true
    }

    /// Ends the connection, with `error` if it failed. A disconnect or a quit (no error) keeps a connection the engine
    /// didn't stop ([`Session::stop_engine`]); one that failed or was lost ends all the same.
    async fn teardown(&mut self, error: Option<String>) {
        if !self.stop_engine(error.is_none()).await {
            return;
        }
        cancel(&mut self.resume);
        self.live.state.send_replace(VpnState { error: error.clone(), ..VpnState::default() });
        self.live.summary.send_replace(String::new());
        // A failure in the background (a resume after a pause, a revoked account) must not pass unnoticed.
        if let Some(e) = error {
            alert(&format!("{APP} is off"), &e);
        }
    }

    /// Traffic leaves without the VPN until resumed, by hand or after `minutes`.
    async fn pause_now(&mut self, minutes: i32) {
        if self.phase() != Phase::On || !self.stop_engine(true).await {
            return;
        }
        self.pauses += 1;
        let pause = self.pauses;
        let ms = i64::from(minutes) * 60_000;
        let until = if minutes > 0 { now_ms() + ms } else { 0 };
        // Short steps against the clock that counts suspend: a single sleep doesn't count while the computer sleeps.
        if until > 0 {
            let (wake, me) = (clock::elapsed_realtime() + ms, self.me.clone());
            self.resume = Some(tokio::spawn(async move {
                while clock::elapsed_realtime() < wake {
                    tokio::time::sleep(Duration::from_millis(
                        (wake - clock::elapsed_realtime()).clamp(1, 15_000) as u64
                    ))
                    .await;
                }
                let _ = me.send(Msg::Resume(pause));
            }));
        }
        self.live.summary.send_replace(paused_text(until));
        self.live.state.send_replace(VpnState {
            phase: Phase::Paused,
            paused_until: until,
            paused_at: now_ms(),
            ..VpnState::default()
        });
    }

    /// What the tray and the command line show of the running connection.
    fn notify(&self, setup: &Setup) {
        self.live.summary.send_replace(summary(setup));
    }
}

/// Checks each provider tunnel the app can move ([`health`]) about once a minute. One that fails is checked again 10 s
/// and 20 s later, then once more a minute after its first failure: WireGuard and OpenVPN usually come back on their own
/// server within that minute. Still failing, it gets another server of its location. A round where every tunnel fails
/// while the computer's own network does too is most likely that network: no server is blamed, and checks slow down (up
/// to every ~8 min) until one works again. Nothing is judged for a while after a new network, an engine start or a
/// sleep. What it decides, it decides on the connection's task ([`locked`]).
async fn watch_health(me: Inbox, live: &'static Live, net: Arc<NetMonitor>, store: Arc<Store>) {
    let mut c = Checks { slow: 1, ..Checks::default() };
    let mut grace = clock::elapsed_realtime() + health::GRACE; // no check before this
    let mut round = clock::elapsed_realtime() + jitter(); // the next regular round
    let mut basis: Option<(i32, Option<String>)> = None; // the engine start and network the streaks are about
    loop {
        let wake = grace.max(c.streaks.iter().filter_map(|(t, s)| health::due(s, c.hold(t))).fold(round, i64::min));
        let slept = asleep();
        // At least 5 s, then in slices: waits don't count deep sleep, and a sleep, an engine start or a new network
        // ends one early.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            let (now, engine) = (clock::elapsed_realtime(), live.state.borrow().engine);
            if now >= wake || asleep() - slept >= health::SLEPT || basis != Some((engine, net.network())) {
                break;
            }
            tokio::time::sleep(Duration::from_millis((wake - now).clamp(1, 15_000) as u64)).await;
        }
        let mut now = clock::elapsed_realtime();
        c.holds.retain(|_, h| *h > now);
        // A sleep in between (the lid closed) says nothing about the servers.
        if asleep() - slept >= health::SLEPT {
            grace = c.restart(live, now);
            round = grace;
            continue;
        }
        let network = net.network();
        let on = live.state.borrow().phase == Phase::On;
        if !on || network.is_none() || speed_test::testing() {
            if now >= round {
                round = now + jitter();
            }
            continue;
        }
        // Ports Automatic learned on another network don't hold here: back to each provider's first port.
        let n = network.clone();
        match locked(&me, move |s| s.new_network(n)).await {
            None => return,
            Some(true) => {
                let _ = me.send(Msg::Reload(Reload::default()));
                continue;
            }
            Some(false) => {}
        }
        let Some((engine, by_tag, servers)) = locked(&me, |s| s.checked_tags()).await else { return };
        // Restarted tunnels or another network: earlier checks don't carry over, and the new ones get time to settle.
        if basis.as_ref() != Some(&(engine, network.clone())) {
            let first = basis.is_none();
            basis = Some((engine, network.clone()));
            if !first {
                c.slow = 1;
                grace = c.restart(live, now);
                round = grace;
                continue;
            }
        }
        if now < grace {
            continue;
        }
        let regular = now >= round;
        // A provider whose new key is still reaching its servers isn't judged yet.
        let setting_up = providers::setting_up(now_ms());
        let running = live.running();
        let settling = |id: &String| {
            running.as_ref().and_then(|s| s.route(Some(id))).is_some_and(|r| setting_up.contains(&r.loc.provider))
        };
        // A regular round checks every tunnel, a quick one only those due again.
        let due = |t: &String| c.streaks.get(t).and_then(|s| health::due(s, c.hold(t))).is_some_and(|d| d <= now);
        let checked: IndexSet<String> = by_tag
            .iter()
            .filter(|(t, ids)| !ids.iter().any(settling) && (regular || due(t)))
            .map(|(t, _)| t.clone())
            .collect();
        if checked.is_empty() {
            if regular {
                round = now + jitter() * c.slow;
            }
            continue;
        }
        let answered = reachable(&checked).await;
        let failed: IndexSet<String> = checked.iter().filter(|t| answered.get(*t) != Some(&true)).cloned().collect();
        let down = health::blame(failed, &checked, async || health::direct(network.as_deref()).await).await;
        now = clock::elapsed_realtime();
        if asleep() - slept >= health::SLEPT {
            grace = c.restart(live, now);
            round = grace;
            continue;
        }
        let r = Round { engine, network, regular, checked, down, now, by_tag, servers };
        let judged = locked(&me, move |s| {
            let mut c = c;
            let m = s.judge(&mut c, &r);
            (c, m)
        });
        let Some((back, moved)) = judged.await else { return };
        c = back;
        if regular {
            round = now + jitter() * c.slow;
        }
        let Some(m) = moved else { continue };
        // A dead tunnel can mean the provider dropped this computer (its device removed on its website).
        let accounts = store.current_accounts();
        let (all, ps) = (accounts.clone(), m.providers.clone());
        let dropped: Vec<String> = blocking(move || {
            ps.into_iter()
                .filter(|p| all.get(p).is_some_and(|a| providers::get(p).is_some_and(|x| x.revoked(a))))
                .collect()
        })
        .await;
        if !dropped.is_empty() {
            let d = dropped.clone();
            locked(&me, move |s| s.dropped(&d, &accounts)).await;
        }
        // The newest setup, not the running one: a change still waiting to apply must never be undone here.
        if m.any_movable || !dropped.is_empty() {
            let _ = me.send(Msg::Reload(Reload { keep: Some(m.keep), avoid: m.avoid, keep_from: m.generation }));
        }
    }
}

/// Each tunnel's health check, four at a time.
async fn reachable(tags: &IndexSet<String>) -> HashMap<String, bool> {
    let gate = Arc::new(tokio::sync::Semaphore::new(4));
    let mut checks = JoinSet::new();
    for t in tags.iter().cloned() {
        let gate = gate.clone();
        checks.spawn(async move {
            let _turn = gate.acquire().await;
            let ok = health::reachable(&t).await;
            (t, ok)
        });
    }
    checks.join_all().await.into_iter().collect()
}

/// Edits to the setup and sign-ins and sign-outs, once they stop for 400 ms.
async fn watch_edits(store: Arc<Store>, me: Inbox) {
    let (mut setup, mut accounts) = (store.setup(), store.accounts());
    loop {
        while tokio::time::timeout(Duration::from_millis(400), changed(&mut setup, &mut accounts)).await.is_ok() {}
        let edit = (setup.borrow_and_update().clone(), accounts.borrow_and_update().clone());
        if me.send(Msg::Edited(Box::new(edit))).is_err() {
            return;
        }
        changed(&mut setup, &mut accounts).await;
    }
}

async fn changed(setup: &mut watch::Receiver<Setup>, accounts: &mut watch::Receiver<IndexMap<String, String>>) {
    tokio::select! {
        _ = setup.changed() => {}
        _ = accounts.changed() => {}
    }
}

/// Engine errors can quote the config, keys included: logged cleaned, shown as a fixed text, the cause dropped.
fn engine<T, E: std::error::Error + 'static>(r: std::result::Result<T, E>, failure: &str) -> Result<T> {
    r.map_err(|e| {
        log::e(TAG, &format!("engine: {}", redact::log(&e)));
        let missing = (&e as &dyn std::error::Error).downcast_ref::<tonic::Status>().is_some_and(engine::missing);
        Error::Fail(if missing { engine::MISSING.into() } else { failure.into() })
    })
}

/// Compiles `i` and makes it the Linux engine's config, off the async threads (it may read the apps' entries).
async fn compile(i: &Input, own: &Option<String>) -> Result<String> {
    let (i, own) = (i.clone(), own.clone());
    blocking(move || {
        let routed: Vec<&str> = i.setup.apps.keys().map(String::as_str).collect();
        Ok(linux_pass::config(&compiler::compile(&i)?, |key| apps::matchers(key, &routed), own.as_deref()))
    })
    .await
}

/// The app's own way into each exit ([`compiler::PROBE`]): a free loopback port and a 24-byte random password.
fn new_probe() -> Result<(u16, String)> {
    let port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?.local_addr()?.port();
    Ok((port, URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>())))
}

/// Blocking work (providers, files, the apps' entries) off the async threads, waited for.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

fn cancel(job: &mut Option<JoinHandle<()>>) {
    if let Some(j) = job.take() {
        j.abort();
    }
}

fn servers(links: &IndexMap<String, Link>) -> IndexMap<String, Server> {
    links.iter().map(|(id, l)| (id.clone(), l.server().clone())).collect()
}

/// A route still waits for its provider to give it a server.
fn waits(p: &Picked) -> bool {
    p.blocked.values().any(link_picker::waiting)
}

/// Providers of `blocked` routes, and whether one refused its account.
fn stuck(setup: &Setup, blocked: &IndexMap<String, Error>) -> IndexMap<String, bool> {
    let mut out = IndexMap::<String, bool>::new();
    for (id, e) in blocked {
        if let Some(r) = setup.route(Some(id)).filter(|r| !r.imported()) {
            *out.entry(r.loc.provider.clone()).or_default() |= matches!(e, Error::Auth { .. });
        }
    }
    out
}

/// One line for Routes: which routes' apps are blocked and why.
fn blocked_text(setup: &Setup, blocked: &IndexMap<String, Error>) -> Option<String> {
    let (_, e) = blocked.first()?;
    let names: Vec<String> =
        blocked.keys().map(|id| setup.route(Some(id)).map_or_else(|| id.clone(), |r| r.name())).collect();
    Some(format!("Apps on {} are blocked: {}", names.join(", "), redact::message(e, "no connection")))
}

/// One line on what runs: each active route's code with "default" or its number of apps.
fn summary(setup: &Setup) -> String {
    let line = setup
        .active_routes()
        .iter()
        .map(|r| {
            if r.id == setup.default_route {
                format!("{} default", r.code())
            } else {
                format!("{} {}", r.code(), setup.apps.values().filter(|v| **v == r.id).count())
            }
        })
        .collect::<Vec<_>>()
        .join("  ·  ");
    if line.is_empty() { "Only selected apps".into() } else { line }
}

/// The summary while paused: until when, as the desktop's clock shows it, or only "Paused" until resumed by hand.
fn paused_text(until: i64) -> String {
    if until <= 0 {
        return "Paused".into();
    }
    let at = chrono::DateTime::from_timestamp_millis(until)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M").to_string())
        .unwrap_or_default();
    format!("Paused until {at}")
}

fn alert(title: &str, text: &str) {
    // Unit tests end connections on purpose: they never reach the desktop.
    if !cfg!(test) {
        desktop::notify(title, text);
    }
}

/// What a disconnect or a pause says when the engine didn't stop.
const NOT_STOPPED: &str = "The unbraid engine didn't stop, so the connection is still on. Try again, or restart the engine: sudo systemctl restart unbraid-engine";

/// Statistics take up the engine's connections again: it numbers them afresh, against the tunnels it runs now.
fn retime() {
    stats::post(|w| {
        w.retime_now();
        Ok(())
    });
}

/// A regular round's wait: about a minute, spread so tunnels of many computers don't line up.
fn jitter() -> i64 {
    48_000 + rand::random_range(0..24_000)
}

/// How long the computer has slept since boot: it grows only while it sleeps.
fn asleep() -> i64 {
    clock::elapsed_realtime() - clock::uptime_millis()
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Profile switches, from the window, the tray or the command line alike, followed until the engine runs them.
pub mod profiles {
    use super::{Phase, VpnState, blocking, live, setup_hash, switch_done};
    use crate::model::Setup;
    use crate::store::Store;
    use std::sync::{Arc, LazyLock};
    use tokio::sync::watch;

    /// A switch to profile `to` the engine refused; `kept` is the profile still in use.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Refused {
        pub to: String,
        pub kept: Option<String>,
    }

    static SWITCHING: LazyLock<watch::Sender<Option<String>>> = LazyLock::new(watch::Sender::default);
    static REFUSED: LazyLock<watch::Sender<Option<Refused>>> = LazyLock::new(watch::Sender::default);

    /// The profile being switched to, until the engine runs it.
    pub fn switching() -> &'static watch::Sender<Option<String>> {
        &SWITCHING
    }

    /// The last switch the engine refused, until the next one starts (or the window lets it go).
    pub fn refused() -> &'static watch::Sender<Option<Refused>> {
        &REFUSED
    }

    /// A switch to `to` was saved: followed while the engine runs.
    pub fn started(to: &str) {
        REFUSED.send_replace(None);
        if live().state.borrow().phase == Phase::On {
            SWITCHING.send_replace(Some(to.into()));
        }
    }

    /// Done once the engine runs the saved setup; refused, the setup it still runs comes back into the app. Call it
    /// inside the async runtime.
    pub(crate) fn watch(store: Arc<Store>) {
        let (mut state, mut setup, mut to) = (live().state.subscribe(), store.setup(), SWITCHING.subscribe());
        tokio::spawn(async move {
            loop {
                let v = state.borrow_and_update().clone();
                look(&v, &store, live().running()).await;
                tokio::select! {
                    _ = state.changed() => {}
                    _ = setup.changed() => {}
                    _ = to.changed() => {}
                }
            }
        });
    }

    /// A look at the switch under way, with the connection as `v` shows it and `running` what the engine runs.
    pub(super) async fn look(v: &VpnState, store: &Arc<Store>, running: Option<Setup>) {
        let Some(to) = SWITCHING.borrow().clone() else { return };
        let Some(done) = switch_done(v, setup_hash(&store.current())) else { return };
        SWITCHING.send_replace(None);
        if done {
            return;
        }
        if let Some(ran) = running {
            let st = store.clone();
            blocking(move || st.update(|s| s.back(&ran))).await;
        }
        REFUSED.send_replace(Some(Refused { to, kept: store.current().profile }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DIRECT, Location, Profile, Route, WgPeer};
    use std::path::Path;

    fn base() -> Setup {
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route::new("us", Location::country("nord", 228, "US", "United States")),
                Route::new("it", Location::country("nord", 106, "IT", "Italy")),
            ],
            default_route: "nl".into(),
            apps: [("netflix".to_string(), "us".to_string())].into_iter().collect(),
            ..Setup::default()
        }
    }

    fn state(phase: Phase, applied: u64, refused: u64) -> VpnState {
        VpnState { phase, applied, refused, ..Default::default() }
    }

    /// A switch is done once the engine runs that exact setup in full, undone once it refused it, and waits otherwise.
    #[test]
    fn switch_outcome() {
        let h = setup_hash(&base().save_as("Home"));
        assert_eq!(Some(true), switch_done(&state(Phase::On, h, 0), h));
        assert_eq!(Some(false), switch_done(&state(Phase::On, 1, h), h));
        assert_eq!(None, switch_done(&state(Phase::On, 1, 2), h)); // still waiting (e.g. a server being found)
        assert_eq!(None, switch_done(&state(Phase::On, 0, 0), h));
        assert_eq!(Some(true), switch_done(&state(Phase::Paused, 0, 0), h)); // nothing runs: nothing to wait for
        assert_eq!(Some(true), switch_done(&state(Phase::Off, 0, h), h));
    }

    /// The hash a switch waits for survives saving and loading (it compares a fresh copy with the one in memory).
    #[test]
    fn hash_survives_saving() {
        let s = base().save_as("Home").save_as("Travel");
        let again: Setup = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(setup_hash(&s), setup_hash(&again));
        // Equal setups hash alike whatever order their apps were added in.
        let mut a = base();
        a.apps.insert("bank".into(), DIRECT.into());
        let mut b = base();
        b.apps.shift_remove("netflix");
        b.apps.insert("bank".into(), DIRECT.into());
        b.apps.insert("netflix".into(), "us".into());
        assert_eq!(a, b);
        assert_eq!(setup_hash(&a), setup_hash(&b));
    }

    /// With nothing waiting, the phase decides: connecting already counts as on.
    #[test]
    fn phase_decides_without_request() {
        assert!(vpn_on(Phase::On, None));
        assert!(vpn_on(Phase::Connecting, None));
        assert!(!vpn_on(Phase::Off, None));
        assert!(!vpn_on(Phase::Paused, None));
    }

    /// A second quick tap undoes the first: a start not yet handled reads as on, a stop or pause as off.
    #[test]
    fn waiting_request_wins() {
        assert!(vpn_on(Phase::Off, Some(Ask { n: 1, on: true })));
        assert!(vpn_on(Phase::Paused, Some(Ask { n: 1, on: true })));
        assert!(!vpn_on(Phase::On, Some(Ask { n: 2, on: false })));
        assert!(!vpn_on(Phase::Connecting, Some(Ask { n: 2, on: false })));
    }

    fn test_store(dir: &Path) -> Arc<Store> {
        Store::new(dir, Box::new(|| Ok([7; 32])))
    }

    /// A connection with its own store and published state, and an engine that isn't there: nothing listens on its
    /// socket and its program is missing, so starts fail as they would without one.
    fn session(dir: &Path) -> Session {
        let engine = Box::leak(Box::new(Engine::new(&dir.join("engine.sock"), &dir.join("unbraid-engine"), dir)));
        let (me, _) = mpsc::unbounded_channel();
        Session::new(Box::leak(Box::default()), test_store(dir), engine, me)
    }

    /// As if `setup` had connected.
    fn connected(s: &mut Session, setup: &Setup) {
        s.store.update(|_| setup.clone());
        s.live.state.send_replace(VpnState {
            phase: Phase::On,
            since: now_ms(),
            engine: s.starts,
            ..VpnState::default()
        });
        *s.live.running.write().unwrap() = Some(setup.clone());
        s.applied = Some(setup.clone());
    }

    const REJECTED: &str = "The connection engine rejected this setup.";

    /// Each command's effect on the phase: with nothing running a pause does nothing and a stop just says off; a start
    /// the engine refuses ends off with why; a repeated start only refreshes the summary; a stop ends without an error.
    #[tokio::test]
    async fn commands_drive_the_phase() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        s.handle(Cmd::Pause(1, 5)).await;
        assert_eq!(VpnState::default(), s.live.state());
        s.handle(Cmd::Stop(2)).await;
        assert_eq!(VpnState::default(), s.live.state());
        s.handle(Cmd::Start(3)).await;
        let v = s.live.state();
        assert_eq!((Phase::Off, Some(REJECTED)), (v.phase, v.error.as_deref()));
        assert!(
            s.live.running().is_none()
                && s.live.probe().is_none()
                && s.live.tags().is_empty()
                && s.live.summary.borrow().is_empty()
        );
        connected(&mut s, &base());
        s.handle(Cmd::Start(4)).await;
        assert_eq!(Phase::On, s.phase());
        assert_eq!("NL default  ·  US 1", *s.live.summary.borrow());
        s.handle(Cmd::Stop(5)).await;
        assert_eq!(VpnState::default(), s.live.state());
        assert!(s.live.summary.borrow().is_empty() && s.live.running().is_none());
    }

    /// A pause drops the tunnel until resumed: by hand, or after its minutes by its own timer only.
    #[tokio::test]
    async fn pause_and_resume() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        connected(&mut s, &base());
        let before = now_ms();
        s.handle(Cmd::Pause(1, 15)).await;
        let v = s.live.state();
        assert_eq!(Phase::Paused, v.phase);
        assert!(v.paused_at >= before && v.paused_at <= now_ms());
        assert!((v.paused_until - v.paused_at - 15 * 60_000).abs() < 1_000);
        let at = s.live.summary.borrow().strip_prefix("Paused until ").unwrap().to_string();
        assert!(at.len() == 5 && at.as_bytes()[2] == b':', "{at}");
        assert!(s.resume.is_some() && s.live.running().is_none());
        // Paused already: another pause changes nothing.
        s.handle(Cmd::Pause(2, 5)).await;
        assert_eq!(v, s.live.state());
        // An earlier pause's timer doesn't resume this one; its own does (and with no engine here, ends off).
        s.on(Msg::Resume(s.pauses - 1)).await;
        assert_eq!(Phase::Paused, s.phase());
        s.on(Msg::Resume(s.pauses)).await;
        assert_eq!((Phase::Off, Some(REJECTED.into())), (s.phase(), s.live.state().error));
        assert!(s.resume.is_none());
        // Until resumed by hand: no timer; a stop ends it, a start resumes it.
        connected(&mut s, &base());
        s.handle(Cmd::Pause(3, 0)).await;
        assert_eq!(
            (Phase::Paused, 0, "Paused"),
            (s.phase(), s.live.state().paused_until, s.live.summary.borrow().as_str())
        );
        assert!(s.resume.is_none());
        s.handle(Cmd::Stop(4)).await;
        assert_eq!(VpnState::default(), s.live.state());
        connected(&mut s, &base());
        s.handle(Cmd::Pause(5, 0)).await;
        s.handle(Cmd::Start(6)).await;
        assert_eq!((Phase::Off, Some(REJECTED.into())), (s.phase(), s.live.state().error));
    }

    /// A disconnect or a pause whose engine didn't stop (here one that takes the call and never answers) leaves the
    /// connection on and says so, rather than showing off or paused while traffic may still go through the tunnel. A
    /// connection that failed or was lost ends all the same.
    #[tokio::test(start_paused = true)]
    async fn a_stop_the_engine_fails_keeps_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        connected(&mut s, &base());
        let _deaf = std::os::unix::net::UnixListener::bind(dir.path().join("engine.sock")).unwrap();
        s.handle(Cmd::Pause(1, 15)).await;
        assert_eq!((Phase::On, Some(NOT_STOPPED)), (s.phase(), s.live.state().error.as_deref()));
        assert!(s.resume.is_none() && s.live.running().is_some());
        s.handle(Cmd::Stop(2)).await;
        assert_eq!((Phase::On, Some(NOT_STOPPED)), (s.phase(), s.live.state().error.as_deref()));
        s.teardown(Some("Connection lost".into())).await;
        assert_eq!((Phase::Off, Some("Connection lost")), (s.phase(), s.live.state().error.as_deref()));
        assert!(s.live.running().is_none());
    }

    /// What the tray and the command line say of the connection, and what Routes says of blocked routes.
    #[test]
    fn summary_and_blocked_texts() {
        let mut s = base();
        s.apps.insert("spotify".into(), "us".into());
        assert_eq!("NL default  ·  US 2", summary(&s));
        s.testing.insert("it".into()); // up only for a speed test
        assert_eq!("NL default  ·  US 2  ·  IT 0", summary(&s));
        assert_eq!(
            "Only selected apps",
            summary(&Setup { default_route: DIRECT.into(), apps: IndexMap::new(), ..base() })
        );
        assert_eq!("Paused", paused_text(0));
        let auth = || Error::Auth { message: "Sign in to NordVPN for Netherlands".into(), url: None };
        let blocked: IndexMap<String, Error> =
            [("nl".to_string(), auth()), ("us".to_string(), Error::Io("connect timed out".into()))]
                .into_iter()
                .collect();
        assert_eq!(
            Some("Apps on Netherlands, United States are blocked: Sign in to NordVPN for Netherlands".into()),
            blocked_text(&base(), &blocked)
        );
        let io: IndexMap<String, Error> =
            [("us".to_string(), Error::Io("connect timed out".into()))].into_iter().collect();
        assert_eq!(
            Some("Apps on United States are blocked: Couldn't reach the server. Check the connection.".into()),
            blocked_text(&base(), &io)
        );
        assert_eq!(None, blocked_text(&base(), &IndexMap::new()));
        // Providers with blocked routes, and whether one refused its account; an imported route has no provider.
        let mut s = base();
        s.routes.push(Route {
            wg: Some(WgPeer::new("Home", "k", vec![], "p", "h.example:51820", vec![])),
            ..Route::new("wg", Location::of("nord"))
        });
        s.apps.insert("ssh".into(), "wg".into());
        let mut b = io.clone();
        b.insert("wg".into(), Error::Fail("unreachable".into()));
        assert_eq!(IndexMap::from([("nord".to_string(), false)]), stuck(&s, &b));
        b.insert("nl".into(), auth());
        assert_eq!(IndexMap::from([("nord".to_string(), true)]), stuck(&s, &b));
    }

    /// Engine failures show a fixed text, or how to start a missing engine. An engine that stops on its own ends the
    /// connection with what it said, unless it came back or that connection already ended.
    #[tokio::test]
    async fn engine_failures_and_losses() {
        let failed = |e: tonic::Status| {
            engine::<(), _>(Err(e), "The connection engine couldn't start.").unwrap_err().to_string()
        };
        assert_eq!(engine::MISSING, failed(tonic::Status::unavailable("connect: no such file")));
        assert_eq!(
            "The connection engine couldn't start.",
            failed(tonic::Status::invalid_argument("private_key: \"aGVsbG8=\""))
        );
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        connected(&mut s, &base());
        s.engine_up.store(true, Ordering::SeqCst);
        s.lost(s.session, None).await;
        s.engine_up.store(false, Ordering::SeqCst);
        s.lost(s.session - 1, None).await;
        assert_eq!(Phase::On, s.phase());
        s.lost(s.session, Some(" ".into())).await;
        assert_eq!(Some(format!("The unbraid engine stopped, so {APP}'s connection ended.")), s.live.state().error);
        connected(&mut s, &base());
        s.lost(s.session, Some("start tun: operation not permitted".into())).await;
        assert_eq!(Some("The unbraid engine stopped: start tun: operation not permitted".into()), s.live.state().error);
    }

    /// An edit the engine refuses leaves what runs, says why and marks that setup refused; the same edit isn't tried
    /// again, and moving off it clears the refusal.
    #[tokio::test]
    async fn refused_edits_wait_for_the_next() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        let setup = base();
        connected(&mut s, &setup);
        s.store.update(|_| Setup { default_route: "us".into(), ..setup.clone() });
        let edit = |store: &Store| Msg::Edited(Box::new((store.current(), store.current_accounts())));
        s.on(edit(&s.store)).await;
        let v = s.live.state();
        assert_eq!(
            (Phase::On, Some(REJECTED), setup_hash(&s.store.current())),
            (v.phase, v.error.as_deref(), v.refused)
        );
        assert_eq!(Some(&setup), s.applied.as_ref());
        assert!(s.rejected.is_some());
        s.store.update(|_| setup.clone());
        s.on(edit(&s.store)).await;
        assert_eq!(0, s.live.state().refused);
        assert!(s.rejected.is_none());
    }

    /// A dead tunnel moves to another server of its location; on Automatic it also tries its provider's next port, which
    /// a new network takes back. A pinned route is checked but never moved.
    #[tokio::test]
    async fn dead_tunnels_move_and_step_ports() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        let pin = Server {
            name: "ch-zrh-wg-001".into(),
            host: "ch-zrh-wg-001".into(),
            ip: "193.32.127.66".into(),
            ..Server::default()
        };
        let setup = Setup {
            routes: vec![
                Route::new("se", Location::country("mullvad", 1, "SE", "Sweden")),
                Route::new(
                    "ch",
                    Location { pinned: Some(pin), ..Location::country("mullvad", 2, "CH", "Switzerland") },
                ),
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
            ],
            default_route: "se".into(),
            apps: [("firefox".to_string(), "ch".to_string()), ("mpv".to_string(), "nl".to_string())]
                .into_iter()
                .collect(),
            ..Setup::default()
        };
        let wg = |ip: &str, ports: Vec<i32>| Link::Wg {
            server: Server { name: ip.into(), host: ip.into(), ip: ip.into(), ..Server::default() },
            peer: WgPeer::new(
                "x",
                "k",
                vec!["10.64.0.2/32".into()],
                "p",
                &format!("{ip}:51820"),
                vec!["0.0.0.0/0".into()],
            ),
            ports,
            entries: vec![],
        };
        s.links = IndexMap::from([
            ("se".into(), wg("185.65.134.1", vec![51820, 53, 443])),
            ("ch".into(), wg("193.32.127.66", vec![51820, 53])),
            ("nl".into(), wg("194.0.0.1", vec![51820, 443])),
        ]);
        connected(&mut s, &setup);
        *s.live.tags.write().unwrap() =
            IndexMap::from([("se".into(), "r-se".into()), ("ch".into(), "r-ch".into()), ("nl".into(), "r-nl".into())]);
        let (engine, by_tag, servers) = s.checked_tags();
        assert_eq!(vec!["mullvad|193.32.127.66".to_string()], servers["r-ch"]);
        // Every tunnel has failed for over a minute; this is its fourth failed check.
        let now = 10_000_000;
        let mut c = Checks { slow: 1, ..Checks::default() };
        for t in by_tag.keys() {
            c.streaks.insert(t.clone(), Streak { fails: 3, since: now - 61_000, last: now - 20_000 });
        }
        let checked: IndexSet<String> = by_tag.keys().cloned().collect();
        let r = Round {
            engine,
            network: None,
            regular: false,
            checked: checked.clone(),
            down: Some(checked),
            now,
            by_tag,
            servers,
        };
        let m = s.judge(&mut c, &r).unwrap();
        assert_eq!(vec!["ch"], m.keep.keys().collect::<Vec<_>>());
        assert_eq!(IndexSet::from(["mullvad|185.65.134.1".to_string(), "nord|194.0.0.1".to_string()]), m.avoid);
        assert_eq!(IndexSet::from(["mullvad".to_string(), "nord".to_string()]), m.providers);
        assert!(m.any_movable);
        assert_eq!(3, s.live.failing().len());
        assert!(c.holds.values().all(|h| *h == now + health::COOLDOWN));
        // Mullvad is on Automatic, with more ports: its tunnels take the next one. NordVPN has no port setting here.
        assert_eq!(IndexMap::from([("mullvad".to_string(), 1)]), s.port_step);
        let input = s.input(&setup, &s.links.clone(), &IndexSet::new(), None, false);
        let endpoint = |id: &str| match &input.links[id] {
            Link::Wg { peer, .. } => peer.endpoint.clone(),
            _ => unreachable!(),
        };
        assert_eq!(("185.65.134.1:53".to_string(), "194.0.0.1:51820".to_string()), (endpoint("se"), endpoint("nl")));
        // Another network: back to each provider's first port.
        assert!(s.new_network(Some("wlp2s0 192.168.1.1".into())));
        assert!(s.port_step.is_empty());
        assert!(!s.new_network(Some("wlp2s0 192.168.1.1".into())));
    }

    /// Tailscale's status: its sign-in link while it waits for one, its exit nodes by name, and once signed in its
    /// tailnet's domain, kept for the next start.
    #[tokio::test]
    async fn tailscale_status_is_shown() {
        use crate::engine_api::daemon::{TailscalePeer, TailscaleUserGroup};
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        let peer = |host: &str, dns: &str, ip: Option<&str>, exit: bool, online: bool, id: &str| TailscalePeer {
            host_name: host.into(),
            dns_name: dns.into(),
            tailscale_i_ps: ip.map(|i| vec![i.to_string()]).unwrap_or_default(),
            exit_node_option: exit,
            online,
            stable_id: id.into(),
            ..TailscalePeer::default()
        };
        let peers = vec![
            peer("", "pi.tail1234.ts.net.", Some("100.64.0.6"), true, true, "nPi"),
            peer("laptop", "", Some("100.64.0.7"), false, true, "nLaptop"),
            peer("NAS", "", Some("100.64.0.5"), true, false, "nNas"),
            peer("phone", "", None, true, true, "nPhone"),
        ];
        let mut ep = TailscaleEndpointStatus {
            backend_state: "NeedsLogin".into(),
            auth_url: "https://login.tailscale.com/a/1a2b3c".into(),
            user_groups: vec![TailscaleUserGroup { peers, ..TailscaleUserGroup::default() }],
            ..TailscaleEndpointStatus::default()
        };
        s.tailscale(&ep).await;
        let v = s.live.state();
        assert_eq!(
            (Some("https://login.tailscale.com/a/1a2b3c"), Some("NeedsLogin")),
            (v.ts_login_url.as_deref(), v.ts_state.as_deref())
        );
        let node = |name: &str, ip: &str, online: bool, id: &str| TsNode {
            name: name.into(),
            ip: ip.into(),
            online,
            id: id.into(),
        };
        assert_eq!(
            vec![node("NAS", "100.64.0.5", false, "nNas"), node("pi", "100.64.0.6", true, "nPi")],
            v.ts_exit_nodes
        );
        assert!(s.ts_login_pending);
        ep.backend_state = "Running".into();
        ep.auth_url.clear();
        ep.magic_dns_suffix = "Tail1234.ts.net.".into();
        s.tailscale(&ep).await;
        let v = s.live.state();
        assert_eq!((None, Some("tail1234.ts.net")), (v.ts_login_url.as_deref(), v.ts_suffix.as_deref()));
        assert!(!s.ts_login_pending);
        assert_eq!(Some("tail1234.ts.net".into()), s.store.ts_suffix());
    }

    /// Work that needs the VPN off runs only while it is.
    #[tokio::test]
    async fn while_stopped_runs_only_when_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = session(dir.path());
        let (tx, rx) = oneshot::channel();
        s.on(Msg::WhileStopped(Box::pin(async move {
            let _ = tx.send(1);
        })))
        .await;
        assert_eq!(Ok(1), rx.await);
        connected(&mut s, &base());
        let (tx, rx) = oneshot::channel::<i32>();
        s.on(Msg::WhileStopped(Box::pin(async move {
            let _ = tx.send(2);
        })))
        .await;
        assert!(rx.await.is_err());
    }

    /// The newest request shows as asked until the connection has handled it, or a later one.
    #[test]
    fn asked_until_handled() {
        let live = Live::default();
        live.asked.send_replace(Some(Ask { n: 3, on: true }));
        handled(&live, 0);
        handled(&live, 2);
        assert_eq!(Some(Ask { n: 3, on: true }), *live.asked.borrow());
        handled(&live, 3);
        assert_eq!(None, *live.asked.borrow());
    }

    /// A switch is followed while connected: done once the engine runs it, put back to what the engine still runs once
    /// it refused it. Started while not connected, nothing waits.
    #[tokio::test]
    async fn switching_profiles() {
        use profiles::{Refused, look, refused, started, switching};
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let home = base().save_as("Home");
        let both = home.add("Travel", false).editing(Some("Travel"), |p| Profile { default_route: "us".into(), ..p });
        store.update(|_| both.use_profile("Travel"));
        started("Travel"); // the app isn't connected
        assert_eq!(None, *switching().borrow());
        let on = |applied, refused| VpnState { phase: Phase::On, applied, refused, ..VpnState::default() };
        let h = setup_hash(&store.current());
        switching().send_replace(Some("Travel".into()));
        look(&on(1, 2), &store, Some(home.clone())).await;
        assert_eq!(Some("Travel".into()), *switching().borrow());
        look(&on(h, 0), &store, Some(home.clone())).await;
        assert_eq!((None, None), (switching().borrow().clone(), refused().borrow().clone()));
        switching().send_replace(Some("Travel".into()));
        look(&on(1, h), &store, Some(home.clone())).await;
        assert_eq!(None, *switching().borrow());
        assert_eq!(Some(Refused { to: "Travel".into(), kept: Some("Home".into()) }), *refused().borrow());
        assert_eq!(
            ("Home", "nl"),
            (store.current().profile.as_deref().unwrap(), store.current().default_route.as_str())
        );
        started("Home");
        assert_eq!(None, *refused().borrow());
    }
}
