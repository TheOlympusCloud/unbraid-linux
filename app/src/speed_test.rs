//! On-demand speed test through one exit with M-Lab's ndt7 ([`crate::ndt7`]), on a server in the exit's own country
//! when known. Results go to [`crate::stats`] with the exit, provider and VPN server they were taken on.
//!
//! A Tailscale exit node that no route uses is tested by switching Tailscale to it for the test and back afterwards
//! (Tailscale has one exit node at a time); the store's `ts_test_from` remembers a switch a killed app couldn't undo.
//!
//! [`start_all`] tests several routed exits at the same time instead ([`All`]); one test or one combined run at a time.
//! Starting, cancelling and restoring spawn their work on the async runtime: call them inside it.

use crate::app::store;
use crate::clock::elapsed_realtime;
use crate::compiler::TS_TAG;
use crate::error::{Error, Result};
use crate::model::{Route, Setup, eq_ignore_case};
use crate::ndt7::{self, Ping, Server};
use crate::vpn::{TsNode, live};
use crate::{engine, limits, log, probe, providers, stats};
use indexmap::{IndexMap, IndexSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;

/// `Deciding`: a combined run waits for the person (an exit without a server at home, or a metered network).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Preparing,
    Deciding,
    Download,
    Upload,
    Done,
    Failed,
}

/// Exit id of a Tailscale exit node tested without a route: "ts:" and its tailnet IP.
pub const NODE: &str = "ts:";

/// M-Lab's limit for interactive users (measurementlab.net/aup).
pub const PER_DAY: i32 = 40;

fn day_limit() -> String {
    format!("M-Lab allows {PER_DAY} tests a day. Try again tomorrow.")
}

/// Speeds in bits/s, `ping` in ms (median, low, high); none = not measured yet. `server` is the M-Lab server once
/// located; `missing` names the exit's country when M-Lab has no server there (the user may then test with the nearest one).
#[derive(Clone, Debug, PartialEq)]
pub struct Run {
    pub exit: String,
    pub phase: Phase,
    pub now: i64,
    pub down: Option<i64>,
    pub up: Option<i64>,
    pub ping: Option<Ping>,
    pub elapsed_ms: i64,
    pub server: Option<Server>,
    pub missing: Option<String>,
    pub error: Option<String>,
}

impl Run {
    pub fn new(exit: &str) -> Run {
        Run { exit: exit.into(), phase: Phase::Preparing, now: 0, down: None, up: None, ping: None, elapsed_ms: 0, server: None, missing: None, error: None }
    }
}

/// Ten seconds each way.
pub const MAX_SECONDS: i32 = 20;

static RUN: LazyLock<watch::Sender<Option<Run>>> = LazyLock::new(|| watch::Sender::new(None));

pub fn run() -> watch::Receiver<Option<Run>> {
    RUN.subscribe()
}

static ATTEMPT: AtomicI32 = AtomicI32::new(0);

/// Guards the attempt with the run and the combined run: a cancelled test can't publish once a newer one (or none) took
/// over. It holds what [`go`] starts, bound to the run it belongs to: a cancelled run's never starts a newer one's
/// measuring.
static LOCK: Mutex<Option<(i32, Arc<Combined>)>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<(i32, Arc<Combined>)>> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn stopped(mine: i32) -> bool {
    ATTEMPT.load(Ordering::SeqCst) != mine
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

type Switch = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Tailscale exit-node switches, in order: a restore never overtakes the next test's switch.
static TSQ: OnceLock<mpsc::UnboundedSender<Switch>> = OnceLock::new();

fn tsq(job: impl Future<Output = ()> + Send + 'static) {
    let q = TSQ.get_or_init(|| {
        let (tx, mut rx) = mpsc::unbounded_channel::<Switch>();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let _ = tokio::spawn(job).await;
            }
        });
        tx
    });
    let _ = q.send(Box::pin(job));
}

/// Tailscale exit nodes the test can switch to: online, and not already carrying a route (those test as the route).
pub fn nodes() -> Vec<TsNode> {
    let setup = store().current();
    if !live().tags().values().any(|t| t == TS_TAG) && !setup.tailscale() {
        return vec![];
    }
    let routed = setup.ts_exit();
    live().state().ts_exit_nodes.into_iter().filter(|n| n.online && !n.id.is_empty() && Some(&n.ip) != routed.as_ref()).collect()
}

/// Counts `n` tests against M-Lab's daily allowance, unless a newer test took over or they don't fit.
fn reserve(n: i32, mine: i32) -> bool {
    let _g = lock();
    let ok = !stopped(mine) && store().tests_today() + n <= PER_DAY;
    if ok {
        store().set_tests_today(store().tests_today() + n);
    }
    ok
}

/// Runs `f` on the located server, then on Locate's other candidates while they turn the test away.
fn any_of<T>(s: &Server, f: impl Fn(&Server) -> Result<T>) -> Result<(Server, T)> {
    let mut s = s.clone();
    loop {
        match f(&s) {
            Err(e) if ndt7::refused(&e) && !s.others.is_empty() => {
                let mut rest = std::mem::take(&mut s.others);
                let next = rest.remove(0);
                s = Server { others: rest, ..next };
            }
            r => return r.map(|t| (s, t)),
        }
    }
}

/// The blocking `f` on a thread of its own, waited for.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| Err(Error::State(e.to_string())))
}

fn set_run(mine: i32, f: impl FnOnce(&mut Run)) {
    let _g = lock();
    if !stopped(mine) {
        RUN.send_if_modified(|r| r.as_mut().map(f).is_some());
    }
}

fn failed_run(mine: i32, why: String) {
    set_run(mine, |r| {
        r.phase = Phase::Failed;
        r.error = Some(why);
    });
}

/// Tests `exit`; `anywhere` = with the nearest M-Lab server even outside the exit's country.
pub fn start(exit: &str, anywhere: bool) -> bool {
    let node = match exit.strip_prefix(NODE) {
        Some(ip) => match nodes().into_iter().find(|n| n.ip == ip) {
            Some(n) => Some(n),
            None => return false,
        },
        None => None,
    };
    let tag = match &node {
        Some(_) => TS_TAG.to_string(),
        None => match live().tag(exit) {
            Some(t) => t,
            None => return false,
        },
    };
    cancel();
    if store().tests_today() >= PER_DAY {
        RUN.send_replace(Some(Run { phase: Phase::Failed, error: Some(day_limit()), ..Run::new(exit) }));
        return false;
    }
    let setup = live().running().unwrap_or_else(|| store().current()); // what the engine runs, for the label and the record
    let route = setup.route(Some(exit)).cloned();
    let vpn_server = live().state().servers.get(exit).cloned();
    let via = if node.is_some() { "Tailscale".to_string() } else { route.as_ref().map(Route::source).unwrap_or_default() };
    let name = node.as_ref().map(|n| n.name.clone()).or_else(|| vpn_server.as_ref().map(|s| s.name.clone())).unwrap_or_else(|| route.as_ref().map(Route::name).unwrap_or_default());
    let ip = node.as_ref().map(|n| n.ip.clone()).unwrap_or_else(|| vpn_server.as_ref().map(|s| s.ip.clone()).unwrap_or_default());
    // Provider routes know their country; imported servers and Tailscale nodes are located by their address alone.
    let country = route.as_ref().filter(|r| !r.imported() && r.ts_exit.is_none()).and_then(|r| r.loc.country_code.as_ref()).map(|c| c.to_uppercase()).filter(|_| !anywhere);
    let epoch = stats::epoch();
    let record_as = stats::note(exit, &setup);
    let mine = {
        let _g = lock();
        RUN.send_replace(Some(Run::new(exit)));
        ATTEMPT.fetch_add(1, Ordering::SeqCst) + 1
    };
    let is_node = node.is_some();
    let measuring = {
        let (tag, exit) = (tag.clone(), exit.to_string());
        async move {
            let located = {
                let (t, c) = (tag.clone(), country.clone());
                blocking(move || ndt7::locate(&t, c.as_deref())).await?
            };
            if stopped(mine) {
                return Ok(());
            }
            let Some(located) = located else {
                // With no country to name there is nothing for "missing" to say: say that no server answered.
                let named = route.as_ref().and_then(|r| r.loc.country.clone()).or(country).filter(|c| !c.trim().is_empty());
                set_run(mine, |r| {
                    r.phase = Phase::Failed;
                    r.error = named.is_none().then(|| "No test server answered. Try again later.".into());
                    r.missing = named;
                });
                return Ok(());
            };
            if !reserve(1, mine) {
                failed_run(mine, day_limit());
                return Ok(());
            }
            set_run(mine, |r| r.server = Some(located.clone()));
            let ping = {
                let (t, s) = (tag.clone(), located.clone());
                blocking(move || ndt7::ping(&t, &s)).await?
            };
            if stopped(mine) {
                return Ok(());
            }
            set_run(mine, |r| {
                r.ping = Some(ping);
                r.phase = Phase::Download;
            });
            let t0 = elapsed_realtime();
            let rate = move |bps: i64| {
                set_run(mine, |r| {
                    r.now = bps;
                    r.elapsed_ms = elapsed_realtime() - t0;
                })
            };
            let (server, down) = {
                let (t, l) = (tag.clone(), located.clone());
                blocking(move || any_of(&l, |s| ndt7::download(&t, &s.download, || stopped(mine), "", |_, _| {}, rate))).await?
            };
            if stopped(mine) {
                return Ok(());
            }
            set_run(mine, |r| {
                r.phase = Phase::Upload;
                r.down = Some(down);
                r.now = 0;
                r.server = Some(server.clone());
                r.ping = r.ping.filter(|_| server == located);
            });
            let up = {
                let (t, u) = (tag.clone(), server.upload.clone());
                blocking(move || ndt7::upload(&t, &u, || stopped(mine), "", |_, _| {}, rate)).await?
            };
            if stopped(mine) {
                return Ok(());
            }
            // Moved to another provider or server meanwhile: the numbers belong to neither.
            if stats::id_in(&exit, &live().running().unwrap_or(setup)) != record_as {
                failed_run(mine, "The route changed during the test. Try again.".into());
                return Ok(());
            }
            set_run(mine, |r| {
                r.phase = Phase::Done;
                r.up = Some(up);
                r.now = 0;
                r.elapsed_ms = MAX_SECONDS as i64 * 1000;
            });
            let Some(done) = RUN.borrow().clone() else { return Ok(()) };
            let test = stats::Test { at: now_ms(), exit: record_as, via, server: name, ip, down, up, idle: done.ping.map_or(0, |p| p.median), busy_down: 0, busy_up: 0, grp: 0, n: 1 };
            stats::save_tests(vec![test], epoch);
            Ok::<_, Error>(())
        }
    };
    let test = async move {
        match tokio::spawn(measuring).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) if ndt7::limited(&e) => failed_run(mine, "M-Lab is limiting tests from this exit's address right now (VPN servers share theirs). Try again later.".into()),
            _ => failed_run(mine, "The test couldn't finish. Check the connection and try again.".into()),
        }
        if is_node {
            restore_node();
        }
    };
    match node {
        // A test through Tailscale's routed node first switches back from a tested node, so it never measures that one.
        None if tag == TS_TAG => tsq(async move {
            if stopped(mine) {
                return;
            }
            if store().ts_test_from().is_some() {
                switch_back().await;
            }
            tokio::spawn(test);
        }),
        None => drop(tokio::spawn(test)),
        Some(node) => tsq(async move {
            if stopped(mine) {
                return; // cancelled before its turn: switch nothing
            }
            // The routed node's stable ID (the switch back needs one), noted with the route's setting it belongs to.
            if store().ts_test_from().is_none() {
                let from = store().current().ts_exit().and_then(|r| restore_to(Some(&r), None, &live().state().ts_exit_nodes).map(|id| format!("{r}\n{id}")));
                store().set_ts_test_from(Some(&from.unwrap_or_default()));
            }
            // Give Tailscale a moment to reach the new node before measuring.
            let ok = engine::get().set_tailscale_exit_node(TS_TAG, &node.id).await.is_ok();
            if ok {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            if stopped(mine) {
                return;
            }
            if ok {
                tokio::spawn(test);
            } else {
                failed_run(mine, format!("Tailscale couldn't switch to {}.", node.name));
                restore_node();
            }
        }),
    }
    true
}

// ---- every exit at once ----------------------------------------------------------------------------------------------

/// Most exits in one combined run: a few people's worth of tests, well inside what M-Lab's terms expect.
pub const MAX_TOGETHER: usize = 10;
/// A combined figure needs the exits to have run together at least this long.
pub const MIN_OVERLAP_MS: i64 = 3000;
/// The exit id of a combined run's own row in [`crate::stats`].
pub const ALL: &str = "all";

/// One exit's part in a combined run. `missing`: M-Lab has no server in its country (`server` is then the nearest
/// one, if any); `limited`: M-Lab turned its address away; `error`: it can't take part, or stopped.
#[derive(Clone, Debug, PartialEq)]
pub struct Leg {
    pub exit: String,
    pub server: Option<Server>,
    pub missing: bool,
    pub limited: bool,
    pub ping: Option<Ping>,
    pub now: i64,
    pub down: Option<i64>,
    pub up: Option<i64>,
    pub error: Option<String>,
}

impl Leg {
    pub fn new(exit: &str) -> Leg {
        Leg { exit: exit.into(), server: None, missing: false, limited: false, ping: None, now: 0, down: None, up: None, error: None }
    }

    pub fn usable(&self) -> bool {
        self.server.is_some() && !self.limited && self.error.is_none()
    }
}

/// Several exits measured at the same time. `down` and `up` count only the stretch every remaining exit was running
/// (`window_ms`, the shorter of the two); `now` is the exits' live rates added up. `metered`: the sheet said so.
#[derive(Clone, Debug, PartialEq)]
pub struct All {
    pub id: i64,
    pub legs: Vec<Leg>,
    pub metered: bool,
    pub phase: Phase,
    pub now: i64,
    pub down: Option<i64>,
    pub up: Option<i64>,
    pub elapsed_ms: i64,
    pub window_ms: i64,
    pub error: Option<String>,
}

static TOGETHER: LazyLock<watch::Sender<Option<All>>> = LazyLock::new(|| watch::Sender::new(None));

pub fn all() -> watch::Receiver<Option<All>> {
    TOGETHER.subscribe()
}

/// Starts the measuring once the person decided: which exits without a server at home go via the nearest one.
pub fn go(nearest: IndexSet<String>) {
    let armed = lock().take().filter(|(n, _)| !stopped(*n));
    if let Some((_, run)) = armed {
        run.start(nearest);
    }
}

/// Runs `f` for every exit at once, each on a thread of its own, and waits for all of them.
async fn parallel(exits: Vec<String>, f: impl Fn(&str) + Send + Sync + 'static) {
    let f = Arc::new(f);
    let mut all = JoinSet::new();
    for e in exits {
        let f = f.clone();
        all.spawn_blocking(move || f(&e));
    }
    while all.join_next().await.is_some() {}
}

/// Routes connected only for a combined run go down again (the engine reloads without them).
fn release() {
    if !store().setup().borrow().testing.is_empty() {
        store().update(|s| Setup { testing: IndexSet::new(), ..s.clone() });
    }
}

fn set_all(mine: i32, f: impl FnOnce(&mut All)) {
    let _g = lock();
    if !stopped(mine) {
        TOGETHER.send_if_modified(|a| a.as_mut().map(f).is_some());
    }
}

fn leg(mine: i32, exit: &str, f: impl FnOnce(&mut Leg)) {
    set_all(mine, |a| {
        if let Some(l) = a.legs.iter_mut().find(|l| l.exit == exit) {
            f(l);
        }
        a.now = a.legs.iter().map(|l| l.now).sum();
    });
}

fn failed(mine: i32, why: &str) {
    set_all(mine, |a| {
        a.phase = Phase::Failed;
        a.now = 0;
        a.error = Some(why.into());
    });
}

fn tag(exit: &str) -> Result<String> {
    live().tag(exit).ok_or_else(|| Error::State("The route isn't connected".into()))
}

fn missing() -> Error {
    Error::State("An exit's measurement went missing".into())
}

/// What a combined run was started with.
struct Combined {
    mine: i32,
    id: i64,
    epoch: i32,
    setup: Setup,
    record_as: IndexMap<String, String>,
    legs: Vec<String>,
}

/// Tests `exits` (route ids) at the same time. Routes without apps are connected for the run, as far as their
/// provider's connection limit allows; a Tailscale route can join only if Tailscale's one exit node is free or its.
/// Every exit first finds its M-Lab server; then, after [`go`], all download together and then all upload together.
pub fn start_all(exits: &[String], metered: bool) -> bool {
    let setup = store().current();
    let legs: Vec<String> = exits.iter().cloned().collect::<IndexSet<_>>().into_iter().filter(|e| setup.route(Some(e)).is_some()).take(MAX_TOGETHER).collect();
    if legs.len() < 2 || live().probe().is_none() {
        return false;
    }
    cancel();
    let id = now_ms();
    let epoch = stats::epoch();
    let record_as = legs.iter().map(|e| (e.clone(), stats::note(e, &setup))).collect();
    let mine = {
        let _g = lock();
        let all = All { id, legs: legs.iter().map(|e| Leg::new(e)).collect(), metered, phase: Phase::Preparing, now: 0, down: None, up: None, elapsed_ms: 0, window_ms: 0, error: None };
        TOGETHER.send_replace(Some(all));
        ATTEMPT.fetch_add(1, Ordering::SeqCst) + 1
    };
    let preparing = tokio::spawn(Arc::new(Combined { mine, id, epoch, setup, record_as, legs }).prepare(metered));
    tokio::spawn(async move {
        if preparing.await.is_err() {
            failed(mine, "The test couldn't start. Check the connection and try again.");
            done(mine);
        }
    });
    true
}

impl Combined {
    fn armed(self: &Arc<Self>) {
        let mut g = lock();
        if !stopped(self.mine) {
            *g = Some((self.mine, self.clone()));
        }
    }

    /// Starts the measuring on a task of its own, never on the caller's (a tap on the sheet).
    fn start(self: &Arc<Self>, nearest: IndexSet<String>) {
        let (run, mine) = (self.clone(), self.mine);
        tokio::spawn(async move {
            if !matches!(tokio::spawn(run.measure(nearest)).await, Ok(Ok(()))) {
                failed(mine, "The test couldn't finish. Check the connection and try again.");
            }
            if !TOGETHER.borrow().as_ref().is_some_and(|a| a.phase == Phase::Deciding) {
                done(mine);
            }
        });
    }

    async fn prepare(self: Arc<Self>, metered: bool) {
        let mine = self.mine;
        // Routes without apps come up for the run, one at a time while each provider's limit allows.
        let accounts = store().current_accounts();
        let limit = |p: &str| accounts.get(p).and_then(|a| providers::get(p).map(|pr| pr.limit(a)));
        let testing = |t: &IndexSet<String>| Setup { testing: t.clone(), ..self.setup.clone() };
        let mut up = IndexSet::<String>::new();
        let active: Vec<String> = self.setup.active_routes().iter().map(|r| r.id.clone()).collect();
        for e in self.legs.iter().filter(|e| !active.contains(e)) {
            let r = self.setup.route(Some(e)).expect("a combined run's legs are routes");
            let more: IndexSet<String> = up.iter().chain([e]).cloned().collect();
            let over = limits::over(&testing(&up), &testing(&more), limit);
            let ts = testing(&up).ts_exit();
            if r.ts_exit.is_some() && ts.is_some() && ts != r.ts_exit {
                leg(mine, e, |l| l.error = Some("Tailscale has one exit node at a time, and another route uses it.".into()));
            } else if let Some(o) = over {
                let name = providers::get(&o.provider).map_or_else(|| o.provider.clone(), |p| p.name().to_string());
                leg(mine, e, |l| l.error = Some(format!("{name} allows {}, all in use.", limits::units(o.limit, &o.unit))));
            } else {
                up = more;
            }
        }
        if !up.is_empty() {
            // With the attempt check, so a cancel either comes first (nothing goes up) or takes them down again.
            let went = {
                let _g = lock();
                !stopped(mine) && {
                    store().update(|s| Setup { testing: up.clone(), ..s.clone() });
                    true
                }
            };
            if !went {
                return;
            }
            let until = elapsed_realtime() + 30_000;
            while !stopped(mine) && up.iter().any(|e| live().tag(e).is_none()) && elapsed_realtime() < until {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            for e in up.iter().filter(|e| live().tag(e).is_none()) {
                leg(mine, e, |l| l.error = Some("It didn't connect for the test.".into()));
            }
        }
        // A cut-off test of another node may have left Tailscale on it: the routed node first, as for a single test.
        if store().ts_test_from().is_some() && self.legs.iter().any(|e| live().tag(e).as_deref() == Some(TS_TAG)) {
            let (switched, back) = oneshot::channel();
            tsq(async move {
                switch_back().await;
                let _ = switched.send(());
            });
            let _ = back.await;
        }
        let legs = TOGETHER.borrow().as_ref().map(|a| a.legs.iter().filter(|l| l.error.is_none()).map(|l| l.exit.clone()).collect()).unwrap_or_default();
        let setup = self.setup.clone();
        parallel(legs, move |e| {
            let country = setup.route(Some(e)).filter(|r| !r.imported() && r.ts_exit.is_none()).and_then(|r| r.loc.country_code.as_ref()).map(|c| c.to_uppercase());
            match tag(e).and_then(|t| ndt7::locate(&t, country.as_deref())) {
                Ok(Some(s)) => leg(mine, e, |l| l.server = Some(s)),
                Ok(None) => {
                    // Outside the lock: a slow answer mustn't hold up a cancel.
                    let near = tag(e).and_then(|t| ndt7::locate(&t, None)).ok().flatten();
                    leg(mine, e, |l| {
                        l.missing = true;
                        l.server = near;
                    });
                }
                Err(x) if ndt7::limited(&x) => leg(mine, e, |l| l.limited = true),
                Err(_) => leg(mine, e, |l| l.error = Some("M-Lab couldn't be reached through it.".into())),
            }
        })
        .await;
        let Some(a) = TOGETHER.borrow().clone() else { return };
        if stopped(mine) {
            return;
        }
        let metered = metered || live().metered();
        if metered || a.legs.iter().any(|l| l.missing || !l.usable()) {
            set_all(mine, |a| {
                a.metered = metered;
                a.phase = Phase::Deciding;
            });
            self.armed();
        } else {
            self.start(IndexSet::new());
        }
    }

    /// One phase through every exit: their own results, and each one's (time, bytes) samples.
    async fn phase(
        &self,
        p: Phase,
        exits: Vec<String>,
        t0: i64,
        f: impl Fn(&str, &(dyn Fn(i64, i64) + Sync), &dyn Fn(i64)) -> Result<i64> + Send + Sync + 'static,
    ) -> IndexMap<String, Vec<(i64, i64)>> {
        let mine = self.mine;
        set_all(mine, |a| a.phase = p);
        let samples = Arc::new(exits.iter().map(|e| (e.clone(), Mutex::new(Vec::<(i64, i64)>::new()))).collect::<IndexMap<_, _>>());
        let all = samples.clone();
        parallel(exits, move |e| {
            let sample = |t: i64, b: i64| held(&all[e]).push((t, b));
            let rate = |bps: i64| {
                leg(mine, e, |l| l.now = bps);
                set_all(mine, |a| a.elapsed_ms = elapsed_realtime() - t0);
            };
            match f(e, &sample, &rate) {
                Ok(r) => leg(mine, e, |l| {
                    if p == Phase::Download { l.down = Some(r) } else { l.up = Some(r) }
                    l.now = 0;
                }),
                Err(x) => {
                    let name = format!("{p:?}").to_lowercase();
                    log::w("Unbraid", &format!("speed test: {name} through one exit stopped: {}", probe::kind(&x)));
                    leg(mine, e, |l| {
                        l.now = 0;
                        l.error = Some(format!("Stopped during the {name}: the exit stopped answering. Not in the totals."));
                    });
                }
            }
        })
        .await;
        samples.iter().map(|(e, s)| (e.clone(), held(s).clone())).collect()
    }

    async fn measure(self: Arc<Self>, nearest: IndexSet<String>) -> Result<()> {
        let mine = self.mine;
        // The network turned metered after GO: the person hasn't agreed to that yet.
        if live().metered() && TOGETHER.borrow().as_ref().is_some_and(|a| !a.metered) {
            set_all(mine, |a| {
                a.metered = true;
                a.phase = Phase::Deciding;
            });
            self.armed();
            return Ok(());
        }
        let legs = TOGETHER.borrow().as_ref().map(|a| a.legs.clone()).unwrap_or_default();
        let going: Vec<Leg> = legs.into_iter().filter(|l| l.usable() && (!l.missing || nearest.contains(&l.exit))).collect();
        if going.len() < 2 {
            failed(mine, "At least two exits need a test server to run together.");
            return Ok(());
        }
        if !reserve(going.len() as i32, mine) {
            failed(mine, &format!("M-Lab allows {PER_DAY} tests a day; this run needs {} of them. Try fewer exits, or tomorrow.", going.len()));
            return Ok(());
        }
        set_all(mine, |a| {
            a.legs = going.clone();
            a.phase = Phase::Preparing;
        });
        let located: Arc<IndexMap<String, Server>> = Arc::new(going.iter().filter_map(|l| Some((l.exit.clone(), l.server.clone()?))).collect());
        let exits: Vec<String> = going.iter().map(|l| l.exit.clone()).collect();
        let servers = located.clone();
        parallel(exits.clone(), move |e| {
            if let Ok(p) = tag(e).and_then(|t| ndt7::ping(&t, &servers[e])) {
                leg(mine, e, |l| l.ping = Some(p));
            }
        })
        .await;
        if stopped(mine) {
            return Ok(());
        }
        // The server keeps this with each result, so M-Lab's data shows the line was shared. Nothing that ties the
        // exits' addresses to each other (no run id): they are published, and some are the person's own.
        let extra = format!("concurrent={}", going.len());
        let used = Arc::new(Mutex::new(IndexMap::<String, Server>::new()));
        let t0 = elapsed_realtime();
        let ok = || TOGETHER.borrow().as_ref().map(|a| a.legs.iter().filter(|l| l.error.is_none()).map(|l| l.exit.clone()).collect::<Vec<_>>()).unwrap_or_default();
        let (servers, taken, x) = (located.clone(), used.clone(), extra.clone());
        let down = self
            .phase(Phase::Download, exits, t0, move |e, sample, rate| {
                let (s, r) = any_of(&servers[e], |s| ndt7::download(&tag(e)?, &s.download, || stopped(mine), &x, sample, rate))?;
                // Another of Locate's servers took the test: its ping wasn't measured, and the card names it.
                if s != servers[e] {
                    leg(mine, e, |l| {
                        l.server = Some(s.clone());
                        l.ping = None;
                    });
                }
                held(&taken).insert(e.to_string(), s);
                Ok(r)
            })
            .await;
        if stopped(mine) {
            return Ok(());
        }
        let both = ok();
        let together = if both.len() >= 2 { both.iter().map(|e| down.get(e).cloned().ok_or_else(missing)).collect::<Result<Vec<_>>>()? } else { vec![] };
        let Some((bps, ms)) = combined(&together) else {
            failed(mine, &apart(ok().len()));
            return Ok(());
        };
        set_all(mine, |a| {
            a.down = Some(bps);
            a.window_ms = ms;
        });
        let up = self
            .phase(Phase::Upload, ok(), t0, move |e, sample, rate| {
                let s = held(&used).get(e).cloned().ok_or_else(missing)?;
                ndt7::upload(&tag(e)?, &s.upload, || stopped(mine), &extra, sample, rate)
            })
            .await;
        if stopped(mine) {
            return Ok(());
        }
        // An exit moved to another provider or server meanwhile: its numbers belong to neither.
        let running = live().running().unwrap_or_else(|| self.setup.clone());
        set_all(mine, |a| {
            for l in a.legs.iter_mut().filter(|l| l.error.is_none() && Some(&stats::id_in(&l.exit, &running)) != self.record_as.get(&l.exit)) {
                l.error = Some("The route changed during the test. Not counted.".into());
            }
        });
        // Both totals over the exits that made it through both phases, so the run adds up to the rows it lists.
        let last = ok();
        let d = combined(&last.iter().map(|e| down.get(e).cloned().ok_or_else(missing)).collect::<Result<Vec<_>>>()?);
        let u = combined(&last.iter().map(|e| up.get(e).cloned().ok_or_else(missing)).collect::<Result<Vec<_>>>()?);
        let (Some(d), Some(u), true) = (d, u, last.len() >= 2) else {
            failed(mine, &apart(last.len()));
            return Ok(());
        };
        set_all(mine, |a| {
            a.phase = Phase::Done;
            a.down = Some(d.0);
            a.up = Some(u.0);
            a.window_ms = d.1.min(u.1);
            a.now = 0;
            a.elapsed_ms = MAX_SECONDS as i64 * 1000;
        });
        let Some(done) = TOGETHER.borrow().clone().filter(|a| a.phase == Phase::Done) else { return Ok(()) };
        let servers = live().state().servers;
        let n = last.len() as i32;
        let mut tests = vec![stats::Test { at: self.id, exit: ALL.into(), via: String::new(), server: String::new(), ip: String::new(), down: d.0, up: u.0, idle: 0, busy_down: 0, busy_up: 0, grp: self.id, n }];
        for (i, l) in done.legs.iter().filter(|l| l.error.is_none()).enumerate() {
            let r = self.setup.route(Some(&l.exit));
            tests.push(stats::Test {
                at: self.id + 1 + i as i64,
                exit: self.record_as[&l.exit].clone(),
                via: r.map(Route::source).unwrap_or_default(),
                server: servers.get(&l.exit).map(|s| s.name.clone()).or_else(|| r.map(Route::name)).unwrap_or_default(),
                ip: servers.get(&l.exit).map(|s| s.ip.clone()).unwrap_or_default(),
                down: l.down.unwrap_or(0),
                up: l.up.unwrap_or(0),
                idle: l.ping.map_or(0, |p| p.median),
                busy_down: 0,
                busy_up: 0,
                grp: self.id,
                n,
            });
        }
        stats::save_tests(tests, self.epoch);
        Ok(())
    }
}

/// A combined run `mine` ended: routes up only for it go down, unless a newer run took over.
fn done(mine: i32) {
    let _g = lock();
    if !stopped(mine) {
        release();
    }
}

fn apart(n: usize) -> String {
    if n < 2 { "Only one exit kept going, so there's nothing to add up. Try again." } else { "The exits didn't run together long enough to add them up. Try again." }.into()
}

/// bits/s through several exits counted only while all of them ran, and that stretch in ms: from the latest first
/// sample to the earliest last one, each exit's bytes read off its (time, bytes) samples at both ends, linearly
/// between samples. None when they overlapped less than [`MIN_OVERLAP_MS`].
pub(crate) fn combined(legs: &[Vec<(i64, i64)>]) -> Option<(i64, i64)> {
    if legs.is_empty() || legs.iter().any(Vec::is_empty) {
        return None;
    }
    let from = legs.iter().map(|l| l[0].0).max()?;
    let to = legs.iter().map(|l| l[l.len() - 1].0).min()?;
    if to - from < MIN_OVERLAP_MS {
        return None;
    }
    Some((legs.iter().map(|l| bytes_at(l, to) - bytes_at(l, from)).sum::<i64>() * 8000 / (to - from), to - from))
}

pub(crate) fn bytes_at(s: &[(i64, i64)], t: i64) -> i64 {
    match s.iter().position(|p| p.0 >= t) {
        None => s[s.len() - 1].1,
        Some(0) => s[0].1,
        Some(i) => {
            let (a, b) = (s[i - 1], s[i]);
            a.1 + (b.1 - a.1) * (t - a.0) / (b.0 - a.0).max(1)
        }
    }
}

/// The exit a running test measures through tunnel `tag`, so its traffic is counted there; none = none.
pub fn exit_on(tag: Option<&str>) -> Option<String> {
    if !testing() {
        return None;
    }
    let tags = live().tags();
    let single = RUN.borrow().as_ref().map(|r| r.exit.clone()).filter(|e| tag == if e.starts_with(NODE) { Some(TS_TAG) } else { tags.get(e).map(String::as_str) });
    single.or_else(|| TOGETHER.borrow().as_ref().and_then(|a| a.legs.iter().find(|l| tags.get(&l.exit).map(String::as_str) == tag).map(|l| l.exit.clone())))
}

fn busy(p: Option<Phase>) -> bool {
    matches!(p, Some(Phase::Preparing | Phase::Download | Phase::Upload))
}

/// A test is under way (Tailscale may be on its test node on purpose).
pub fn testing() -> bool {
    busy(RUN.borrow().as_ref().map(|r| r.phase)) || busy(TOGETHER.borrow().as_ref().map(|a| a.phase))
}

/// Puts Tailscale back on the exit node the routes use (or none). Safe to call any time; runs off the caller's thread.
/// The node in use before the test comes back by its stable ID; failing that, the routed node by address or name. If
/// neither is known yet Tailscale is left with no exit (apps on its route wait, never using the tested node) and the
/// next Tailscale status tries again.
pub fn restore_node() {
    tsq(async {
        let own = {
            let _g = lock();
            testing() && RUN.borrow().as_ref().is_some_and(|r| r.exit.starts_with(NODE))
        };
        if !own {
            switch_back().await; // else that test switches back when it ends
        }
    });
}

/// On the switch queue only.
async fn switch_back() {
    let want = restore_to(store().current().ts_exit().as_deref(), store().ts_test_from().as_deref(), &live().state().ts_exit_nodes);
    // A node Tailscale won't take back (gone, no longer an exit) is no reason to stay on the tested one: no exit then.
    async fn set(id: &str) -> bool {
        engine::get().set_tailscale_exit_node(TS_TAG, id).await.is_ok()
    }
    if set(want.as_deref().unwrap_or("")).await && want.is_some() {
        store().set_ts_test_from(None);
    } else if want.as_deref() != Some("") {
        set("").await;
    }
}

/// The stable ID to switch back to, for the route's setting now (`routed`, an address, ID or name): "" for no exit
/// node; none when not known yet (then no exit meanwhile). A name counts only if one node has it; the `hint` noted at
/// the test's start ("setting\nID") helps only while the setting is unchanged.
pub(crate) fn restore_to(routed: Option<&str>, hint: Option<&str>, nodes: &[TsNode]) -> Option<String> {
    let Some(routed) = routed else { return Some(String::new()) };
    let r = routed.trim_end_matches('.');
    if let Some(n) = nodes.iter().find(|n| n.ip == r || n.id == r) {
        return Some(n.id.clone());
    }
    let host = r.split('.').next().unwrap_or(r);
    let named: Vec<&TsNode> = nodes.iter().filter(|n| eq_ignore_case(&n.name, r) || eq_ignore_case(&n.name, host)).collect();
    match named[..] {
        [n] => Some(n.id.clone()),
        [] => hint.filter(|h| h.split('\n').next() == Some(routed)).map(|h| h.split_once('\n').map_or(h, |(_, id)| id)).filter(|id| !id.is_empty()).map(String::from),
        _ => None, // two nodes by that name: neither is surely the one
    }
}

/// Stops a running test or combined run (or one waiting for a decision); its sockets close as soon as they notice.
pub fn cancel() {
    let mut g = lock();
    let was_node = RUN.borrow().as_ref().is_some_and(|r| r.exit.starts_with(NODE));
    ATTEMPT.fetch_add(1, Ordering::SeqCst);
    *g = None;
    let deciding = TOGETHER.borrow().as_ref().is_some_and(|a| a.phase == Phase::Deciding);
    if testing() || deciding {
        ndt7::abort();
        let running = busy(RUN.borrow().as_ref().map(|r| r.phase));
        if running {
            RUN.send_replace(None);
        }
        TOGETHER.send_replace(None);
        if was_node {
            restore_node();
        }
    }
    release();
}

/// Leaving the result screen forgets the last run (it's in History if stats are on).
pub fn clear() {
    let _g = lock();
    if !testing() {
        RUN.send_replace(None);
        let deciding = TOGETHER.borrow().as_ref().is_some_and(|a| a.phase == Phase::Deciding);
        if !deciding {
            TOGETHER.send_replace(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, ip: &str, id: &str) -> TsNode {
        TsNode { name: name.into(), ip: ip.into(), online: true, id: id.into() }
    }

    /// After testing another node, Tailscale goes back to the node it used, else the routed one, else to no exit at all.
    #[test]
    fn the_exit_node_comes_back_or_none_is_used() {
        let nodes = vec![node("nas", "100.64.0.5", "nStable1"), node("pi", "100.64.0.6", "nStable2")];
        let some = |s: &str| Some(s.to_string());
        assert_eq!(some(""), restore_to(None, Some("100.64.0.5\nnStable1"), &nodes)); // no route on Tailscale's exit any more
        // The route's setting now, by address, ID or a unique name.
        assert_eq!(some("nStable2"), restore_to(Some("100.64.0.6"), Some(""), &nodes));
        assert_eq!(some("nStable1"), restore_to(Some("NAS"), None, &nodes));
        assert_eq!(some("nStable2"), restore_to(Some("pi.tail1234.ts.net."), Some(""), &nodes));
        // The route changed during the test: the new setting wins over the note from the start.
        assert_eq!(some("nStable2"), restore_to(Some("100.64.0.6"), Some("100.64.0.5\nnStable1"), &nodes));
        // The node isn't listed now: the note helps only for the same setting.
        assert_eq!(some("nStable1"), restore_to(Some("nas"), Some("nas\nnStable1"), &[]));
        assert_eq!(None, restore_to(Some("nas"), Some("pi\nnStable2"), &[]));
        // A name two nodes share is no match; not known at all: no exit node meanwhile (none), never the tested one.
        let twins = [nodes.clone(), vec![node("nas", "100.64.0.9", "nStable3")]].concat();
        assert_eq!(None, restore_to(Some("nas"), Some(""), &twins));
        assert_eq!(None, restore_to(Some("nas"), Some("nas\nnStable1"), &twins));
        assert_eq!(None, restore_to(Some("gone"), Some(""), &nodes));
    }

    fn leg_of(start: i64, end: i64, bytes_per_ms: i64) -> Vec<(i64, i64)> {
        (start..=end).step_by(20).map(|t| (t, (t - start) * bytes_per_ms)).collect()
    }

    /// A sample is returned as is, a time between two samples is interpolated, and outside the samples the nearest one holds.
    #[test]
    fn bytes_are_interpolated_and_clamped_at_the_ends() {
        let s = [(1000, 100), (2000, 300)];
        assert_eq!(100, bytes_at(&s, 1000));
        assert_eq!(300, bytes_at(&s, 2000));
        assert_eq!(200, bytes_at(&s, 1500));
        assert_eq!(150, bytes_at(&s, 1250));
        assert_eq!(100, bytes_at(&s, 500));
        assert_eq!(300, bytes_at(&s, 3000));
    }

    /// Only the stretch both legs ran counts, so a leg that was fast early on does not inflate the sum.
    #[test]
    fn only_the_overlap_counts() {
        // A: 2000 B/ms until 2 s, then 250 B/ms until 10 s. B: 100 B/ms from 2 s to 8 s. Overlap 2 s..8 s = 6000 ms.
        // A moves 5_500_000 - 4_000_000 = 1_500_000 B, B moves 600_000 B: 2_100_000 * 8000 / 6000 = 2_800_000 bit/s.
        let a = vec![(0, 0), (2000, 4_000_000), (10_000, 6_000_000)];
        let b = vec![(2000, 0), (8000, 600_000)];
        let r = combined(&[a, b]);
        assert_eq!(Some((2_800_000, 6000)), r);
        // Summing each leg's whole-run average would give 4_800_000 + 800_000 = 5_600_000.
        assert_ne!(5_600_000, r.unwrap().0);
    }

    /// An overlap under 3 s is too short to report; exactly 3 s is enough.
    #[test]
    fn a_short_overlap_gives_nothing() {
        let a = leg_of(0, 5000, 10);
        assert_eq!(None, combined(&[a.clone(), leg_of(2001, 5000, 10)]));
        assert_eq!(Some(3000), combined(&[a, leg_of(2000, 5000, 10)]).map(|r| r.1));
    }

    /// No legs, or a leg that never got a sample, gives nothing.
    #[test]
    fn no_legs_or_an_empty_leg_gives_nothing() {
        assert_eq!(None, combined(&[]));
        assert_eq!(None, combined(&[leg_of(0, 5000, 10), vec![]]));
    }

    /// Three exits at 400, 200 and 100 Mbit/s that started a little apart add up to about 700 Mbit/s.
    #[test]
    fn three_staggered_legs_add_up() {
        let r = combined(&[leg_of(0, 10_000, 50_000), leg_of(150, 10_150, 25_000), leg_of(300, 10_300, 12_500)]).unwrap();
        assert_eq!(9700, r.1);
        assert!((693_000_000..=707_000_000).contains(&r.0), "{r:?}");
    }
}
