//! What the window shows and does, apart from how it looks: each screen's words, figures and actions. The window's
//! toolkit code only shows them.
//!
//! [`Ui`] is the window's one model: sign-in, routes, profiles, apps and settings. Thin: the state lives in the store
//! and the connection; what is the window's own is in watches the window redraws on. Its methods return at once, never
//! waiting on the disk, the keyring or the network: that work runs on the app's runtime.

pub mod apps;
pub mod importer;
pub mod limit_sheet;
pub mod picker;
pub mod profiles;
pub mod qr;
pub mod routes;
pub mod settings;
pub mod sign_in;
pub mod stats;
pub mod status;
pub mod tour;
pub mod welcome;

use crate::error::{Challenge, Error};
use crate::exit_check::{self, ExitReport};
use crate::model::{
    Country, DIRECT, Home, Location, MAX_PROFILES, OvpnProfile, OwnServer, Prefs, Profile, Route, Setup, SsProfile,
    WgPeer,
};
use crate::prefs::SharedPreferences;
use crate::providers::{self, PROTECT, Provider, nord};
use crate::store::Store;
use crate::ui::apps::AppInfo;
use crate::ui::importer::Draft;
use crate::ui::sign_in::form_key;
use crate::vpn::{Live, Phase, VpnState};
use crate::{app, desktop, http, limits, wg_conf};
use image::RgbaImage;
use indexmap::{IndexMap, IndexSet};
use resvg::{tiny_skia, usvg};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinSet;

// What the connection is asked. Tests answer it themselves, so they never start the app's own connection.
#[cfg(not(test))]
use crate::vpn as ctl;
#[cfg(test)]
use tests::ctl;

/// Removed routes' apps follow the default; a removed default becomes `fallback`, the first route left, or Direct.
fn without(s: &Setup, gone: &HashSet<String>, fallback: Option<&str>) -> Setup {
    let routes: Vec<Route> = s.routes.iter().filter(|r| !gone.contains(&r.id)).cloned().collect();
    let default_route = match fallback {
        _ if !gone.contains(&s.default_route) => s.default_route.clone(),
        Some(f) => f.into(),
        None => routes.first().map_or_else(|| DIRECT.into(), |r| r.id.clone()),
    };
    let apps = s.apps.iter().filter(|(_, v)| !gone.contains(*v)).map(|(k, v)| (k.clone(), v.clone())).collect();
    Setup { routes, default_route, apps, ..s.clone() }
}

/// A route change that would take a provider over its connection limit, waiting for the user's answer: `apply` saves
/// it all the same; `share`, when one of that provider's routes is already on a server, names that server and puts
/// both routes on it.
pub struct LimitAsk {
    pub text: String,
    pub apply: Box<dyn Fn() + Send + Sync>,
    pub share: Option<(String, Box<dyn Fn() + Send + Sync>)>,
}

/// The sign-in forms, by provider. In memory only (they hold secrets): they last as long as the app, never longer.
#[derive(Clone, Debug, Default)]
pub struct Forms {
    /// What is typed, by [`form_key`] ("provider:field").
    pub form: IndexMap<String, String>,
    /// The last sign-in error per provider id.
    pub errors: IndexMap<String, String>,
    /// Where the user can fix that error (a device list), per provider id.
    pub links: IndexMap<String, String>,
    /// A question the provider asked before it signs in (a two-factor code, a captcha), per provider id.
    pub challenges: IndexMap<String, Challenge>,
}

/// What the forms' background work checks before it lands, taken together with the forms' own changes.
#[derive(Default)]
struct Pending {
    /// Files being read into a form, per provider: closing the form or picking another file makes an older read moot.
    reads: HashMap<String, i32>,
    /// Sign-ins whose form was closed while they ran: a failure leaves no error and brings nothing back.
    dismissed: HashSet<String>,
}

impl Pending {
    fn bump(&mut self, provider: &str) -> i32 {
        let n = self.reads.entry(provider.into()).or_insert(0);
        *n += 1;
        *n
    }
}

/// The window's model, one for as long as the window lives.
pub struct Ui {
    store: Arc<Store>,
    rt: Handle,
    live: &'static Live,
    ui_prefs: Option<&'static SharedPreferences>,
    /// A Tailscale node is kept for this user ([`Store::ts_stored`]); refreshed by [`Ui::check_tailscale`].
    pub ts_stored: watch::Sender<bool>,
    /// Signed in to at least one provider, or holding an imported config.
    pub signed_in: watch::Sender<bool>,
    /// Server catalog per provider id.
    pub countries: watch::Sender<IndexMap<String, Vec<Country>>>,
    /// True once the saved catalogs are read: until then an empty one means not read yet, not missing.
    pub catalogs_read: watch::Sender<bool>,
    /// Counts catalog refreshes, also ones that brought the same list (its saved copy is fresh again).
    pub refreshed: watch::Sender<i32>,
    pub apps: watch::Sender<Vec<AppInfo>>,
    /// The installed-apps notice: the app list is read only once the user accepted it.
    pub disclosed: watch::Sender<bool>,
    /// Exit checks by route id ([`exit_check`]): kept in memory only, and dropped when the VPN stops.
    pub exits: watch::Sender<IndexMap<String, ExitReport>>,
    /// Engine start and attempts asked of it: four at most, also when Routes is opened again.
    tried: Mutex<(i32, i32)>,
    /// Something sign-out couldn't finish and the user must do by hand; shown in Settings, cleared by setting none.
    pub notice: watch::Sender<Option<String>>,
    pub forms: watch::Sender<Forms>,
    pending: Mutex<Pending>,
    /// Provider ids with a sign-in in flight. It runs here, not in the screen, so leaving the screen can't drop or repeat it.
    pub signing: watch::Sender<IndexSet<String>>,
    /// Import prompts waiting for input; same lifetime as [`Ui::forms`].
    pub import_draft: watch::Sender<Draft>,
    group_countries: Mutex<HashMap<String, IndexSet<String>>>,
    /// App list reads asked for: only the newest one's answer is used.
    apps_asked: Mutex<i32>,
    /// Icons drawn, the most recently used last.
    icons: Mutex<IndexMap<String, Arc<RgbaImage>>>,
    pub limit_ask: watch::Sender<Option<Arc<LimitAsk>>>,
    /// The profile shown on Routes and Apps when it isn't the one in use; none = the one in use (the live setup).
    pub viewing: watch::Sender<Option<String>>,
    /// Set by a profile asked for from the command line: the window shows Routes, where the profile is shown to be used.
    pub routes_wanted: watch::Sender<bool>,
}

fn held<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// `f` on the runtime's blocking threads: the store, files, the clipboard and the network.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match tokio::task::spawn_blocking(f).await {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// Don't leave a secret on the clipboard for the next app to read: cleared only if the clip is `secret` (surrounding
/// space ignored, as pasted configs carry it). Blocks on the clipboard.
fn clear_clip_if(secret: &str) {
    if !secret.trim().is_empty() && desktop::clip_text().is_some_and(|c| c.trim() == secret.trim()) {
        desktop::clear_clip();
    }
}

/// True if the provider released this computer's slot (or has nothing to release).
fn release(id: &str, blob: &str) -> bool {
    providers::get(id).is_none_or(|p| p.sign_out(blob))
}

fn provider_name(id: &str) -> String {
    providers::get(id).map_or_else(|| id.to_string(), |p| p.name().to_string())
}

/// Unique even for two routes added in the same millisecond (ids key the route lists).
fn new_id(s: &Setup) -> String {
    loop {
        let id = format!("r{:08x}", rand::random::<u32>());
        if s.routes.iter().all(|r| r.id != id) {
            return id;
        }
    }
}

fn new_server_id(taken: &[OwnServer]) -> String {
    loop {
        let id = format!("s{:08x}", rand::random::<u32>());
        if taken.iter().all(|s| s.id != id) {
            return id;
        }
    }
}

fn next_hue(s: &Setup) -> i32 {
    (0..=6).find(|h| s.routes.iter().all(|r| r.hue != *h)).unwrap_or(s.routes.len() as i32)
}

/// The viewed profile, if it exists in `s` and isn't the one in use: edits go to it alone.
fn draft_of(viewing: Option<&str>, s: &Setup) -> Option<String> {
    viewing.filter(|n| Some(*n) != s.profile.as_deref() && s.profiles.iter().any(|p| p.name == *n)).map(str::to_string)
}

/// Gives a server's config, whichever kind it is, the name `n`.
fn name_all(n: &str, wg: &mut Option<WgPeer>, ovpn: &mut Option<OvpnProfile>, ss: &mut Option<SsProfile>) {
    if let Some(w) = wg {
        w.name = n.into();
    }
    if let Some(o) = ovpn {
        o.name = n.into();
    }
    if let Some(x) = ss {
        x.name = n.into();
    }
}

/// `f` as straight RGBA: a PNG at its own size, an SVG drawn to fill 96 px.
fn raster(f: &Path) -> Option<RgbaImage> {
    let bytes = std::fs::read(f).ok()?;
    if !f.extension().is_some_and(|e| e.eq_ignore_ascii_case("svg")) {
        return image::load_from_memory(&bytes).ok().map(|i| i.to_rgba8());
    }
    let tree = usvg::Tree::from_data(&bytes, &usvg::Options::default()).ok()?;
    let mut p = tiny_skia::Pixmap::new(96, 96)?;
    let k = 96.0 / tree.size().width().max(tree.size().height());
    resvg::render(&tree, tiny_skia::Transform::from_scale(k, k), &mut p.as_mut());
    let rgba = p.pixels().iter().flat_map(|c| {
        let c = c.demultiply();
        [c.red(), c.green(), c.blue(), c.alpha()]
    });
    RgbaImage::from_raw(96, 96, rgba.collect())
}

impl Ui {
    /// The window's model on the app's store, runtime and connection: after [`app::init`].
    pub fn new() -> Arc<Ui> {
        Ui::with(
            app::store().clone(),
            app::runtime().clone(),
            crate::vpn::live(),
            SharedPreferences::named("unbraid_ui").ok(),
        )
    }

    pub(crate) fn with(
        store: Arc<Store>,
        rt: Handle,
        live: &'static Live,
        ui_prefs: Option<&'static SharedPreferences>,
    ) -> Arc<Ui> {
        let s = store.current();
        // A running VPN keeps its controls, also after its last provider signed out (its routes' apps wait blocked).
        let signed_in = !store.accounts().borrow().is_empty()
            || s.routes.iter().any(Route::imported)
            || !s.servers.is_empty()
            || s.home.tailscale
            || live.state.borrow().phase != Phase::Off;
        let disclosed = ui_prefs.is_some_and(|p| p.get_boolean("disclosure_accepted", false));
        let ui = Arc::new(Ui {
            store,
            rt,
            live,
            ui_prefs,
            ts_stored: watch::Sender::new(false),
            signed_in: watch::Sender::new(signed_in),
            countries: watch::Sender::new(IndexMap::new()),
            catalogs_read: watch::Sender::new(false),
            refreshed: watch::Sender::new(0),
            apps: watch::Sender::new(vec![]),
            disclosed: watch::Sender::new(disclosed),
            exits: watch::Sender::new(IndexMap::new()),
            tried: Mutex::new((0, 0)),
            notice: watch::Sender::new(None),
            forms: watch::Sender::new(Forms::default()),
            pending: Mutex::default(),
            signing: watch::Sender::new(IndexSet::new()),
            import_draft: watch::Sender::new(Draft::default()),
            group_countries: Mutex::default(),
            apps_asked: Mutex::new(0),
            icons: Mutex::default(),
            limit_ask: watch::Sender::new(None),
            viewing: watch::Sender::new(None),
            routes_wanted: watch::Sender::new(false),
        });
        let u = ui.clone();
        ui.rt.spawn_blocking(move || {
            // Catalogs are multi-MB: refreshed once a day, not on every launch (the picker refreshes an empty one itself).
            for id in u.store.current_accounts().keys().filter(|id| !u.store.countries_fresh(id)) {
                u.refresh_countries(id);
            }
            // Read off the window's thread, for the same reason. A list fetched meanwhile is newer and stays.
            let saved: IndexMap<String, Vec<Country>> =
                providers::all().into_iter().map(|p| (p.id().to_string(), u.store.countries(p.id()))).collect();
            u.countries.send_modify(|c| {
                let fetched = std::mem::replace(c, saved);
                c.extend(fetched);
            });
            u.catalogs_read.send_replace(true);
        });
        ui.follow_exits();
        ui.save_imported_servers();
        ui
    }

    /// The setup as it stands, and its changes to come.
    pub fn setup(&self) -> watch::Receiver<Setup> {
        self.store.setup()
    }

    /// The accounts signed in, by provider id.
    pub fn accounts(&self) -> watch::Receiver<IndexMap<String, String>> {
        self.store.accounts()
    }

    /// The connection as it stands, and its changes to come.
    pub fn vpn(&self) -> watch::Receiver<VpnState> {
        self.live.state.subscribe()
    }

    // ---- Tailscale's node, catalogs and the exit checks --------------------------------------------------------------

    pub fn check_tailscale(self: &Arc<Self>) {
        let ui = self.clone();
        self.rt.spawn_blocking(move || {
            ui.ts_stored.send_replace(ui.store.ts_stored());
        });
    }

    // A stop or a restart retires every answer: they were about tunnels that no longer run.
    fn follow_exits(self: &Arc<Self>) {
        let (me, mut state) = (Arc::downgrade(self), self.live.state.subscribe());
        self.rt.spawn(async move {
            loop {
                {
                    let Some(ui) = me.upgrade() else { return };
                    let v = state.borrow_and_update();
                    let stale = v.phase != Phase::On || ui.exits.borrow().values().any(|r| r.engine != v.engine);
                    if stale {
                        ui.exits.send_if_modified(|x| !std::mem::take(x).is_empty());
                    }
                }
                if state.changed().await.is_err() {
                    return;
                }
            }
        });
    }

    /// Whether the engine that runs now may still be asked.
    pub fn exit_tries_left(&self) -> bool {
        let e = self.live.state.borrow().engine;
        let (engine, n) = *held(&self.tried);
        engine != e || n < 4
    }

    /// Asks the exits of running routes that have no answer yet from the engine that runs now; routes sharing a tunnel
    /// share one request. Dropping the future stops the asking, so leaving the screen stops it. True when every route
    /// has an answer.
    pub async fn check_exits(self: &Arc<Self>) -> bool {
        let ui = self.clone();
        let mut asking = JoinSet::new();
        asking.spawn_on(async move { ui.ask_exits().await }, &self.rt);
        asking.join_next().await.and_then(Result::ok).unwrap_or(false)
    }

    async fn ask_exits(&self) -> bool {
        let now = self.live.state();
        if now.phase != Phase::On {
            return true;
        }
        let Some(running) = self.live.running() else { return true };
        let answered: HashSet<String> = self
            .exits
            .borrow()
            .iter()
            .filter(|(_, r)| r.engine == now.engine && r.ip.is_some())
            .map(|(id, _)| id.clone())
            .collect();
        let active: HashSet<&str> = running.active_routes().into_iter().map(|r| r.id.as_str()).collect();
        let tags: IndexMap<String, String> = self
            .live
            .tags()
            .into_iter()
            .filter(|(id, _)| !answered.contains(id) && active.contains(id.as_str()))
            .collect();
        if tags.is_empty() {
            return true;
        }
        {
            let mut tried = held(&self.tried);
            let (e, n) = *tried;
            if e == now.engine && n >= 4 {
                return false;
            }
            *tried = (now.engine, if e == now.engine { n + 1 } else { 1 });
        }
        let seen = exit_check::ask(tags.values().cloned()).await;
        let at = now_ms();
        let reports: IndexMap<String, ExitReport> = tags
            .iter()
            .map(|(id, t)| {
                (
                    id.clone(),
                    ExitReport {
                        ip: seen.get(t).cloned().flatten(),
                        at,
                        engine: now.engine,
                        server: now.servers.get(id).cloned(),
                    },
                )
            })
            .collect();
        let all = reports.values().all(|r| r.ip.is_some());
        // Held while they land, as the clearing above reads it: a restart while asking means these answers are stale.
        let v = self.live.state.borrow();
        if v.phase == Phase::On && v.engine == now.engine {
            self.exits.send_modify(|x| {
                x.retain(|_, r| r.engine == now.engine);
                x.extend(reports);
            });
        }
        all
    }

    pub fn accept_disclosure(self: &Arc<Self>) {
        if let Some(p) = self.ui_prefs {
            self.rt.spawn_blocking(move || p.edit(|e| e.put_boolean("disclosure_accepted", true)));
        }
        if !*self.disclosed.borrow() {
            self.disclosed.send_replace(true);
            self.load_apps();
        }
    }

    // ---- signing in and out -----------------------------------------------------------------------------------------

    /// Forgets a provider's half-filled sign-in form, on an explicit Back or Close. Leaving the window keeps it, so the
    /// user can fetch a key from the browser and come back.
    pub fn discard_form(&self, id: &str) {
        let mut pending = held(&self.pending);
        pending.bump(id);
        // A sign-in in flight still finishes (a device slot it registers must be saved), but its form is gone for good.
        if self.signing.borrow().contains(id) {
            pending.dismissed.insert(id.into());
        }
        let prefix = format!("{id}:");
        self.forms.send_modify(|f| {
            f.form.retain(|k, _| !k.starts_with(&prefix));
            f.errors.shift_remove(id);
            f.links.shift_remove(id);
            f.challenges.shift_remove(id);
        });
    }

    /// Signs in to `provider` using `input` as typed: secrets are never trimmed. The outcome lands in [`Forms::errors`]
    /// (or the accounts on success). Ignored while one is already running for this provider.
    pub fn sign_in(self: &Arc<Self>, provider: &str, input: IndexMap<String, String>) {
        let Some(p) = providers::get(provider) else { return };
        let id = p.id();
        if self.signing.borrow().contains(id) {
            return;
        }
        if self.store.accounts().borrow().contains_key(id) {
            self.forms.send_modify(|f| {
                f.errors.insert(id.into(), format!("Already signed in to {}", p.name()));
            });
            return;
        }
        let asked = self.forms.borrow().challenges.get(id).cloned();
        self.forms.send_modify(|f| {
            f.errors.shift_remove(id);
            f.links.shift_remove(id);
        });
        self.signing.send_modify(|s| {
            s.insert(id.into());
        });
        let ui = self.clone();
        self.rt.spawn(async move {
            let u = ui.clone();
            let failure = match tokio::task::spawn_blocking(move || u.signed_in_to(p, &input, asked.as_ref())).await {
                Ok(done) => done.err(),
                // A sign-in that broke down is explained as one that went wrong.
                Err(_) => Some(Error::State(String::new())),
            };
            let error = failure
                .as_ref()
                .map(|e| if let Error::Challenge(c) = e { c.message.clone() } else { http::explain(e, p.name()) });
            // With the form's own changes, as Back makes them: a form closed now never gets this attempt's error.
            let mut pending = held(&ui.pending);
            ui.forms.send_modify(|f| {
                if error.is_none() {
                    // A file still being read must not refill the form just used.
                    pending.bump(id);
                    f.form.retain(|k, _| !k.starts_with(&format!("{id}:")));
                }
                if !pending.dismissed.remove(id) {
                    if let Some(e) = &error {
                        f.errors.insert(id.into(), e.clone());
                    }
                    if let Some(Error::Auth { url: Some(u), .. }) = &failure {
                        f.links.insert(id.into(), u.clone());
                    }
                    // A new question replaces the last one (its answer is spent); any other outcome ends the questions.
                    if let Some(Error::Challenge(c)) = &failure {
                        f.form.shift_remove(&form_key(id, &c.field.key));
                        f.challenges.insert(id.into(), (**c).clone());
                    } else {
                        f.challenges.shift_remove(id);
                    }
                }
            });
            ui.signing.send_modify(|s| {
                s.shift_remove(id);
            });
        });
    }

    /// The sign-in itself: the account saved, a fresh install's default route pointed at it, its countries read.
    fn signed_in_to(
        self: &Arc<Self>,
        p: &'static dyn Provider,
        input: &IndexMap<String, String>,
        asked: Option<&Challenge>,
    ) -> Result<(), Error> {
        let id = p.id();
        let mut fields = p.fields();
        fields.extend(asked.map(|c| c.field.clone()));
        let mut clean: IndexMap<String, String> = fields
            .iter()
            .map(|f| {
                let v = input.get(&f.key).map_or("", String::as_str);
                (f.key.clone(), if f.secret { v.to_string() } else { v.trim().to_string() })
            })
            .collect();
        clean.extend(asked.map(|c| c.keep.clone()).unwrap_or_default());
        let blob = p.sign_in(&clean)?;
        let saved = self.store.account(id, Some(&blob));
        held(&providers::SIGNED_IN_AT).insert(id.into(), now_ms());
        // First provider on a fresh install: point the default route at it.
        let accounts = self.store.current_accounts();
        self.store.update(|s| {
            let d =
                s.route(Some(&s.default_route)).filter(|d| !d.imported() && !accounts.contains_key(&d.loc.provider));
            match d {
                _ if s.routes.is_empty() => Setup {
                    routes: vec![Route::new("main", Location::of(id))],
                    default_route: "main".into(),
                    ..s.clone()
                },
                Some(d) => Setup {
                    routes: s
                        .routes
                        .iter()
                        .map(|r| if r.id == d.id { Route { loc: Location::of(id), ..r.clone() } } else { r.clone() })
                        .collect(),
                    ..s.clone()
                },
                None => s.clone(),
            }
        });
        self.signed_in.send_replace(true);
        if saved {
            input.values().for_each(|v| clear_clip_if(v));
        }
        self.refresh_countries(id);
        Ok(())
    }

    /// A config file picked in a sign-in form, read off the window's thread, into `form_key`.
    pub fn load_form_file(self: &Arc<Self>, file: PathBuf, form_key: String, provider: String) {
        let mine = held(&self.pending).bump(&provider);
        let ui = self.clone();
        self.rt.spawn_blocking(move || {
            let text = importer::read_capped(&file);
            let pending = held(&ui.pending);
            if pending.reads.get(&provider) != Some(&mine) {
                return; // the form was closed, or another file chosen, meanwhile
            }
            ui.forms.send_modify(|f| match text {
                None => {
                    f.errors.insert(provider.clone(), importer::UNREADABLE.into());
                }
                Some(t) => {
                    f.form.insert(form_key, t);
                    f.errors.shift_remove(&provider);
                }
            });
        });
    }

    /// A QR code read for a sign-in field from the picture `file` (none: the chooser was cancelled), off the window's
    /// thread.
    pub fn read_qr(self: &Arc<Self>, file: Option<PathBuf>, form_key: String, provider: String) {
        let mine = held(&self.pending).bump(&provider);
        let Some(file) = file else { return };
        let ui = self.clone();
        self.rt.spawn_blocking(move || {
            let text = qr::decode(&file).filter(|t| !t.trim().is_empty());
            let pending = held(&ui.pending);
            if pending.reads.get(&provider) != Some(&mine) {
                return; // closed, or another read started meanwhile
            }
            ui.forms.send_modify(|f| match text {
                None => {
                    f.errors.insert(
                        provider.clone(),
                        "No QR code found in that picture. Try again closer, or type it in.".into(),
                    );
                }
                Some(t) => {
                    f.form.insert(form_key, t.trim().chars().take(200).collect());
                    f.errors.shift_remove(&provider);
                    f.links.shift_remove(&provider);
                    f.challenges.shift_remove(&provider);
                }
            });
        });
    }

    /// Clears the clipboard of `secret` if it holds it, off the window's thread; see [`clear_clip_if`].
    pub fn clear_clipboard_if(&self, secret: String) {
        self.rt.spawn_blocking(move || clear_clip_if(&secret));
    }

    fn warn(&self, text: &str) {
        self.notice.send_modify(|n| {
            *n = Some(match n.take() {
                Some(old) => format!("{old}\n{text}"),
                None => text.into(),
            })
        });
    }

    fn unreleased(&self, names: &[String]) {
        let all = names.join(", ");
        self.warn(&format!(
            "Couldn't release this computer's device slot at {all}. Remove it in your {all} account{}.",
            if names.len() > 1 { "s" } else { "" }
        ));
    }

    pub fn sign_out(self: &Arc<Self>, provider: &str) {
        let (ui, provider) = (self.clone(), provider.to_string());
        self.rt.spawn_blocking(move || {
            let blob = ui.store.current_accounts().get(&provider).cloned();
            ui.store.account(&provider, None); // a failed save shows the unsaved banner; the account is out of memory either way
            ui.reset_if_empty();
            if blob.is_some_and(|b| !release(&provider, &b)) {
                ui.unreleased(&[provider_name(&provider)]);
            }
        });
    }

    /// Stops the VPN and waits for the engine to let go of its files. With `logout_tailscale` the node is first logged
    /// out of its tailnet, which only works while the engine runs. None = not asked; false = couldn't, so the device
    /// lingers in the admin console.
    async fn stop_vpn(&self, logout_tailscale: bool) -> Option<bool> {
        let out = if logout_tailscale { Some(ctl::tailscale_logout().await) } else { None };
        ctl::stop();
        let mut state = self.live.state.subscribe();
        let _ = tokio::time::timeout(Duration::from_secs(5), state.wait_for(|v| v.phase == Phase::Off)).await;
        out
    }

    /// Runs `f` while the VPN is off and can't start, as deleting the engine's files needs; else asks the user to try
    /// `what` again.
    async fn while_stopped<T: Send + 'static>(
        &self,
        what: &str,
        f: impl Future<Output = T> + Send + 'static,
    ) -> Option<T> {
        let done = ctl::while_stopped(f).await;
        if done.is_none() {
            self.notice.send_replace(Some(format!("Couldn't stop the VPN to {what}. Try again.")));
        }
        done
    }

    fn tailscale_left(&self, logged_out: Option<bool>) {
        if logged_out == Some(false) {
            self.warn("Couldn't log this computer out of Tailscale. Remove it in your tailnet's admin console.");
        }
    }

    /// Nothing left to route through: back to the first-run screen, but never by stopping a running VPN (its apps stay
    /// blocked).
    fn reset_if_empty(self: &Arc<Self>) {
        let s = self.store.current();
        let off = self.live.state.borrow().phase == Phase::Off;
        if off
            && self.store.accounts().borrow().is_empty()
            && !s.routes.iter().any(Route::imported)
            && s.servers.is_empty()
            && !s.home.tailscale
        {
            self.sign_out_all();
        }
    }

    /// A new control server or auth key means a new node: the engine must be fully down before its Tailscale state is
    /// deleted, then it reconnects fresh.
    pub fn set_tailscale_server(self: &Arc<Self>, url: Option<String>, auth_key: Option<String>) {
        let ui = self.clone();
        self.rt.spawn(async move {
            ui.stop_vpn(false).await;
            let (store, key) = (ui.store.clone(), auth_key.clone());
            // The new server is saved before the lock opens: a connect waiting for it starts with the new node, never the old one.
            let saved = ui.while_stopped("switch servers", async move {
                ctl::forget_tailscale().await;
                blocking(move || {
                    store.set_ts_suffix(None);
                    store.update(|s| {
                        let mut s = s.clone();
                        let h = &mut s.home;
                        h.ts_auth_key =
                            key.clone().or_else(|| h.ts_auth_key.clone().filter(|_| url == h.ts_control_url));
                        h.ts_control_url = url;
                        h.ts_suffix_allowed = None;
                        s
                    })
                })
                .await
            });
            let Some(saved) = saved.await else { return };
            if let Some(k) = auth_key.filter(|_| saved) {
                blocking(move || clear_clip_if(&k)).await;
            }
            ui.check_tailscale();
        });
    }

    /// Turns Tailscale off, drops its exit routes (their apps follow the default) and logs this device out of its tailnet.
    pub fn sign_out_tailscale(self: &Arc<Self>) {
        let had = self.store.current().tailscale();
        let ui = self.clone();
        self.rt.spawn(async move {
            let logged_out = ui.stop_vpn(had).await;
            let store = ui.store.clone();
            let off = ui.while_stopped("turn Tailscale off", async move {
                let st = store.clone();
                blocking(move || {
                    st.update(|s| {
                        let gone = s.routes.iter().filter(|r| r.ts_exit.is_some()).map(|r| r.id.clone()).collect();
                        let mut s = without(s, &gone, None);
                        s.home.tailscale = false;
                        s.home.ts_auth_key = None;
                        s
                    })
                })
                .await;
                ctl::forget_tailscale().await;
                blocking(move || store.set_ts_suffix(None)).await;
            });
            if off.await.is_none() {
                return;
            }
            // Off already (only a node left behind): the engine isn't running, so the tailnet still lists this computer.
            ui.tailscale_left(if had { logged_out } else { Some(false) });
            ui.check_tailscale();
            ui.reset_if_empty();
        });
    }

    /// Signs out of everything: back to the first-run screen.
    pub fn sign_out_all(self: &Arc<Self>) {
        let accounts = self.store.current_accounts();
        let tailscale = self.store.current().tailscale();
        let ui = self.clone();
        self.rt.spawn(async move {
            let logged_out = ui.stop_vpn(tailscale).await;
            let store = ui.store.clone();
            if ui.while_stopped("sign out", async move { blocking(move || store.sign_out_all()).await }).await.is_none()
            {
                return;
            }
            // Released only now: a running tunnel would lose its key while still carrying traffic.
            let revoked: Vec<_> = accounts
                .into_iter()
                .map(|(id, blob)| (provider_name(&id), tokio::task::spawn_blocking(move || release(&id, &blob))))
                .collect();
            // Nothing a provider asked or linked to outlives signing out of everything.
            ui.forms.send_modify(|f| {
                f.form.clear();
                f.errors.clear();
                f.links.clear();
                f.challenges.clear();
            });
            ui.import_draft.send_modify(Draft::clear);
            ui.signed_in.send_replace(false);
            ui.tailscale_left(logged_out);
            let mut kept = vec![];
            for (name, released) in revoked {
                if !released.await.unwrap_or(false) {
                    kept.push(name);
                }
            }
            if !kept.is_empty() {
                ui.unreleased(&kept);
            }
        });
    }

    pub fn refresh_countries(self: &Arc<Self>, provider: &str) {
        let (ui, id) = (self.clone(), provider.to_string());
        self.rt.spawn_blocking(move || {
            let Some(p) = providers::get(&id) else { return };
            let Some(account) = ui.store.current_accounts().get(&id).cloned() else { return };
            if let Ok(c) = p.countries(&account) {
                ui.countries.send_modify(|all| {
                    all.insert(id.clone(), c.clone());
                });
                // A fetched list is shown even when its cache can't be written; only a saved one counts as refreshed.
                if ui.store.set_countries(&id, &c) {
                    ui.refreshed.send_modify(|n| *n += 1);
                }
            }
        });
    }

    /// Countries offering a Nord specialty group; none if unknown (offline).
    pub async fn nord_group_countries(&self, group: &str) -> Option<IndexSet<String>> {
        if let Some(known) = held(&self.group_countries).get(group) {
            return Some(known.clone());
        }
        let g = group.to_string();
        let found = self.rt.spawn_blocking(move || nord::group_countries(&g).ok()).await.ok().flatten()?;
        held(&self.group_countries).insert(group.into(), found.clone());
        Some(found)
    }

    // ---- the apps -------------------------------------------------------------------------------------------------

    /// Reads the installed apps again (on every return to the window: the VPN keeps this process, and so this list,
    /// alive for days), so new apps can be routed and removed ones drop their route. Only after the installed-apps
    /// notice.
    pub fn refresh_apps(self: &Arc<Self>) {
        if *self.disclosed.borrow() {
            self.load_apps();
        }
    }

    fn load_apps(self: &Arc<Self>) {
        let n = {
            let mut asked = held(&self.apps_asked);
            *asked += 1;
            *asked
        };
        let ui = self.clone();
        self.rt.spawn_blocking(move || {
            let entries = crate::apps::scan();
            // Programs routed by their own path (no desktop entry) are listed too, while they are installed.
            let known: HashSet<&str> = entries.iter().map(|e| e.key.as_str()).collect();
            let s0 = ui.store.current();
            let programs: IndexSet<String> = s0
                .apps
                .keys()
                .chain(s0.profiles.iter().flat_map(|p| p.apps.keys()))
                .filter(|k| k.starts_with('/') && !known.contains(k.as_str()) && Path::new(k).exists())
                .cloned()
                .collect();
            // A program one of the apps runs (added before that app was installed) joins that app's group, after its entries.
            let owned: Vec<(String, Vec<String>)> = programs
                .iter()
                .filter_map(|p| {
                    entries
                        .iter()
                        .find(|e| crate::apps::matches(&e.matchers, p))
                        .map(|o| (p.clone(), if o.group.is_empty() { vec![o.key.clone()] } else { o.group.clone() }))
                })
                .collect();
            let group = |g: &[String]| -> Vec<String> {
                let all: Vec<String> = g
                    .iter()
                    .cloned()
                    .chain(owned.iter().filter(|(_, o)| o.as_slice() == g).map(|(p, _)| p.clone()))
                    .collect();
                if all.len() > 1 { all } else { vec![] }
            };
            let mut listed: Vec<AppInfo> = entries
                .iter()
                .map(|e| AppInfo {
                    pkg: e.key.clone(),
                    label: e.label.clone(),
                    system: e.system,
                    routable: !e.matchers.is_empty(),
                    group: group(if e.group.is_empty() { std::slice::from_ref(&e.key) } else { &e.group }),
                    kind: e.kind,
                })
                .collect();
            listed.extend(programs.iter().map(|p| AppInfo {
                pkg: p.clone(),
                label: Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                system: false,
                routable: crate::apps::unroutable(Path::new(p)).is_none(),
                group: owned.iter().find(|(q, _)| q == p).map(|(_, g)| group(g)).unwrap_or_default(),
                kind: "Program",
            }));
            let asked = held(&ui.apps_asked);
            if *asked != n {
                return; // a newer read is under way
            }
            let mut sorted = listed.clone();
            sorted.sort_by_cached_key(|a| a.label.to_lowercase());
            ui.apps.send_replace(sorted);
            let installed: HashSet<&str> = listed.iter().filter(|a| a.routable).map(|a| a.pkg.as_str()).collect();
            let groups: IndexSet<&Vec<String>> = listed.iter().map(|a| &a.group).filter(|g| !g.is_empty()).collect();
            // The one of `k`'s group that leads in `apps`: the first with a route there.
            let lead = |k: &str, apps: &IndexMap<String, String>| {
                groups
                    .iter()
                    .find(|g| g.iter().any(|x| x == k))
                    .and_then(|g| g.iter().find(|x| apps.contains_key(x.as_str())))
                    .cloned()
            };
            // An uninstalled app must not keep its route (and a tunnel) alive, nor one the engine can't tell apart (a
            // script or an AppImage), which would show on a route its traffic never takes; nor, of apps that run as one
            // program, a route after the group's first (it takes that one). Saved profiles too: one used later must not
            // bring such an exception back.
            let keep = |apps: &IndexMap<String, String>| -> IndexMap<String, String> {
                apps.iter()
                    .filter(|(k, _)| installed.contains(k.as_str()) && lead(k, apps).is_none_or(|l| l == **k))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            };
            let now = ui.store.current();
            // A route that loses to another of its group's is said, never dropped silently.
            let label: HashMap<&str, &str> = listed.iter().map(|a| (a.pkg.as_str(), a.label.as_str())).collect();
            let mut lost = vec![];
            for (profile, a) in
                std::iter::once((None, &now.apps)).chain(now.profiles.iter().map(|p| (Some(p.name.as_str()), &p.apps)))
            {
                let kept = keep(a);
                for k in a.keys().filter(|k| installed.contains(k.as_str()) && !kept.contains_key(*k)) {
                    let (k, l) = (
                        label.get(k.as_str()).copied().unwrap_or_default(),
                        lead(k, a).map(|l| label.get(l.as_str()).copied().unwrap_or_default()).unwrap_or_default(),
                    );
                    lost.push(format!(
                        "{k} runs as {l}, so it takes {l}'s route now{}.",
                        profile.map(|p| format!(" in {p}")).unwrap_or_default()
                    ));
                }
            }
            if !lost.is_empty() {
                ui.warn(&lost.join(" "));
            }
            let gone = |s: &Setup| s.apps != keep(&s.apps) || s.profiles.iter().any(|p| p.apps != keep(&p.apps));
            if gone(&now) {
                ui.store.edit(|s| Setup {
                    apps: keep(&s.apps),
                    profiles: s.profiles.iter().map(|p| Profile { apps: keep(&p.apps), ..p.clone() }).collect(),
                    ..s.clone()
                });
            }
            drop(asked);
        });
    }

    /// A program without a desktop entry (a command-line tool, a game), picked by its file and routed by its own path,
    /// which becomes its key; none, with the reason in [`Ui::notice`], for one the engine can't tell apart
    /// ([`crate::apps::unroutable`]) or one a listed app runs, which takes that app's route. It stays listed once it
    /// has a route.
    pub async fn add_program(self: &Arc<Self>, file: PathBuf) -> Option<String> {
        let ui = self.clone();
        let added = self.rt.spawn_blocking(move || {
            if let Some(why) = crate::apps::unroutable(&file) {
                ui.notice.send_replace(Some(why));
                return None;
            }
            let path = std::fs::canonicalize(&file).ok()?.to_string_lossy().into_owned();
            let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let routed: Vec<String> = ui.store.current().apps.keys().cloned().collect();
            let k = crate::apps::key_of(&path, &routed.iter().map(String::as_str).collect::<Vec<_>>());
            if k != path {
                let app = ui.apps.borrow().iter().find(|a| a.pkg == k).map_or_else(|| k.clone(), |a| a.label.clone());
                ui.notice.send_replace(Some(format!("{name} is part of {app}: it takes {app}'s route.")));
                return None;
            }
            ui.apps.send_if_modified(|list| {
                if list.iter().any(|a| a.pkg == path) {
                    return false;
                }
                list.push(AppInfo { kind: "Program", ..AppInfo::new(&path, &name) });
                list.sort_by_cached_key(|a| a.label.to_lowercase());
                true
            });
            Some(path)
        });
        added.await.ok().flatten()
    }

    /// An app's icon from its desktop entry (PNG or SVG), as straight RGBA, an SVG at 96 px; cached.
    pub async fn icon(&self, pkg: &str) -> Option<Arc<RgbaImage>> {
        {
            let mut icons = held(&self.icons);
            if let Some(i) = icons.shift_remove(pkg) {
                icons.insert(pkg.into(), i.clone());
                return Some(i);
            }
        }
        let key = pkg.to_string();
        let drawn = Arc::new(
            self.rt
                .spawn_blocking(move || crate::apps::icon_file(&key).and_then(|f| raster(&f)))
                .await
                .ok()
                .flatten()?,
        );
        let mut icons = held(&self.icons);
        icons.insert(pkg.into(), drawn.clone());
        if icons.len() > 200 {
            icons.shift_remove_index(0);
        }
        Some(drawn)
    }

    // ---- connection -------------------------------------------------------------------------------------------------

    pub fn connect(&self) {
        ctl::start();
    }

    pub fn disconnect(&self) {
        ctl::stop();
    }

    pub fn pause(&self, minutes: i32) {
        ctl::pause(minutes);
    }

    // ---- routes -----------------------------------------------------------------------------------------------------

    /// Adds a route for `loc` (or reuses one already exiting there) to the profile shown, and returns its id.
    pub fn add_route(&self, loc: &Location) -> String {
        let id = self.route_at(loc);
        self.keep(&id);
        id
    }

    /// The route exiting at `loc`: an existing one, or a new one.
    fn route_at(&self, loc: &Location) -> String {
        let s = self.store.current();
        if let Some(r) = s.routes.iter().find(|r| !r.imported() && r.loc.ident() == loc.ident()) {
            return r.id.clone();
        }
        let id = new_id(&s);
        self.store.edit(|s| {
            let mut s = s.clone();
            let hue = next_hue(&s);
            s.routes.push(Route { hue, ..Route::new(&id, loc.clone()) });
            s
        });
        id
    }

    /// Keeps route `id` on the profile shown, which then lists it even while no app uses it.
    fn keep(&self, id: &str) {
        let viewing = self.viewing.borrow().clone();
        self.store.edit(|s| {
            s.editing(draft_of(viewing.as_deref(), s).as_deref(), |mut p| {
                if !p.added.iter().any(|a| a == id) {
                    p.added.push(id.into());
                }
                p
            })
        });
    }

    /// Points route `id` at a provider location, dropping any imported source it had.
    pub fn set_location(&self, id: &str, loc: &Location) {
        let (id, loc) = (id.to_string(), loc.clone());
        self.guarded(
            || {},
            move |s| {
                let routes = s
                    .routes
                    .iter()
                    .map(|r| {
                        if r.id != id {
                            return r.clone();
                        }
                        // A route's blocking choice belongs to its provider: another provider starts from its own page.
                        let filter = r.filter.filter(|_| r.loc.provider == loc.provider && !r.imported());
                        Route {
                            loc: loc.clone(),
                            wg: None,
                            ovpn: None,
                            ss: None,
                            ts_exit: None,
                            ts_name: None,
                            own: None,
                            filter,
                            ..r.clone()
                        }
                    })
                    .collect();
                Setup { routes, ..s.clone() }
            },
        );
    }

    /// A new route for `loc` (or the one already exiting there) for app `pkg`, as one change; in the profile being
    /// viewed.
    pub fn add_route_for(&self, pkg: &str, loc: &Location) {
        let (pkg, loc, viewing) = (pkg.to_string(), loc.clone(), self.viewing.subscribe());
        let f = move |s: &Setup| {
            let r = s
                .routes
                .iter()
                .find(|r| !r.imported() && r.loc.ident() == loc.ident())
                .cloned()
                .unwrap_or_else(|| Route { hue: next_hue(s), ..Route::new(&new_id(s), loc.clone()) });
            let mut n = s.clone();
            if !n.routes.contains(&r) {
                n.routes.push(r.clone());
            }
            // As assign: an app given the default route follows the default.
            n.editing(draft_of(viewing.borrow().as_deref(), s).as_deref(), |mut p| {
                if r.id == p.default_route {
                    p.apps.shift_remove(&pkg);
                } else {
                    p.apps.insert(pkg.clone(), r.id.clone());
                }
                p
            })
        };
        if self.draft().is_some() { self.store.edit(f) } else { self.guarded(|| {}, f) }
    }

    /// Sets the default route of the profile being viewed to `loc` (a route already exiting there, or a new one).
    pub fn choose_default(&self, loc: &Location) {
        if self.draft().is_some() {
            let id = self.route_at(loc);
            self.set_default(&id);
        }
    }

    /// Saves `f`, unless it takes a provider over its limit ([`limits::over`]): then nothing changes until the user
    /// answers [`Ui::limit_ask`]. With one route of that provider already on a server, it offers to put both routes on
    /// that server. `after` runs once `f` is saved, whether at once or on the user's yes.
    fn guarded(&self, after: impl Fn() + Send + Sync + 'static, f: impl Fn(&Setup) -> Setup + Send + Sync + 'static) {
        let old = self.store.current();
        let accounts = self.store.current_accounts();
        let Some(o) =
            limits::over(&old, &f(&old), |p| accounts.get(p).and_then(|a| providers::get(p).map(|pr| pr.limit(a))))
        else {
            self.store.edit(&f);
            after();
            return;
        };
        let name = provider_name(&o.provider);
        // Only a route the engine runs as saved has a server worth sharing; checked again when the user answers.
        let running = self.live.running();
        let mut of = old.active_routes().into_iter().filter(|r| !r.imported() && r.loc.provider == o.provider);
        let anchor = match (of.next(), of.next()) {
            (Some(a), None) => Some(a.clone())
                .filter(|a| running.as_ref().and_then(|s| s.route(Some(&a.id))).is_some_and(|r| r.loc == a.loc)),
            _ => None,
        };
        let server = anchor.as_ref().and_then(|a| self.live.state.borrow().servers.get(&a.id).cloned());
        let (f, after) = (Arc::new(f), Arc::new(after));
        let apply = {
            let (store, f, after) = (self.store.clone(), f.clone(), after.clone());
            move || {
                store.edit(|s| f(s));
                after();
            }
        };
        let share = anchor.zip(server).map(|(anchor, sv)| {
            let (store, live, provider, name) = (self.store.clone(), self.live, o.provider.clone(), sv.name.clone());
            let share = move || {
                let same = store.current().route(Some(&anchor.id)).is_some_and(|r| r.loc == anchor.loc)
                    && live.state.borrow().servers.get(&anchor.id) == Some(&sv);
                if !same {
                    return;
                }
                store.edit(|s| {
                    let mut n = f(s);
                    let active: HashSet<String> = n.active_routes().into_iter().map(|r| r.id.clone()).collect();
                    for r in n
                        .routes
                        .iter_mut()
                        .filter(|r| !r.imported() && r.loc.provider == provider && active.contains(&r.id))
                    {
                        r.loc = Location { pinned: Some(sv.clone()), ..anchor.loc.clone() };
                    }
                    n
                });
                after();
            };
            (name, Box::new(share) as Box<dyn Fn() + Send + Sync>)
        });
        let text = limits::warning(&name, o.limit, &o.unit, o.n as i32);
        self.limit_ask.send_replace(Some(Arc::new(LimitAsk { text, apply: Box::new(apply), share })));
    }

    // ---- own servers ------------------------------------------------------------------------------------------------

    /// Before saved servers existed, an imported config lived only in its route: save each one once and link it.
    fn save_imported_servers(&self) {
        let unsaved = |r: &Route| (r.wg.is_some() || r.ovpn.is_some() || r.ss.is_some()) && r.own.is_none();
        if !self.store.current().routes.iter().any(unsaved) {
            return;
        }
        self.store.edit(|s| {
            let mut n = s.clone();
            for i in 0..n.routes.len() {
                let r = &n.routes[i];
                if !unsaved(r) {
                    continue;
                }
                let id = match n.servers.iter().find(|v| v.wg == r.wg && v.ovpn == r.ovpn && v.ss == r.ss) {
                    Some(v) => v.id.clone(),
                    None => {
                        let v = OwnServer {
                            id: new_server_id(&n.servers),
                            wg: r.wg.clone(),
                            ovpn: r.ovpn.clone(),
                            ss: r.ss.clone(),
                        };
                        let id = v.id.clone();
                        n.servers.push(v);
                        id
                    }
                };
                n.routes[i].own = Some(id);
            }
            n
        });
    }

    /// Saves one of the user's own servers; with a `target` ("" new route, "app:<key>" or a route id) that route uses
    /// it too. It applies at once; the future says whether it was written, so the window clears the clipboard only then.
    pub fn import_server(
        &self,
        target: Option<&str>,
        server: OwnServer,
    ) -> impl Future<Output = bool> + Send + 'static {
        let s = OwnServer { id: new_server_id(&self.store.current().servers), ..server };
        let added = s.clone();
        self.store.edit(|c| {
            let mut c = c.clone();
            c.servers.push(added);
            c
        });
        self.signed_in.send_replace(true);
        if let Some(t) = target {
            self.use_server(t, &s);
        }
        self.saved()
    }

    /// Writes the setup as it stands now, off the window's thread: true once it is on disk.
    fn saved(&self) -> impl Future<Output = bool> + Send + 'static {
        let store = self.store.clone();
        let written = self.rt.spawn_blocking(move || store.update(Setup::clone));
        async move { written.await.unwrap_or(false) }
    }

    /// Route `target` exits through saved server `s`; returns the route id.
    pub fn use_server(&self, target: &str, s: &OwnServer) -> String {
        self.add_imported(target, |r| Route {
            wg: s.wg.clone(),
            ovpn: s.ovpn.clone(),
            ss: s.ss.clone(),
            own: Some(s.id.clone()),
            ..r
        })
    }

    /// Renames a saved server and every route using it.
    pub fn rename_server(&self, id: &str, name: &str) {
        let n: String = name.trim().chars().take(40).collect();
        if n.is_empty() {
            return;
        }
        self.store.edit(|s| {
            let mut s = s.clone();
            for v in s.servers.iter_mut().filter(|v| v.id == id) {
                name_all(&n, &mut v.wg, &mut v.ovpn, &mut v.ss);
            }
            for r in s.routes.iter_mut().filter(|r| r.own.as_deref() == Some(id)) {
                name_all(&n, &mut r.wg, &mut r.ovpn, &mut r.ss);
            }
            s
        });
    }

    /// Removes a saved server and the routes using it; their apps follow the default route (or go Direct if that was
    /// one).
    pub fn remove_server(self: &Arc<Self>, id: &str) {
        self.store.edit(|s| {
            let gone = s.routes.iter().filter(|r| r.own.as_deref() == Some(id)).map(|r| r.id.clone()).collect();
            let mut n = without(s, &gone, None);
            n.servers.retain(|v| v.id != id);
            n
        });
        self.reset_if_empty();
    }

    /// Gives an imported source to a route and returns its id. `target` is "" (new route), "app:<key>" (new route for
    /// that app) or a route id (replace that route's source). `source` receives the blank route and sets wg/ovpn/ss or
    /// ts_exit. With no provider signed in, the unusable provider routes are dropped and the new route becomes the default.
    pub fn add_imported(&self, target: &str, source: impl FnOnce(Route) -> Route) -> String {
        let s = self.store.current();
        let id = if s.route(Some(target)).is_some() { target.to_string() } else { new_id(&s) };
        let no_accounts = self.store.accounts().borrow().is_empty();
        let viewing = self.viewing.borrow().clone();
        self.store.edit(|s| {
            let blank = match s.route(Some(&id)) {
                Some(r) => Route {
                    loc: Location::default(),
                    wg: None,
                    ovpn: None,
                    ss: None,
                    ts_exit: None,
                    ts_name: None,
                    own: None,
                    ..r.clone()
                },
                None => Route { hue: next_hue(s), ..Route::new(&id, Location::default()) },
            };
            let r = source(blank);
            let mut next = s.clone();
            match next.routes.iter_mut().find(|x| x.id == id) {
                Some(x) => *x = r,
                None => next.routes.push(r),
            }
            // With no provider account left, provider routes go; not while editing a profile not in use (nothing live changes).
            if no_accounts && draft_of(viewing.as_deref(), s).is_none() {
                let dead = next.routes.iter().filter(|r| !r.imported()).map(|r| r.id.clone()).collect();
                next = without(&next, &dead, Some(&id));
            }
            next
        });
        if let Some(pkg) = target.strip_prefix("app:") {
            self.assign(pkg, Some(&id));
        }
        if target.is_empty() {
            self.keep(&id); // a new route, added to the profile shown
        }
        self.signed_in.send_replace(true);
        id
    }

    /// Tailscale runs one exit node at a time: an existing exit route is retargeted instead of adding another. True if
    /// one was. `ip` is the node's tailnet address (what Tailscale is told, unambiguous); `name` is only for display.
    pub fn add_ts_exit(&self, target: &str, ip: &str, name: Option<&str>) -> bool {
        if self.ts_lock(ip).is_some() {
            return false;
        }
        if let Some(d) = self.draft() {
            self.draft_ts_exit(&d, target, ip, name);
            return true;
        }
        let old = self.store.current().routes.into_iter().find(|r| r.ts_exit.is_some());
        self.store.edit(|s| {
            let mut s = s.clone();
            for r in s.routes.iter_mut().filter(|r| r.ts_exit.is_some()) {
                r.ts_exit = Some(ip.into());
                r.ts_name = name.map(str::to_string);
            }
            s
        });
        let via = |r: Route| Route { ts_exit: Some(ip.into()), ts_name: name.map(str::to_string), ..r };
        let t = self.store.current().route(Some(target)).cloned();
        match (t, &old) {
            (Some(t), _) if t.ts_exit.is_none() => {
                self.add_imported(target, via);
            }
            (_, Some(o)) => {
                if let Some(pkg) = target.strip_prefix("app:") {
                    self.assign(pkg, Some(&o.id));
                } else if target.is_empty() {
                    self.keep(&o.id);
                }
            }
            _ => {
                self.add_imported(target, via);
            }
        }
        old.is_some()
    }

    /// Skips providers: Tailscale becomes the only network feature, and the unusable provider route goes.
    pub fn use_tailscale_only(&self) {
        let no_accounts = self.store.accounts().borrow().is_empty();
        self.store.edit(|s| {
            let routes: Vec<Route> = if no_accounts {
                s.routes.iter().filter(|r| r.imported()).cloned().collect()
            } else {
                s.routes.clone()
            };
            let has = |id: &str| routes.iter().any(|r| r.id == id);
            let default_route = if has(&s.default_route) {
                s.default_route.clone()
            } else {
                routes.first().map_or_else(|| DIRECT.into(), |r| r.id.clone())
            };
            let apps =
                s.apps.iter().filter(|(_, v)| *v == DIRECT || has(v)).map(|(k, v)| (k.clone(), v.clone())).collect();
            Setup { routes, default_route, apps, home: Home { tailscale: true, ..s.home.clone() }, ..s.clone() }
        });
        self.signed_in.send_replace(true);
    }

    /// Renames one of the user's own servers (WireGuard, OpenVPN, Shadowsocks, Tailscale exit); a saved one everywhere.
    pub fn rename_route(&self, id: &str, name: &str) {
        if let Some(own) = self.store.current().route(Some(id)).and_then(|r| r.own.clone()) {
            return self.rename_server(&own, name);
        }
        let n: String = name.trim().chars().take(40).collect();
        if n.is_empty() {
            return;
        }
        self.store.edit(|s| {
            let mut s = s.clone();
            for r in s.routes.iter_mut().filter(|r| r.id == id) {
                name_all(&n, &mut r.wg, &mut r.ovpn, &mut r.ss);
                r.ts_name = r.ts_exit.as_ref().map(|_| n.clone());
            }
            s
        });
    }

    pub fn remove_route(&self, id: &str) {
        self.store.edit(|s| {
            if s.routes.len() <= 1 && s.default_route == id {
                s.clone()
            } else {
                without(s, &HashSet::from([id.to_string()]), None)
            }
        });
    }

    /// Makes route `id` the default of the profile being viewed (saved only, nothing connects) or of the live setup.
    pub fn set_default(&self, id: &str) {
        let id = id.to_string();
        self.edit_routes(move |mut p| {
            p.apps.retain(|_, v| *v != id);
            p.default_route = id.clone();
            p
        });
    }

    /// `f` on the profile being viewed when it isn't the one in use (nothing connects, no limit to check), else live and
    /// guarded.
    fn edit_routes(&self, f: impl Fn(Profile) -> Profile + Send + Sync + 'static) {
        match self.draft() {
            Some(d) => self.store.edit(|s| s.editing(Some(&d), &f)),
            None => self.guarded(|| {}, move |s| s.editing(None, &f)),
        }
    }

    // ---- viewing a profile ------------------------------------------------------------------------------------------

    /// The setup as the viewed profile routes it: what Routes and Apps show.
    pub fn shown(&self) -> Setup {
        self.store.current().view_as(self.viewing.borrow().as_deref())
    }

    /// The viewed profile, if it exists and isn't the one in use: edits go to it alone.
    fn draft(&self) -> Option<String> {
        draft_of(self.viewing.borrow().as_deref(), &self.store.current())
    }

    /// Route `id`, ready to be changed for the profile being viewed: if the live setup or another profile uses it too,
    /// the viewed one gets its own copy first (same exit, new id), so nothing live or elsewhere changes. Otherwise `id`
    /// itself.
    pub fn own_route(&self, id: &str) -> String {
        let Some(d) = self.draft() else { return id.into() };
        let s = self.store.current();
        // Shared with the live setup or another profile: those keep theirs.
        let shared = s.active_routes().iter().any(|r| r.id == id)
            || s.added.iter().any(|a| a == id)
            || s.saved().iter().any(|p| p.name != d && p.own().contains(id));
        let Some(r) = s.route(Some(id)).filter(|_| shared).cloned() else { return id.into() };
        let copy = new_id(&s);
        self.store.edit(|c| {
            let mut c = c.clone();
            let hue = next_hue(&c);
            c.routes.push(Route { id: copy.clone(), hue, ..r });
            c.editing(Some(&d), |mut p| {
                if p.default_route == id {
                    p.default_route = copy.clone();
                }
                p.apps.values_mut().filter(|v| *v == id).for_each(|v| *v = copy.clone());
                p.added.iter_mut().filter(|a| *a == id).for_each(|a| *a = copy.clone());
                p
            })
        });
        copy
    }

    /// Takes route `id` out of the profile being viewed: its apps there follow that profile's default. The route stays
    /// for others.
    pub fn drop_route(&self, id: &str) {
        if let Some(d) = self.draft() {
            self.store.edit(|s| {
                s.editing(Some(&d), |mut p| {
                    p.apps.retain(|_, v| v != id);
                    p.added.retain(|a| a != id);
                    p
                })
            });
        }
    }

    /// Exit node `ip` for profile `d`, not in use: only its own routes change, never another profile's. It reuses a route
    /// already through that node, else retargets one of its Tailscale routes (copied first if shared), else adds one.
    /// Tailscale uses one exit node at a time, so the profile's other Tailscale routes follow to the same node.
    fn draft_ts_exit(&self, d: &str, target: &str, ip: &str, name: Option<&str>) {
        let s = self.store.current();
        let own = s.profiles.iter().find(|p| p.name == d).map(Profile::own).unwrap_or_default();
        // Replaces the route's whole source (a saved server's config goes), in place.
        let via = |id: &str| {
            self.add_imported(id, |r| Route { ts_exit: Some(ip.into()), ts_name: name.map(str::to_string), ..r })
        };
        let id = if let Some(r) = s.route(Some(target)) {
            via(&r.id);
            r.id.clone()
        } else if let Some(r) = s.routes.iter().find(|r| r.ts_exit.as_deref() == Some(ip)) {
            r.id.clone()
        } else if let Some(r) = s.routes.iter().find(|r| r.ts_exit.is_some() && own.contains(&r.id)) {
            let copy = self.own_route(&r.id);
            via(&copy);
            copy
        } else {
            via(target)
        };
        // Read again: a route copied above is the profile's now, the original no longer.
        let now = self.store.current();
        let mine = now.profiles.iter().find(|p| p.name == d).map(Profile::own).unwrap_or_default();
        let others: Vec<String> = now
            .routes
            .iter()
            .filter(|r| r.ts_exit.as_ref().is_some_and(|t| t != ip) && mine.contains(&r.id) && r.id != id)
            .map(|r| r.id.clone())
            .collect();
        for o in others {
            via(&self.own_route(&o));
        }
        if let Some(pkg) = target.strip_prefix("app:") {
            self.assign(pkg, Some(&id));
        } else if target == "default" {
            self.set_default(&id);
        } else if target.is_empty() {
            self.keep(&id);
        }
    }

    /// While a profile not in use is edited: the live route through another Tailscale exit node, which keeps `ip` from
    /// being chosen (Tailscale uses one exit node at a time, and the live one must not change before Use).
    pub fn ts_lock(&self, ip: &str) -> Option<Route> {
        self.draft()?;
        self.store.current().active_routes().into_iter().find(|r| r.ts_exit.as_ref().is_some_and(|t| t != ip)).cloned()
    }

    /// Shows profile `name` without using it: nothing reconnects until [`Ui::use_profile`].
    pub fn view(&self, name: Option<&str>) {
        let in_use = self.store.current().profile;
        self.viewing.send_replace(name.filter(|n| Some(*n) != in_use.as_deref()).map(str::to_string));
    }

    // ---- profiles ---------------------------------------------------------------------------------------------------

    /// Switches to profile `name` from outside the window (the tray). True when the switch waits on the window: an
    /// empty profile, shown to be given a default route, or a provider's limit to answer ([`Ui::limit_ask`], which only
    /// it shows).
    pub fn use_profile_outside(self: &Arc<Self>, name: &str) -> bool {
        self.limit_ask.send_replace(None); // a question left from an earlier switch: this one replaces it
        self.use_profile(name);
        self.limit_ask.borrow().is_some() || self.viewing.borrow().as_deref() == Some(name)
    }

    /// Switches to profile `name`, at once or after the user's yes to a provider's limit.
    pub fn use_profile(self: &Arc<Self>, name: &str) {
        ctl::profiles::refused().send_replace(None);
        let s = self.store.current();
        let Some(p) = s.profiles.iter().find(|p| p.name == name) else { return };
        if s.profile.as_deref() == Some(name) {
            self.viewing.send_replace(None);
            return;
        }
        // An empty profile can't be used yet: it is shown, to be given a default route.
        if !p.ready() {
            self.viewing.send_replace(Some(name.into()));
            return;
        }
        let (me, to, n) = (Arc::downgrade(self), name.to_string(), name.to_string());
        let after = move || {
            if let Some(ui) = me.upgrade() {
                ui.viewing.send_replace(None);
                ctl::profiles::started(&to);
            }
        };
        self.guarded(after, move |s| s.use_profile(&n));
    }

    /// A new profile `raw`: with none in use, the current setup saved as it and in use (nothing reconnects); otherwise a
    /// copy of the current setup, or `empty`, shown but not in use.
    pub fn new_profile(&self, raw: &str, empty: bool) {
        let mut added = None;
        self.store.edit(|s| {
            let Some(n) = s.profile_name(raw, None).filter(|_| s.profiles.len() < MAX_PROFILES) else {
                return s.clone();
            };
            if s.profile.is_none() && !empty {
                return s.save_as(&n);
            }
            let next = s.add(&n, empty);
            added = Some(n);
            next
        });
        self.viewing.send_replace(added);
    }

    pub fn rename_profile(&self, old: &str, name: &str) {
        self.store.edit(|s| s.profile_name(name, Some(old)).map_or_else(|| s.clone(), |n| s.rename(old, &n)));
        // Renamed while shown: keep showing it under its new name.
        let gone = !self.store.current().profiles.iter().any(|p| p.name == old);
        if gone && self.viewing.borrow().as_deref() == Some(old) {
            self.viewing.send_replace(Some(name.trim().into()));
        }
    }

    pub fn forget_profile(&self, name: &str) {
        self.store.edit(|s| s.forget(name));
        if self.viewing.borrow().as_deref() == Some(name) {
            self.viewing.send_replace(None);
        }
    }

    pub fn move_profile(&self, name: &str, by: i32) {
        self.store.edit(|s| s.move_profile(name, by));
    }

    /// `route_id` none or equal to the default: the app follows the default.
    pub fn assign(&self, pkg: &str, route_id: Option<&str>) {
        let (pkg, route) = (pkg.to_string(), route_id.map(str::to_string));
        self.edit_routes(move |mut p| {
            match route.as_ref().filter(|r| **r != p.default_route) {
                Some(r) => {
                    p.apps.insert(pkg.clone(), r.clone());
                }
                None => {
                    p.apps.shift_remove(&pkg);
                }
            }
            p
        });
    }

    // ---- settings ---------------------------------------------------------------------------------------------------

    // Settings apply at once and reach the disk on the store's writer, in the order they were made, as every edit does.

    /// Route `id`'s own blocking choice; one equal to its provider page's is dropped, so the route follows the page again.
    pub fn set_filter(&self, id: &str, on: bool) {
        self.store.edit(|s| {
            let mut n = s.clone();
            for r in n.routes.iter_mut().filter(|r| r.id == id) {
                let page = s.opt(&r.loc.provider, PROTECT).as_deref() == Some("on");
                r.filter = Some(on).filter(|o| *o != page);
            }
            n
        });
    }

    /// One setting on `provider`'s page. A page setting can change which servers a provider lists (Mullvad-owned only),
    /// so its countries are read again.
    pub fn set_opt(self: &Arc<Self>, provider: &str, key: &str, value: &str) {
        self.store.edit(|s| {
            let mut n = s.clone();
            n.opts.entry(provider.into()).or_default().insert(key.into(), value.into());
            n
        });
        self.refresh_countries(provider);
    }

    pub fn toggle_favorite(&self, loc: &Location) {
        let l = loc.fav_key();
        self.store.edit(|s| {
            let mut n = s.clone();
            // Matched by identity, so favourites saved with older ids are found (and dropped) too.
            if n.favorites.iter().any(|f| f.fav_key() == l) {
                n.favorites.retain(|f| f.fav_key() != l);
            } else {
                // Saved whole (a pinned server keeps its address and key, to connect to it later), matched by identity only.
                n.favorites.push(Location { group: None, protocol: None, ..loc.clone() });
            }
            n
        });
    }

    pub fn set_prefs(&self, f: impl FnOnce(&Prefs) -> Prefs) {
        self.store.edit(|s| Setup { prefs: f(&s.prefs), ..s.clone() });
    }

    /// Statistics on or off; while off nothing is recorded ([`app::init`] starts and stops the collector).
    pub fn set_stats(&self, on: bool) {
        self.set_prefs(|p| Prefs { stats: on, ..p.clone() });
    }

    /// Erases all statistics and the engine's record of looked-up domains. Recording, if on, carries on from now.
    pub fn delete_stats(&self) {
        crate::stats::delete();
        ctl::forget_lookups();
    }

    pub fn set_home(&self, f: impl FnOnce(&Home) -> Home) {
        self.store.edit(|s| Setup { home: f(&s.home), ..s.clone() });
    }

    /// The home tunnel from a router's WireGuard config: none once it applies, else why it can't. The clipboard is
    /// cleared of the config once it is written.
    pub fn import_home_wire_guard(&self, text: &str) -> Option<String> {
        let p = match wg_conf::parse(text, "Home") {
            Ok(p) => p,
            Err(e) => {
                let m = e.to_string();
                return Some(if m.is_empty() { "Not a WireGuard config".into() } else { m });
            }
        };
        self.set_home(|h| Home { wg: Some(p), ..h.clone() });
        let (saved, text) = (self.saved(), text.to_string());
        self.rt.spawn(async move {
            if saved.await {
                blocking(move || clear_clip_if(&text)).await;
            }
        });
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The connection, as these tests have it: commands do nothing, work that needs the VPN off runs unless
    /// [`ctl::REFUSES`], and Tailscale logs out as [`ctl::LOGS_OUT`] says.
    pub(super) mod ctl {
        use std::sync::LazyLock;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::sync::watch;

        pub static REFUSES: AtomicBool = AtomicBool::new(false);
        pub static LOGS_OUT: AtomicBool = AtomicBool::new(true);

        pub fn start() {}
        pub fn stop() {}
        pub fn pause(_: i32) {}

        pub async fn while_stopped<T: Send + 'static>(f: impl Future<Output = T> + Send + 'static) -> Option<T> {
            if REFUSES.load(Ordering::SeqCst) { None } else { Some(f.await) }
        }

        pub async fn tailscale_logout() -> bool {
            LOGS_OUT.load(Ordering::SeqCst)
        }

        pub async fn forget_tailscale() -> bool {
            true
        }

        pub fn forget_lookups() -> bool {
            true
        }

        pub mod profiles {
            use super::*;
            pub use crate::vpn::profiles::Refused;

            static REFUSED: LazyLock<watch::Sender<Option<Refused>>> = LazyLock::new(watch::Sender::default);

            pub fn refused() -> &'static watch::Sender<Option<Refused>> {
                &REFUSED
            }

            pub fn started(_: &str) {
                REFUSED.send_replace(None);
            }
        }
    }

    use crate::limits::LIMIT_OPT;
    use crate::model::Server;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    /// A window's model on a store, a runtime and a connection of its own.
    struct World {
        ui: Arc<Ui>,
        live: &'static Live,
        rt: tokio::runtime::Runtime,
        _dir: tempfile::TempDir,
    }

    impl World {
        fn setup(&self) -> Setup {
            self.ui.store.current()
        }
    }

    impl Drop for World {
        // The last edits reach the disk before the folder goes.
        fn drop(&mut self) {
            self.ui.store.flush();
        }
    }

    /// `setup` with `accounts` signed in, each with a catalogue just saved, so nothing is fetched.
    fn world(setup: Setup, accounts: &[(&str, &str)]) -> World {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path(), Box::new(|| Ok([5; 32])));
        store.update(|_| setup.clone());
        for (id, blob) in accounts {
            store.account(id, Some(blob));
            store.set_countries(id, &[]);
        }
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let live: &'static Live = Box::leak(Box::default());
        let prefs = Box::leak(Box::new(SharedPreferences::new(dir.path().join("unbraid_ui.properties"))));
        let ui = Ui::with(store, rt.handle().clone(), live, Some(prefs));
        World { ui, live, rt, _dir: dir }
    }

    /// Waits for `f` to hold, as the window would see it happen.
    fn until(what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !f() {
            assert!(Instant::now() < end, "never: {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Tests that sign out take turns: they share the connection's answers.
    fn signing_out() -> MutexGuard<'static, ()> {
        static TURN: Mutex<()> = Mutex::new(());
        held(&TURN)
    }

    fn nl() -> Route {
        Route::new("nl", Location::country("nord", 153, "NL", "Netherlands"))
    }

    fn us() -> Route {
        Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) }
    }

    fn base() -> Setup {
        Setup { routes: vec![nl(), us()], default_route: "nl".into(), ..Setup::default() }
    }

    fn apps(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn ids(s: &Setup) -> Vec<&str> {
        s.routes.iter().map(|r| r.id.as_str()).collect()
    }

    fn wg(name: &str) -> OwnServer {
        let peer =
            WgPeer::new(name, "priv", vec!["10.0.0.2/32".into()], "pub", "192.0.2.1:51820", vec!["0.0.0.0/0".into()]);
        OwnServer { id: String::new(), wg: Some(peer), ovpn: None, ss: None }
    }

    fn profile<'a>(s: &'a Setup, name: &str) -> &'a Profile {
        s.profiles.iter().find(|p| p.name == name).unwrap()
    }

    /// A change that would take a provider over its limit waits for the user's answer; within it, it saves at once.
    /// Connected, with one route of that provider on a server, both routes can share it, if it still runs as asked.
    #[test]
    fn guarded_edits_ask_before_the_limit() {
        let mut s = base();
        s.opts.insert("nord".into(), IndexMap::from([(LIMIT_OPT.to_string(), "1".to_string())]));
        let w = world(s, &[("nord", "{}")]);
        w.ui.set_default("us");
        assert_eq!(("us", true), (w.setup().default_route.as_str(), w.ui.limit_ask.borrow().is_none()));
        w.ui.assign("firefox", Some("nl"));
        let ask = w.ui.limit_ask.borrow().clone().expect("asked");
        assert_eq!(
            "NordVPN allows 1 connection. This would make it 2. Over the limit, routes can stop working without an error.",
            ask.text
        );
        assert!(ask.share.is_none(), "nothing runs: no server to share");
        assert!(w.setup().apps.is_empty(), "nothing changes before the answer");
        (ask.apply)();
        assert_eq!(apps(&[("firefox", "nl")]), w.setup().apps);

        w.ui.assign("firefox", None);
        let sv = Server {
            name: "us5".into(),
            host: "us5.nordvpn.com".into(),
            ip: "192.0.2.5".into(),
            public_key: "k".into(),
            load: 3,
            ..Server::default()
        };
        *w.live.running.write().unwrap() = Some(w.setup());
        w.live.state.send_replace(VpnState {
            phase: Phase::On,
            servers: IndexMap::from([("us".to_string(), sv.clone())]),
            ..VpnState::default()
        });
        w.ui.assign("code", Some("nl"));
        let ask = w.ui.limit_ask.borrow().clone().expect("asked");
        let (name, share) = ask.share.as_ref().expect("a server to share");
        assert_eq!("us5", name);
        // Checked again on the answer: a server that changed meanwhile isn't offered any more.
        w.live.state.send_modify(|v| v.servers.clear());
        share();
        assert!(w.setup().apps.is_empty());
        w.live.state.send_modify(|v| {
            v.servers.insert("us".into(), sv.clone());
        });
        share();
        let s = w.setup();
        let pinned = Location { pinned: Some(sv), ..us().loc };
        assert_eq!(apps(&[("code", "nl")]), s.apps);
        assert_eq!((&pinned, &pinned), (&s.route(Some("us")).unwrap().loc, &s.route(Some("nl")).unwrap().loc));
    }

    /// New routes get unique ids ("r" and 8 hex digits) and the first free of seven hues, then one per route. A place
    /// already routed is reused; either way the route is kept on the profile shown.
    #[test]
    fn route_ids_and_hues() {
        let w = world(base(), &[("nord", "{}")]);
        let it = Location::country("nord", 106, "IT", "Italy");
        let id = w.ui.add_route(&it);
        assert!(id.len() == 9 && id.starts_with('r') && id[1..].bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
        assert_eq!((2, vec![id.clone()]), (w.setup().route(Some(&id)).unwrap().hue, w.setup().added));
        assert_eq!(id, w.ui.add_route(&it));
        assert_eq!(3, w.setup().routes.len());
        w.ui.remove_route("nl");
        let fr = w.ui.add_route(&Location::country("nord", 74, "FR", "France"));
        assert_eq!(0, w.setup().route(Some(&fr)).unwrap().hue, "a free hue comes back");
        for (i, c) in ["DE", "ES", "PT", "SE"].into_iter().enumerate() {
            w.ui.add_route(&Location::country("nord", 300 + i as i32, c, c));
        }
        let ch = w.ui.add_route(&Location::country("nord", 209, "CH", "Switzerland"));
        let s = w.setup();
        assert_eq!(7, s.route(Some(&ch)).unwrap().hue, "all seven taken: one per route");
        assert_eq!(8, s.routes.iter().map(|r| &r.id).collect::<HashSet<_>>().len());
    }

    /// A removed route's apps follow the default, and a removed default gives way to the first route left; the last
    /// route stays while it is the default. A saved server takes the routes using it along.
    #[test]
    fn removing_routes_and_servers() {
        let mut s = base();
        s.apps = apps(&[("firefox", "us"), ("code", "nl")]);
        let w = world(s, &[("nord", "{}")]);
        w.ui.remove_route("nl");
        let s = w.setup();
        assert_eq!((vec!["us"], "us", apps(&[("firefox", "us")])), (ids(&s), s.default_route.as_str(), s.apps.clone()));
        w.ui.remove_route("us");
        assert_eq!(vec!["us"], ids(&w.setup()), "the only route, and the default");
        assert!(w.rt.block_on(w.ui.import_server(Some(""), wg("Home VPS"))));
        let server = w.setup().servers[0].clone();
        let app = w.ui.use_server("app:mpv", &server);
        assert_eq!((3, Some(&app)), (w.setup().routes.len(), w.setup().apps.get("mpv")));
        w.ui.remove_server(&server.id);
        let s = w.setup();
        assert_eq!((vec!["us"], 0, None), (ids(&s), s.servers.len(), s.apps.get("mpv")));
    }

    /// With no provider signed in, an import drops the unusable provider routes, whose apps follow it, and becomes the
    /// default; Direct apps stay Direct.
    #[test]
    fn without_accounts_an_import_becomes_the_default() {
        let mut s = base();
        s.apps = apps(&[("firefox", "us"), ("bank", DIRECT)]);
        let w = world(s, &[]);
        assert!(!*w.ui.signed_in.borrow());
        let id = w.ui.use_server("", &wg("Home VPS"));
        let s = w.setup();
        assert_eq!(
            (vec![id.as_str()], id.as_str(), apps(&[("bank", DIRECT)])),
            (ids(&s), s.default_route.as_str(), s.apps.clone())
        );
        assert!(*w.ui.signed_in.borrow());
    }

    /// The last thing to route through removed: no route is left (the default is Direct), and the app goes back to
    /// its first run.
    #[test]
    fn removing_the_last_server_signs_out() {
        let _turn = signing_out();
        let w = world(base(), &[]);
        assert!(w.rt.block_on(w.ui.import_server(Some(""), wg("Home VPS"))));
        let s = w.setup();
        assert_eq!(vec![s.default_route.as_str()], ids(&s));
        w.ui.remove_server(&s.servers[0].id);
        let s = w.setup();
        assert_eq!((0, DIRECT), (s.routes.len(), s.default_route.as_str()));
        until("signed out", || !*w.ui.signed_in.borrow());
    }

    /// Signing out releases each provider's device slot once the VPN is down and says which it couldn't, after the
    /// tailnet this computer stays in; a VPN that won't stop signs nothing out and asks to try again.
    #[test]
    fn sign_out_releases_and_says_what_it_couldnt() {
        let _turn = signing_out();
        let mut s = base();
        s.home.tailscale = true;
        // Mullvad, IVPN and AirVPN can't read these accounts, so their slots can't be released; NordVPN has none.
        let w = world(s, &[("nord", "{}"), ("mullvad", "not an account"), ("ivpn", "neither"), ("airvpn", "nor this")]);
        let notice = || w.ui.notice.borrow().clone();
        w.ui.sign_out("mullvad");
        until("Mullvad's slot", || notice().is_some());
        assert_eq!(
            Some("Couldn't release this computer's device slot at Mullvad. Remove it in your Mullvad account."),
            notice().as_deref()
        );
        assert_eq!(
            vec!["nord", "ivpn", "airvpn"],
            w.ui.store.current_accounts().keys().map(String::as_str).collect::<Vec<_>>()
        );
        assert!(*w.ui.signed_in.borrow());
        w.ui.notice.send_replace(None);

        ctl::REFUSES.store(true, Ordering::SeqCst);
        w.ui.sign_out_all();
        until("asked to try again", || notice().is_some());
        ctl::REFUSES.store(false, Ordering::SeqCst);
        assert_eq!(Some("Couldn't stop the VPN to sign out. Try again."), notice().as_deref());
        assert_eq!(3, w.ui.store.current_accounts().len());
        w.ui.notice.send_replace(None);

        w.ui.forms.send_modify(|f| {
            f.form.insert(form_key("pia", "username"), "p1234567".into());
            f.errors.insert("pia".into(), "Wrong password".into());
        });
        w.ui.import_draft.send_modify(Draft::shadowsocks);
        ctl::LOGS_OUT.store(false, Ordering::SeqCst);
        w.ui.sign_out_all();
        until("signed out", || !*w.ui.signed_in.borrow() && notice().is_some_and(|n| n.contains("slot")));
        ctl::LOGS_OUT.store(true, Ordering::SeqCst);
        assert_eq!(
            Some(
                "Couldn't log this computer out of Tailscale. Remove it in your tailnet's admin console.\nCouldn't release this computer's device slot at IVPN, AirVPN. Remove it in your IVPN, AirVPN accounts."
            ),
            notice().as_deref()
        );
        assert!(w.ui.store.current_accounts().is_empty());
        let f = w.ui.forms.borrow().clone();
        assert!(f.form.is_empty() && f.errors.is_empty());
        assert_eq!(None, w.ui.import_draft.borrow().link);
    }

    /// While a profile not in use is shown, a route it shares gets a copy of its own before it changes, so the live
    /// setup and the other profiles keep theirs. Dropping a route takes it out of that profile only.
    #[test]
    fn a_draft_owns_and_drops_its_routes() {
        let mut s = base();
        s.apps = apps(&[("firefox", "us")]);
        let w = world(s.save_as("Home").add("Travel", false), &[("nord", "{}")]);
        assert_eq!("us", w.ui.own_route("us"), "the profile in use changes the route itself");
        w.ui.view(Some("Travel"));
        let us2 = w.ui.own_route("us");
        let nl2 = w.ui.own_route("nl");
        let s = w.setup();
        let travel = profile(&s, "Travel");
        assert_eq!((nl2.as_str(), Some(&us2)), (travel.default_route.as_str(), travel.apps.get("firefox")));
        assert_eq!(
            ("nl", Some(&"us".to_string())),
            (s.default_route.as_str(), s.apps.get("firefox")),
            "the live setup keeps its own"
        );
        assert_eq!(
            (us().loc, 2, 3),
            (
                s.route(Some(&us2)).unwrap().loc.clone(),
                s.route(Some(&us2)).unwrap().hue,
                s.route(Some(&nl2)).unwrap().hue
            )
        );
        assert_eq!(us2, w.ui.own_route(&us2), "its own already");
        w.ui.drop_route(&us2);
        let s = w.setup();
        assert!(profile(&s, "Travel").apps.is_empty());
        assert!(s.route(Some(&us2)).is_some(), "the route stays for the others");
        w.ui.view(None);
        w.ui.drop_route("us");
        assert_eq!(Some(&"us".to_string()), w.setup().apps.get("firefox"), "only a profile not in use drops routes");
    }

    /// The tray's switch says when it waits on the window: an empty profile, shown to be given a default route, or a
    /// provider's limit to answer. One that completes doesn't.
    #[test]
    fn a_tray_switch_says_when_it_waits_on_the_window() {
        let mut s = base();
        s.apps = apps(&[("firefox", "us")]);
        let mut s = s.save_as("Home");
        s.profiles.extend([Profile::new("Travel", ""), Profile::new("Solo", "nl")]);
        s.opts.insert("nord".into(), IndexMap::from([(LIMIT_OPT.to_string(), "1".to_string())]));
        let w = world(s, &[("nord", "{}")]);
        let in_use = || w.setup().profile;
        assert!(w.ui.use_profile_outside("Travel"));
        assert_eq!(Some("Travel"), w.ui.viewing.borrow().as_deref());
        w.ui.view(None);
        w.ui.use_profile("Solo"); // NordVPN: the Netherlands only, within 1
        assert_eq!(Some("Solo".into()), in_use());
        assert!(w.ui.use_profile_outside("Home")); // and the United States: over 1
        assert_eq!(Some("Solo".into()), in_use());
        let ask = w.ui.limit_ask.borrow().clone().expect("asked");
        (ask.apply)();
        assert_eq!((Some("Home".into()), None), (in_use(), w.ui.viewing.borrow().clone()));
        w.ui.use_profile("Solo");
        w.ui.store.update(|s| {
            let mut s = s.clone();
            s.opts["nord"].insert(LIMIT_OPT.into(), "10".into());
            s
        });
        assert!(!w.ui.use_profile_outside("Home"));
        assert!(w.ui.limit_ask.borrow().is_none());
        assert_eq!(Some("Home".into()), in_use());
    }

    /// Tailscale has one exit node at a time: an exit route is retargeted rather than another added. While a profile
    /// not in use is shown, the live setup's node can't change before Use, so another one is refused.
    #[test]
    fn tailscale_exits_one_at_a_time() {
        let w = world(base(), &[("nord", "{}")]);
        assert!(!w.ui.add_ts_exit("", "100.64.0.9", Some("nas")), "none to retarget: a new route");
        let s = w.setup();
        let r = s.routes.last().unwrap();
        assert_eq!(
            (Some("100.64.0.9"), "nas".to_string(), true),
            (r.ts_exit.as_deref(), r.name(), s.added.contains(&r.id))
        );

        let ts = Route {
            ts_exit: Some("100.64.0.1".into()),
            ts_name: Some("pi".into()),
            hue: 2,
            ..Route::new("ts", Location::default())
        };
        let mut s = base();
        s.routes.push(ts);
        s.apps = apps(&[("firefox", "ts")]);
        let w = world(s.save_as("Home").add("Travel", false), &[("nord", "{}")]);
        assert!(w.ui.ts_lock("100.64.0.2").is_none(), "the setup in use is never locked");
        assert!(w.ui.add_ts_exit("app:code", "100.64.0.2", Some("nas")));
        let s = w.setup();
        let r = s.route(Some("ts")).unwrap();
        assert_eq!(
            (3, Some("100.64.0.2"), Some("nas"), Some(&"ts".to_string())),
            (s.routes.len(), r.ts_exit.as_deref(), r.ts_name.as_deref(), s.apps.get("code"))
        );
        w.ui.view(Some("Travel"));
        assert_eq!("ts", w.ui.ts_lock("100.64.0.3").expect("locked").id);
        let before = w.setup();
        assert!(!w.ui.add_ts_exit("", "100.64.0.3", None));
        assert_eq!(before, w.setup());
        // The live node itself is free: the profile reuses the route through it, and the live setup doesn't change.
        assert!(w.ui.ts_lock("100.64.0.2").is_none());
        assert!(w.ui.add_ts_exit("app:mpv", "100.64.0.2", None));
        let s = w.setup();
        assert_eq!((Some(&"ts".to_string()), None), (profile(&s, "Travel").apps.get("mpv"), s.apps.get("mpv")));
    }

    /// An engine start's exits are asked at most four times, also when Routes opens again: a fifth ask doesn't go out.
    /// A new engine start may be asked again; a restart or a stop drops every answer.
    #[test]
    fn exit_checks_ask_four_times_per_engine() {
        let w = world(base(), &[("nord", "{}")]);
        assert!(w.rt.block_on(w.ui.check_exits()), "nothing runs: nothing to ask");
        *w.live.running.write().unwrap() = Some(base());
        *w.live.tags.write().unwrap() =
            IndexMap::from([("nl".to_string(), "nl-tag".to_string()), ("us".to_string(), "us-tag".to_string())]);
        w.live.state.send_replace(VpnState { phase: Phase::On, engine: 1, ..VpnState::default() });
        // There is no way into these tunnels here: they never answer.
        for _ in 0..4 {
            assert!(w.ui.exit_tries_left());
            assert!(!w.rt.block_on(w.ui.check_exits()));
        }
        let asked = w.ui.exits.borrow().clone();
        assert_eq!(vec!["nl"], asked.keys().map(String::as_str).collect::<Vec<_>>(), "only routes that carry traffic");
        assert_eq!((None, 1), (asked["nl"].ip.clone(), asked["nl"].engine));
        assert!(!w.ui.exit_tries_left());
        assert!(!w.rt.block_on(w.ui.check_exits()));
        assert_eq!(asked, *w.ui.exits.borrow(), "the fifth didn't go out");
        w.live.state.send_replace(VpnState { phase: Phase::On, engine: 2, ..VpnState::default() });
        until("the last engine's answers dropped", || w.ui.exits.borrow().is_empty());
        assert!(w.ui.exit_tries_left());
        assert!(!w.rt.block_on(w.ui.check_exits()));
        assert_eq!(2, w.ui.exits.borrow()["nl"].engine);
        w.live.state.send_replace(VpnState::default());
        until("stopped", || w.ui.exits.borrow().is_empty());
    }
}
