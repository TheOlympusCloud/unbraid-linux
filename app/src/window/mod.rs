//! The window: the pages and what lies over them, the keys, the theme and the window's place, wired to the view model.
//! It lives on the main thread. What blocks (the disk, the network, statistics) runs on the app's runtime; its answers
//! come back through [`post`], and any change the window shows asks for a redraw through [`poke`].

slint::include_modules!();

mod apps;
mod keys;
mod picker;
mod routes;
mod settings;
mod sign_in;
mod start;
mod stats;

pub use keys::{Ask, keys};

use crate::desktop_settings as ds;
use crate::instance::{self, Args};
use crate::model::Setup;
use crate::ui::{Ui, tour};
use crate::vpn::{self, VpnState};
use crate::{APP, VERSION_NAME, app, desktop, stats as recorded, tray};
use slint::winit_030::{WinitWindowAccessor, winit};
use slint::{
    CloseRequestResponse, ComponentHandle, Global, LogicalPosition, LogicalSize, ModelRc, SharedString, VecModel,
};
use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

/// The sidebar's pages, by index.
pub const ROUTES: usize = 0;
pub const APPS: usize = 1;
pub const STATS: usize = 2;
pub const SETTINGS: usize = 3;

/// What the window itself keeps: the page, what is open over it, and where the tour is.
#[derive(Default)]
pub struct State {
    pub tab: usize,
    /// The location picker: none when closed, "" for a new route, a route id, or "app:<key>" for a new route for an app.
    pub picker: Option<String>,
    /// Add provider, beside the sidebar.
    pub adding: bool,
    /// The tour's stop; none when it is off.
    pub tour: Option<usize>,
    /// The disclosure open: 1 the VPN's, 2 the installed apps'.
    pub sheet: i32,
    /// A connect waits for the VPN disclosure's Agree.
    pub connect_after: bool,
    /// Settings' Turn on for statistics, asking first.
    pub stats_consent: bool,
    pub shortcuts: bool,
    /// The welcome's whole introduction (a new install) or only the terms; read once, when it first shows.
    pub fresh: Option<bool>,
    /// It was on at a redraw, and no redraw has seen it off since ([`ds::quits_when_hidden`]).
    pub was_on: bool,
    /// A Tailscale sign-in link to ask about (a host other than the control server's), or one refused.
    pub ts: Option<crate::ts_login::Check>,
    /// The page last shown, to let it go when another shows.
    pub shown: Option<usize>,
    /// What showed at the last redraw, pages and dialogs: when it changes, the window's keys get the focus back.
    pub layer: (i32, usize, bool, i32, bool, bool),
}

/// The window, its model, and each page's own state.
pub struct Win {
    pub w: AppWindow,
    pub ui: Arc<Ui>,
    pub s: RefCell<State>,
    routes: RefCell<routes::Glue>,
    apps: RefCell<apps::Glue>,
    stats: RefCell<stats::Glue>,
    settings: RefCell<settings::Glue>,
    picker: RefCell<picker::Glue>,
    sign_in: RefCell<sign_in::Glue>,
    start: RefCell<start::Glue>,
    timers: RefCell<Vec<slint::Timer>>,
    /// Apps' icons as drawn, by key; an empty one shows the initial.
    icons: RefCell<std::collections::HashMap<String, slint::Image>>,
}

thread_local! {
    static WIN: RefCell<Option<Rc<Win>>> = const { RefCell::new(None) };
}

/// A redraw is asked for and not yet done.
static DIRTY: AtomicBool = AtomicBool::new(false);
type Job = Box<dyn FnOnce(&Win) + Send>;
static POSTED: Mutex<Vec<Job>> = Mutex::new(Vec::new());
/// The window shows; hidden, only the connection and the tray keep running.
static VISIBLE: AtomicBool = AtomicBool::new(false);
/// A profile asked for from the command line, for Routes to show.
static WANTED: Mutex<Option<String>> = Mutex::new(None);
/// The desktop's own dark (true) or light, while the theme follows it; none when it states none.
static SYSTEM_DARK: Mutex<Option<bool>> = Mutex::new(None);
static TRAY: OnceLock<tray::Tray> = OnceLock::new();

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `f` with the window, on its thread; nothing before the window is open.
pub fn with<T>(f: impl FnOnce(&Win) -> T) -> Option<T> {
    let win = WIN.with(|w| w.borrow().clone())?;
    Some(f(&win))
}

/// `f` on the window's thread with the window, soon (from any thread); then the window shows its inputs again.
pub fn post(f: impl FnOnce(&Win) + Send + 'static) {
    locked(&POSTED).push(Box::new(f));
    poke();
}

/// Something the window shows changed (on any thread): it shows its inputs again, once, soon.
pub fn poke() {
    if !DIRTY.swap(true, Ordering::SeqCst) {
        // No event loop (a test's window): the window's own timer drains instead.
        let _ = slint::invoke_from_event_loop(drain);
    }
}

fn drain() {
    if DIRTY.swap(false, Ordering::SeqCst) {
        with(|win| {
            let jobs = std::mem::take(&mut *locked(&POSTED));
            for f in jobs {
                f(win);
            }
            win.refresh();
        });
    }
}

pub(crate) fn text(s: &str) -> SharedString {
    s.into()
}

pub(crate) fn list<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

/// The connection's phase as the window's components take it.
pub(crate) fn phase(p: vpn::Phase) -> Phase {
    match p {
        vpn::Phase::Off => Phase::Off,
        vpn::Phase::Connecting => Phase::Connecting,
        vpn::Phase::On => Phase::On,
        vpn::Phase::Paused => Phase::Paused,
    }
}

/// Opens the window on the app's model (after [`app::init`]), wired and showing its first frame's state; it shows on
/// the screen once [`Win::show`] is called. The window stays this thread's until [`close`].
pub fn open() -> Rc<Win> {
    let w = AppWindow::new().expect("open the window");
    let win = Rc::new(Win {
        w,
        ui: Ui::new(),
        s: RefCell::default(),
        routes: RefCell::default(),
        apps: RefCell::default(),
        stats: RefCell::default(),
        settings: RefCell::default(),
        picker: RefCell::default(),
        sign_in: RefCell::default(),
        start: RefCell::default(),
        timers: RefCell::default(),
        icons: RefCell::default(),
    });
    WIN.with(|w| *w.borrow_mut() = Some(win.clone()));
    // The desktop's reduced motion, read once.
    Motion::get(&win.w).set_reduced(!desktop::animations());
    win.wire();
    routes::wire(&win.w);
    apps::wire(&win.w);
    stats::wire(&win.w);
    settings::wire(&win.w);
    picker::wire(&win.w);
    sign_in::wire(&win.w);
    start::wire(&win.w);
    follow_all(&win.ui);
    // What was asked before the window opened (a start's connect, a later start's show): done now, redrawn below.
    DIRTY.store(false, Ordering::SeqCst);
    for f in std::mem::take(&mut *locked(&POSTED)) {
        f(&win);
    }
    // Without an event loop to send redraws to (a test's window), a timer takes them up.
    if slint::invoke_from_event_loop(|| {}).is_err() {
        win.every(Duration::from_millis(50), drain);
    }
    win.refresh();
    win
}

/// Lets go of this thread's window.
pub fn close() {
    WIN.with(|w| w.borrow_mut().take());
}

/// The app's window, until it quits: the command line's later starts and the tray reach it, the window shows unless
/// it starts for the background (`args`), and a connect asked for at start is started. `socket` is the one-instance
/// socket: none serves it yet.
pub fn run(args: &Args, socket: &Path) {
    if !instance::serve(socket, Arc::new(handle)) {
        return; // lost a race with another start
    }
    // The engine's worker and statistics end with the app; the tunnels end with it too, however it ends: SIGTERM,
    // Ctrl+C, its terminal closing (SIGHUP), the event loop's end (below), or an exit() inside a library, such as Xlib's
    // when the display goes (atexit).
    app::runtime().spawn(async {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int), Ok(mut hup)) =
            (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup()))
        else {
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
        }
        quit();
    });
    extern "C" fn at_exit() {
        end();
    }
    // SAFETY: a plain function with no arguments, as atexit takes; it runs on the thread that calls exit().
    unsafe { libc::atexit(at_exit) };
    let _ = slint::set_xdg_app_id(APP); // the launcher entry's StartupWMClass and the desktop's app id
    start_tray();
    // A connect that can't happen yet (setup unfinished) shows the window too.
    if ds::shows_at_start(args.background, args.connect, &args.command, tray_shown()) {
        VISIBLE.store(true, Ordering::SeqCst);
    }
    if args.connect || args.command == "connect" {
        if ready() {
            vpn::start();
        } else {
            VISIBLE.store(true, Ordering::SeqCst);
        }
    }
    // The theme before the first frame, so the window doesn't open in the other one.
    *locked(&SYSTEM_DARK) = desktop::system_dark();
    let win = open();
    follow_theme();
    // The window's last place, if it is still on a screen, before it shows: the screens are known once the loop runs.
    let placed = slint::winit_030::invoke_from_active_event_loop(|el| {
        let screens: Vec<ds::Rect> =
            el.available_monitors().map(|m| screen(m.position(), m.size(), m.scale_factor())).collect();
        with(|win| {
            win.place(&screens);
            if VISIBLE.load(Ordering::SeqCst) {
                win.show();
            }
        });
    });
    if placed.is_err() && VISIBLE.load(Ordering::SeqCst) {
        win.show();
    }
    let _ = slint::run_event_loop_until_quit();
    end();
}

/// A screen's area in the units of [`ds::Placement`] (logical pixels), from what the windowing system says of it.
fn screen(at: winit::dpi::PhysicalPosition<i32>, size: winit::dpi::PhysicalSize<u32>, scale: f64) -> ds::Rect {
    let (at, size) = (at.to_logical::<f64>(scale), size.to_logical::<f64>(scale));
    ds::Rect {
        x: at.x.round() as i32,
        y: at.y.round() as i32,
        width: size.width.round() as i32,
        height: size.height.round() as i32,
    }
}

/// Ends the app: what is still to be saved, then its connection (up to 10 s), off the window's thread and the runtime.
pub fn quit() {
    with(|win| win.save_place());
    std::thread::spawn(|| {
        end();
        std::process::exit(0)
    });
}

/// What is still to be saved, then the connection's end (up to 10 s): once, whichever way the app ends first. A second
/// way waits for the first to finish.
fn end() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        app::store().flush();
        vpn::quit();
    });
}

/// Everything for a command line connect: the terms and the VPN disclosure accepted, and a provider or a server.
fn ready() -> bool {
    let s = app::store().current();
    tour::terms_ok()
        && tour::vpn_ok()
        && (!app::store().current_accounts().is_empty()
            || s.routes.iter().any(|r| r.imported())
            || !s.servers.is_empty()
            || s.home.tailscale)
}

/// Shows the window, from any thread.
pub fn show() {
    VISIBLE.store(true, Ordering::SeqCst);
    post(Win::show);
}

/// One command from a later start, the launcher or the command line.
pub fn handle(line: &str) -> String {
    let line = line.trim();
    let (cmd, arg) = line.split_once(' ').map_or((line, ""), |(c, a)| (c, a.trim()));
    match cmd {
        "ping" => "ok".into(),
        "show" | "" => {
            show();
            "ok".into()
        }
        "connect" if ready() => {
            vpn::start();
            "ok".into()
        }
        "connect" => {
            show();
            format!("Finish setting up {APP} in its window first.")
        }
        "disconnect" => {
            vpn::stop();
            "ok".into()
        }
        "pause" => match instance::pause_minutes(arg) {
            Some(m) => {
                vpn::pause(m);
                "ok".into()
            }
            None => instance::PAUSE_REFUSED.into(),
        },
        "profile" => {
            *locked(&WANTED) = Some(arg.to_string());
            show();
            "ok".into()
        }
        "status" => status(&vpn::live().state(), &vpn::live().summary.borrow()),
        "quit" => {
            quit();
            "ok".into()
        }
        _ => "unknown command".into(),
    }
}

/// The command line's `status`: the phase, what runs, and the error on a line of its own.
pub fn status(v: &VpnState, summary: &str) -> String {
    let phase = match v.phase {
        vpn::Phase::Off => "off",
        vpn::Phase::Connecting => "connecting",
        vpn::Phase::On => "on",
        vpn::Phase::Paused => "paused",
    };
    let summary = if summary.is_empty() { String::new() } else { format!(" · {summary}") };
    format!("{phase}{summary}{}", v.error.as_ref().map(|e| format!("\n{e}")).unwrap_or_default())
}

fn tray_shown() -> bool {
    TRAY.get().is_some_and(tray::Tray::shown)
}

/// The tray, showing the connection as it goes; its clicks do what the window's own buttons do.
fn start_tray() {
    let live = vpn::live();
    let state = tray::state(&live.state(), &live.summary.borrow(), &app::store().current());
    let t = TRAY.get_or_init(|| tray::Tray::start(state, tray_action));
    let (mut state, mut summary, mut setup) = (live.state.subscribe(), live.summary.subscribe(), app::store().setup());
    app::runtime().spawn(async move {
        loop {
            let now = tray::state(&state.borrow_and_update(), &summary.borrow_and_update(), &setup.borrow_and_update());
            t.show(now);
            tokio::select! {
                r = state.changed() => if r.is_err() { break },
                r = summary.changed() => if r.is_err() { break },
                r = setup.changed() => if r.is_err() { break },
            }
        }
    });
}

/// What a click in the tray's menu asks for, done as the window's own buttons do it. From the tray's thread: it returns
/// at once.
pub fn tray_action(a: tray::Action) {
    match a {
        tray::Action::Connect => {
            handle("connect");
        }
        tray::Action::Disconnect => vpn::stop(),
        tray::Action::Pause(m) => vpn::pause(m),
        tray::Action::Resume => vpn::start(),
        // A switch that waits on the window (an empty profile, a provider's limit to answer) opens it on Routes.
        tray::Action::Profile(name) => post(move |win| {
            if win.ui.use_profile_outside(&name) {
                win.set_tab(ROUTES);
                win.show();
            }
        }),
        tray::Action::Open => show(),
        tray::Action::Quit => quit(),
    }
}

/// Redraws on every change the window shows, wherever it is made.
fn follow_all(ui: &Arc<Ui>) {
    fn follow<T: Send + Sync + 'static>(mut rx: tokio::sync::watch::Receiver<T>) {
        app::runtime().spawn(async move {
            while rx.changed().await.is_ok() {
                poke();
            }
        });
    }
    let live = vpn::live();
    follow(ui.setup());
    follow(ui.accounts());
    follow(live.state.subscribe());
    follow(live.summary.subscribe());
    follow(live.asked.subscribe());
    follow(vpn::profiles::switching().subscribe());
    follow(vpn::profiles::refused().subscribe());
    follow(app::store().unsaved.subscribe());
    follow(ui.signed_in.subscribe());
    follow(ui.apps.subscribe());
    follow(ui.disclosed.subscribe());
    follow(ui.exits.subscribe());
    follow(ui.notice.subscribe());
    follow(ui.forms.subscribe());
    follow(ui.signing.subscribe());
    follow(ui.import_draft.subscribe());
    follow(ui.limit_ask.subscribe());
    follow(ui.viewing.subscribe());
    follow(ui.routes_wanted.subscribe());
    follow(ui.countries.subscribe());
    follow(ui.catalogs_read.subscribe());
    follow(ui.refreshed.subscribe());
    follow(ui.ts_stored.subscribe());
    follow(ds::theme().subscribe());
    follow(ds::close_to_tray().subscribe());
    follow(ds::remember_window().subscribe());
    follow(recorded::live());
    follow(crate::speed_test::run());
    follow(crate::taildrop::sending().subscribe());
    follow(crate::speed_test::all());
}

/// The desktop's light or dark, while the theme follows it: every 30 s while the window shows.
fn follow_theme() {
    app::runtime().spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if VISIBLE.load(Ordering::SeqCst) && *ds::theme().borrow() == ds::Theme::System {
                let dark = tokio::task::spawn_blocking(desktop::system_dark).await.ok().flatten();
                if std::mem::replace(&mut *locked(&SYSTEM_DARK), dark) != dark {
                    poke();
                }
            }
        }
    });
}

impl Win {
    /// A repeating timer that lives as long as the window.
    pub(crate) fn every(&self, d: Duration, f: impl FnMut() + 'static) {
        let t = slint::Timer::default();
        t.start(slint::TimerMode::Repeated, d, f);
        self.timers.borrow_mut().push(t);
    }

    pub(crate) fn tab(&self) -> usize {
        self.s.borrow().tab
    }

    /// Another page, from the sidebar, the keys, the tour or the tray: what was open over the last one closes.
    pub fn set_tab(&self, tab: usize) {
        let mut s = self.s.borrow_mut();
        s.tab = tab;
        s.picker = None;
        s.adding = false;
    }

    /// The sidebar's page `tab`: the one shown again goes back to its start, or to its top.
    fn page_clicked(&self, tab: usize) {
        let again = {
            let s = self.s.borrow();
            tab == s.tab && s.picker.is_none() && !s.adding
        };
        if again {
            match tab {
                ROUTES => routes::reselected(self),
                APPS => apps::reselected(self),
                STATS => stats::reselected(self),
                _ => settings::reselected(self),
            }
        }
        self.set_tab(tab);
        self.refresh();
    }

    /// Connect; until the VPN disclosure is accepted, it comes first.
    pub fn connect(&self) {
        if tour::vpn_ok() {
            self.ui.connect();
        } else {
            let mut s = self.s.borrow_mut();
            s.connect_after = true;
            s.sheet = 1;
        }
        self.refresh();
    }

    /// The location picker over the page shown, for `target` (see [`State::picker`]).
    pub fn open_picker(&self, target: &str) {
        self.s.borrow_mut().picker = Some(target.into());
        picker::opened(self, target);
        self.refresh();
    }

    pub fn close_picker(&self) {
        self.s.borrow_mut().picker = None;
        self.refresh();
    }

    /// Add provider, beside the sidebar.
    pub fn add_provider(&self) {
        let mut s = self.s.borrow_mut();
        s.picker = None;
        s.adding = true;
        drop(s);
        self.refresh();
    }

    /// A shortcut: the window's keys, before anything in it sees them. True for one it used.
    fn key(&self, text: &str, ctrl: bool, shift: bool, alt: bool) -> bool {
        let Some(ask) = keys(text, ctrl, shift, alt) else { return false };
        let (terms, signed_in) = (tour::terms_ok(), *self.ui.signed_in.borrow());
        let phase = self.ui.vpn().borrow().phase;
        match ask {
            Ask::Page(t) => self.set_tab(t),
            Ask::Search => {
                self.set_tab(APPS);
                self.w.set_search_wanted(true);
            }
            Ask::Shortcuts => self.s.borrow_mut().shortcuts = terms,
            // A dialog: it opens over whichever page is shown.
            Ask::NewRoute => {
                if terms && signed_in {
                    self.s.borrow_mut().picker = Some(String::new());
                    picker::opened(self, "");
                }
            }
            Ask::Connect => {
                if terms && signed_in {
                    match phase {
                        vpn::Phase::Off | vpn::Phase::Paused => self.connect(),
                        _ => self.ui.disconnect(),
                    }
                }
            }
            Ask::Pause => match phase {
                vpn::Phase::On => self.ui.pause(15),
                vpn::Phase::Paused => self.ui.connect(),
                _ => {}
            },
            Ask::Close => self.close(),
            Ask::Quit => quit(),
        }
        self.refresh();
        true
    }

    /// Closing the window: it hides where there is a way back to it (the tray, or a connection the launcher can bring
    /// it back from); otherwise unbraid quits.
    pub fn close(&self) {
        let on = self.ui.vpn().borrow().phase != vpn::Phase::Off;
        if ds::close_hides(*ds::close_to_tray().borrow(), tray_shown(), on) {
            self.hide();
        } else {
            quit();
        }
    }

    pub fn show(&self) {
        let first = !self.w.window().is_visible();
        VISIBLE.store(true, Ordering::SeqCst);
        let _ = self.w.show();
        if !first {
            // Already shown, maybe behind other windows or minimised: it comes to the front. On Wayland the compositor
            // decides; without an activation token it may only flag the window.
            self.w.window().with_winit_window(|w| {
                w.set_minimized(false);
                w.focus_window();
            });
        }
        if first {
            // The installed apps can change while unbraid is in the background.
            self.ui.refresh_apps();
            app::runtime().spawn_blocking(recorded::maintain);
        }
        self.refresh();
    }

    pub fn hide(&self) {
        self.save_place();
        VISIBLE.store(false, Ordering::SeqCst);
        let _ = self.w.hide();
        self.refresh();
    }

    /// The place and size the window had when it last closed, if it is to be remembered and still on one of `screens`
    /// (one may have gone since).
    fn place(&self, screens: &[ds::Rect]) {
        let Some(p) = ds::placement().filter(|p| ds::on_screen(*p, screens)) else { return };
        let w = self.w.window();
        w.set_position(LogicalPosition::new(p.x as f32, p.y as f32));
        w.set_size(LogicalSize::new(p.width.max(880) as f32, p.height.max(600) as f32));
        if p.maximized {
            w.set_maximized(true);
        }
    }

    /// Notes where the window is, so a logout or a crash keeps it too; maximized keeps the size to come back to.
    pub(crate) fn save_place(&self) {
        if !*ds::remember_window().borrow() || !self.w.window().is_visible() {
            return;
        }
        let w = self.w.window();
        let (k, max) = (w.scale_factor(), w.is_maximized());
        let (at, size) = (w.position().to_logical(k), w.size().to_logical(k));
        let to = ds::to_save(
            ds::placement(),
            Some(at.x as i32),
            Some(at.y as i32),
            size.width as i32,
            size.height as i32,
            max,
            !max && !w.is_fullscreen(),
        );
        if let Some(p) = to {
            ds::save(p);
        }
    }

    fn wire(&self) {
        let w = &self.w;
        w.on_key(|t, c, s, a| with(|win| win.key(&t, c, s, a)).unwrap_or(false));
        w.on_page_clicked(|i| {
            with(|win| win.page_clicked(i.max(0) as usize));
        });
        w.on_connect(|| {
            with(Win::connect);
        });
        w.on_pause(|| {
            with(|win| win.ui.pause(15));
        });
        w.on_disconnect(|| {
            with(|win| win.ui.disconnect());
        });
        w.on_manage_profiles(|| {
            with(|win| {
                win.set_tab(ROUTES);
                win.refresh();
                ProfilesPage::get(&win.w).invoke_manage();
            });
        });
        w.on_profile_clicked(|name| {
            with(|win| {
                win.ui.view(Some(&name));
                win.set_tab(ROUTES);
                win.refresh();
            });
        });
        w.on_shortcuts_asked(|| {
            with(|win| {
                win.s.borrow_mut().shortcuts = true;
                win.refresh();
            });
        });
        w.on_shortcuts_closed(|| {
            with(|win| {
                win.s.borrow_mut().shortcuts = false;
                win.refresh();
            });
        });
        w.on_sheet_agreed(|| {
            with(|win| {
                let sheet = std::mem::take(&mut win.s.borrow_mut().sheet);
                if sheet == 1 {
                    tour::accept_vpn();
                    if std::mem::take(&mut win.s.borrow_mut().connect_after) {
                        win.ui.connect();
                    }
                } else {
                    win.ui.accept_disclosure();
                }
                win.refresh();
            });
        });
        w.on_sheet_dismissed(|| {
            with(|win| {
                let mut s = win.s.borrow_mut();
                s.sheet = 0;
                s.connect_after = false;
                drop(s);
                win.refresh();
            });
        });
        w.on_stats_consent_answered(|on| {
            with(|win| {
                win.s.borrow_mut().stats_consent = false;
                if on {
                    win.ui.set_stats(true);
                }
                win.refresh();
            });
        });
        w.on_save_again(|| {
            app::runtime().spawn_blocking(|| app::store().save_again());
        });
        w.on_placed(|| {
            with(|win| win.placed());
        });
        w.on_ts_open(|| {
            with(|win| {
                let url = win.s.borrow_mut().ts.take().and_then(|c| c.url);
                if let Some(u) = url {
                    desktop::open(&u);
                }
                win.refresh();
            });
        });
        w.on_ts_dismissed(|| {
            with(|win| {
                win.s.borrow_mut().ts = None;
                win.refresh();
            });
        });
        w.window().on_close_requested(|| {
            with(Win::close);
            CloseRequestResponse::KeepWindowShown
        });
        w.set_logo(logo());
        w.set_version(text(VERSION_NAME));
    }

    /// An app's icon, drawn off the window's thread the first time it is asked for; until then (or without one), none,
    /// and the app shows its initial.
    pub(crate) fn icon(&self, pkg: &str) -> slint::Image {
        if let Some(i) = self.icons.borrow().get(pkg) {
            return i.clone();
        }
        self.icons.borrow_mut().insert(pkg.into(), slint::Image::default());
        let (ui, pkg) = (self.ui.clone(), pkg.to_string());
        app::runtime().spawn(async move {
            let Some(img) = ui.icon(&pkg).await else { return };
            let buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(
                img.as_raw(),
                img.width(),
                img.height(),
            );
            post(move |win| {
                win.icons.borrow_mut().insert(pkg, slint::Image::from_rgba8(buf));
                // The rows are set again, so they ask for their icons again.
                win.forget_views();
            });
        });
        slint::Image::default()
    }

    /// The pages show everything again on the next redraw, as if new.
    fn forget_views(&self) {
        routes::forget(self);
        apps::forget(self);
        stats::forget(self);
    }

    /// A Tailscale sign-in link: opened when it goes to the control server, asked about when it goes elsewhere,
    /// refused when it isn't a secure web address.
    pub(crate) fn ts_login(&self, url: &str) {
        let control = self.ui.setup().borrow().home.ts_control_url.clone();
        let c = crate::ts_login::check(url, control.as_deref());
        if c.verdict == crate::ts_login::Verdict::Open {
            if let Some(u) = &c.url {
                desktop::open(u);
            }
            return;
        }
        self.s.borrow_mut().ts = Some(c);
        self.refresh();
    }

    /// The window moved or changed size: noted once it stays so for 800 ms.
    fn placed(&self) {
        let mut st = self.start.borrow_mut();
        let t = st.place_timer.get_or_insert_with(slint::Timer::default);
        t.start(slint::TimerMode::SingleShot, Duration::from_millis(800), || {
            with(|win| win.save_place());
        });
    }

    /// Shows the window's inputs as they are now: the theme, which step or page shows, the sidebar, the page shown
    /// and what is open over it.
    pub fn refresh(&self) {
        let ui = &self.ui;
        let setup = ui.setup().borrow().clone();
        let vpn = ui.vpn().borrow().clone();
        let w = &self.w;
        Ink::get(w).set_light(!ds::dark(*ds::theme().borrow(), *locked(&SYSTEM_DARK)));

        // Hidden with nothing running and no tray to come back from (disconnected from the command line): nothing left
        // to do.
        let visible = VISIBLE.load(Ordering::SeqCst);
        {
            let mut s = self.s.borrow_mut();
            if ds::quits_when_hidden(visible, vpn.phase != vpn::Phase::Off, &mut s.was_on, tray_shown()) {
                drop(s);
                quit();
                return;
            }
        }

        let terms = tour::terms_ok();
        let signed_in = *ui.signed_in.borrow();
        if terms {
            // A profile asked for from the command line opens Routes on it: it switches only on Use there.
            let asked = locked(&WANTED).take();
            if let Some(name) = asked.filter(|n| setup.profiles.iter().any(|p| p.name == *n)) {
                ui.view(Some(&name));
                ui.routes_wanted.send_replace(true);
            }
            // Taken only when set: a replace would tell the watchers, and redraw again, forever.
            if ui.routes_wanted.send_if_modified(std::mem::take) {
                self.set_tab(ROUTES);
            }
            // A new install gets the tour once it is set up.
            if signed_in && tour::tour_pending() && self.s.borrow().tour.is_none() {
                start::tour_to(self, 0);
            }
        }
        let s = self.s.borrow();
        let stage = if !terms {
            0
        } else if !signed_in {
            1
        } else if s.adding {
            3
        } else {
            2
        };
        w.set_stage(stage);
        w.set_tab(s.tab as i32);
        w.set_picker(stage >= 2 && s.picker.is_some());
        w.set_touring(stage >= 2 && s.tour.is_some());
        w.set_sheet(s.sheet);
        w.set_shortcuts(s.shortcuts);
        w.set_stats_consent(s.stats_consent);
        w.set_unsaved(*app::store().unsaved.borrow());
        let (tab, picker_open, touring) = (s.tab, s.picker.is_some(), s.tour.is_some());
        let ts = s.ts.clone();
        let layer = (stage, tab, picker_open, s.sheet, s.shortcuts || s.stats_consent, ts.is_some());
        drop(s);
        // What had the focus may be gone with what closed: the window's keys take it back, before what opens takes it.
        if std::mem::replace(&mut self.s.borrow_mut().layer, layer) != layer {
            w.invoke_refocus();
        }
        w.set_ts_host(
            ts.as_ref()
                .filter(|c| c.verdict == crate::ts_login::Verdict::Ask)
                .and_then(|c| c.host.as_deref())
                .unwrap_or("")
                .into(),
        );
        w.set_ts_refused(ts.as_ref().is_some_and(|c| c.verdict == crate::ts_login::Verdict::Refuse));
        self.sidebar(&setup, &vpn);
        // The page shown before lets go of what it follows (its clock, its samples, its checks), also when the window
        // hides: in the background only the connection and the tray keep running.
        let page = (stage == 2 && visible).then_some(tab);
        let before = std::mem::replace(&mut self.s.borrow_mut().shown, page);
        if before != page {
            match before {
                Some(ROUTES) => routes::left(self),
                Some(APPS) => apps::left(self),
                Some(STATS) => stats::left(self),
                Some(_) => settings::left(self),
                None => {}
            }
        }
        if !visible {
            return;
        }
        match stage {
            0 => start::show_welcome(self),
            1 | 3 => sign_in::show(self, stage == 3),
            _ => match tab {
                ROUTES => routes::show(self, &setup, &vpn),
                APPS => apps::show(self, &setup),
                STATS => stats::show(self, &setup, &vpn),
                _ => settings::show(self, &setup, &vpn),
            },
        }
        if stage >= 2 {
            routes::show_limit(self);
            if picker_open {
                picker::show(self, &setup, &vpn);
            }
            if touring {
                start::show_tour(self);
            }
        }
        if stage >= 1 {
            settings::show_importer(self);
        }
    }

    /// The sidebar: the connection, and the saved profiles.
    fn sidebar(&self, setup: &Setup, vpn: &VpnState) {
        let w = &self.w;
        w.set_phase(phase(vpn.phase));
        w.set_exit(setup.route(Some(&setup.default_route)).map_or_else(|| "Direct".into(), |r| r.name()).into());
        w.set_summary(vpn::live().summary.borrow().as_str().into());
        let viewing = self.ui.viewing.borrow().clone();
        let shown = viewing.as_ref().or(setup.profile.as_ref());
        let chips: Vec<ProfileChip> = setup
            .profiles
            .iter()
            .map(|p| ProfileChip {
                name: text(&p.name),
                in_use: setup.profile.as_ref() == Some(&p.name),
                shown: shown == Some(&p.name),
            })
            .collect();
        let mut st = self.start.borrow_mut();
        if st.chips != chips {
            st.chips = chips.clone();
            w.set_chips(list(chips));
        }
    }
}

/// Updates `model` to `rows` row by row: a new model builds every row again, and a field typed in loses the focus.
pub(crate) fn sync<T: Clone + PartialEq + 'static>(model: &VecModel<T>, rows: Vec<T>) {
    use slint::Model;
    for (i, r) in rows.iter().enumerate() {
        if i >= model.row_count() {
            model.push(r.clone());
        } else if model.row_data(i).as_ref() != Some(r) {
            model.set_row_data(i, r.clone());
        }
    }
    while model.row_count() > rows.len() {
        model.remove(model.row_count() - 1);
    }
}

/// The logo, for the desktop's task bar.
fn logo() -> slint::Image {
    use resvg::{tiny_skia, usvg};
    let Ok(tree) = usvg::Tree::from_str(include_str!("../../ui/unbraid.svg"), &usvg::Options::default()) else {
        return slint::Image::default();
    };
    let Some(mut p) = tiny_skia::Pixmap::new(128, 128) else { return slint::Image::default() };
    let k = 128.0 / tree.size().width().max(tree.size().height());
    resvg::render(&tree, tiny_skia::Transform::from_scale(k, k), &mut p.as_mut());
    image(
        128,
        128,
        p.pixels().iter().flat_map(|c| {
            let c = c.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        }),
    )
}

/// Straight RGBA pixels as an image.
pub(crate) fn image(width: u32, height: u32, rgba: impl IntoIterator<Item = u8>) -> slint::Image {
    let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(width, height);
    for (to, from) in buf.make_mut_bytes().iter_mut().zip(rgba) {
        *to = from;
    }
    slint::Image::from_rgba8(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen in logical pixels, as a saved place is: a 2× screen right of a 1920 px one is 1280 logical wide.
    #[test]
    fn screens_in_the_places_units() {
        let r = screen(winit::dpi::PhysicalPosition::new(3840, 0), winit::dpi::PhysicalSize::new(2560, 1440), 2.0);
        assert_eq!(ds::Rect { x: 1920, y: 0, width: 1280, height: 720 }, r);
        assert!(ds::on_screen(ds::Placement { x: 2000, y: 100, width: 1100, height: 600, maximized: false }, &[r]));
    }
}
