//! The tray icon: the connection's state at a glance, and a menu for what is done most.
//! A StatusNotifierItem on the session bus, which the desktop's tray (its StatusNotifierWatcher) shows. GNOME has none
//! without the AppIndicator extension: there [`Tray::shown`] stays false, and the window closes as without a tray
//! ([`crate::desktop_settings`]). A click only becomes an [`Action`] for the window, which does it as its own buttons do.

use crate::model::{Route, Setup};
use crate::vpn::{Phase, VpnState};
use ksni::menu::{RadioGroup, RadioItem, StandardItem, SubMenu};
use ksni::{MenuItem, TrayMethods};
use resvg::{tiny_skia, usvg};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::watch;

/// What a click asks the window for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Connect,
    Disconnect,
    /// Pause for this many minutes.
    Pause(i32),
    Resume,
    /// Switch to this saved profile.
    Profile(String),
    /// Show the window.
    Open,
    Quit,
}

/// What the tray shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub phase: Phase,
    /// The default route's name ("Direct" without one).
    pub route: String,
    /// The connection's one line ([`crate::vpn::Live::summary`]), for the tooltip.
    pub summary: String,
    /// While paused: when it resumes by itself (epoch ms), 0 = only when resumed by hand.
    pub paused_until: i64,
    /// The saved profiles' names, in their order, and the one in use.
    pub profiles: Vec<String>,
    pub profile: Option<String>,
}

/// What the tray shows of the connection `vpn`, its `summary` and the live `setup`.
pub fn state(vpn: &VpnState, summary: &str, setup: &Setup) -> State {
    State {
        phase: vpn.phase,
        route: setup.route(Some(&setup.default_route)).map_or_else(|| "Direct".into(), Route::name),
        summary: summary.into(),
        paused_until: vpn.paused_until,
        profiles: setup.profiles.iter().map(|p| p.name.clone()).collect(),
        profile: setup.profile.clone(),
    }
}

/// One entry of the menu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// Says how things stand; it can't be clicked.
    Line(String),
    Button(String, Action),
    Menu(String, Vec<Item>),
    /// One option of a choice; true for the one in use, which a click leaves as it is.
    Radio(String, bool, Action),
    Separator,
}

/// What the menu offers to pause for, in minutes, with its words.
const PAUSES: [(i32, &str); 4] = [(5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"), (60, "1 hour")];

/// The menu for `s` at `now` (epoch ms).
pub fn menu(s: &State, now: i64) -> Vec<Item> {
    let button = |text: &str, a: Action| Item::Button(text.into(), a);
    let mut m = vec![Item::Line(status_line(s, now)), Item::Separator];
    m.push(if s.phase == Phase::Off { button("Connect", Action::Connect) } else { button("Disconnect", Action::Disconnect) });
    match s.phase {
        Phase::On => m.push(Item::Menu("Pause for".into(), PAUSES.iter().map(|&(n, text)| button(text, Action::Pause(n))).collect())),
        Phase::Paused => m.push(button("Resume now", Action::Resume)),
        Phase::Connecting | Phase::Off => {}
    }
    if !s.profiles.is_empty() {
        m.push(Item::Menu("Profile".into(), s.profiles.iter().map(|p| Item::Radio(p.clone(), s.profile.as_ref() == Some(p), Action::Profile(p.clone()))).collect()));
    }
    m.extend([Item::Separator, button("Open dashboard", Action::Open), button("Quit", Action::Quit)]);
    m
}

/// The menu's first line: how the connection stands, and while paused, the time left.
pub fn status_line(s: &State, now: i64) -> String {
    match s.phase {
        Phase::On => format!("Protected · {}", s.route),
        Phase::Paused if s.paused_until <= 0 => "Paused".into(),
        // Past its end a pause is about to reconnect (also just after the computer wakes up).
        Phase::Paused if s.paused_until <= now => "Resuming…".into(),
        // Whole minutes, rounded up: a pause of 15 minutes starts at 15 and ends at 1.
        Phase::Paused => format!("Paused · {} min left", (s.paused_until - now + 59_999) / 60_000),
        Phase::Connecting => "Connecting…".into(),
        Phase::Off => "Not connected".into(),
    }
}

/// The tooltip: the app, and what runs ("unbraid · NL default  ·  US 1").
pub fn tooltip(s: &State) -> String {
    if s.summary.is_empty() { crate::APP.into() } else { format!("{} · {}", crate::APP, s.summary) }
}

const LOGO: &str = include_str!("../ui/unbraid.svg");
const PAUSE_BADGE: &str = include_str!("../assets/tray/paused.svg");
/// The sizes trays draw icons at; a tray takes the nearest.
const SIZES: [u32; 5] = [16, 22, 24, 32, 48];

/// The icon for `phase`: the logo in its colour while connected, without it otherwise, with a pause badge while paused.
fn icon(phase: Phase) -> &'static [ksni::Icon] {
    static ICONS: LazyLock<[Vec<ksni::Icon>; 3]> =
        LazyLock::new(|| [(false, false), (true, false), (true, true)].map(|(grey, badge)| SIZES.iter().map(|&n| pixmap(n, grey, badge)).collect()));
    &ICONS[match phase {
        Phase::On => 0,
        Phase::Connecting | Phase::Off => 1,
        Phase::Paused => 2,
    }]
}

/// The logo `size` pixels square as ARGB32 in network byte order, greyed for `grey`, with the pause badge for `badge`.
fn pixmap(size: u32, grey: bool, badge: bool) -> ksni::Icon {
    let mut p = tiny_skia::Pixmap::new(size, size).expect("a tray icon's size");
    draw(&mut p, LOGO);
    if grey {
        // Each pixel's luminance: the logo without its colour.
        for [r, g, b, _] in p.data_mut().as_chunks_mut::<4>().0 {
            let y = (0.213 * f32::from(*r) + 0.715 * f32::from(*g) + 0.072 * f32::from(*b)).round() as u8;
            (*r, *g, *b) = (y, y, y);
        }
    }
    if badge {
        draw(&mut p, PAUSE_BADGE);
    }
    let data = p
        .pixels()
        .iter()
        .flat_map(|c| {
            let c = c.demultiply();
            [c.alpha(), c.red(), c.green(), c.blue()]
        })
        .collect();
    ksni::Icon { width: size as i32, height: size as i32, data }
}

fn draw(p: &mut tiny_skia::Pixmap, svg: &str) {
    let tree = usvg::Tree::from_str(svg, &usvg::Options::default()).expect("the app's own icon");
    let k = p.width() as f32 / tree.size().width();
    resvg::render(&tree, tiny_skia::Transform::from_scale(k, k), &mut p.as_mut());
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// The item ksni serves on the session bus.
struct Sni {
    state: State,
    on: Arc<dyn Fn(Action) + Send + Sync>,
    shown: Arc<AtomicBool>,
}

impl ksni::Tray for Sni {
    fn id(&self) -> String {
        crate::APP.into()
    }
    fn title(&self) -> String {
        crate::TITLE.into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        icon(self.state.phase).to_vec()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip { title: tooltip(&self.state), ..Default::default() }
    }
    /// A left click on the icon.
    fn activate(&mut self, _x: i32, _y: i32) {
        (self.on)(Action::Open);
    }
    fn menu(&self) -> Vec<MenuItem<Self>> {
        menu(&self.state, now_ms()).into_iter().map(entry).collect()
    }
    fn watcher_online(&self) {
        self.shown.store(true, Ordering::Relaxed);
    }
    /// The item stays, waiting for a watcher: a desktop's tray may start after unbraid, or restart.
    fn watcher_offline(&self, _: ksni::OfflineReason) -> bool {
        self.shown.store(false, Ordering::Relaxed);
        true
    }
}

fn entry(i: Item) -> MenuItem<Sni> {
    // A label's underscores mark its access key; doubled, they show as they are (a profile named "Work_2").
    let text = |s: String| s.replace('_', "__");
    match i {
        Item::Line(label) => StandardItem { label: text(label), enabled: false, ..Default::default() }.into(),
        Item::Button(label, a) => StandardItem { label: text(label), activate: Box::new(move |t: &mut Sni| (t.on)(a.clone())), ..Default::default() }.into(),
        Item::Menu(label, items) => SubMenu { label: text(label), submenu: items.into_iter().map(entry).collect(), ..Default::default() }.into(),
        // A dbusmenu radio item is one with a radio mark, grouped by nothing: each option is a group of its own.
        Item::Radio(label, on, a) => RadioGroup {
            selected: if on { 0 } else { usize::MAX },
            select: Box::new(move |t: &mut Sni, _| {
                if !on {
                    (t.on)(a.clone());
                }
            }),
            options: vec![RadioItem { label: text(label), ..Default::default() }],
        }
        .into(),
        Item::Separator => MenuItem::Separator,
    }
}

/// The tray icon, once started. Dropping it takes the icon away.
pub struct Tray {
    state: watch::Sender<State>,
    shown: Arc<AtomicBool>,
}

impl Tray {
    /// Puts the icon on the session bus, showing `state`; returns once it is there (or can't be). A click becomes an
    /// [`Action`] for `on`, called on the tray's own thread: it must return at once.
    pub fn start(state: State, on: impl Fn(Action) + Send + Sync + 'static) -> Tray {
        let shown = Arc::new(AtomicBool::new(true));
        let (tx, rx) = watch::channel(state.clone());
        let sni = Sni { state, on: Arc::new(on), shown: shown.clone() };
        let failed = shown.clone();
        let (done, started) = std::sync::mpsc::channel();
        // A runtime of its own on one thread answers a host's calls in the order they come: Xfce's tray
        // (libdbusmenu-gtk) leaves a submenu empty when its entries' properties come back before the submenu's own.
        let thread = std::thread::Builder::new().name("tray".into()).spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            rt.block_on(async move {
                // Without a watcher yet, ksni keeps the item and registers it once one comes (watcher_offline above).
                match sni.assume_sni_available(true).spawn().await {
                    Ok(handle) => {
                        let _ = done.send(());
                        follow(handle, rx).await;
                    }
                    Err(e) => {
                        failed.store(false, Ordering::Relaxed);
                        crate::log::w("Unbraid", &format!("tray: {e}"));
                    }
                }
            });
        });
        // A watcher that doesn't answer keeps the item waiting in the background, not the start.
        if thread.is_err() || started.recv_timeout(Duration::from_secs(5)) == Err(std::sync::mpsc::RecvTimeoutError::Disconnected) {
            shown.store(false, Ordering::Relaxed);
        }
        Tray { state: tx, shown }
    }

    /// Whether the desktop shows the icon: false while no StatusNotifierWatcher is on the session bus.
    pub fn shown(&self) -> bool {
        self.shown.load(Ordering::Relaxed)
    }

    /// Shows `state`: the icon, the tooltip and the menu follow.
    pub fn show(&self, state: State) {
        self.state.send_if_modified(|s| {
            let changed = *s != state;
            *s = state;
            changed
        });
    }
}

/// Keeps the item showing the newest state, and a timed pause's time left, until the [`Tray`] is dropped.
async fn follow(handle: ksni::Handle<Sni>, mut rx: watch::Receiver<State>) {
    loop {
        let counting = {
            let s = rx.borrow_and_update();
            s.phase == Phase::Paused && s.paused_until > now_ms()
        };
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { break },
            () = tokio::time::sleep(Duration::from_secs(1)), if counting => {}
        }
        let s = rx.borrow().clone();
        if handle.update(|t| t.state = s).await.is_none() {
            break;
        }
    }
    handle.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, Profile};

    fn texts(m: &[Item]) -> Vec<String> {
        m.iter()
            .map(|i| match i {
                Item::Line(t) => format!("({t})"),
                Item::Button(t, _) => t.clone(),
                Item::Menu(t, sub) => format!("{t} › {}", texts(sub).join(", ")),
                Item::Radio(t, on, _) => format!("{}{t}", if *on { "• " } else { "" }),
                Item::Separator => "—".into(),
            })
            .collect()
    }

    fn on() -> State {
        State {
            phase: Phase::On,
            route: "Netherlands".into(),
            summary: "NL default  ·  US 1".into(),
            profiles: vec!["Home".into(), "Work_2".into()],
            profile: Some("Home".into()),
            ..State::default()
        }
    }

    const NOW: i64 = 1_800_000_000_000;

    /// Each phase offers what can be done from it; the profiles are there whenever there are some.
    #[test]
    fn menu_in_each_phase() {
        assert_eq!(
            vec!["(Protected · Netherlands)", "—", "Disconnect", "Pause for › 5 minutes, 15 minutes, 30 minutes, 1 hour", "Profile › • Home, Work_2", "—", "Open dashboard", "Quit"],
            texts(&menu(&on(), NOW))
        );
        let paused = State { phase: Phase::Paused, paused_until: NOW + 12 * 60_000, ..on() };
        assert_eq!(vec!["(Paused · 12 min left)", "—", "Disconnect", "Resume now", "Profile › • Home, Work_2", "—", "Open dashboard", "Quit"], texts(&menu(&paused, NOW)));
        let connecting = State { phase: Phase::Connecting, profiles: vec![], profile: None, ..on() };
        assert_eq!(vec!["(Connecting…)", "—", "Disconnect", "—", "Open dashboard", "Quit"], texts(&menu(&connecting, NOW)));
        let off = State { phase: Phase::Off, profile: None, ..on() };
        assert_eq!(vec!["(Not connected)", "—", "Connect", "Profile › Home, Work_2", "—", "Open dashboard", "Quit"], texts(&menu(&off, NOW)));

        // What each entry asks for.
        let m = menu(&on(), NOW);
        let Item::Menu(_, pauses) = &m[3] else { panic!("Pause for") };
        assert_eq!(vec![Action::Pause(5), Action::Pause(15), Action::Pause(30), Action::Pause(60)], pauses.iter().map(|i| match i { Item::Button(_, a) => a.clone(), _ => panic!() }).collect::<Vec<_>>());
        assert_eq!(Item::Menu("Profile".into(), vec![Item::Radio("Home".into(), true, Action::Profile("Home".into())), Item::Radio("Work_2".into(), false, Action::Profile("Work_2".into()))]), m[4]);
        assert_eq!((Item::Button("Disconnect".into(), Action::Disconnect), Item::Button("Quit".into(), Action::Quit)), (m[2].clone(), m[7].clone()));
        assert_eq!(Item::Button("Resume now".into(), Action::Resume), menu(&paused, NOW)[3]);
        assert_eq!(Item::Button("Connect".into(), Action::Connect), menu(&off, NOW)[2]);
        assert_eq!(Item::Button("Open dashboard".into(), Action::Open), menu(&off, NOW)[5]);
    }

    /// A timed pause counts down in whole minutes, rounded up; one until resumed by hand has no end to show.
    #[test]
    fn time_left() {
        let paused = |left: i64| State { phase: Phase::Paused, paused_until: NOW + left, ..on() };
        assert_eq!("Paused · 15 min left", status_line(&paused(15 * 60_000), NOW));
        assert_eq!("Paused · 15 min left", status_line(&paused(14 * 60_000 + 1), NOW));
        assert_eq!("Paused · 14 min left", status_line(&paused(14 * 60_000), NOW));
        assert_eq!("Paused · 1 min left", status_line(&paused(1), NOW));
        assert_eq!("Paused · 60 min left", status_line(&paused(60 * 60_000), NOW));
        assert_eq!("Resuming…", status_line(&paused(0), NOW));
        assert_eq!("Resuming…", status_line(&paused(-30_000), NOW));
        assert_eq!("Paused", status_line(&State { phase: Phase::Paused, paused_until: 0, ..on() }, NOW));
        // The tooltip shows the connection's own line, as the command line's status does.
        assert_eq!("unbraid · NL default  ·  US 1", tooltip(&on()));
        assert_eq!("unbraid", tooltip(&State::default()));
    }

    /// The tray's state from the connection and the setup: the default route by name, Direct without one.
    #[test]
    fn state_of_the_setup() {
        let setup = Setup { profiles: vec![Profile::new("Home", "nl"), Profile::new("Empty", "")], profile: Some("Home".into()), ..Setup::default() };
        let vpn = VpnState { phase: Phase::Paused, paused_until: NOW, ..VpnState::default() };
        let s = state(&vpn, "Paused until 14:30", &setup);
        assert_eq!(
            State { phase: Phase::Paused, route: Setup::default().routes[0].name(), summary: "Paused until 14:30".into(), paused_until: NOW, profiles: vec!["Home".into(), "Empty".into()], profile: Some("Home".into()) },
            s
        );
        let direct = Setup { default_route: crate::model::DIRECT.into(), routes: vec![Route::new("nl", Location::country("nord", 153, "NL", "Netherlands"))], ..Setup::default() };
        assert_eq!("Direct", state(&VpnState::default(), "", &direct).route);
    }

    /// Connected shows the logo in its colour; connecting and disconnected without it; paused adds the pause badge.
    #[test]
    fn icons_follow_the_phase() {
        let coloured = |i: &ksni::Icon| i.data.as_chunks::<4>().0.iter().any(|&[a, r, g, b]| a > 0 && (r != g || g != b));
        let (on, off, paused) = (icon(Phase::On), icon(Phase::Off), icon(Phase::Paused));
        assert_eq!(SIZES.to_vec(), on.iter().map(|i| i.width as u32).collect::<Vec<_>>());
        assert!(on.iter().chain(off).chain(paused).all(|i| i.width == i.height && i.data.len() == (i.width * i.height * 4) as usize));
        assert!(on.iter().all(coloured));
        assert!(!off.iter().any(coloured));
        assert_eq!(off.as_ptr(), icon(Phase::Connecting).as_ptr());
        assert!(paused.iter().all(coloured));
        // ARGB: a rounded corner is clear; the left edge, beside the routes, is the logo's ink (#0F1214), opaque.
        let big = &on[4];
        assert_eq!(0, big.data[0]);
        let left = ((24 * 48 + 2) * 4) as usize;
        assert_eq!([255, 0x0F, 0x12, 0x14], big.data[left..left + 4]);
        // The badge sits low on the right, in the accent; the grey logo shows above it.
        let at = |i: &ksni::Icon, x: i32, y: i32| i.data[((y * i.width + x) * 4) as usize..][..4].to_vec();
        assert_eq!(at(&off[4], 10, 10), at(&paused[4], 10, 10));
        assert_ne!(at(&off[4], 33, 33), at(&paused[4], 33, 33));
    }

    /// On a session bus of its own: with no StatusNotifierWatcher the tray says it doesn't show; once a watcher comes,
    /// the item registers with it, and a host's clicks (dbusmenu's Event, the icon's Activate) arrive as their actions.
    #[test]
    fn private_bus_round_trip() {
        // ksni joins the bus DBUS_SESSION_BUS_ADDRESS names: the test runs again in a process with a bus of its own.
        if std::env::var_os("UNBRAID_TRAY_BUS").is_none() {
            let exe = std::env::current_exe().unwrap();
            let Ok(out) = std::process::Command::new("dbus-run-session").arg("--").arg(exe).args(["--exact", "tray::tests::private_bus_round_trip"]).env("UNBRAID_TRAY_BUS", "1").output() else {
                eprintln!("skipped: no dbus-run-session");
                return;
            };
            assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            return;
        }
        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(round_trip());
    }

    /// Each entry's id and label in a dbusmenu layout, `(ia{sv}av)`, children included.
    fn entries(v: &zbus::Variant, out: &mut Vec<(i32, String)>) {
        use zbus::Variant;
        let v = if let Variant::Variant(inner) = v { inner } else { v };
        if let Variant::Structure(s) = v
            && let [Variant::I32(id), Variant::Dict(props), Variant::Array(children)] = s.fields()
        {
            if let Some(label) = props.iter().find_map(|(k, v)| matches!(k, Variant::Str(k) if k.as_str() == "label").then(|| v.downcast_ref::<String>().ok()).flatten()) {
                out.push((*id, label));
            }
            children.inner().iter().for_each(|c| entries(c, out));
        }
    }

    async fn round_trip() {
        use tokio_stream::StreamExt;
        use zbus::message::Type as Kind;
        use zbus::{Connection, MessageStream, OwnedVariant, Structure, Variant};
        let (tx, mut clicks) = tokio::sync::mpsc::unbounded_channel();
        let tray = Tray::start(on(), move |a| {
            let _ = tx.send(a);
        });
        assert!(!tray.shown());

        // A stand-in for the desktop's watcher, which keeps the names of the items that register.
        let watcher = zbus::connection::Builder::session().build().await.unwrap();
        let mut calls = MessageStream::from(&watcher);
        watcher.request_name("org.kde.StatusNotifierWatcher").await.unwrap();
        let (got, mut registered) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(Ok(m)) = calls.next().await {
                let h = m.header();
                if h.message_type() == Kind::MethodCall && h.member().is_some_and(|n| n.as_str() == "RegisterStatusNotifierItem") {
                    watcher.reply(&h, &()).await.unwrap();
                    let _ = got.send(m.body().deserialize().unwrap());
                }
            }
        });
        let item = registered.recv().await.unwrap();
        assert!(item.starts_with(&format!("org.kde.StatusNotifierItem-{}-", std::process::id())), "{item}");
        assert!(tray.shown());
        // Started while a watcher runs, a tray shows at once.
        let other = Tray::start(State::default(), |_| {});
        assert!(other.shown());
        assert_ne!(item, registered.recv().await.unwrap());
        drop(other);

        // A tray host's calls.
        let host = zbus::connection::Builder::session().build().await.unwrap();
        async fn call<B: serde::Serialize + zbus::DynamicType>(host: &Connection, item: &str, path: &str, iface: &str, member: &str, body: &B) -> zbus::Message {
            host.call_method(Some(item), path, Some(iface), member, body).await.unwrap()
        }
        let prop = async |name: &str| -> OwnedVariant {
            call(&host, &item, "/StatusNotifierItem", "org.freedesktop.DBus.Properties", "Get", &("org.kde.StatusNotifierItem", name)).await.body().deserialize().unwrap()
        };
        assert_eq!("Unbraid by TheOlympus", String::try_from(prop("Title").await).unwrap());
        assert_eq!("/MenuBar", zbus::OwnedObjectPath::try_from(prop("Menu").await).unwrap().as_str());
        // Every entry's id and label, from the layout as a host reads it ("Work_2" doubles its underscore: one alone
        // would mark an access key).
        let labels = async || -> Vec<(i32, String)> {
            let m = call(&host, &item, "/MenuBar", "com.canonical.dbusmenu", "GetLayout", &(0i32, -1i32, Vec::<&str>::new())).await;
            let body = m.body();
            let layout: Structure = body.deserialize().unwrap();
            let mut out = vec![];
            entries(&layout.fields()[1], &mut out);
            out
        };
        let id = async |label: &str| labels().await.into_iter().find(|(_, l)| l == label).unwrap_or_else(|| panic!("{label}")).0;
        let click = async |id: i32| {
            call(&host, &item, "/MenuBar", "com.canonical.dbusmenu", "Event", &(id, "clicked", Variant::from(0i32), 0u32)).await;
        };
        click(id("15 minutes").await).await;
        assert_eq!(Some(Action::Pause(15)), clicks.recv().await);
        click(id("Work__2").await).await;
        assert_eq!(Some(Action::Profile("Work_2".into())), clicks.recv().await);
        // The status line and the profile in use do nothing.
        click(id("Protected · Netherlands").await).await;
        click(id("Home").await).await;
        call(&host, &item, "/StatusNotifierItem", "org.kde.StatusNotifierItem", "Activate", &(0i32, 0i32)).await;
        assert_eq!(Some(Action::Open), clicks.recv().await);

        // A new state reaches the menu, the tooltip and the icon.
        let tooltip = async || {
            let v = prop("ToolTip").await;
            let Variant::Structure(s) = &*v else { panic!("ToolTip") };
            s.fields()[2].downcast_ref::<String>().unwrap()
        };
        assert_eq!("unbraid · NL default  ·  US 1", tooltip().await);
        let connected = prop("IconPixmap").await;
        tray.show(State { phase: Phase::Paused, summary: "Paused until 14:30".into(), paused_until: now_ms() + 5 * 60_000, ..on() });
        let mut shown = vec![];
        for _ in 0..50 {
            shown = labels().await.into_iter().map(|(_, l)| l).collect();
            if shown.iter().any(|l| l == "Resume now") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(shown.contains(&"Paused · 5 min left".to_string()) && !shown.contains(&"15 minutes".to_string()), "{shown:?}");
        assert_eq!("unbraid · Paused until 14:30", tooltip().await);
        assert_ne!(connected, prop("IconPixmap").await);
        click(id("Resume now").await).await;
        assert_eq!(Some(Action::Resume), clicks.recv().await);
        drop(tray);
    }
}
