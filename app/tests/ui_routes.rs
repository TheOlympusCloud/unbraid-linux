//! Renders Routes headless beside the sidebar, as the window shows it, with the data of the approved screenshots: the
//! set-up app in both themes, before its apps are listed, at the smallest window, with a route's menu and sheet open;
//! then a profile not in use, the Profiles page and its sheet, and the connection-limit sheet. Shots go to
//! `target/screenshots/routes-*.png`, `profiles-*.png` and `limit-sheet.png`.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use indexmap::IndexMap;
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, LogicalPosition, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::model::{DIRECT, Location, Profile, Route, Setup, WgPeer};
use unbraid::ui::{limit_sheet, profiles as plogic, routes as logic};
use unbraid::vpn::{self, VpnState};

slint::slint! {
    import { Sidebar, ProfileChip } from "../ui/shell.slint";
    import { RoutesScreen, RoutesPage } from "../ui/routes.slint";
    import { ProfilesPage } from "../ui/profiles.slint";
    import { LimitSheet, LimitSheetPage } from "../ui/limit_sheet.slint";
    import { Ink } from "../ui/theme.slint";
    import { Motion } from "../ui/motion.slint";
    export { RoutesPage, ProfilesPage, LimitSheetPage, Ink, Motion }
    export { Act, RouteAction, Sheet, ExitLine, AppMark, RouteCard, ExitRow, HomeRow, Phase } from "../ui/routes.slint";
    export { ProfileRow, ProfileSheetView, UseBarView } from "../ui/profiles.slint";

    // The window as it will be: the sidebar, then the page; the limit sheet over both.
    export component Shot inherits Window {
        in property <bool> wide: true;
        in property <[ProfileChip]> chips;
        background: Ink.ground;
        HorizontalLayout {
            Sidebar {
                wide: root.wide;
                current: 0;
                phase: RoutesPage.phase;
                version: "2.8.2";
                profiles: root.chips;
            }
            RoutesScreen { }
        }
        LimitSheet { }
    }
}

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

fn text(s: &str) -> SharedString {
    s.into()
}

fn list<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn action(a: &logic::RouteAction) -> RouteAction {
    let act = match a.act {
        logic::Act::ChangeLocation => Act::ChangeLocation,
        logic::Act::Rename => Act::Rename,
        logic::Act::MakeDefault => Act::MakeDefault,
        logic::Act::MakeDirectDefault => Act::MakeDirectDefault,
        logic::Act::AssignInApps => Act::AssignInApps,
        logic::Act::Remove => Act::Remove,
        logic::Act::Drop => Act::Drop,
        logic::Act::Pause => Act::Pause,
        logic::Act::Disconnect => Act::Disconnect,
    };
    RouteAction { act, text: text(&a.text), danger: a.danger, minutes: a.minutes }
}

fn sheet(s: &logic::Sheet) -> Sheet {
    Sheet { title: text(&s.title), lead: text(&s.lead), actions: list(s.actions.iter().map(action).collect()), note: text(&s.note) }
}

fn exit(e: &logic::ExitLine) -> ExitLine {
    ExitLine { text: text(&e.text), ip: e.ip, failed: e.failed }
}

fn card(c: &logic::RouteCard) -> RouteCard {
    RouteCard {
        id: text(&c.id),
        direct: c.direct,
        code: text(&c.code),
        hue: c.hue,
        name: text(&c.name),
        place: text(&c.place),
        server: text(&c.server),
        apps_label: text(&c.apps_label),
        no_apps: c.no_apps,
        apps: list(c.apps.iter().map(|a| AppMark { pkg: text(&a.pkg), letter: text(&a.letter) }).collect()),
        more: c.more,
        exit: exit(&c.exit),
        wide: c.wide,
        menu: list(c.menu.iter().map(action).collect()),
        sheet: sheet(&c.sheet),
    }
}

fn use_bar(b: &plogic::UseBarView) -> UseBarView {
    UseBarView { name: text(&b.name), title: text(&b.title), sub: text(&b.sub), back: text(&b.back), ready: b.ready }
}

/// Routes' view on its Page global, as the window will set it.
fn show_routes(shot: &Shot, v: &logic::RoutesView) {
    let page = RoutesPage::get(shot);
    page.set_overline(text(&v.overline));
    page.set_phase(match v.phase {
        vpn::Phase::Off => Phase::Off,
        vpn::Phase::Connecting => Phase::Connecting,
        vpn::Phase::On => Phase::On,
        vpn::Phase::Paused => Phase::Paused,
    });
    page.set_switching(v.switching);
    page.set_status(text(&v.status));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_sub_bad(v.sub_bad);
    page.set_label(text(&v.label));
    page.set_power_menu(v.power_menu);
    page.set_paused_ring(v.paused_ring);
    page.set_paused_left(v.paused_left);
    page.set_speeds(v.speeds);
    page.set_down(text(&v.down));
    page.set_down_unit(text(&v.down_unit));
    page.set_up(text(&v.up));
    page.set_up_unit(text(&v.up_unit));
    page.set_refused(text(&v.refused));
    page.set_retry(text(&v.retry));
    page.set_use_bar(v.use_bar.as_ref().map(use_bar).unwrap_or_default());
    page.set_not_set(v.not_set);
    page.set_default_route(card(&v.default_route));
    page.set_exceptions(list(v.exceptions.iter().map(card).collect()));
    page.set_all_default(v.all_default);
    page.set_nord_note(v.nord_note);
    page.set_lit(v.lit);
    page.set_exits(list(v.exits.iter().map(|e| ExitRow { code: text(&e.code), hue: e.hue, name: text(&e.name), place: text(&e.place), speed: text(&e.speed), exit: exit(&e.exit) }).collect()));
    page.set_home(v.home.as_ref().map(|h| HomeRow { sub: text(&h.sub), login_url: text(&h.login_url), lit: h.lit }).unwrap_or_default());
    page.set_power(sheet(&v.power));
}

/// The profile sheet for profile `editing` ("" new), a new one `empty`, with `name` typed.
fn show_sheet(shot: &Shot, s: &Setup, editing: &str, empty: bool, name: &str) {
    let p = plogic::sheet(s, Some(editing).filter(|e| !e.is_empty()), empty, name);
    ProfilesPage::get(shot).set_sheet(ProfileSheetView {
        title: text(&p.title),
        sub: text(&p.sub),
        copy: text(&p.copy),
        name: text(&p.name),
        valid: text(&p.valid),
        taken: p.taken,
        hint: text(&p.hint),
        count: text(&p.count),
        keeps_default: text(&p.keeps_default),
        keeps_exceptions: list(p.keeps_exceptions.iter().map(|e| text(e)).collect()),
        save: text(&p.save),
    });
}

/// The Profiles page's view, and the sidebar's chips; `viewing` is the one Routes shows.
fn show_profiles(shot: &Shot, s: &Setup, viewing: Option<&str>) {
    let v = plogic::view(s);
    let page = ProfilesPage::get(shot);
    page.set_sub(text(&v.sub));
    page.set_at_limit(v.at_limit);
    page.set_full_note(text(&v.full_note));
    page.set_profiles(list(v.rows.iter().map(|r| ProfileRow { name: text(&r.name), in_use: r.in_use, summary: text(&r.summary), code: text(&r.code), hue: r.hue, direct: r.direct }).collect()));
    shot.set_chips(list(v.rows.iter().map(|r| ProfileChip { name: text(&r.name), in_use: r.in_use, shown: Some(r.name.as_str()) == viewing }).collect()));
}

/// The set-up app of the approved screenshots: three Nord countries and a WireGuard server no profile uses, apps on
/// routes and Direct, and two saved profiles, neither in use.
fn set_up() -> Setup {
    let lab = WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
    Setup {
        routes: vec![
            Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
            Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
            Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
            Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
        ],
        default_route: "nl".into(),
        apps: [("firefox", "us"), ("spotify", "it"), ("org.gnome.Terminal", DIRECT), ("thunderbird", "us"), ("discord", "it"), ("code", DIRECT)].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        profiles: vec![Profile::with_apps("Work", "nl", &[("firefox-private", "it")]), Profile::with_apps("Home", "nl", &[("firefox", "us")])],
        ..Setup::default()
    }
}

/// The apps the set-up app lists once their scan is allowed.
fn listed() -> Vec<logic::App> {
    let app = |pkg: &str, label: &str, group: &[&str]| logic::App { pkg: pkg.into(), label: label.into(), group: group.iter().map(|g| g.to_string()).collect() };
    let fx = ["firefox", "firefox-private", "alacarte-made-1"];
    let lo = ["libreoffice-startcenter", "libreoffice-writer"];
    vec![
        app("firefox", "Firefox", &fx),
        app("spotify", "Spotify", &[]),
        app("org.gnome.Terminal", "Terminal", &[]),
        app("chromium", "Chromium", &[]),
        app("thunderbird", "Thunderbird", &[]),
        app("signal-desktop", "Signal", &[]),
        app("discord", "Discord", &[]),
        app("code", "Visual Studio Code", &[]),
        app("libreoffice-startcenter", "LibreOffice", &lo),
        app("org.gimp.GIMP", "GIMP", &[]),
        app("libreoffice-writer", "LibreOffice Writer", &lo),
        app("steam", "Steam", &[]),
        app("firefox-private", "Private Browsing", &fx),
        app("org.example.Tool", "Tool", &[]),
        app("alacarte-made-1", "Browser", &fx),
        app("/usr/bin/true", "true", &[]),
    ]
}

fn routes_view(s: &Setup, viewing: Option<&str>, apps: &[logic::App], vpn: &VpnState) -> logic::RoutesView {
    let exits = IndexMap::new();
    let setting_up = HashSet::new();
    logic::view(&logic::Inputs { setup: s, viewing, vpn, asked: None, switching: None, refused: None, apps, exits: &exits, asking: false, setting_up: &setting_up, live: None, now: 0 })
}

/// A new shot of `s` (as `viewing` shows it), with or without its apps listed, the sidebar wide or folded.
fn routes_shot(s: &Setup, viewing: Option<&str>, apps: &[logic::App], light: bool, wide: bool) -> Shot {
    let shot = Shot::new().expect("create the window");
    Ink::get(&shot).set_light(light);
    shot.set_wide(wide);
    show_routes(&shot, &routes_view(s, viewing, apps, &VpnState::default()));
    show_profiles(&shot, s, viewing);
    shot
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

/// Close to `want` within a few levels: antialiasing and rounding differ by a step or two.
fn near(got: [u8; 3], want: [u8; 3]) -> bool {
    got.iter().zip(want).all(|(g, w)| g.abs_diff(w) <= 3)
}

fn click(shot: &Shot, x: f32, y: f32, button: PointerEventButton) {
    let position = LogicalPosition::new(x, y);
    shot.window().dispatch_event(WindowEvent::PointerMoved { position });
    shot.window().dispatch_event(WindowEvent::PointerPressed { position, button });
    shot.window().dispatch_event(WindowEvent::PointerReleased { position, button });
}

const GROUND: [u8; 3] = [0x0f, 0x12, 0x14];
const SURFACE: [u8; 3] = [0x17, 0x1b, 0x1e];
const SURFACE_TOP: [u8; 3] = [0x23, 0x2a, 0x2e];
const BAD: [u8; 3] = [0xff, 0x8a, 0x80];

/// The set-up app, as approved: dark and light at the default size; the band, the default route's card and its
/// cookie sit where the approved look has them.
#[test]
fn routes_as_approved() {
    headless();
    let dir = shots_dir();
    let s = set_up();
    for (light, file) in [(false, "routes-dark.png"), (true, "routes-light.png")] {
        let shot = routes_shot(&s, None, &listed(), light, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        if light {
            assert_eq!([0xf5, 0xf2, 0xee], at(&px, 1280, 700, 290), "{file}: the light ground");
            continue;
        }
        assert_eq!(GROUND, at(&px, 1280, 700, 290), "{file}: the ground between band and cards");
        assert_eq!(SURFACE, at(&px, 1280, 700, 120), "{file}: the band's surface");
        assert_eq!(BAD, at(&px, 1280, 1178, 160), "{file}: the power cookie, red while unprotected");
        assert_eq!(SURFACE_TOP, at(&px, 1280, 700, 345), "{file}: the default route's card");
        assert_eq!(SURFACE, at(&px, 1280, 600, 535), "{file}: the first exception's row");
        assert_eq!(GROUND, at(&px, 1280, 600, 700), "{file}: Direct's row has no fill");
        assert_eq!(SURFACE, at(&px, 1280, 1000, 300), "{file}: the Exits card");
    }
}

/// Before the apps are listed, as first approved (5-routes); and the smallest window, the sidebar a rail.
#[test]
fn routes_before_apps_and_smallest() {
    headless();
    let dir = shots_dir();
    // As saved before the scan: Tool (a script) and Private Browsing (Firefox's program) still had routes of their own.
    let mut s = set_up();
    s.apps = [("firefox", "us"), ("spotify", "it"), ("org.gnome.Terminal", DIRECT), ("org.example.Tool", "us"), ("firefox-private", "it"), ("thunderbird", "us"), ("discord", "it"), ("code", DIRECT)]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let shot = routes_shot(&s, None, &[], false, true);
    render(&shot, 1280, 800, &dir.join("routes-before-apps.png"));
    drop(shot);
    let shot = routes_shot(&set_up(), None, &[], false, false);
    let px = render(&shot, 880, 600, &dir.join("routes-small.png"));
    assert_eq!([0x13, 0x17, 0x1a], at(&px, 880, 30, 400), "the rail's bar");
    assert_eq!(BAD, at(&px, 880, 777, 160), "the power cookie keeps its place at the band's end");
}

/// A right click on the default route offers what its sheet does; a click opens the sheet over the whole window;
/// Esc closes it; its Make Direct the default calls the page.
#[test]
fn route_menu_and_sheet() {
    headless();
    let dir = shots_dir();
    let shot = routes_shot(&set_up(), None, &listed(), false, true);
    let made = std::rc::Rc::new(std::cell::RefCell::new(String::new()));
    let m = made.clone();
    RoutesPage::get(&shot).on_make_default(move |id| *m.borrow_mut() = id.to_string());
    shoot(&shot, 1280, 800, Duration::from_secs(20));
    click(&shot, 568.0, 398.0, PointerEventButton::Right);
    let px = render(&shot, 1280, 800, &dir.join("routes-menu.png"));
    assert_eq!(SURFACE_TOP, at(&px, 1280, 700, 480), "the menu's panel below the card");
    click(&shot, 680.0, 463.0, PointerEventButton::Left);
    assert_eq!("direct", made.borrow().as_str(), "Make Direct the default");
    click(&shot, 400.0, 398.0, PointerEventButton::Left);
    let px = render(&shot, 1280, 800, &dir.join("routes-sheet.png"));
    assert!(near(at(&px, 1280, 100, 400), [0x0d, 0x10, 0x12]) || near(at(&px, 1280, 100, 400), [0x0d, 0x0f, 0x11]), "the sidebar dims behind the sheet: {:?}", at(&px, 1280, 100, 400));
    assert_eq!(SURFACE, at(&px, 1280, 640, 700), "the sheet's surface at the bottom");
    assert_eq!([0x9a, 0xa5, 0xad], at(&px, 1280, 640, 611), "the drag handle");
    shot.window().dispatch_event(WindowEvent::KeyPressed { text: slint::platform::Key::Escape.into() });
    shot.window().dispatch_event(WindowEvent::KeyReleased { text: slint::platform::Key::Escape.into() });
    let px = shoot(&shot, 1280, 800, Duration::from_secs(1));
    assert_eq!(GROUND, at(&px, 1280, 600, 700), "Esc closed the sheet");
}

/// A profile shown but not in use, empty: the use bar and Not set; the Profiles page; a new profile's sheet.
#[test]
fn profiles() {
    headless();
    let dir = shots_dir();
    let s = set_up().save_as("Desk").add("Trip", true);
    let shot = routes_shot(&s, Some("Trip"), &listed(), false, true);
    render(&shot, 1280, 800, &dir.join("routes-draft.png"));
    ProfilesPage::get(&shot).set_managing(true);
    render(&shot, 1280, 800, &dir.join("profiles-page.png"));
    drop(shot);
    // A new profile's sheet, its name typed: each change goes to the page, which answers with what the sheet shows.
    let s = set_up().save_as("Desk");
    let shot = routes_shot(&s, None, &listed(), false, true);
    let weak = shot.as_weak();
    let at_change = s.clone();
    ProfilesPage::get(&shot).on_sheet_changed(move |editing, empty, name| show_sheet(&weak.unwrap(), &at_change, &editing, empty, &name));
    ProfilesPage::get(&shot).invoke_add_profile(false);
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(&shot, 640.0, 480.0, PointerEventButton::Left);
    for c in "Weekend at home".chars() {
        shot.window().dispatch_event(WindowEvent::KeyPressed { text: c.to_string().into() });
        shot.window().dispatch_event(WindowEvent::KeyReleased { text: c.to_string().into() });
    }
    let sheet = ProfilesPage::get(&shot).get_sheet();
    assert_eq!(("Weekend at h", "12/12", "Weekend at h"), (sheet.name.as_str(), sheet.count.as_str(), sheet.valid.as_str()), "typing stops at twelve characters");
    let px = render(&shot, 1280, 800, &dir.join("profiles-sheet.png"));
    assert_eq!(SURFACE, at(&px, 1280, 330, 790), "the sheet");
}

/// Connected and recording statistics: the clock, the speeds, the routes in their colours, the default route's server
/// and load, and each exit's address, being checked, or an IPv6 one on a line of its own.
#[test]
fn routes_connected() {
    headless();
    let mut s = set_up();
    s.prefs.stats = true;
    let server = |host: &str, load: i32, city: &str| unbraid::model::Server { name: host.into(), host: format!("{host}.nordvpn.com"), load, city: city.into(), ..Default::default() };
    let vpn = VpnState {
        phase: vpn::Phase::On,
        since: 1_000,
        engine: 1,
        servers: [("nl", server("nl1256", 9, "Amsterdam")), ("us", server("us8812", 31, "New York")), ("it", server("it201", 12, "Milan"))].into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        ..Default::default()
    };
    let report = |id: &str, ip: Option<&str>| unbraid::exit_check::ExitReport { ip: ip.map(str::to_string), at: 0, engine: 1, server: vpn.servers.get(id).cloned() };
    let exits: IndexMap<String, _> = [("nl".to_string(), report("nl", Some("185.212.170.53"))), ("it".to_string(), report("it", Some("2a0d:5600:24:a10::f")))].into_iter().collect();
    let mut live = unbraid::stats::Live { down_now: 48_300_000, up_now: 3_100_000, ..Default::default() };
    for (id, bps) in [("nl", 31_200_000.0), ("us", 12_800_000.0), ("it", 4_300_000.0)] {
        live.down.insert(unbraid::stats::id_of(s.route(Some(id)).unwrap()), vec![bps]);
    }
    let setting_up = HashSet::new();
    let apps = listed();
    let v = logic::view(&logic::Inputs { setup: &s, viewing: None, vpn: &vpn, asked: None, switching: None, refused: None, apps: &apps, exits: &exits, asking: true, setting_up: &setting_up, live: Some(&live), now: 3_724_000 });
    let shot = routes_shot(&s, None, &apps, false, true);
    show_routes(&shot, &v);
    let px = render(&shot, 1280, 800, &shots_dir().join("routes-connected.png"));
    assert_eq!([0x8e, 0xe0, 0xa8], at(&px, 1280, 1178, 160), "the cookie, green while protected");
    assert_eq!("Connected · 01:02:03", v.status);
}

/// Over the limit: the question, the offer to share a server, Cancel and Change anyway.
#[test]
fn limit_sheet() {
    headless();
    let dir = shots_dir();
    let shot = routes_shot(&set_up(), None, &listed(), false, true);
    let v = limit_sheet::view(&unbraid::limits::warning("NordVPN", 10, "connection", 11), Some("nl1256"));
    let page = LimitSheetPage::get(&shot);
    page.set_text(text(&v.text));
    page.set_share(text(&v.share));
    page.set_shown(true);
    let px = render(&shot, 1280, 800, &dir.join("limit-sheet.png"));
    assert_eq!([0xff, 0xa6, 0x6b], at(&px, 1280, 640, 760 - 112), "the share button, in the accent");
}
