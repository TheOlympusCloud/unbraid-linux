//! The Apps page and the two disclosures, rendered headless beside the sidebar as the window shows them, with the data
//! of the approved screenshots (app/build/screenshots/6-apps*.png), to `target/screenshots/apps-*.png`; and what a
//! still picture can't show: the right-click menu's choices, the keys and the dialogs' buttons.

mod common;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, Image, LogicalPosition, Model, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::model::{DIRECT, Location, Profile, Route, Setup, WgPeer};
use unbraid::ui::apps::{self, AppInfo, AppsView, Sort, Table};

slint::slint! {
    import { Sidebar } from "../ui/shell.slint";
    import { AppsScreen } from "../ui/apps.slint";
    import { VpnDisclosure, AppsDisclosure } from "../ui/disclosures.slint";
    export { AppsPage, ExitChip, ColumnHead, AppRow, RouteChoice, AlsoRow, AppDetail } from "../ui/apps.slint";
    import { Ink } from "../ui/theme.slint";
    export { Ink }

    // The page as the window holds it: the sidebar on Apps, the page, and a disclosure over both.
    export component AppsWindow inherits Window {
        // 0: none, 1: the VPN disclosure, 2: the installed apps'.
        in property <int> sheet;
        // The window is at least Metrics.wide: the sidebar names its pages.
        in property <bool> wide: true;
        in-out property <int> agreed;
        in-out property <int> dismissed;
        background: Ink.ground;
        public function focus-search() {
            screen.focus-search();
        }
        HorizontalLayout {
            Sidebar {
                wide: root.wide;
                current: 1;
                profiles: [{ name: "Work" }, { name: "Home" }];
                version: "2.8.2";
            }
            screen := AppsScreen { }
        }
        if root.sheet == 1: VpnDisclosure {
            agree => {
                root.agreed += 1;
            }
            dismiss => {
                root.dismissed += 1;
            }
        }
        if root.sheet == 2: AppsDisclosure {
            agree => {
                root.agreed += 1;
            }
            dismiss => {
                root.dismissed += 1;
            }
        }
    }
}

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

/// The set-up app of the approved screenshots, once its apps were read: Private Browsing's and Tool's own routes went
/// (one runs as Firefox, one is a script).
fn setup() -> Setup {
    let lab = WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
    let route = |id: &str, loc: Location, hue: i32| Route { hue, ..Route::new(id, loc) };
    let mut s = Setup {
        routes: vec![
            route("nl", Location::country("nord", 153, "NL", "Netherlands"), 0),
            route("us", Location::country("nord", 228, "US", "United States"), 1),
            route("it", Location::country("nord", 106, "IT", "Italy"), 2),
            Route { wg: Some(lab), ..route("lab", Location::default(), 3) },
        ],
        default_route: "nl".into(),
        profiles: vec![Profile::with_apps("Work", "nl", &[("firefox-private", "it")]), Profile::with_apps("Home", "nl", &[("firefox", "us")])],
        ..Setup::default()
    };
    for (k, v) in [("firefox", "us"), ("spotify", "it"), ("org.gnome.Terminal", DIRECT), ("thunderbird", "us"), ("discord", "it"), ("code", DIRECT)] {
        s.apps.insert(k.into(), v.into());
    }
    s.prefs.stats = true;
    s
}

/// The installed apps: 14 at first, 15 once a menu editor's "Browser" entry for Firefox's program appeared, 16 with
/// /usr/bin/true added as a program.
fn installed(n: usize) -> Vec<AppInfo> {
    let app = AppInfo::new;
    let firefox: &[&str] = if n > 14 { &["alacarte-made-1", "firefox", "firefox-private"] } else { &["firefox", "firefox-private"] };
    let group = |pkg: &str, label: &str, g: &[&str]| AppInfo { group: g.iter().map(|k| k.to_string()).collect(), ..app(pkg, label) };
    let office = ["libreoffice-startcenter", "libreoffice-writer"];
    let mut all = vec![
        app("chromium", "Chromium"),
        app("discord", "Discord"),
        group("firefox", "Firefox", firefox),
        app("org.gimp.GIMP", "GIMP"),
        group("libreoffice-startcenter", "LibreOffice", &office),
        group("libreoffice-writer", "LibreOffice Writer", &office),
        group("firefox-private", "Private Browsing", firefox),
        app("signal-desktop", "Signal"),
        app("spotify", "Spotify"),
        AppInfo { routable: false, ..app("steam", "Steam") },
        app("org.gnome.Terminal", "Terminal"),
        app("thunderbird", "Thunderbird"),
        AppInfo { routable: false, ..app("org.example.Tool", "Tool") },
        app("code", "Visual Studio Code"),
    ];
    if n > 14 {
        all.insert(0, group("alacarte-made-1", "Browser", firefox));
    }
    if n > 15 {
        all.push(AppInfo { kind: "Program", ..app("/usr/bin/true", "true") });
    }
    all
}

fn today() -> HashMap<String, i64> {
    [("chromium", 16_000_000), ("discord", 4_000_000), ("firefox", 25_000_000), ("signal-desktop", 2_000_000), ("spotify", 10_000_000), ("thunderbird", 6_000_000)]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

/// Each app's stand-in program, as the screenshots' test made them: Private Browsing and Browser run Firefox's, Writer
/// LibreOffice's; Steam's launcher script and Tool's interpreter name none.
fn program(key: &str) -> Option<String> {
    let of = |p: &str| Some(format!("/tmp/unbraid-ui-test/opt/{p}/{p}"));
    match key {
        "steam" | "org.example.Tool" => None,
        "firefox-private" | "alacarte-made-1" => of("firefox"),
        "libreoffice-writer" => of("libreoffice-startcenter"),
        _ if key.starts_with('/') => Some(key.into()),
        _ => of(key),
    }
}

/// What the page reads, and what its clicks asked for.
struct State {
    apps: Vec<AppInfo>,
    setup: Setup,
    viewing: Option<String>,
    disclosed: bool,
    table: Table,
    view: AppsView,
    asked: Vec<String>,
}

fn text(s: &str) -> SharedString {
    s.into()
}

fn model<T: Clone + 'static>(items: impl Iterator<Item = T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items.collect::<Vec<_>>()))
}

/// The view, as the window's code hands it to the page: field for field, with no pictures (every icon its initial).
fn show(page: &AppsPage, v: &AppsView) {
    page.set_counts(text(&v.counts));
    page.set_disclosed(v.disclosed);
    page.set_editing(text(&v.editing));
    page.set_editing_hint(text(&v.editing_hint));
    page.set_back_label(text(&v.back_label));
    page.set_use_label(text(&v.use_label));
    page.set_query(text(&v.query));
    page.set_all(v.all);
    page.set_chips(model(v.chips.iter().map(|c| ExitChip { id: text(&c.id), label: text(&c.label), hue: c.hue, direct: c.direct, on: c.on })));
    page.set_system(v.system);
    page.set_heads(model(v.heads.iter().map(|h| ColumnHead { text: text(&h.text), label: text(&h.label), on: h.on })));
    page.set_stats(v.stats);
    page.set_rows(model(v.rows.iter().map(|r| AppRow {
        key: text(&r.key),
        label: text(&r.label),
        letter: text(&r.letter),
        icon: Image::default(),
        kind: text(&r.kind),
        unset: text(&r.unset),
        code: text(&r.code),
        hue: r.hue,
        filled: r.filled,
        direct: r.direct,
        note: text(&r.note),
        today: text(&r.today),
    })));
    page.set_selected(text(&v.selected));
    page.set_selected_index(v.selected_index);
    let d = &v.detail;
    page.set_detail(AppDetail {
        key: text(&d.key),
        label: text(&d.label),
        letter: text(&d.letter),
        icon: Image::default(),
        program: text(&d.program),
        copy: text(&d.copy),
        leader: text(&d.leader),
        leader_note: text(&d.leader_note),
        leader_menu: text(&d.leader_menu),
        show_leader: text(&d.show_leader),
        default_only: d.default_only,
        choices: model(d.choices.iter().map(|c| RouteChoice {
            id: text(&c.id),
            name: text(&c.name),
            sub: text(&c.sub),
            menu: text(&c.menu),
            code: text(&c.code),
            hue: c.hue,
            direct: c.direct,
            on: c.on,
        })),
        also: model(d.also.iter().map(|a| AlsoRow { key: text(&a.key), label: text(&a.label), letter: text(&a.letter), icon: Image::default(), note: text(&a.note) })),
        lookups: d.lookups,
        lookups_sub: text(&d.lookups_sub),
        lookups_on: d.lookups_on,
        own: d.own,
        today: text(&d.today),
    });
}

fn refresh(w: &AppsWindow, s: &mut State) {
    s.view = apps::view(&s.apps, &s.setup, s.viewing.as_deref(), s.disclosed, &today(), &s.table, program);
    show(&AppsPage::get(w), &s.view);
}

/// The window with the page on `apps`, its clicks answered here as the window's code will: the page's own ones
/// change its table, the others are noted (and a route chosen is set, as the view model does).
fn window(apps: Vec<AppInfo>, table: Table) -> (AppsWindow, Rc<RefCell<State>>) {
    let w = AppsWindow::new().expect("create the window");
    let state = Rc::new(RefCell::new(State { apps, setup: setup(), viewing: None, disclosed: true, table, view: AppsView::default(), asked: vec![] }));
    let page = AppsPage::get(&w);
    let on = |f: fn(&mut State, &str)| {
        let (state, weak) = (state.clone(), w.as_weak());
        move |arg: SharedString| {
            let mut s = state.borrow_mut();
            f(&mut s, &arg);
            refresh(&weak.unwrap(), &mut s);
        }
    };
    let on0 = |f: fn(&mut State)| {
        let (state, weak) = (state.clone(), w.as_weak());
        move || {
            let mut s = state.borrow_mut();
            f(&mut s);
            refresh(&weak.unwrap(), &mut s);
        }
    };
    page.on_select(on(|s, key| s.table.selected = Some(key.into())));
    page.on_search(on(|s, q| s.table.query = q.into()));
    page.on_filter(on(|s, id| s.table.filter = Some(id.into())));
    page.on_filter_all(on0(|s| s.table.filter = None));
    page.on_toggle_system(on0(|s| s.table.system = !s.table.system));
    page.on_show_apps(on0(|s| s.asked.push("show apps".into())));
    page.on_add_program(on0(|s| s.asked.push("add a program".into())));
    page.on_back(on0(|s| s.asked.push("back".into())));
    page.on_use_profile(on0(|s| s.asked.push("use profile".into())));
    page.on_use_default(on(|s, key| s.asked.push(format!("use default {key}"))));
    page.on_new_route(on(|s, key| s.asked.push(format!("new route app:{key}"))));
    page.on_copy_path(on(|s, path| s.asked.push(format!("copy {path}"))));
    page.on_filter_lookups(on(|s, key| s.asked.push(format!("lookups {key}"))));
    page.on_sort({
        let (state, weak) = (state.clone(), w.as_weak());
        move |column| {
            let mut s = state.borrow_mut();
            s.table.sort_by(Sort::ALL[column as usize]);
            refresh(&weak.unwrap(), &mut s);
        }
    });
    page.on_step({
        let (state, weak) = (state.clone(), w.as_weak());
        move |by| {
            let mut s = state.borrow_mut();
            let rows = s.view.rows.clone();
            s.table.step(&rows, by);
            refresh(&weak.unwrap(), &mut s);
        }
    });
    page.on_assign({
        let (state, weak) = (state.clone(), w.as_weak());
        move |key, route| {
            let mut s = state.borrow_mut();
            s.asked.push(format!("assign {key} {route}"));
            if route == s.setup.default_route {
                s.setup.apps.shift_remove(key.as_str());
            } else {
                s.setup.apps.insert(key.into(), route.into());
            }
            refresh(&weak.unwrap(), &mut s);
        }
    });
    refresh(&w, &mut state.borrow_mut());
    (w, state)
}

fn pointer(w: &AppsWindow, x: f32, y: f32) {
    w.window().dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(x, y) });
}

fn click(w: &AppsWindow, x: f32, y: f32, button: PointerEventButton) {
    let position = LogicalPosition::new(x, y);
    w.window().dispatch_event(WindowEvent::PointerMoved { position });
    w.window().dispatch_event(WindowEvent::PointerPressed { position, button });
    w.window().dispatch_event(WindowEvent::PointerReleased { position, button });
}

fn press(w: &AppsWindow, key: impl Into<SharedString>) {
    let text = key.into();
    w.window().dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    w.window().dispatch_event(WindowEvent::KeyReleased { text });
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

/// The table as first shown: every app by name, the pointer over Steam's row (6-apps.png).
#[test]
fn the_table_renders_dark_and_light() {
    headless();
    let dir = shots_dir();
    {
        let (w, _) = window(installed(14), Table::default());
        shoot(&w, 1280, 800, Duration::ZERO);
        pointer(&w, 598.0, 747.0);
        let pixels = render(&w, 1280, 800, &dir.join("apps-dark.png"));
        assert_eq!([0x1B, 0x21, 0x24], at(&pixels, 1280, 285, 747), "the row under the pointer: surface-high, and the hover's layer");
        assert_eq!([0x0F, 0x12, 0x14], at(&pixels, 1280, 600, 252), "the page's ground above the first row");
        assert_eq!([0x1E, 0x24, 0x28], at(&pixels, 1280, 600, 246), "the line under the heads, where the approved look has it");
        assert_eq!([0x17, 0x1B, 0x1E], at(&pixels, 1280, 1100, 400), "the panel: surface");
        assert_eq!([0x1E, 0x24, 0x28], at(&pixels, 1280, 939, 400), "the panel's edge");
        let page = AppsPage::get(&w);
        assert_eq!("14 installed · 4 routed · 2 direct", page.get_counts().as_str());
    }
    {
        let (w, _) = window(installed(16), Table::default());
        Ink::get(&w).set_light(true);
        let pixels = render(&w, 1280, 800, &dir.join("apps-light.png"));
        assert_eq!([0xF5, 0xF2, 0xEE], at(&pixels, 1280, 600, 252), "the light ground");
        assert_eq!([0xFF, 0xFF, 0xFF], at(&pixels, 1280, 1100, 400), "the light panel");
    }
}

/// An app that runs as another: its panel says so and shows the other (6-apps-runs-as-another.png).
#[test]
fn an_app_that_runs_as_another_says_so() {
    headless();
    let (w, state) = window(installed(15), Table::default());
    shoot(&w, 1280, 800, Duration::ZERO);
    click(&w, 598.0, 643.0, PointerEventButton::Left);
    assert_eq!(Some("firefox-private"), state.borrow().table.selected.as_deref(), "a click selects the row");
    let pixels = render(&w, 1280, 800, &shots_dir().join("apps-runs-as-another.png"));
    assert_eq!([0x35, 0x26, 0x1C], at(&pixels, 1280, 285, 643), "selected, under the pointer: the accent's container, and the hover's layer");
    let detail = AppsPage::get(&w).get_detail();
    assert_eq!("Takes Firefox's route: it runs as Firefox, and unbraid can't tell their traffic apart.", detail.leader_note.as_str());
    // Show Firefox, at the panel's button.
    click(&w, 1036.0, 161.0, PointerEventButton::Left);
    assert_eq!(Some("firefox"), state.borrow().table.selected.as_deref(), "Show Firefox selects it");
}

/// A right click selects the app and offers its routes at once; one chosen there is set (6-apps-menu.png).
#[test]
fn a_right_click_offers_the_routes() {
    headless();
    let (w, state) = window(installed(15), Table::default());
    shoot(&w, 1280, 800, Duration::ZERO);
    click(&w, 598.0, 747.0, PointerEventButton::Right);
    assert_eq!(Some("spotify"), state.borrow().table.selected.as_deref());
    let pixels = render(&w, 1280, 800, &shots_dir().join("apps-menu.png"));
    assert_eq!([0x23, 0x2A, 0x2E], at(&pixels, 1280, 700, 340), "the menu opens above the row, as tall as its rows");
    assert_eq!([0x23, 0x2A, 0x2E], at(&pixels, 1280, 700, 690));
    assert_eq!([0x0F, 0x12, 0x14], at(&pixels, 1280, 700, 326), "and no taller");
    // United States: the second route, under the label.
    click(&w, 700.0, 421.0, PointerEventButton::Left);
    assert_eq!(vec!["assign spotify us"], state.borrow().asked);
    let spotify = state.borrow().view.rows.iter().find(|r| r.key == "spotify").cloned().unwrap();
    assert_eq!(("US", true), (spotify.code.as_str(), spotify.filled));
    // Again, Italy; then the default route, from the menu's own row.
    click(&w, 598.0, 747.0, PointerEventButton::Right);
    click(&w, 700.0, 459.0, PointerEventButton::Left);
    assert_eq!(Some("it"), state.borrow().setup.apps.get("spotify").map(String::as_str));
    click(&w, 598.0, 747.0, PointerEventButton::Right);
    click(&w, 700.0, 582.0, PointerEventButton::Left);
    assert_eq!("use default spotify", state.borrow().asked.last().unwrap());
    click(&w, 598.0, 747.0, PointerEventButton::Right);
    click(&w, 700.0, 667.0, PointerEventButton::Left);
    assert_eq!("copy /tmp/unbraid-ui-test/opt/spotify/spotify", state.borrow().asked.last().unwrap());
}

/// The keys: Ctrl+F's search narrows the table and Down goes on into it; the arrows walk it; a head sorts it.
#[test]
fn the_keys_search_and_walk_the_table() {
    headless();
    let (w, state) = window(installed(15), Table::default());
    shoot(&w, 1280, 800, Duration::ZERO);
    w.invoke_focus_search();
    for c in ["l", "i", "b"] {
        press(&w, c);
    }
    assert_eq!("lib", state.borrow().table.query);
    assert_eq!(2, AppsPage::get(&w).get_rows().iter().count(), "LibreOffice and its Writer");
    press(&w, Key::DownArrow);
    assert_eq!(Some("libreoffice-startcenter"), state.borrow().table.selected.as_deref(), "Down in the search: the first match");
    press(&w, Key::DownArrow);
    press(&w, Key::DownArrow);
    assert_eq!(Some("libreoffice-writer"), state.borrow().table.selected.as_deref(), "the table has the keys now, and stops at its end");
    press(&w, Key::UpArrow);
    assert_eq!(Some("libreoffice-startcenter"), state.borrow().table.selected.as_deref());
    // The Kind head.
    click(&w, 560.0, 230.0, PointerEventButton::Left);
    assert_eq!("KIND ▲", AppsPage::get(&w).get_heads().iter().nth(1).unwrap().text.as_str());
    click(&w, 560.0, 230.0, PointerEventButton::Left);
    assert_eq!("KIND ▼", AppsPage::get(&w).get_heads().iter().nth(1).unwrap().text.as_str());
}

/// The smallest window: the sidebar folds to a rail, the table keeps its columns and the panel its width.
#[test]
fn the_smallest_window_keeps_the_layout() {
    headless();
    let (w, _) = window(installed(15), Table { selected: Some("spotify".into()), ..Table::default() });
    w.set_wide(false);
    let pixels = render(&w, 880, 600, &shots_dir().join("apps-small.png"));
    assert_eq!([0x17, 0x1B, 0x1E], at(&pixels, 880, 870, 590), "the panel keeps its 340 px");
    assert_eq!([0x1E, 0x24, 0x28], at(&pixels, 880, 539, 590), "and its edge");
}

/// A profile not in use, shown: what it is and the way back; an empty one has no exits, and a chip finds those apps.
#[test]
fn a_profile_not_in_use_says_so() {
    headless();
    let (w, state) = window(installed(15), Table { filter: Some(String::new()), ..Table::default() });
    {
        let mut s = state.borrow_mut();
        s.setup.profiles.push(Profile::new("Travel", ""));
        s.setup = s.setup.use_profile("Work").view_as(Some("Travel"));
        s.viewing = Some("Travel".into());
        refresh(&w, &mut s);
    }
    render(&w, 1280, 800, &shots_dir().join("apps-editing.png"));
    let page = AppsPage::get(&w);
    assert_eq!("Editing Travel · not in use. Work is in use.", page.get_editing().as_str());
    assert_eq!("Not set", page.get_rows().iter().next().unwrap().unset.as_str());
}

/// Before the list may be read the page asks; its disclosure, and the VPN's, agree or close (Esc, Not now).
#[test]
fn the_disclosures_ask_first() {
    headless();
    let dir = shots_dir();
    {
        let (w, state) = window(vec![], Table::default());
        state.borrow_mut().disclosed = false;
        refresh(&w, &mut state.borrow_mut());
        render(&w, 1280, 800, &dir.join("apps-not-disclosed.png"));
        click(&w, 300.0, 175.0, PointerEventButton::Left);
        assert_eq!(vec!["show apps"], state.borrow().asked, "Show my apps");
        w.set_sheet(2);
        let pixels = render(&w, 1280, 800, &dir.join("apps-disclosure.png"));
        assert_eq!([0x17, 0x1B, 0x1E], at(&pixels, 1280, 640, 400), "the sheet: surface, in the middle");
        press(&w, Key::Escape);
        assert_eq!(1, w.get_dismissed(), "Esc is Not now");
        // Not now, then Agree and continue: the sheet's buttons, in that order.
        press(&w, Key::Tab);
        press(&w, Key::Tab);
        press(&w, Key::Space);
        assert_eq!(1, w.get_agreed(), "Agree and continue");
    }
    {
        let (w, _) = window(installed(15), Table::default());
        w.set_sheet(1);
        render(&w, 1280, 800, &dir.join("apps-vpn-disclosure.png"));
        Ink::get(&w).set_light(true);
        let pixels = render(&w, 1280, 800, &dir.join("apps-vpn-disclosure-light.png"));
        assert_eq!([0xFF, 0xFF, 0xFF], at(&pixels, 1280, 640, 400), "the light sheet");
        press(&w, Key::Tab);
        press(&w, Key::Space);
        assert_eq!((1, 0), (w.get_dismissed(), w.get_agreed()), "Not now");
    }
}
