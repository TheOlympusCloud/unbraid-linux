//! Renders the location picker headless as the window shows it, a dialog over a page beside the sidebar, and signing
//! in as a card in the middle of the window, with the data of the approved screenshots: the picker as it opens and
//! with a country's cities beside the list (both themes, the smallest window), Route options and My servers; then the
//! provider list, a provider's form and a provider's question. Shots go to `target/screenshots/picker-*.png` and
//! `sign-in-*.png`. The tests play the window: each callback changes its state, and the page is shown again.

mod common;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use indexmap::{IndexMap, IndexSet};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, LogicalPosition, Model, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::model::{City, Country, Location, OwnServer, Route, Server, Setup, WgPeer};
use unbraid::ui::{picker as logic, sign_in as signin};
use unbraid::vpn::TsNode;

slint::slint! {
    import { Sidebar } from "../ui/shell.slint";
    import { PickerDialog, PickerPage } from "../ui/picker.slint";
    import { Ink } from "../ui/theme.slint";
    export { PickerPage, Ink }
    export { PickRow, PickKind, Lead, Choice, Blocking } from "../ui/picker.slint";

    // The window as the picker opens over a page: the sidebar, a plain page, and the dialog over both.
    export component Shot inherits Window {
        in property <bool> wide: true;
        background: Ink.ground;
        HorizontalLayout {
            Sidebar {
                wide: root.wide;
                current: 3;
                version: "2.8.2";
                profiles: [{ name: "Work" }, { name: "Home" }];
            }
            Rectangle { }
        }
        PickerDialog {}
    }
}

mod card {
    slint::slint! {
        import { SignInScreen, SignInPage } from "../ui/sign_in.slint";
        import { Ink } from "../ui/theme.slint";
        export { SignInPage, Ink }
        export { ProviderRow, OtherRow, Other, FormField, FormView } from "../ui/sign_in.slint";

        // A step before the app proper: a card in the middle of the window, as wide as reading wants.
        export component Card inherits Window {
            background: Ink.ground;
            HorizontalLayout {
                padding: 24px;
                alignment: center;
                Rectangle {
                    preferred-width: 600px;
                    max-width: 600px;
                    border-radius: 28px;
                    background: Ink.ground;
                    clip: true;
                    SignInScreen {
                        width: 100%;
                        height: 100%;
                    }
                    Rectangle {
                        border-radius: 28px;
                        border-width: 1px;
                        border-color: Ink.surface-high;
                    }
                }
            }
        }
    }
}

use card::{Card, FormField, FormView, Other, OtherRow, ProviderRow, SignInPage};

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";
const GROUND: [u8; 3] = [0x0f, 0x12, 0x14];
const SURFACE: [u8; 3] = [0x17, 0x1b, 0x1e];
const SURFACE_HIGH: [u8; 3] = [0x1e, 0x24, 0x28];
const LINE: [u8; 3] = [0x34, 0x3c, 0x42];
const ACCENT: [u8; 3] = [0xff, 0xa6, 0x6b];
const LIGHT_GROUND: [u8; 3] = [0xf5, 0xf2, 0xee];

fn text(s: &str) -> SharedString {
    s.into()
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

/// Close to `want` within a few levels: antialiasing and rounding differ by a step or two.
fn near(got: [u8; 3], want: [u8; 3]) -> bool {
    got.iter().zip(want).all(|(g, w)| g.abs_diff(w) <= 3)
}

/// Pixels of a colour close to `want` in a box: a word or a mark drawn there in that ink.
fn inked(pixels: &[Rgb8Pixel], width: u32, (x0, y0, x1, y1): (u32, u32, u32, u32), want: [u8; 3]) -> usize {
    (y0..y1).flat_map(|y| (x0..x1).map(move |x| (x, y))).filter(|(x, y)| near(at(pixels, width, *x, *y), want)).count()
}

fn click(window: &slint::Window, x: f32, y: f32) {
    let (position, button) = (LogicalPosition::new(x, y), PointerEventButton::Left);
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });
}

fn press(window: &slint::Window, key: impl Into<SharedString>) {
    let text = key.into();
    window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    window.dispatch_event(WindowEvent::KeyReleased { text });
}

fn typed(window: &slint::Window, s: &str) {
    for c in s.chars() {
        press(window, c.to_string());
    }
}

/// The window's way with a list: one model, its rows updated in place, so the rows on screen keep their state (a
/// field's focus, the hover under the pointer).
fn sync<T: Clone + PartialEq + 'static>(model: &VecModel<T>, rows: Vec<T>) {
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

fn nord_countries() -> Vec<Country> {
    let country = |id: i32, name: &str, code: &str, server_count: i32, cities: &[(i32, &str)]| Country {
        id,
        name: name.into(),
        code: code.into(),
        server_count,
        cities: cities.iter().map(|(id, name)| City { id: *id, name: name.to_string(), key: None }).collect(),
    };
    vec![
        country(81, "Germany", "DE", 322, &[(2, "Frankfurt"), (3, "Berlin"), (4, "Hamburg")]),
        country(74, "France", "FR", 176, &[(5, "Paris"), (6, "Marseille")]),
        country(106, "Italy", "IT", 120, &[(15, "Milan"), (16, "Rome")]),
        country(108, "Japan", "JP", 113, &[(14, "Tokyo")]),
        country(153, "Netherlands", "NL", 214, &[(1, "Amsterdam")]),
        country(208, "Sweden", "SE", 98, &[(8, "Stockholm")]),
        country(209, "Switzerland", "CH", 131, &[(7, "Zurich")]),
        country(227, "United Kingdom", "GB", 440, &[(9, "London"), (10, "Manchester")]),
        country(228, "United States", "US", 1960, &[(11, "New York"), (12, "Los Angeles"), (13, "Chicago")]),
    ]
}

/// The set-up app of the approved screenshots: three Nord countries and a WireGuard server; the default favourites.
fn set_up() -> Setup {
    let lab = WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
    Setup {
        routes: vec![
            Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
            Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
            Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
            Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
        ],
        ..Setup::default()
    }
}

/// What the window keeps for the picker and what it reads, signed in to NordVPN with its countries.
struct Picker {
    setup: Setup,
    target: String,
    picks: logic::Picks,
    accounts: IndexMap<String, String>,
    catalogs: IndexMap<String, Vec<Country>>,
    nodes: Vec<TsNode>,
    servers: Option<Vec<Server>>,
    view: logic::PickerView,
    /// What the page asked of the rest of the app, in order.
    asked: Vec<String>,
    rows: Rc<VecModel<PickRow>>,
    panel: Rc<VecModel<PickRow>>,
}

impl Picker {
    fn new(target: &str) -> Picker {
        let setup = set_up();
        let accounts = IndexMap::from([("nord".to_string(), "test".to_string())]);
        Picker {
            picks: logic::Picks::open(&setup, target, &accounts),
            setup,
            target: target.into(),
            accounts,
            catalogs: IndexMap::from([("nord".to_string(), nord_countries())]),
            nodes: vec![],
            servers: None,
            view: logic::PickerView::default(),
            asked: vec![],
            rows: Rc::new(VecModel::default()),
            panel: Rc::new(VecModel::default()),
        }
    }
}

fn row(r: &logic::PickRow) -> PickRow {
    PickRow {
        kind: match r.kind {
            logic::PickKind::Place => PickKind::Place,
            logic::PickKind::Label => PickKind::Label,
            logic::PickKind::Title => PickKind::Title,
            logic::PickKind::All => PickKind::All,
            logic::PickKind::Note => PickKind::Note,
            logic::PickKind::Message => PickKind::Message,
            logic::PickKind::Device => PickKind::Device,
            logic::PickKind::Typed => PickKind::Typed,
            logic::PickKind::Server => PickKind::Server,
            logic::PickKind::Settings => PickKind::Settings,
        },
        key: text(&r.key),
        title: text(&r.title),
        sub: text(&r.sub),
        lead: match r.lead {
            logic::Lead::None => Lead::None,
            logic::Lead::Code => Lead::Code,
            logic::Lead::Fastest => Lead::Fastest,
            logic::Lead::Direct => Lead::Direct,
        },
        code: text(&r.code),
        on: r.on,
        online: r.online,
        star: r.star,
        starred: r.starred,
        more: r.more,
        action: text(&r.action),
        i: r.i,
        n: r.n,
        small: r.small,
    }
}

fn choices(c: &[logic::Choice]) -> ModelRc<Choice> {
    ModelRc::new(VecModel::from(c.iter().map(|c| Choice { key: text(&c.key), label: text(&c.label), sub: text(&c.sub), on: c.on, enabled: c.enabled }).collect::<Vec<_>>()))
}

/// The picker's view on its Page global, as the window will set it.
fn show(shot: &Shot, p: &mut Picker) {
    let v = logic::view(&logic::Inputs {
        setup: &p.setup,
        target: &p.target,
        picks: &p.picks,
        accounts: &p.accounts,
        catalogs: &p.catalogs,
        catalogs_read: true,
        nodes: &p.nodes,
        allowed: None,
        servers: p.servers.as_deref(),
    });
    let page = PickerPage::get(shot);
    page.set_overline(text(&v.overline));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_hue(v.hue);
    page.set_mine(v.mine);
    page.set_fields(v.fields);
    page.set_provider_id(text(&v.provider_id));
    page.set_provider(text(&v.provider));
    page.set_providers(choices(&v.providers));
    page.set_protocol(text(&v.protocol));
    page.set_protocols(choices(&v.protocols));
    page.set_query(text(&v.query));
    page.set_placeholder(text(&v.placeholder));
    sync(&p.rows, v.rows.iter().map(row).collect());
    page.set_rows(ModelRc::from(p.rows.clone()));
    page.set_options(text(&v.options));
    page.set_country(text(&v.country));
    sync(&p.panel, v.panel.iter().map(row).collect());
    page.set_panel(ModelRc::from(p.panel.clone()));
    page.set_hint(text(&v.hint));
    page.set_options_open(v.options_open);
    page.set_groups(choices(&v.groups));
    page.set_blocking(v.blocking.as_ref().map(|b| Blocking { title: text(&b.title), sub: text(&b.sub), on: b.on, enabled: b.enabled }).unwrap_or_default());
    p.view = v;
}

/// Each callback does to the window's state what the window will do, then the page is shown again.
fn wire(shot: &Shot, state: &Rc<RefCell<Picker>>) {
    let go = {
        let (w, s) = (shot.as_weak(), state.clone());
        move |f: &dyn Fn(&mut Picker)| {
            let mut p = s.borrow_mut();
            f(&mut p);
            show(&w.unwrap(), &mut p);
        }
    };
    let page = PickerPage::get(shot);
    macro_rules! on {
        ($set:ident, |$p:ident $(, $a:ident)*| $body:expr) => {{
            let go = go.clone();
            page.$set(move |$($a),*| go(&|$p: &mut Picker| { $body; }));
        }};
    }
    on!(on_tab, |p, mine| p.picks.tab(mine));
    on!(on_search, |p, t| p.picks.query = t.to_string());
    on!(on_choose_provider, |p, id| p.picks.provider(&id));
    on!(on_choose_protocol, |p, k| {
        let to = p.picks.set_protocol(&p.setup, &p.target, Some(k.as_str()).filter(|k| !k.is_empty()));
        p.asked.push(format!("protocol {k} {}", to.is_some()));
    });
    on!(on_toggle_all, |p| p.picks.all_open = !p.picks.all_open);
    on!(on_open_country, |p, key| {
        let l = p.view.places[key.as_str()].clone();
        p.picks.open_country(&l);
    });
    on!(on_close_country, |p| p.picks.show(logic::Sheet::None));
    on!(on_toggle_servers, |p| p.picks.servers_open = !p.picks.servers_open);
    on!(on_open_options, |p| p.picks.show(logic::Sheet::Options));
    on!(on_close_options, |p| p.picks.show(logic::Sheet::None));
    on!(on_group, |p, k| p.picks.group = Some(k.to_string()).filter(|k| !k.is_empty()));
    on!(on_choose, |p, key| p.asked.push(format!("choose {}", logic::picked(&p.view.places[key.as_str()]).label())));
    on!(on_star, |p, key| p.asked.push(format!("star {}", p.view.places[key.as_str()].label())));
    on!(on_ts_exit, |p, ip, name| p.asked.push(format!("ts-exit {ip} {name}")));
    on!(on_use_server, |p, id| p.asked.push(format!("use-server {id}")));
    on!(on_retry, |p, id| p.asked.push(format!("retry {id}")));
    on!(on_protection, |p, on| p.asked.push(format!("protection {on}")));
    on!(on_close, |p| p.asked.push("close".into()));
    on!(on_direct, |p| p.asked.push("direct".into()));
    on!(on_settings, |p| p.asked.push("settings".into()));
    on!(on_add_provider, |p| p.asked.push("add-provider".into()));
}

/// A new window with the picker open on `p`, in a theme, the sidebar wide or folded.
fn open(p: Picker, light: bool, wide: bool) -> (Shot, Rc<RefCell<Picker>>) {
    let shot = Shot::new().expect("create the window");
    Ink::get(&shot).set_light(light);
    shot.set_wide(wide);
    let state = Rc::new(RefCell::new(p));
    show(&shot, &mut state.borrow_mut());
    wire(&shot, &state);
    (shot, state)
}

/// A new route (Ctrl+N), as approved: dark and light, and the smallest window.
#[test]
fn picker_as_approved() {
    headless();
    let dir = shots_dir();
    for (light, file) in [(false, "picker-dark.png"), (true, "picker-light.png")] {
        let (shot, _state) = open(Picker::new(""), light, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        if light {
            assert_eq!(LIGHT_GROUND, at(&px, 1280, 300, 600), "{file}: the dialog's light ground");
            continue;
        }
        assert_eq!(LINE, at(&px, 1280, 120, 300), "{file}: the dialog's edge, 120 px in");
        assert_eq!(LINE, at(&px, 1280, 600, 40), "{file}: its top edge, 40 px down");
        assert_eq!(GROUND, at(&px, 1280, 300, 600), "{file}: the list's ground");
        assert_eq!(SURFACE_HIGH, at(&px, 1280, 759, 300), "{file}: the line before the panel");
        assert_eq!(SURFACE, at(&px, 1280, 900, 400), "{file}: the panel");
        assert!(near(at(&px, 1280, 60, 400), [0x0b, 0x0e, 0x10]), "{file}: the sidebar, dimmed: {:?}", at(&px, 1280, 60, 400));
        assert!(near(at(&px, 1280, 300, 232), [0x44, 0x33, 0x27]), "{file}: the chosen tab, in the route's tint: {:?}", at(&px, 1280, 300, 232));
        assert!(inked(&px, 1280, (690, 520, 730, 660), ACCENT) > 100, "{file}: the favourites' stars, filled");
        assert_eq!(SURFACE_HIGH, at(&px, 1280, 400, 740), "{file}: Route options at the bottom");
    }
    let (shot, _state) = open(Picker::new(""), false, false);
    let px = render(&shot, 880, 600, &dir.join("picker-small.png"));
    assert_eq!(LINE, at(&px, 880, 24, 300), "the smallest window: the dialog fills it but for its margins");
    assert_eq!(SURFACE, at(&px, 880, 700, 300), "the panel keeps its width");
}

/// All countries opens the list; a country's ⋯ opens its cities and servers beside it, and picks nothing. As approved
/// (10-picker-country): the list scrolled to All countries, the pointer still on Germany's ⋯.
#[test]
fn a_country_beside_the_list() {
    headless();
    let (shot, state) = open(Picker::new(""), false, true);
    let window = shot.window();
    let scroll = |by: f32| {
        window.dispatch_event(WindowEvent::PointerScrolled { position: LogicalPosition::new(440.0, 550.0), delta_x: 0.0, delta_y: -by });
        shoot(&shot, 1280, 800, Duration::from_secs(1));
    };
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    // Down to All countries (as far as the list goes, 85 px), open it, then on to where the approved shot has it.
    scroll(85.0);
    click(window, 440.0, 628.0);
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    scroll(202.0);
    click(window, 711.0, 490.0);
    let px = render(&shot, 1280, 800, &shots_dir().join("picker-country.png"));
    {
        let p = state.borrow();
        assert!(p.picks.all_open, "All countries opened");
        assert_eq!(logic::Sheet::Country(81), p.picks.sheet, "Germany's ⋯ opened Germany");
        assert!(p.asked.is_empty(), "nothing was picked: {:?}", p.asked);
        assert_eq!(vec!["Germany", "Fastest in Germany", "Cities", "Frankfurt", "Berlin", "Hamburg", "Servers"], p.view.panel.iter().map(|r| r.title.as_str()).collect::<Vec<_>>());
    }
    assert!(near(at(&px, 1280, 400, 500), [0x0d, 0x10, 0x12]), "the row under the pointer, hovered: {:?}", at(&px, 1280, 400, 500));
    assert!(inked(&px, 1280, (1080, 400, 1130, 424), ACCENT) > 20, "the servers' Show, in the accent");
    // Show asks for the servers; Hide puts them away; the panel's close button closes it.
    click(window, 1105.0, 412.0);
    assert_eq!(Some("Loading servers"), state.borrow().view.panel.last().map(|r| r.title.as_str()));
    assert!(state.borrow().view.load.is_some(), "the window loads them");
    click(window, 1132.0, 68.0);
    assert_eq!(logic::Sheet::None, state.borrow().picks.sheet);
    // A click on a country picks its fastest server.
    click(window, 400.0, 546.0);
    assert_eq!(vec!["choose France"], state.borrow().asked);
}

/// Route options in a sheet over the whole window; Esc closes the sheet, then the picker, even from the search.
#[test]
fn route_options_and_esc() {
    headless();
    let (shot, state) = open(Picker::new(""), false, true);
    let window = shot.window();
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(window, 440.0, 724.0);
    assert_eq!(logic::Sheet::Options, state.borrow().picks.sheet);
    let px = render(&shot, 1280, 800, &shots_dir().join("picker-options.png"));
    assert_eq!(SURFACE, at(&px, 1280, 640, 790), "the sheet at the bottom of the window");
    assert!(near(at(&px, 1280, 60, 400), [0x06, 0x08, 0x09]), "dimmed twice behind it: {:?}", at(&px, 1280, 60, 400));
    press(window, Key::Escape);
    assert_eq!(logic::Sheet::None, state.borrow().picks.sheet, "Esc closed the sheet");
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    // The search, typed into: it narrows the list at once; Esc in the field still closes the picker.
    click(window, 440.0, 369.0);
    typed(window, "ham");
    let rows: Vec<_> = state.borrow().view.rows.iter().map(|r| r.title.clone()).collect();
    assert_eq!(vec!["Locations", "Hamburg"], rows);
    assert_eq!("", state.borrow().view.options, "no Route options while searching");
    press(window, Key::Escape);
    assert_eq!(vec!["close"], state.borrow().asked, "then the picker");
}

/// The fields' menus: a protocol for the next pick (NordVPN's three, each with what it is for); Add a provider from the
/// provider's menu (UiFlowTest's Add provider from the picker).
#[test]
fn the_fields_menus() {
    headless();
    let (shot, state) = open(Picker::new(""), false, true);
    let window = shot.window();
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(window, 590.0, 305.0);
    let px = render(&shot, 1280, 800, &shots_dir().join("picker-menu.png"));
    assert_eq!([0x23, 0x2a, 0x2e], at(&px, 1280, 480, 350), "the menu's surface under the field");
    // OpenVPN TCP, the third: a new route only remembers it.
    click(window, 520.0, 341.0 + 2.5 * 48.0);
    assert_eq!(("OpenVPN TCP".to_string(), vec!["protocol openvpn_tcp false".to_string()]), (state.borrow().view.protocol.clone(), state.borrow().asked.clone()));
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(window, 280.0, 305.0);
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(window, 200.0, 341.0 + 1.5 * 48.0);
    assert_eq!(Some("add-provider"), state.borrow().asked.last().map(String::as_str));
}

/// My servers, for a route through a saved server: the tailnet's devices, online first, and the servers saved in
/// Settings, the route's own checked; a device picks it as the route's exit.
#[test]
fn my_servers() {
    headless();
    let mut p = Picker::new("lab");
    p.setup.home.tailscale = true;
    p.setup.servers = vec![OwnServer { id: "s1".into(), wg: p.setup.routes[3].wg.clone(), ovpn: None, ss: None }];
    p.setup.routes[3].own = Some("s1".into());
    p.nodes = vec![
        TsNode { name: "nas".into(), ip: "100.101.1.2".into(), online: false, id: String::new() },
        TsNode { name: "pi".into(), ip: "100.101.1.3".into(), online: true, id: String::new() },
    ];
    let (shot, state) = open(p, false, true);
    assert!(state.borrow().view.mine, "a route through a saved server opens on My servers");
    let px = render(&shot, 1280, 800, &shots_dir().join("picker-mine.png"));
    assert!(near(at(&px, 1280, 600, 232), [0x2b, 0x3f, 0x35]), "the chosen tab, in the route's green: {:?}", at(&px, 1280, 600, 232));
    let rows: Vec<_> = state.borrow().view.rows.iter().map(|r| r.title.clone()).collect();
    assert_eq!(vec!["Tailscale exit node", "pi", "nas", "Saved servers", "Home lab", "Add or manage servers in Settings."], rows);
}

/// What the window keeps for the sign-in, and the view model's forms.
#[derive(Default)]
struct SignIn {
    adding: bool,
    accounts: IndexMap<String, String>,
    step: Option<String>,
    form: IndexMap<String, String>,
    signing: IndexSet<String>,
    errors: IndexMap<String, String>,
    links: IndexMap<String, String>,
    challenges: IndexMap<String, unbraid::error::Challenge>,
    asked: Vec<String>,
    fields: Rc<VecModel<FormField>>,
}

impl SignIn {
    fn inputs(&self) -> signin::Inputs<'_> {
        signin::Inputs {
            adding: self.adding,
            accounts: &self.accounts,
            notice: None,
            import_error: None,
            step: self.step.as_deref(),
            form: &self.form,
            signing: &self.signing,
            errors: &self.errors,
            links: &self.links,
            challenges: &self.challenges,
        }
    }
}

/// A PNG as the window gets it from the provider, decoded for the page.
fn picture(png: &[u8]) -> slint::Image {
    let rgba = image::load_from_memory(png).expect("a PNG").to_rgba8();
    slint::Image::from_rgba8(slint::SharedPixelBuffer::clone_from_slice(rgba.as_raw(), rgba.width(), rgba.height()))
}

fn show_sign_in(c: &Card, s: &SignIn) {
    let v = signin::view(&s.inputs());
    let page = SignInPage::get(c);
    page.set_overline(text(&v.overline));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_closable(v.closable);
    page.set_notice(text(&v.notice));
    page.set_providers(ModelRc::new(VecModel::from(v.providers.iter().map(|p| ProviderRow { id: text(&p.id), name: text(&p.name), fields: text(&p.fields) }).collect::<Vec<_>>())));
    let other = |o: signin::Other| match o {
        signin::Other::File => Other::File,
        signin::Other::Shadowsocks => Other::Shadowsocks,
        signin::Other::Tailscale => Other::Tailscale,
    };
    page.set_others(ModelRc::new(VecModel::from(v.others.iter().map(|o| OtherRow { other: other(o.other), title: text(&o.title), sub: text(&o.sub) }).collect::<Vec<_>>())));
    page.set_import_error(text(&v.import_error));
    let f = &v.form;
    let fields = f
        .fields
        .iter()
        .map(|x| FormField {
            key: text(&x.key),
            label: text(&x.label),
            value: text(&x.value),
            placeholder: text(&x.placeholder),
            secret: x.secret,
            qr: x.qr,
            file: x.file,
            file_note: text(&x.file_note),
            last: x.last,
            asked: x.asked,
        })
        .collect();
    sync(&s.fields, fields);
    page.set_form(FormView {
        id: text(&f.id),
        name: text(&f.name),
        fields: ModelRc::from(s.fields.clone()),
        captcha: f.captcha.as_deref().map(picture).unwrap_or_default(),
        error: text(&f.error),
        question: f.question,
        link: text(&f.link),
        link_label: text(&f.link_label),
        help: text(&f.help),
        ready: f.ready,
        busy: f.busy,
        done: f.done,
    });
}

fn sign_in_card(s: SignIn, light: bool) -> (Card, Rc<RefCell<SignIn>>) {
    let c = Card::new().expect("create the window");
    card::Ink::get(&c).set_light(light);
    let state = Rc::new(RefCell::new(s));
    show_sign_in(&c, &state.borrow());
    let go = {
        let (w, s) = (c.as_weak(), state.clone());
        move |f: &dyn Fn(&mut SignIn)| {
            f(&mut s.borrow_mut());
            show_sign_in(&w.unwrap(), &s.borrow());
        }
    };
    let page = SignInPage::get(&c);
    macro_rules! on {
        ($set:ident, |$s:ident $(, $a:ident)*| $body:expr) => {{
            let go = go.clone();
            page.$set(move |$($a),*| go(&|$s: &mut SignIn| { $body; }));
        }};
    }
    on!(on_pick, |s, id| s.step = Some(id.to_string()));
    // As the view model's discardForm: the provider's half-filled form is forgotten.
    on!(on_back, |s, id| {
        s.form.retain(|k, _| !k.starts_with(&format!("{id}:")));
        s.step = None;
    });
    on!(on_field_changed, |s, id, key, t| {
        s.form.insert(signin::form_key(&id, &key), t.to_string());
    });
    on!(on_submit, |s, id| s.asked.push(format!("submit {id} {:?}", signin::submit(&s.inputs()).map(|a| a.into_values().collect::<Vec<_>>()))));
    on!(on_close, |s| s.asked.push("close".into()));
    on!(on_import_file, |s| s.asked.push("import-file".into()));
    on!(on_shadowsocks, |s| s.asked.push("shadowsocks".into()));
    on!(on_tailscale_only, |s| s.asked.push("tailscale-only".into()));
    on!(on_scan_qr, |s, id, key| s.asked.push(format!("scan-qr {id} {key}")));
    on!(on_choose_file, |s, id, key| s.asked.push(format!("choose-file {id} {key}")));
    on!(on_open_link, |s, url| s.asked.push(format!("open-link {url}")));
    (c, state)
}

/// The first run, as approved (4-sign-in): every provider, then the other ways in; dark, light and the smallest window.
#[test]
fn sign_in_as_approved() {
    headless();
    let dir = shots_dir();
    for (light, file, w, h) in [(false, "sign-in-dark.png", 1280, 800), (true, "sign-in-light.png", 1280, 800), (false, "sign-in-small.png", 880, 600)] {
        let (c, _state) = sign_in_card(SignIn::default(), light);
        let px = render(&c, w, h, &dir.join(file));
        if light {
            assert_eq!(LIGHT_GROUND, at(&px, w, w / 2, 30), "{file}: the light ground");
            continue;
        }
        let left = (w - 600) / 2;
        assert_eq!(SURFACE_HIGH, at(&px, w, left, 300), "{file}: the card's edge");
        assert_eq!(GROUND, at(&px, w, left - 10, 300), "{file}: the window around it");
        assert_eq!(SURFACE, at(&px, w, w / 2, 190), "{file}: NordVPN's row");
        assert!(inked(&px, w, (left + 24, 70, left + 200, 120), ACCENT) > 50, "{file}: the wordmark's slash");
    }
}

/// A provider's form: typing lands in the view model's form; Esc in the field goes back to the list and the form is
/// forgotten (UiFlowTest's sign-in); Enter sends a filled one.
#[test]
fn a_providers_form() {
    headless();
    let (c, state) = sign_in_card(SignIn::default(), false);
    let window = c.window();
    shoot(&c, 1280, 800, Duration::from_secs(1));
    click(window, 640.0, 194.0);
    assert_eq!(Some("nord"), state.borrow().step.as_deref(), "NordVPN's form");
    shoot(&c, 1280, 800, Duration::from_secs(1));
    click(window, 640.0, 261.0);
    typed(window, "half a token");
    assert_eq!(Some("half a token"), state.borrow().form.get("nord:token").map(String::as_str), "every key reached the form, the field kept its focus");
    let px = render(&c, 1280, 800, &shots_dir().join("sign-in-form.png"));
    assert!(near(at(&px, 1280, 640, 769 - 28), ACCENT), "Continue, enabled once filled: {:?}", at(&px, 1280, 640, 741));
    press(window, Key::Return);
    assert_eq!(vec!["submit nord Some([\"half a token\"])"], state.borrow().asked);
    press(window, Key::Escape);
    assert_eq!((None, true), (state.borrow().step.clone(), state.borrow().form.is_empty()), "Esc stepped back and forgot what was typed");
    let px = shoot(&c, 1280, 800, Duration::from_secs(1));
    assert_eq!(SURFACE, at(&px, 1280, 640, 190), "the list again");
}

/// A provider's question with its picture (IVPN's captcha): one more field under it, the question in the text's ink.
#[test]
fn a_providers_question() {
    headless();
    let mut png = std::io::Cursor::new(Vec::new());
    image::RgbImage::from_fn(240, 80, |x, y| if (x / 12 + y / 12) % 2 == 0 { image::Rgb([40, 40, 40]) } else { image::Rgb([200, 200, 200]) })
        .write_to(&mut png, image::ImageFormat::Png)
        .expect("encode a PNG");
    let mut s = SignIn { step: Some("ivpn".into()), ..SignIn::default() };
    s.form.insert("ivpn:account".into(), "i-AB12-CD34-EF56".into());
    let field = unbraid::providers::Field { secret: false, ..unbraid::providers::Field::new("captcha", "Characters in the picture") };
    s.challenges.insert("ivpn".into(), unbraid::error::Challenge { message: "Type the characters in the picture to continue.".into(), field, image: Some(png.into_inner()), keep: IndexMap::new() });
    s.errors.insert("ivpn".into(), "Type the characters in the picture to continue.".into());
    let (c, state) = sign_in_card(s, false);
    let px = render(&c, 1280, 800, &shots_dir().join("sign-in-question.png"));
    assert_eq!(2, state.borrow().fields.row_count(), "the account and the question");
    assert!(inked(&px, 1280, (356, 300, 924, 520), [0xff, 0xff, 0xff]) > 2000, "the picture on white");
}
