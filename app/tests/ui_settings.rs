//! Renders Settings headless beside the sidebar, as the window shows it, with the data of the approved screenshots:
//! Providers & servers and Desktop in both themes and at the smallest window; then a provider's page, Local & home
//! access with its Advanced settings open, Tailscale's devices to send files to, About, Legal, the licences, a sheet, a
//! prompt and an import prompt. Shots go to `target/screenshots/settings-*.png`.

mod common;

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use indexmap::IndexMap;
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, LogicalPosition, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::desktop_settings::Theme;
use unbraid::model::{Location, OwnServer, Route, Setup, WgPeer};
use unbraid::providers::{self, Opt};
use unbraid::taildrop::Sending;
use unbraid::ui::importer::{self as ilogic, Draft};
use unbraid::ui::settings::{self as logic, Act, End, Glyph};
use unbraid::ui::status::Tone;
use unbraid::vpn::{TsNode, VpnState};

slint::slint! {
    import { Sidebar, ProfileChip } from "../ui/shell.slint";
    import { SettingsScreen, SettingsPage, SettingsDialogs } from "../ui/settings.slint";
    import { ImportDialogs, ImporterPage } from "../ui/importer.slint";
    import { Ink } from "../ui/theme.slint";
    export { SettingsPage, ImporterPage, Ink }
    export { SettingsAct, SettingsEnd, SettingsGlyph, SettingsTone, SettingsRow, SettingsGroup, SettingsSubject, SettingsLicence, SettingsInput, SettingsDialog } from "../ui/settings.slint";
    export { ImportPrompt } from "../ui/importer.slint";

    // The window as it will be: the sidebar, then Settings; its dialogs and the import prompts over both.
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
            SettingsScreen { }
        }
        SettingsDialogs { }
        ImportDialogs { }
    }
}

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

fn text(s: &str) -> SharedString {
    s.into()
}

fn list<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

/// The page's enums as the window's: the same variants by name.
macro_rules! same {
    ($f:ident: $from:ident => $to:ident [$($v:ident),* $(,)?]) => {
        fn $f(x: $from) -> $to {
            match x {
                $($from::$v => $to::$v),*
            }
        }
    };
}
same!(act: Act => SettingsAct [None, Open, Pick, Url, Dialog, Advanced, Tailscale, TsLogin, Suffix, Lan, HomeConfig, Opt, Filter, FilterRoutes, FilterDirect, Outside, Through, Stats, Login, Connect, Minimised, CloseToTray, RememberWindow, Theme, Tour, AddProvider, ImportFile, Shadowsocks, SaveFilter, SignOutTailscale, TsServer, TsDomains, SendFiles, CancelSend, Subnets, DeleteStats, Limit, SignOut, RenameServer, RemoveServer]);
same!(end: End => SettingsEnd [None, Chevron, Dot, Toggle, Radio, External, Delete, Mark, Keys, Remove, Expand]);
same!(glyph: Glyph => SettingsGlyph [None, VpnKey, Hub, Home, Tunnel, Shield, Layers, Stats, Bolt, Info, File, Phone, Dns, Lan, Router, Power, Routes, Sliders]);
same!(tone: Tone => SettingsTone [Good, Warn, Bad, Idle]);

fn row(r: &logic::Row) -> SettingsRow {
    SettingsRow {
        act: act(r.act),
        arg: text(&r.arg),
        title: text(&r.title),
        sub: text(&r.sub),
        icon: glyph(r.icon),
        end: end(r.end),
        checked: r.checked,
        cta: r.cta,
        danger: r.danger,
        tone: tone(r.tone),
        value: text(&r.value),
        hue: r.hue,
        wordmark: r.wordmark,
    }
}

fn group(g: &logic::Group) -> SettingsGroup {
    SettingsGroup {
        label: text(&g.label),
        rows: list(g.rows.iter().map(row).collect()),
        advanced: g.advanced,
        open_sub: text(&g.open_sub),
        button: text(&g.button),
        error: text(&g.error),
        caption: text(&g.caption),
    }
}

fn dialog(d: &logic::Dialog) -> SettingsDialog {
    SettingsDialog {
        key: text(&d.key),
        sheet: d.sheet,
        title: text(&d.title),
        text: text(&d.text),
        inputs: list(
            d.inputs
                .iter()
                .map(|i| SettingsInput {
                    label: text(&i.label),
                    placeholder: text(&i.placeholder),
                    value: text(&i.value),
                    secret: i.secret,
                })
                .collect(),
        ),
        hint: text(&d.hint),
        error: text(&d.error),
        rows: list(d.rows.iter().map(row).collect()),
        confirm: row(&d.confirm),
        other: row(&d.other),
        stays: d.stays,
    }
}

/// Settings' view on its Page global, as the window will set it; its checks are the page's own.
fn show(shot: &Shot, v: &logic::SettingsView) {
    let p = SettingsPage::get(shot);
    p.set_version(text(&v.version));
    p.set_subjects(list(
        v.subjects
            .iter()
            .map(|s| SettingsSubject {
                key: text(&s.key),
                title: text(&s.title),
                icon: glyph(s.icon),
                group: text(&s.group),
            })
            .collect(),
    ));
    p.set_subject(text(&v.subject));
    p.set_page(text(&v.page));
    p.set_over(text(&v.over));
    p.set_title(text(&v.title));
    p.set_back(v.back);
    p.set_provider(text(&v.provider));
    p.set_notice(text(&v.notice));
    p.set_groups(list(v.groups.iter().map(group).collect()));
    p.set_licences(list(
        v.licences.iter().map(|l| SettingsLicence { title: text(&l.title), text: text(&l.text) }).collect(),
    ));
    p.set_dialogs(list(v.dialogs.iter().map(dialog).collect()));
    p.on_valid(|key, typed| logic::valid(&key, &typed));
    p.on_clean(|key, typed| logic::clean(&key, &typed).into());
}

/// What Settings is shown with: the approved screenshots' set-up app, and how the computer is set.
struct World {
    setup: Setup,
    accounts: IndexMap<String, String>,
    stack: Vec<String>,
    vpn: VpnState,
    opts: Vec<Opt>,
    login: (bool, bool, bool),
    theme: Theme,
    sending: Option<Sending>,
}

impl World {
    /// NordVPN with three routes, and a WireGuard server of the user's own on one more.
    fn new() -> World {
        let lab = WgPeer::new(
            "Home lab",
            KEY,
            vec!["10.8.0.2/32".into()],
            KEY,
            "203.0.113.7:51820",
            vec!["0.0.0.0/0".into()],
        );
        let setup = Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
                Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
                Route {
                    wg: Some(lab.clone()),
                    own: Some("s1".into()),
                    hue: 3,
                    ..Route::new("lab", Location::default())
                },
            ],
            default_route: "nl".into(),
            apps: [("firefox", "us"), ("spotify", "it"), ("thunderbird", "us"), ("discord", "it")]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            servers: vec![OwnServer { id: "s1".into(), wg: Some(lab), ovpn: None, ss: None }],
            ..Setup::default()
        };
        // As a computer without an autostart entry has it: off, its two choices showing what turning it on keeps.
        World {
            setup,
            accounts: [("nord".to_string(), "{}".to_string())].into_iter().collect(),
            stack: vec![],
            vpn: VpnState::default(),
            opts: vec![],
            login: (false, true, true),
            theme: Theme::System,
            sending: None,
        }
    }

    fn at(mut self, stack: &[&str]) -> World {
        self.stack = stack.iter().map(|s| s.to_string()).collect();
        if let Some(id) = stack.last().and_then(|p| p.strip_prefix("provider:")) {
            self.opts = logic::provider_opts(providers::get(id).unwrap(), "{}");
        }
        self
    }

    fn view(&self) -> logic::SettingsView {
        let fresh: HashSet<String> = self.accounts.keys().cloned().collect();
        let (dates, setting_up, tags) = (IndexMap::new(), HashSet::new(), IndexMap::new());
        logic::view(&logic::Inputs {
            setup: &self.setup,
            vpn: &self.vpn,
            accounts: &self.accounts,
            stack: &self.stack,
            notice: None,
            fresh: &fresh,
            list_dates: &dates,
            setting_up: &setting_up,
            running: None,
            tags: &tags,
            opts: &self.opts,
            device: None,
            plan: None,
            ts_stored: false,
            sending: self.sending.as_ref(),
            login: self.login,
            theme: self.theme,
            close_to_tray: true,
            remember_window: true,
            stats_size: 0,
            key_file: None,
            wg_error: None,
            now: 0,
        })
    }

    /// A new window showing this, light or dark, the sidebar wide or a rail.
    fn shot(&self, light: bool, wide: bool) -> Shot {
        let shot = Shot::new().expect("create the window");
        Ink::get(&shot).set_light(light);
        shot.set_wide(wide);
        show(&shot, &self.view());
        shot
    }
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

fn point(shot: &Shot, x: f32, y: f32) {
    shot.window().dispatch_event(WindowEvent::PointerMoved { position: LogicalPosition::new(x, y) });
}

fn click(shot: &Shot, x: f32, y: f32) {
    let position = LogicalPosition::new(x, y);
    let button = PointerEventButton::Left;
    point(shot, x, y);
    shot.window().dispatch_event(WindowEvent::PointerPressed { position, button });
    shot.window().dispatch_event(WindowEvent::PointerReleased { position, button });
}

fn key(shot: &Shot, k: slint::platform::Key) {
    shot.window().dispatch_event(WindowEvent::KeyPressed { text: k.into() });
    shot.window().dispatch_event(WindowEvent::KeyReleased { text: k.into() });
}

const GROUND: [u8; 3] = [0x0f, 0x12, 0x14];
const SURFACE: [u8; 3] = [0x17, 0x1b, 0x1e];
const ACCENT: [u8; 3] = [0xff, 0xa6, 0x6b];
const ACCENT_CONTAINER: [u8; 3] = [0x3a, 0x2a, 0x1f];
const GOOD: [u8; 3] = [0x8e, 0xe0, 0xa8];

/// Providers & servers, as approved: the subject picked, NordVPN with its green dot, the server, Add connection.
#[test]
fn hub_as_approved() {
    headless();
    let dir = shots_dir();
    for (light, file) in [(false, "settings-dark.png"), (true, "settings-light.png")] {
        let shot = World::new().shot(light, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        if light {
            assert_eq!([0xf5, 0xf2, 0xee], at(&px, 1280, 900, 600), "{file}: the light ground");
            assert_eq!([0xfb, 0xe2, 0xd0], at(&px, 1280, 500, 166), "{file}: the subject picked");
            continue;
        }
        assert_eq!(GROUND, at(&px, 1280, 900, 600), "{file}: the ground under the page");
        assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 500, 166), "{file}: Providers & servers, picked");
        assert_eq!(GROUND, at(&px, 1280, 500, 208), "{file}: Tailscale, not picked");
        assert_eq!(SURFACE, at(&px, 1280, 900, 140), "{file}: NordVPN's row");
        assert_eq!(GOOD, at(&px, 1280, 1219, 163), "{file}: its status dot");
        assert_eq!(SURFACE, at(&px, 1280, 900, 260), "{file}: Home lab's row");
        assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 700, 358), "{file}: Add connection");
        assert_eq!([0x1e, 0x24, 0x28], at(&px, 1280, 539, 600), "{file}: the line between subjects and page");
    }
}

/// Desktop, as approved, dark and light (the pointer on Light, just clicked); a subject's click picks it and the
/// theme's row sets the theme.
#[test]
fn desktop_as_approved() {
    headless();
    let dir = shots_dir();
    let world = World::new().at(&["desktop"]);
    let shot = world.shot(false, true);
    let picked = Rc::new(RefCell::new(Vec::<String>::new()));
    let (p, t) = (picked.clone(), picked.clone());
    SettingsPage::get(&shot).on_pick(move |s| p.borrow_mut().push(format!("pick {s}")));
    SettingsPage::get(&shot).on_set_theme(move |s| t.borrow_mut().push(format!("theme {s}")));
    let px = render(&shot, 1280, 800, &dir.join("settings-desktop-dark.png"));
    assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 500, 440), "Desktop, picked");
    assert_eq!(ACCENT, at(&px, 1280, 1206, 414), "close to tray: on, in the accent");
    assert_eq!(ACCENT, at(&px, 1280, 1228, 597), "System: picked");
    click(&shot, 400.0, 482.0);
    click(&shot, 900.0, 729.0);
    assert_eq!(vec!["pick stats".to_string(), "theme Light".to_string()], *picked.borrow());
    drop(shot);
    let world = World { theme: Theme::Light, ..world };
    let shot = world.shot(true, true);
    point(&shot, 900.0, 729.0);
    let px = render(&shot, 1280, 800, &dir.join("settings-desktop-light.png"));
    assert_eq!([0xb8, 0x5a, 0x1a], at(&px, 1280, 1228, 729), "Light: picked, in the light accent");
    assert_ne!([0xff, 0xff, 0xff], at(&px, 1280, 900, 745), "Light's row, under the pointer");
    assert_eq!([0xff, 0xff, 0xff], at(&px, 1280, 900, 680), "Dark's row");
}

/// The smallest window: the sidebar a rail, the subjects and the page keep their layout.
#[test]
fn smallest_window() {
    headless();
    let shot = World::new().shot(false, false);
    let px = render(&shot, 880, 600, &shots_dir().join("settings-small.png"));
    assert_eq!([0x13, 0x17, 0x1a], at(&px, 880, 30, 400), "the rail's bar");
    assert_eq!(ACCENT_CONTAINER, at(&px, 880, 300, 166), "Providers & servers, picked");
    assert_eq!(SURFACE, at(&px, 880, 700, 140), "NordVPN's row");
}

/// NordVPN's page: its account, limit and settings, the routes on it and the sign-out; Esc goes back.
#[test]
fn provider_page() {
    headless();
    let shot = World::new().at(&["providers", "provider:nord"]).shot(false, true);
    let backs = Rc::new(RefCell::new(0));
    let b = backs.clone();
    SettingsPage::get(&shot).on_go_back(move || *b.borrow_mut() += 1);
    let px = render(&shot, 1280, 800, &shots_dir().join("settings-provider.png"));
    assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 500, 166), "its subject stays picked");
    assert_eq!(SURFACE, at(&px, 1280, 900, 140), "the Account row");
    click(&shot, 900.0, 140.0);
    key(&shot, slint::platform::Key::Escape);
    assert_eq!(1, *backs.borrow(), "Esc on a page with Back goes back");
}

/// Local & home access: Advanced settings opens in place, home subnets and domains through Tailscale under it, and
/// closes again.
#[test]
fn advanced_settings_open() {
    headless();
    let mut world = World::new().at(&["local"]);
    world.setup.home.subnets = vec!["192.168.178.0/24".into()];
    world.setup.home.domains = vec!["corp.example.com".into(), "internal".into()];
    let shot = world.shot(false, true);
    let closed = shoot(&shot, 1280, 800, Duration::from_secs(20));
    let v = world.view();
    let y = 458;
    click(&shot, 900.0, y as f32);
    let px = render(&shot, 1280, 800, &shots_dir().join("settings-advanced.png"));
    assert!(v.groups.last().unwrap().advanced);
    assert_eq!(SURFACE, at(&px, 1280, 900, y + 66), "the subnets row, shown under the head");
    assert_eq!(GROUND, at(&closed, 1280, 900, y + 66), "closed, nothing under the head");
    click(&shot, 900.0, y as f32);
    point(&shot, 1270.0, 790.0);
    assert!(shoot(&shot, 1280, 800, Duration::from_secs(20)) == closed, "a second click closes it");
}

/// Tailscale's page on a tailnet that allows sending files: the devices that take them, the send under way and its
/// Cancel. A device's row asks for its files, by its Tailscale ID.
#[test]
fn send_files() {
    headless();
    let mut world = World::new().at(&["tailscale"]);
    world.setup.home.tailscale = true;
    world.vpn.phase = unbraid::vpn::Phase::On;
    world.vpn.ts_state = Some("Running".into());
    world.vpn.ts_files = true;
    let node =
        |name: &str, online: bool, id: &str| TsNode { name: name.into(), online, id: id.into(), ..TsNode::default() };
    world.vpn.ts_targets =
        vec![node("pixel-8", true, "nPixel"), node("nas", false, "nNas"), node("laptop", true, "nLaptop")];
    world.sending =
        Some(Sending { to: "laptop".into(), files: 3, sent: 42_000_000, total: 118_000_000, ..Sending::default() });
    let shot = world.shot(false, true);
    let px = render(&shot, 1280, 800, &shots_dir().join("settings-send-files.png"));
    assert_eq!(SURFACE, at(&px, 1280, 900, 140), "the first group");
    world.sending = None;
    let v = world.view();
    let files = v.groups.iter().find(|g| g.label == "Send files").unwrap();
    let asked = Rc::new(RefCell::new(Vec::<String>::new()));
    let a = asked.clone();
    let p = SettingsPage::get(&shot);
    p.on_send_files(move |id| a.borrow_mut().push(id.into()));
    p.invoke_run(row(&files.rows[1]), "".into(), "".into());
    p.invoke_run(row(&files.rows[2]), "".into(), "".into());
    assert_eq!(vec!["nLaptop"], *asked.borrow(), "the offline nas takes no files");
}

/// About, Legal and Licences.
#[test]
fn about_legal_and_licences() {
    headless();
    let dir = shots_dir();
    for (stack, file) in [(&["about"][..], "settings-about.png"), (&["legal"][..], "settings-legal.png")] {
        let shot = World::new().at(stack).shot(false, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        assert_eq!(SURFACE, at(&px, 1280, 1000, 140), "{file}: the first group");
    }
    let shot = World::new().at(&["legal", "notices"]).shot(false, true);
    let started = std::time::Instant::now();
    let px = render(&shot, 1280, 800, &dir.join("settings-licences.png"));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "only the licences in view are laid out ({:?})",
        started.elapsed()
    );
    assert!((564..1260).any(|x| at(&px, 1280, x, 145) != GROUND), "the GPL's first lines");
    assert_eq!(GROUND, at(&px, 1280, 1275, 300), "nothing runs past the page's edge");
}

/// Add connection's sheet over the whole window, the server's rename prompt with what it keeps of a long name, and
/// the Shadowsocks prompt warning of a weak cipher.
#[test]
fn dialogs_and_import() {
    headless();
    let dir = shots_dir();
    let shot = World::new().shot(false, true);
    let calls = Rc::new(RefCell::new(Vec::<String>::new()));
    let c = calls.clone();
    SettingsPage::get(&shot).on_rename_server(move |id, name| c.borrow_mut().push(format!("{id} {name}")));
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    click(&shot, 900.0, 358.0);
    let px = render(&shot, 1280, 800, &dir.join("settings-add.png"));
    assert_eq!("add", SettingsPage::get(&shot).get_dialog().as_str(), "Add connection opens its sheet");
    assert_eq!(SURFACE, at(&px, 1280, 640, 760), "the sheet");
    key(&shot, slint::platform::Key::Escape);
    shoot(&shot, 1280, 800, Duration::from_secs(1));
    assert_eq!("", SettingsPage::get(&shot).get_dialog().as_str(), "Esc closes it");
    click(&shot, 900.0, 281.0);
    let px = render(&shot, 1280, 800, &dir.join("settings-server.png"));
    assert_eq!("server:s1", SettingsPage::get(&shot).get_dialog().as_str());
    assert_eq!(SURFACE, at(&px, 1280, 640, 400), "the prompt");
    drop(shot);

    let shot = World::new().shot(false, true);
    let mut d = Draft::default();
    d.shadowsocks();
    d.edited("", "", "", "ss://YWVzLTI1Ni1jZmI6cHc@198.51.100.4:8388#Outline");
    assert_eq!(None, d.import());
    let p = ilogic::prompt(&d);
    ImporterPage::get(&shot).set_prompt(ImportPrompt {
        kind: text(&p.kind),
        title: text(&p.title),
        text: text(&p.text),
        confirm: text(&p.confirm),
        danger: p.danger,
        ready: p.ready,
        name: text(&p.name),
        warning: text(&p.warning),
        error: text(&p.error),
    });
    let px = render(&shot, 1280, 800, &dir.join("settings-import.png"));
    assert_eq!(SURFACE, at(&px, 1280, 640, 400), "the Shadowsocks prompt");
    assert!(calls.borrow().is_empty());
}
