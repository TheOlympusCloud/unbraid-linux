//! The screens as a person first meets them, in the app's own window, headless and clicked through: the welcome and
//! terms, sign-in, then Routes, Apps, Stats, Settings and the location picker of a set-up app; the smallest window; the
//! tray's profile switch. Each step leaves a shot in `target/screenshots/flow-*.png`, to set beside the approved ones
//! (`app/build/screenshots/`). The data folder is a temporary one, and there is no engine.

mod common;

use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Condvar, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use common::{headless, render, shoot, shots_dir};
use indexmap::IndexMap;
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, LogicalPosition, Model, SharedString};
use unbraid::desktop_settings::{self as ds, Theme};
use unbraid::limits::LIMIT_OPT;
use unbraid::model::{City, Country, DIRECT, Location, Profile, Route, Setup, VERSION, WgPeer};
use unbraid::window::{self, AppWindow, AppsPage, Ink, PickerPage, SettingsPage, SignInPage, StatsPage, WelcomePage, Win};
use unbraid::{app, paths, stats, tray, ui};

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

/// The apps' stand-in programs: an /opt of their own, which the shots show (never this computer's paths), where the
/// approved ones had it.
fn programs() -> PathBuf {
    PathBuf::from("/tmp/unbraid-ui-test/opt")
}

/// The test's own folders: data, config, the desktop's apps and the runtime folder.
fn folders() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| std::env::temp_dir().join("unbraid-ui-flow"))
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a runtime"))
}

/// One app per test process, as on the desktop: the store and onboarding are the process's. Fake desktop apps to route.
fn app_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = folders();
        let _ = std::fs::remove_dir_all(dir);
        for (var, sub) in [("XDG_DATA_HOME", "home"), ("XDG_CONFIG_HOME", "config"), ("XDG_DATA_DIRS", "share"), ("XDG_RUNTIME_DIR", "run")] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
            // SAFETY: set before anything reads them, while the other flows wait for this one.
            unsafe { std::env::set_var(var, dir.join(sub)) };
        }
        let apps = dir.join("home/applications");
        std::fs::create_dir_all(&apps).unwrap();
        // Each app its own program in its own folder (stand-ins, never run): apps on one program share its route.
        let _ = std::fs::remove_dir_all(programs());
        let program = |id: &str| {
            let p = programs().join(id).join(id);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, [0x7f, 69, 76, 70, 2, 1]).unwrap();
            executable(&p);
            p
        };
        for (id, name) in [
            ("firefox", "Firefox"),
            ("spotify", "Spotify"),
            ("org.gnome.Terminal", "Terminal"),
            ("chromium", "Chromium"),
            ("thunderbird", "Thunderbird"),
            ("signal-desktop", "Signal"),
            ("discord", "Discord"),
            ("code", "Visual Studio Code"),
            ("libreoffice-startcenter", "LibreOffice"),
            ("org.gimp.GIMP", "GIMP"),
        ] {
            std::fs::write(apps.join(format!("{id}.desktop")), format!("[Desktop Entry]\nType=Application\nName={name}\nExec={} %u\n", program(id).display())).unwrap();
        }
        // Runs as LibreOffice: Writer is the same program.
        let office = programs().join("libreoffice-startcenter/libreoffice-startcenter");
        std::fs::write(apps.join("libreoffice-writer.desktop"), format!("[Desktop Entry]\nType=Application\nName=LibreOffice Writer\nExec={} --writer %U\n", office.display())).unwrap();
        // A launcher script that starts its program through a variable it can't see into: the default route only.
        let steam = programs().join("steam/steam");
        std::fs::create_dir_all(steam.parent().unwrap()).unwrap();
        std::fs::write(&steam, "#!/bin/sh\nexec \"$HOME/.steam/steam.sh\" \"$@\"\n").unwrap();
        executable(&steam);
        std::fs::write(apps.join("steam.desktop"), format!("[Desktop Entry]\nType=Application\nName=Steam\nExec={} %U\n", steam.display())).unwrap();
        // Runs as Firefox: it takes Firefox's route.
        let firefox = programs().join("firefox/firefox");
        std::fs::write(apps.join("firefox-private.desktop"), format!("[Desktop Entry]\nType=Application\nName=Private Browsing\nExec={} --private-window %u\n", firefox.display())).unwrap();
        // Runs as python3, like every other Python program: the engine can't tell it apart.
        std::fs::write(apps.join("org.example.Tool.desktop"), "[Desktop Entry]\nType=Application\nName=Tool\nExec=python3 /opt/tool/tool.py\n").unwrap();
        ui::tour::init();
        app::init(runtime().handle(), paths::data().unwrap());
    });
}

fn executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The flows share one app, as the approved ones did, in their order: each waits for the ones before it that this run
/// started (one left out by a filter never starts, and isn't waited for).
static TURNS: Mutex<([bool; 4], [bool; 4])> = Mutex::new(([false; 4], [false; 4]));
static TURNED: Condvar = Condvar::new();

struct Turn(usize);

impl Drop for Turn {
    fn drop(&mut self) {
        window::close();
        TURNS.lock().unwrap_or_else(|e| e.into_inner()).1[self.0] = true;
        TURNED.notify_all();
    }
}

fn turn(n: usize) -> Turn {
    let mut t = TURNS.lock().unwrap_or_else(|e| e.into_inner());
    t.0[n] = true;
    let since = Instant::now();
    while (0..n).any(|i| !t.1[i] && (t.0[i] || since.elapsed() < Duration::from_secs(3))) {
        t = TURNED.wait_timeout(t, Duration::from_millis(100)).unwrap_or_else(|e| e.into_inner()).0;
    }
    drop(t);
    app_once();
    Turn(n)
}

/// The app's window on this thread, shown.
fn open() -> Rc<Win> {
    headless();
    let win = window::open();
    win.show();
    win
}

fn shot(win: &Win, name: &str, width: u32, height: u32) -> Vec<slint::Rgb8Pixel> {
    render(&win.w, width, height, &shots_dir().join(format!("flow-{name}.png")))
}

/// Lets the window and the app's own threads work until `done`, as a person waits for the screen to change.
fn wait_until(win: &Win, what: &str, done: impl Fn(&Win) -> bool) {
    let since = Instant::now();
    while !done(win) {
        assert!(since.elapsed() < Duration::from_secs(20), "waited too long for {what}");
        std::thread::sleep(Duration::from_millis(40));
        shoot(&win.w, 1280, 800, Duration::from_millis(100));
    }
}

fn click(w: &AppWindow, x: f32, y: f32) {
    click_with(w, x, y, PointerEventButton::Left);
}

fn click_with(w: &AppWindow, x: f32, y: f32, button: PointerEventButton) {
    let position = LogicalPosition::new(x, y);
    w.window().dispatch_event(WindowEvent::PointerMoved { position });
    w.window().dispatch_event(WindowEvent::PointerPressed { position, button });
    w.window().dispatch_event(WindowEvent::PointerReleased { position, button });
}

fn press(w: &AppWindow, key: impl Into<SharedString>) {
    let text = key.into();
    w.window().dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    w.window().dispatch_event(WindowEvent::KeyReleased { text });
}

/// A shortcut, Ctrl held.
fn ctrl(w: &AppWindow, key: &str) {
    w.window().dispatch_event(WindowEvent::KeyPressed { text: Key::Control.into() });
    press(w, key);
    w.window().dispatch_event(WindowEvent::KeyReleased { text: Key::Control.into() });
}

fn edit(f: impl FnOnce(&mut Setup)) {
    app::store().update(|s| {
        let mut s = s.clone();
        f(&mut s);
        s
    });
}

fn at(px: &[slint::Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = px[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

#[test]
fn a_welcome_terms_and_sign_in() {
    let _turn = turn(0);
    let win = open();
    assert_eq!(0, win.w.get_stage(), "the welcome before anything else");
    assert!(WelcomePage::get(&win.w).get_fresh(), "a new install gets the whole welcome");
    shot(&win, "1-welcome", 1280, 800);
    click(&win.w, 873.0, 738.0); // Next
    shot(&win, "2-welcome-routes", 1280, 800);
    click(&win.w, 873.0, 736.0); // Next
    click(&win.w, 376.0, 384.0); // I accept the Terms of use
    shot(&win, "3-terms", 1280, 800);
    click(&win.w, 815.0, 736.0); // Accept and continue
    wait_until(&win, "sign-in", |w| w.w.get_stage() == 1);
    let page = SignInPage::get(&win.w);
    assert!([page.get_overline(), page.get_title(), page.get_sub()].iter().any(|t| t.contains("Choose your VPN")), "the first run's sign-in");
    assert!(page.get_providers().iter().any(|p| p.name == "NordVPN"));
    shot(&win, "4-sign-in", 1280, 800);
    // Esc in a provider's form, typed in its field: the form's Back takes it and forgets what was typed.
    page.invoke_pick("nord".into());
    shoot(&win.w, 1280, 800, Duration::from_millis(500));
    let field = page.get_form().fields.row_data(0).expect("the form's first field").key;
    page.invoke_field_changed("nord".into(), field, "half a token".into());
    assert!(win.ui.forms.borrow().form.keys().any(|k| k.starts_with("nord:")));
    press(&win.w, Key::Escape);
    wait_until(&win, "the providers again", |w| SignInPage::get(&w.w).get_form().id.is_empty());
    assert!(win.ui.forms.borrow().form.keys().all(|k| !k.starts_with("nord:")));
}

/// Recorded traffic, as the statistics worker writes it: a week of it, each hour, for six apps on three exits.
fn week_of_traffic(s: &Setup) {
    // The stats file, made as the worker makes it: it makes its tables in a file that is there.
    let file = paths::data().unwrap().join("stats.db");
    std::fs::write(&file, "").unwrap();
    stats::read(|w| w.exits());
    let db = rusqlite::Connection::open(&file).expect("the stats file");
    let route = |id: &str| s.routes.iter().find(|r| r.id == id).unwrap();
    for id in ["nl", "us", "it"] {
        let r = route(id);
        db.execute("INSERT OR REPLACE INTO exit VALUES(?,?,?,?,?)", rusqlite::params![stats::id_of(r), r.code(), r.name(), r.hue, r.source()]).unwrap();
    }
    let hour = 3_600_000i64;
    let now = chrono::Utc::now().timestamp_millis();
    let mut hourly: IndexMap<(i64, String), (i64, i64)> = IndexMap::new();
    let mut daily: IndexMap<(i64, String, String), (i64, i64)> = IndexMap::new();
    for h in 0..24 * 7 {
        let at = now - h * hour;
        let quiet = if (1..=6).contains(&((at / hour) % 24)) { 0.1 } else { 1.0 };
        let w = 0.4 + 0.6 * (h as f64 / 4.0).sin().powi(2) * quiet;
        for (app, exit, up, down) in [
            ("firefox", "us", 3e6, 60e6),
            ("spotify", "it", 1e6, 24e6),
            ("chromium", "nl", 2e6, 38e6),
            ("thunderbird", "us", 1e6, 6e6),
            ("discord", "it", 2e6, 9e6),
            ("signal-desktop", "nl", 1e6, 3e6),
        ] {
            let exit = stats::id_of(route(exit));
            let (up, down) = ((up * w) as i64, (down * w) as i64);
            let e = hourly.entry((stats::hour_of(at), exit.clone())).or_default();
            (e.0, e.1) = (e.0 + up, e.1 + down);
            let d = daily.entry((stats::day_of(at), app.to_string(), exit)).or_default();
            (d.0, d.1) = (d.0 + up, d.1 + down);
        }
    }
    for ((h, exit), (up, down)) in hourly {
        db.execute("INSERT INTO hourly VALUES(?,?,?,?)", rusqlite::params![h, exit, up, down]).unwrap();
    }
    for ((d, app, exit), (up, down)) in daily {
        db.execute("INSERT INTO daily VALUES(?,?,?,?,?)", rusqlite::params![d, app, exit, up, down]).unwrap();
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

/// A set-up app: provider routes, an imported WireGuard server, and desktop apps on routes and Direct.
#[test]
fn b_screens_of_a_set_up_app() {
    let _turn = turn(1);
    // As the first flow leaves it, also when it ran in an earlier process.
    ui::tour::accept_terms(true);
    let lab = WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
    edit(|s| {
        s.routes = vec![
            Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
            Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
            Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
            Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
        ];
        s.default_route = "nl".into();
        s.apps = [
            ("firefox", "us"),
            ("spotify", "it"),
            ("org.gnome.Terminal", DIRECT),
            ("org.example.Tool", "us"),
            ("firefox-private", "it"),
            ("thunderbird", "us"),
            ("discord", "it"),
            ("code", DIRECT),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        s.version = VERSION;
        // Here Private Browsing is the one of its group with a route: it leads, and keeps it. In Home both have one: the
        // first keeps it, and the notice names the profile.
        s.profiles = vec![Profile::with_apps("Work", "nl", &[("firefox-private", "it")]), Profile::with_apps("Home", "nl", &[("firefox", "us"), ("firefox-private", "it")])];
    });
    ui::tour::tour_seen();
    // A week of recorded traffic, so Stats and the Apps table's Today column have something to show.
    edit(|s| s.prefs.stats = true);
    week_of_traffic(&app::store().current());
    // Signed in to NordVPN, with its countries, so the location picker lists them (nothing is fetched: the list is new).
    app::store().account("nord", Some("test"));
    app::store().set_countries("nord", &nord_countries());

    let win = open();
    let w = &win.w;
    assert_eq!(2, w.get_stage());
    wait_until(&win, "the default route", |w| unbraid::window::RoutesPage::get(&w.w).get_default_route().name == "Netherlands");
    shot(&win, "5-routes", 1280, 800);

    w.invoke_page_clicked(1); // Apps
    AppsPage::get(w).invoke_show_apps();
    assert_eq!(2, w.get_sheet(), "the installed apps' disclosure first");
    w.invoke_sheet_agreed();
    wait_until(&win, "the apps", |w| w.ui.apps.borrow().iter().any(|a| a.pkg == "spotify"));
    // Two of a group with routes (Firefox's own and its private window's): the first keeps its route, and the other's
    // is said.
    wait_until(&win, "Private Browsing's route to go", |_| !app::store().current().apps.contains_key("firefox-private"));
    let notice = win.ui.notice.borrow().clone().unwrap_or_default();
    assert!(notice.contains("Private Browsing runs as Firefox, so it takes Firefox's route now."), "{notice}");
    assert!(notice.contains("Private Browsing runs as Firefox, so it takes Firefox's route now in Home."), "{notice}");
    win.ui.notice.send_replace(None);
    let profile = |name: &str| app::store().current().profiles.into_iter().find(|p| p.name == name).unwrap().apps;
    assert_eq!(IndexMap::from([("firefox-private".to_string(), "it".to_string())]), profile("Work"));
    assert_eq!(IndexMap::from([("firefox".to_string(), "us".to_string())]), profile("Home"));
    shot(&win, "6-apps", 1280, 800);

    // An app that runs as a script loses the route it could never take, and its panel says it follows the default.
    wait_until(&win, "Tool's route to go", |_| !app::store().current().apps.contains_key("org.example.Tool"));
    AppsPage::get(w).invoke_select("org.example.Tool".into());
    assert!(AppsPage::get(w).get_detail().leader_note.contains("Follows the default route") || AppsPage::get(w).get_detail().default_only);
    // A new entry for Firefox's program, whose label sorts first, doesn't take Firefox's route: it takes the route too.
    let entries = folders().join("home/applications");
    std::fs::write(entries.join("alacarte-made-1.desktop"), format!("[Desktop Entry]\nType=Application\nName=Browser\nExec={}\n", programs().join("firefox/firefox").display())).unwrap();
    win.ui.refresh_apps();
    wait_until(&win, "Browser", |w| w.ui.apps.borrow().iter().any(|a| a.pkg == "alacarte-made-1"));
    assert_eq!(Some("us"), app::store().current().apps.get("firefox").map(String::as_str));
    assert_eq!(IndexMap::from([("firefox-private".to_string(), "it".to_string())]), profile("Work"));
    AppsPage::get(w).invoke_select("alacarte-made-1".into());
    assert!(AppsPage::get(w).get_detail().leader_note.contains("Takes Firefox's route"), "{:?}", AppsPage::get(w).get_detail().leader_note);
    // So does one that runs as another app and has no route of its own here.
    AppsPage::get(w).invoke_select("firefox-private".into());
    assert!(AppsPage::get(w).get_detail().leader_note.contains("Takes Firefox's route"));
    shot(&win, "6-apps-runs-as-another", 1280, 800);
    // A right click offers the routes at once.
    AppsPage::get(w).invoke_select("spotify".into());
    shoot(w, 1280, 800, Duration::from_millis(200));
    click_with(w, 598.0, 747.0, PointerEventButton::Right);
    shot(&win, "6-apps-menu", 1280, 800);
    press(w, Key::Escape);
    AppsPage::get(w).invoke_assign("spotify".into(), "us".into());
    assert_eq!(Some("us"), app::store().current().apps.get("spotify").map(String::as_str));
    AppsPage::get(w).invoke_assign("spotify".into(), "it".into());
    assert_eq!(Some("it"), app::store().current().apps.get("spotify").map(String::as_str));
    // A program the launcher doesn't list is added by its file (the chooser is the desktop's own), keyed by its real
    // path.
    let rt = runtime();
    let canonical = std::fs::canonicalize("/bin/true").unwrap().to_string_lossy().into_owned();
    assert_eq!(Some(canonical), rt.block_on(win.ui.add_program("/bin/true".into())));
    assert_eq!(None, rt.block_on(win.ui.add_program(paths::data().unwrap().join("unbraid_ui.properties"))));
    // A script runs as its interpreter, an AppImage from a mount of its own: neither can have a route of its own.
    let script = paths::data().unwrap().join("tool.sh");
    std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
    executable(&script);
    assert_eq!(None, rt.block_on(win.ui.add_program(script)));
    let app_image = paths::data().unwrap().join("App.AppImage");
    std::fs::write(&app_image, [0x7f, 69, 76, 70, 2, 1, 1, 0, 65, 73, 2, 0]).unwrap();
    executable(&app_image);
    assert_eq!(None, rt.block_on(win.ui.add_program(app_image)));
    assert!(win.ui.notice.borrow().as_deref().is_some_and(|n| n.contains("AppImage")));
    // A program an app runs takes that app's route: it can't have one of its own.
    assert_eq!(None, rt.block_on(win.ui.add_program(programs().join("spotify/spotify"))));
    assert!(win.ui.notice.borrow().as_deref().is_some_and(|n| n.contains("part of Spotify")));
    win.ui.notice.send_replace(None); // the refusal's notice, which would show on the next screens

    w.invoke_page_clicked(2); // Stats
    wait_until(&win, "the hub", |w| StatsPage::get(&w.w).get_loaded() && StatsPage::get(&w.w).get_hub().apps.row_count() > 0);
    shot(&win, "7-stats", 1280, 800);
    // A tile opens its section, at a reading width; Back returns to the overview.
    StatsPage::get(w).invoke_go("usage".into());
    wait_until(&win, "usage", |w| StatsPage::get(&w.w).get_section() == "usage");
    shot(&win, "7-stats-usage", 1280, 800);
    StatsPage::get(w).invoke_go("".into());
    w.invoke_page_clicked(3); // Settings
    shot(&win, "8-settings", 1280, 800);
    // Settings › Desktop: login, the tray, the window and the theme. Light turns the whole window at once.
    SettingsPage::get(w).invoke_pick("desktop".into());
    shot(&win, "8-settings-desktop", 1280, 800);
    SettingsPage::get(w).invoke_set_theme("Light".into());
    assert_eq!(Theme::Light, *ds::theme().borrow());
    wait_until(&win, "light", |w| Ink::get(&w.w).get_light());
    shot(&win, "8-settings-desktop-light", 1280, 800);
    w.invoke_page_clicked(1);
    shot(&win, "6-apps-light", 1280, 800);
    w.invoke_page_clicked(0);
    shot(&win, "5-routes-light", 1280, 800);
    w.invoke_page_clicked(3);
    SettingsPage::get(w).invoke_set_theme("Dark".into());
    wait_until(&win, "dark", |w| !Ink::get(&w.w).get_light());

    // The window's keys: the pages, search, and the list of every shortcut (Esc closes it).
    ctrl(w, "2");
    assert_eq!(1, w.get_tab());
    ctrl(w, ",");
    assert_eq!(3, w.get_tab());
    ctrl(w, "f");
    assert_eq!(1, w.get_tab());
    wait_until(&win, "the search to take it", |w| !w.w.get_search_wanted());
    ctrl(w, "/");
    assert!(w.get_shortcuts());
    shot(&win, "shortcuts", 1280, 800);
    // Esc: the window's keys leave it, so it goes to the list on top.
    press(w, Key::Escape);
    wait_until(&win, "the shortcuts to close", |w| !w.w.get_shortcuts());
    ctrl(w, "z");
    assert_eq!(1, w.get_tab(), "a key that isn't a shortcut");
    w.invoke_page_clicked(3);
    // A new route (Ctrl+N): the location picker, a dialog over the page; a country's cities open beside the list.
    ctrl(w, "n");
    assert!(w.get_picker(), "the location picker");
    shot(&win, "10-picker", 1280, 800);
    PickerPage::get(w).invoke_toggle_all();
    let germany = PickerPage::get(w).get_rows().iter().find(|r| r.title == "Germany").expect("Germany listed").key;
    PickerPage::get(w).invoke_open_country(germany);
    wait_until(&win, "Germany's cities", |w| PickerPage::get(&w.w).get_country().contains("Germany"));
    shot(&win, "10-picker-country", 1280, 800);
    // Esc in the picker, where its focus stays: it closes the dialog, never the Settings page behind it.
    press(w, Key::Escape);
    wait_until(&win, "the picker to close", |w| !w.w.get_picker());
    assert_eq!(3, w.get_tab());
    // Add provider, from the picker: Esc in a provider's form steps back to the list and forgets what was typed; on
    // the list, Esc closes Add provider.
    ctrl(w, "n");
    assert!(w.get_picker());
    PickerPage::get(w).invoke_add_provider();
    assert_eq!(3, w.get_stage(), "Add provider beside the sidebar");
    let page = SignInPage::get(w);
    shot(&win, "add-provider", 1280, 800);
    assert!(page.get_providers().iter().any(|p| p.id == "mullvad"));
    page.invoke_pick("mullvad".into());
    shoot(w, 1280, 800, Duration::from_millis(500));
    let field = page.get_form().fields.row_data(0).expect("Mullvad's field").key;
    page.invoke_field_changed("mullvad".into(), field, "1234".into());
    assert!(win.ui.forms.borrow().form.keys().any(|k| k.starts_with("mullvad:")));
    press(w, Key::Escape);
    wait_until(&win, "the providers again", |w| SignInPage::get(&w.w).get_form().id.is_empty());
    assert!(win.ui.forms.borrow().form.keys().all(|k| !k.starts_with("mullvad:")));
    press(w, Key::Escape);
    wait_until(&win, "Add provider to close", |w| w.w.get_stage() == 2);
    assert_eq!(3, w.get_tab());

    w.invoke_page_clicked(0);
    // Routes with the apps known: their names, and the default's share.
    wait_until(&win, "the apps' names", |w| {
        unbraid::window::RoutesPage::get(&w.w).get_exceptions().iter().any(|c| c.apps_label.contains("Thunderbird"))
    });
    shot(&win, "5-routes-set-up", 1280, 800);
    // A right click on a route offers what its sheet does.
    click_with(w, 568.0, 399.0, PointerEventButton::Right);
    shot(&win, "9-route-menu", 1280, 800);
    press(w, Key::Escape); // Esc closes the menu
    shoot(w, 1280, 800, Duration::from_millis(500));
    click(w, 568.0, 399.0);
    shot(&win, "9-route-sheet", 1280, 800);
    press(w, Key::Escape);
    shoot(w, 1280, 800, Duration::from_millis(500));
    // Removing a route takes it from the saved profiles that list it too: the menu says which, as the sheet does.
    let us = unbraid::window::RoutesPage::get(w).get_exceptions().iter().find(|c| c.id == "us").expect("the US route");
    assert!(us.menu.iter().any(|a| a.text == "Remove route, also from Home"), "{:?}", us.menu.iter().map(|a| a.text).collect::<Vec<_>>());
}

/// The smallest window: the sidebar folds to a rail of icons whose names show on hover; the pages keep their layout.
#[test]
fn c_smallest_window() {
    let _turn = turn(2);
    let win = open();
    win.set_tab(window::ROUTES);
    win.refresh();
    // Once the apps are read (the window reads them when it shows), so the shot doesn't depend on when they come.
    wait_until(&win, "the apps' names", |w| {
        unbraid::window::RoutesPage::get(&w.w).get_exceptions().iter().any(|c| c.apps_label.contains("Thunderbird"))
    });
    let px = shot(&win, "11-smallest-window", 880, 600);
    // The rail: 72 px of the sidebar's ground, then its edge.
    let bar = if Ink::get(&win.w).get_light() { [0xed, 0xe8, 0xe2] } else { [0x13, 0x17, 0x1a] };
    assert_eq!(bar, at(&px, 880, 60, 590), "the folded sidebar");
    assert_ne!(bar, at(&px, 880, 200, 590), "no wide sidebar");
}

/// The tray's profile switch (the set-up app's profiles): one that waits on the window opens it, an empty profile to be
/// given a default route and a provider's limit, whose question only the window shows. One that completes doesn't.
#[test]
fn d_tray_profile_switch() {
    let _turn = turn(3);
    let win = open();
    let ui = &win.ui;
    edit(|s| {
        s.profiles.extend([Profile::new("Travel", ""), Profile::new("Solo", "nl")]);
        s.opts.insert("nord".into(), IndexMap::from([(LIMIT_OPT.to_string(), "1".to_string())]));
    });
    assert!(ui.use_profile_outside("Travel"));
    assert_eq!(Some("Travel"), ui.viewing.borrow().as_deref());
    ui.view(None);
    ui.use_profile("Solo"); // NordVPN: the Netherlands only, within 1
    assert_eq!(Some("Solo"), app::store().current().profile.as_deref());
    assert!(ui.use_profile_outside("Home"));
    assert!(ui.limit_ask.borrow().is_some()); // and the United States: over 1
    ui.limit_ask.send_replace(None);
    edit(|s| {
        s.opts.insert("nord".into(), IndexMap::from([(LIMIT_OPT.to_string(), "10".to_string())]));
    });
    assert!(!ui.use_profile_outside("Home"));
    assert!(ui.limit_ask.borrow().is_none());
    assert_eq!(Some("Home"), app::store().current().profile.as_deref());
    // From the tray's menu: a switch that waits on the window shows it, on Routes.
    win.set_tab(window::SETTINGS);
    window::tray_action(tray::Action::Profile("Travel".into()));
    wait_until(&win, "Routes, for Travel", |w| w.w.get_tab() == 0 && w.ui.viewing.borrow().as_deref() == Some("Travel"));
    win.ui.view(None);
    // The tour from Settings › About: each stop on its page, its spot on what it is about.
    SettingsPage::get(&win.w).invoke_tour();
    assert!(win.w.get_touring());
    let px = shot(&win, "tour-power", 1280, 800);
    let scrim = at(&px, 1280, 600, 700);
    assert_ne!(scrim, at(&px, 1280, 1177, 187), "the power button, not dimmed");
    unbraid::window::TourPage::get(&win.w).invoke_next();
    unbraid::window::TourPage::get(&win.w).invoke_next();
    unbraid::window::TourPage::get(&win.w).invoke_next();
    unbraid::window::TourPage::get(&win.w).invoke_next();
    unbraid::window::TourPage::get(&win.w).invoke_next();
    assert_eq!(3, win.w.get_tab(), "Connections is in Settings");
    shot(&win, "tour-connections", 1280, 800);
    unbraid::window::TourPage::get(&win.w).invoke_close();
    assert!(!win.w.get_touring());
    assert_eq!(0, win.w.get_tab(), "the tour ends on Routes");
}
