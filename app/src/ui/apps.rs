//! The Apps page: which apps go out through which route. The installed apps as a table (search, filter by exit, sort
//! by any column); the selected app's route choices in the panel beside it, and in its menu at a right click.

use crate::ui::stats::bytes_text;
use std::cmp::Reverse;
use std::collections::HashMap;

use crate::APP;
use crate::model::{DIRECT, Prefs, Route, Setup, take_graphemes};

/// An app the Apps page lists, by `pkg`: the key the setup routes it by (a desktop entry's id, or a program's path).
/// `routable`: the engine can tell its traffic apart (not a script, an interpreter or an AppImage,
/// [`crate::apps::unroutable`]). `group`: the apps it runs as one program with, itself included, in the order that
/// picks which leads (LibreOffice's Writer and Calc, a browser and its web apps); empty for an app on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppInfo {
    pub pkg: String,
    pub label: String,
    pub system: bool,
    pub routable: bool,
    pub group: Vec<String>,
    /// "App", "Flatpak", "Snap", or "Program" for one added by its file.
    pub kind: &'static str,
}

impl AppInfo {
    /// An app on its own, routable, of kind "App".
    pub fn new(pkg: &str, label: &str) -> Self {
        AppInfo { pkg: pkg.into(), label: label.into(), system: false, routable: true, group: vec![], kind: "App" }
    }

    /// The app whose route this one takes in `s`: the first of its group with a route there, when that isn't itself.
    pub fn follows(&self, s: &Setup) -> Option<&str> {
        self.group.iter().find(|k| s.apps.contains_key(k.as_str())).filter(|k| **k != self.pkg).map(String::as_str)
    }
}

/// The column the table sorts by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sort {
    #[default]
    Name,
    Kind,
    Route,
    Today,
}

impl Sort {
    /// The columns in their order: a head's index is its column.
    pub const ALL: [Sort; 4] = [Sort::Name, Sort::Kind, Sort::Route, Sort::Today];

    fn label(self) -> &'static str {
        match self {
            Sort::Name => "Name",
            Sort::Kind => "Kind",
            Sort::Route => "Route",
            Sort::Today => "Today",
        }
    }
}

/// What the page keeps while it shows: the search, the exit filter, whether system apps show, the order and the
/// selected app.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub query: String,
    /// The exit the table is narrowed to: a route's id, [`DIRECT`], or "" for apps without one yet; none for all.
    pub filter: Option<String>,
    pub system: bool,
    pub sort: Sort,
    /// The other way round.
    pub down: bool,
    pub selected: Option<String>,
}

impl Table {
    /// A column head: sorts by it, or the other way round when it already does.
    pub fn sort_by(&mut self, s: Sort) {
        if s == self.sort {
            self.down = !self.down;
        } else {
            self.sort = s;
            self.down = false;
        }
    }

    /// The arrow keys walk the table, as in any desktop list: `by` rows on from the selected one, or the first.
    pub fn step(&mut self, rows: &[AppRow], by: i32) {
        let at = rows.iter().position(|r| self.selected.as_deref() == Some(r.key.as_str()));
        let i = at.map_or(0, |at| (at as i32 + by).clamp(0, rows.len() as i32 - 1) as usize);
        if let Some(r) = rows.get(i) {
            self.selected = Some(r.key.clone());
        }
    }

    /// Another profile shown: a filter by the last one's exits starts over; the search stays.
    pub fn viewed(&mut self) {
        self.filter = None;
    }

    /// The page's own entry clicked again: the selection and the filter go; with neither, true, and the table goes
    /// back to its top.
    pub fn reselected(&mut self) -> bool {
        if self.selected.is_none() && self.filter.is_none() {
            return true;
        }
        self.selected = None;
        self.filter = None;
        false
    }

    /// A program just added: shown and selected, whatever the search and the filter would leave out.
    pub fn added(&mut self, key: &str) {
        self.query.clear();
        self.filter = None;
        self.selected = Some(key.into());
    }
}

/// An exit filter: a route's chip (a dot in its colour), "Not set" (no dot) or Direct (its glyph).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitChip {
    /// What the filter becomes: a route's id, "" for apps without an exit, or [`DIRECT`].
    pub id: String,
    pub label: String,
    /// The route's colour; -1 for none.
    pub hue: i32,
    pub direct: bool,
    pub on: bool,
}

/// A column head: its words with the order's arrow, what a click on it does, and whether the table sorts by it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColumnHead {
    pub text: String,
    pub label: String,
    pub on: bool,
}

/// A row of the table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppRow {
    pub key: String,
    pub label: String,
    /// The initial its icon shows without a picture.
    pub letter: String,
    pub kind: String,
    /// "Not set", in place of the route's mark, while the app has no exit (an empty profile's default); "" otherwise.
    pub unset: String,
    /// The route it goes out through, as its mark: the code, the colour (-1: Direct's), filled for the app's own
    /// choice and outlined when it follows the default or another app, Direct's glyph.
    pub code: String,
    pub hue: i32,
    pub filled: bool,
    pub direct: bool,
    /// Beside the mark: "Runs as Firefox", "Default only", or "".
    pub note: String,
    /// Today's data, "—" for none; "" while statistics are off.
    pub today: String,
}

/// A route the selected app can take: a tile in the panel, a row of its menu.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteChoice {
    /// The route's id, or [`DIRECT`].
    pub id: String,
    pub name: String,
    /// The tile's second line: "Default · Nord", the city or who carries it; "No VPN" for Direct.
    pub sub: String,
    /// The menu's words: the name, with "(default)" after the default route's.
    pub menu: String,
    pub code: String,
    /// The route's colour; -1 for Direct.
    pub hue: i32,
    pub direct: bool,
    /// The app goes out through it now.
    pub on: bool,
}

/// An app that runs as the selected one, and so takes its route.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AlsoRow {
    pub key: String,
    pub label: String,
    pub letter: String,
    /// "runs as Spotify".
    pub note: String,
}

/// The selected app, in the panel beside the table and in its right-click menu. `key` is "" with none selected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppDetail {
    pub key: String,
    pub label: String,
    pub letter: String,
    /// The program it runs, else its key.
    pub program: String,
    /// What Copy program path copies: the program, "" when it isn't known.
    pub copy: String,
    /// The app it runs as, whose route it takes ("" when it can have its own), and what the panel and the menu say.
    pub leader: String,
    pub leader_note: String,
    pub leader_menu: String,
    pub show_leader: String,
    /// It can only follow the default route: the engine can't tell its traffic apart.
    pub default_only: bool,
    /// The routes it can take, the default's first, then Direct; none when it can't have its own.
    pub choices: Vec<RouteChoice>,
    /// The apps that take its route.
    pub also: Vec<AlsoRow>,
    /// The switch for a Direct app's lookups, offered while unbraid's filter is set: its line, and its state.
    pub lookups: bool,
    pub lookups_sub: String,
    pub lookups_on: bool,
    /// It has a route of its own, so Use the default route is offered.
    pub own: bool,
    /// Today's data and where it went; "" while statistics are off.
    pub today: String,
}

/// What the Apps page shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppsView {
    /// The overline: "14 installed · 4 routed · 2 direct".
    pub counts: String,
    /// The installed apps may be read. Until then the page asks, and lists nothing.
    pub disclosed: bool,
    /// While a profile not in use is shown: which, and which is ("" otherwise).
    pub editing: String,
    /// What the shown profile needs before it can be used ("" for nothing).
    pub editing_hint: String,
    /// The buttons under it: back to the profile in use, and Use the shown one ("" while it can't be used).
    pub back_label: String,
    pub use_label: String,
    pub query: String,
    /// The filters: All, the exits' chips, System.
    pub all: bool,
    pub chips: Vec<ExitChip>,
    pub system: bool,
    pub heads: Vec<ColumnHead>,
    /// Statistics are recorded: the Today column, and today's data in the panel.
    pub stats: bool,
    pub rows: Vec<AppRow>,
    pub selected: String,
    /// The selected app's row, -1 when it has none.
    pub selected_index: i32,
    pub detail: AppDetail,
}

/// The page: `apps` as `setup` routes them (the profile shown, `viewing`, or the one in use for none), each app's data
/// `today` while statistics are recorded, and the page's own `table`. `program_of` names the program an app runs
/// ([`crate::apps::program_of`]).
pub fn view(
    apps: &[AppInfo],
    setup: &Setup,
    viewing: Option<&str>,
    disclosed: bool,
    today: &HashMap<String, i64>,
    table: &Table,
    program_of: impl Fn(&str) -> Option<String>,
) -> AppsView {
    let stats = setup.prefs.stats;
    let draft = viewing.is_some() && viewing != setup.profile.as_deref();
    let place = |a: &AppInfo| setup.route_of(a.follows(setup).unwrap_or(&a.pkg));
    let name_of = |id: &str| {
        setup.route(Some(id)).map_or_else(|| if id == DIRECT { "Direct".into() } else { String::new() }, Route::name)
    };
    let label_of = |key: &str| apps.iter().find(|a| a.pkg == key).map_or(key, |a| a.label.as_str()).to_string();
    let direct = apps.iter().filter(|a| setup.apps.get(&a.pkg).is_some_and(|r| r == DIRECT)).count();
    let routed = apps.iter().filter(|a| setup.apps.contains_key(&a.pkg)).count() - direct;

    let (editing, editing_hint, back_label, use_label) = match viewing.filter(|_| draft) {
        Some(v) => (
            format!(
                "Editing {v} · not in use. {}",
                setup.profile.as_ref().map_or_else(|| "No profile is in use.".into(), |p| format!("{p} is in use."))
            ),
            if setup.default_route.is_empty() { "Choose a default route on Routes".into() } else { String::new() },
            format!("Back to {}", setup.profile.as_deref().unwrap_or("current setup")),
            if setup.default_route.is_empty() { String::new() } else { format!("Use {v}") },
        ),
        None => Default::default(),
    };

    let filter = table.filter.as_deref();
    let mut chips: Vec<ExitChip> = setup
        .routes
        .iter()
        .map(|r| {
            let code = r.code();
            // Two routes with one country code (NordVPN NL, Mullvad NL) are told apart by provider.
            let label = if setup.routes.iter().filter(|o| o.code() == code).count() > 1 {
                format!("{code} · {}", r.source())
            } else {
                code
            };
            ExitChip { id: r.id.clone(), label, hue: r.hue, direct: false, on: filter == Some(r.id.as_str()) }
        })
        .collect();
    if setup.default_route.is_empty() {
        chips.push(ExitChip {
            id: String::new(),
            label: "Not set".into(),
            hue: -1,
            direct: false,
            on: filter == Some(""),
        });
    }
    chips.push(ExitChip {
        id: DIRECT.into(),
        label: "Direct".into(),
        hue: -1,
        direct: true,
        on: filter == Some(DIRECT),
    });

    let heads = Sort::ALL
        .into_iter()
        .filter(|s| stats || *s != Sort::Today)
        .map(|s| {
            let on = s == table.sort;
            let arrow = match (on, table.down) {
                (false, _) => "",
                (true, false) => " ▲",
                (true, true) => " ▼",
            };
            ColumnHead {
                text: format!("{}{arrow}", s.label().to_uppercase()),
                label: format!("Sort by {}", s.label()),
                on,
            }
        })
        .collect();

    let query = table.query.trim().to_lowercase();
    let shown: Vec<&AppInfo> = apps
        .iter()
        .filter(|a| {
            (table.system || !a.system || setup.apps.contains_key(&a.pkg))
                && filter.is_none_or(|f| place(a) == f)
                && (query.is_empty()
                    || a.label.to_lowercase().contains(&query)
                    || a.pkg.to_lowercase().contains(&query))
        })
        .collect();
    let keys: Vec<_> = shown
        .iter()
        .map(|a| {
            let label = a.label.to_lowercase();
            match table.sort {
                Sort::Name => (String::new(), Reverse(0), label),
                Sort::Kind => (a.kind.to_string(), Reverse(0), label),
                Sort::Route => (name_of(&place(a)).to_lowercase(), Reverse(0), label),
                Sort::Today => (String::new(), Reverse(today.get(&a.pkg).copied().unwrap_or(0)), label),
            }
        })
        .collect();
    let mut order: Vec<usize> = (0..shown.len()).collect();
    // Stable either way round: apps alike keep the list's order.
    order.sort_by(|&i, &j| if table.down { keys[j].cmp(&keys[i]) } else { keys[i].cmp(&keys[j]) });

    let rows: Vec<AppRow> = order
        .into_iter()
        .map(|i| {
            let a = shown[i];
            let follows = a.follows(setup);
            let current = setup.route_of(follows.unwrap_or(&a.pkg));
            let route = setup.route(Some(&current));
            // An empty profile has no default route yet: its unassigned apps have no exit.
            let unset = if current.is_empty() { "Not set".into() } else { String::new() };
            // An app that runs as another takes that one's route; one that can't be told apart only the default.
            let note = match follows {
                Some(o) => format!("Runs as {}", label_of(o)),
                None if !a.routable => "Default only".into(),
                None => String::new(),
            };
            AppRow {
                key: a.pkg.clone(),
                label: a.label.clone(),
                letter: letter(&a.label),
                kind: a.kind.into(),
                unset,
                code: route.map_or_else(|| "··".into(), Route::code),
                hue: route.map_or(-1, |r| r.hue),
                filled: setup.apps.contains_key(&a.pkg),
                direct: current == DIRECT,
                note,
                today: if stats {
                    today.get(&a.pkg).map_or_else(|| "—".into(), |b| bytes_text(*b))
                } else {
                    String::new()
                },
            }
        })
        .collect();

    let selected = table.selected.clone().unwrap_or_default();
    let selected_index = rows.iter().position(|r| r.key == selected).map_or(-1, |i| i as i32);
    let detail = apps.iter().find(|a| a.pkg == selected).map(|a| {
        let follows = a.follows(setup);
        let explicit = setup.apps.get(&a.pkg);
        let current = setup.route_of(follows.unwrap_or(&a.pkg));
        let program = program_of(&a.pkg);
        let own_route = follows.is_none() && a.routable;
        let mut d = AppDetail {
            key: a.pkg.clone(),
            label: a.label.clone(),
            letter: letter(&a.label),
            program: program.clone().unwrap_or_else(|| a.pkg.clone()),
            copy: program.unwrap_or_default(),
            default_only: follows.is_none() && !a.routable,
            today: match today.get(&a.pkg) {
                _ if !stats => String::new(),
                Some(b) => {
                    let to = setup.route(Some(&current)).map_or_else(
                        || if current == DIRECT { "your own connection".into() } else { "the default route".into() },
                        Route::name,
                    );
                    format!("{} through {to}", bytes_text(*b))
                }
                None => "No traffic yet today".into(),
            },
            ..AppDetail::default()
        };
        if let Some(o) = follows.map(label_of) {
            d.leader = follows.unwrap_or_default().into();
            d.leader_note = format!("Takes {o}'s route: it runs as {o}, and {APP} can't tell their traffic apart.");
            d.leader_menu = format!("Takes {o}'s route");
            d.show_leader = format!("Show {o}");
        }
        if own_route {
            let mut tiles: Vec<&Route> = setup.routes.iter().collect();
            tiles.sort_by_key(|r| r.id != setup.default_route);
            d.choices = tiles
                .into_iter()
                .map(|r| {
                    let default = r.id == setup.default_route;
                    RouteChoice {
                        id: r.id.clone(),
                        name: r.name(),
                        sub: if default {
                            format!("Default · {}", r.source())
                        } else {
                            r.loc.city.clone().unwrap_or_else(|| r.source())
                        },
                        menu: if default { format!("{} (default)", r.name()) } else { r.name() },
                        code: r.code(),
                        hue: r.hue,
                        direct: false,
                        on: current == r.id,
                    }
                })
                .collect();
            d.choices.push(RouteChoice {
                id: DIRECT.into(),
                name: "Direct".into(),
                sub: "No VPN".into(),
                menu: "Direct".into(),
                code: String::new(),
                hue: -1,
                direct: true,
                on: current == DIRECT,
            });
            d.also = apps
                .iter()
                .filter(|f| f.follows(setup) == Some(a.pkg.as_str()))
                .map(|f| AlsoRow {
                    key: f.pkg.clone(),
                    label: f.label.clone(),
                    letter: letter(&f.label),
                    note: format!("runs as {}", a.label),
                })
                .collect();
            // A Direct app's lookups: outside unbraid (the computer's DNS) or through it, with unbraid's filter. A setting of
            // every profile, so not offered while editing a profile not in use.
            let f = &setup.prefs.filter;
            if let Some(server) = f.server().filter(|_| explicit.is_some_and(|r| r == DIRECT) && !draft) {
                d.lookups = true;
                d.lookups_on = f.through(&a.pkg);
                d.lookups_sub = if d.lookups_on {
                    format!("Through {APP}, with {}. The app can see a VPN is on", server.name)
                } else {
                    format!("Outside {APP}, with the computer's DNS")
                };
            }
            d.own = explicit.is_some();
        }
        d
    });

    AppsView {
        counts: format!("{} installed · {routed} routed · {direct} direct", apps.len()),
        disclosed,
        editing,
        editing_hint,
        back_label,
        use_label,
        query: table.query.clone(),
        all: filter.is_none(),
        chips,
        system: table.system,
        heads,
        stats,
        rows,
        selected,
        selected_index,
        detail: detail.unwrap_or_default(),
    }
}

/// The switch of a Direct app's lookups: its filtering flips, and a choice equal to every Direct app's is dropped.
pub fn filter_lookups(p: &Prefs, pkg: &str) -> Prefs {
    let on = p.filter.through(pkg);
    let mut f = p.filter.clone();
    if !on == f.direct_apps {
        f.apps.shift_remove(pkg);
    } else {
        f.apps.insert(pkg.into(), !on);
    }
    Prefs { filter: f, ..p.clone() }
}

/// The initial an app's icon shows without a picture.
fn letter(label: &str) -> String {
    take_graphemes(label, 1).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Filter, Location, Profile, WgPeer};

    const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

    fn app(pkg: &str, label: &str) -> AppInfo {
        AppInfo::new(pkg, label)
    }

    fn in_group(pkg: &str, label: &str, group: &[&str]) -> AppInfo {
        AppInfo { group: group.iter().map(|g| g.to_string()).collect(), ..app(pkg, label) }
    }

    /// The set-up app the approved screenshots show: provider routes, a WireGuard server, desktop apps on routes and
    /// Direct, after the list was read (Private Browsing's and Tool's routes went: one runs as Firefox, one is a script).
    fn setup() -> Setup {
        let lab = WgPeer::new(
            "Home lab",
            KEY,
            vec!["10.8.0.2/32".into()],
            KEY,
            "203.0.113.7:51820",
            vec!["0.0.0.0/0".into()],
        );
        let route = |id: &str, loc: Location, hue: i32| Route { hue, ..Route::new(id, loc) };
        let mut s = Setup {
            routes: vec![
                route("nl", Location::country("nord", 153, "NL", "Netherlands"), 0),
                route("us", Location::country("nord", 228, "US", "United States"), 1),
                route("it", Location::country("nord", 106, "IT", "Italy"), 2),
                Route { wg: Some(lab), ..route("lab", Location::default(), 3) },
            ],
            default_route: "nl".into(),
            profiles: vec![
                Profile::with_apps("Work", "nl", &[("firefox-private", "it")]),
                Profile::with_apps("Home", "nl", &[("firefox", "us")]),
            ],
            ..Setup::default()
        };
        for (k, v) in [
            ("firefox", "us"),
            ("spotify", "it"),
            ("org.gnome.Terminal", DIRECT),
            ("thunderbird", "us"),
            ("discord", "it"),
            ("code", DIRECT),
        ] {
            s.apps.insert(k.into(), v.into());
        }
        s.prefs.stats = true;
        s
    }

    fn apps() -> Vec<AppInfo> {
        let firefox = ["alacarte-made-1", "firefox", "firefox-private"];
        let office = ["libreoffice-startcenter", "libreoffice-writer"];
        vec![
            in_group("alacarte-made-1", "Browser", &firefox),
            app("chromium", "Chromium"),
            app("discord", "Discord"),
            in_group("firefox", "Firefox", &firefox),
            app("org.gimp.GIMP", "GIMP"),
            in_group("libreoffice-startcenter", "LibreOffice", &office),
            in_group("libreoffice-writer", "LibreOffice Writer", &office),
            in_group("firefox-private", "Private Browsing", &firefox),
            app("signal-desktop", "Signal"),
            app("spotify", "Spotify"),
            AppInfo { routable: false, ..app("steam", "Steam") },
            app("org.gnome.Terminal", "Terminal"),
            app("thunderbird", "Thunderbird"),
            AppInfo { routable: false, ..app("org.example.Tool", "Tool") },
            app("code", "Visual Studio Code"),
        ]
    }

    fn today() -> HashMap<String, i64> {
        [
            ("chromium", 16_000_000),
            ("discord", 4_000_000),
            ("firefox", 25_000_000),
            ("signal-desktop", 2_000_000),
            ("spotify", 10_000_000),
            ("thunderbird", 6_000_000),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    fn program(key: &str) -> Option<String> {
        Some(format!("/tmp/unbraid-ui-test/opt/{key}/{key}"))
    }

    fn page(table: &Table) -> AppsView {
        view(&apps(), &setup(), None, true, &today(), table, program)
    }

    fn selected(key: &str) -> Table {
        Table { selected: Some(key.into()), ..Table::default() }
    }

    fn row<'a>(v: &'a AppsView, key: &str) -> &'a AppRow {
        v.rows.iter().find(|r| r.key == key).unwrap()
    }

    fn keys(v: &AppsView) -> Vec<&str> {
        v.rows.iter().map(|r| r.key.as_str()).collect()
    }

    /// The first of a group with a route leads it; the others take its route, the leader keeps its own.
    #[test]
    fn the_first_routed_app_of_a_group_leads() {
        let s = setup();
        let firefox = &apps()[3];
        let private = &apps()[7];
        assert_eq!(None, firefox.follows(&s));
        assert_eq!(Some("firefox"), private.follows(&s));
        assert_eq!(Some("firefox"), apps()[0].follows(&s), "Browser sorts first in the group, but has no route");
        let work = s.use_profile("Work");
        assert_eq!(None, private.follows(&work), "in Work only Private Browsing has a route: it leads");
        assert_eq!(Some("firefox-private"), firefox.follows(&work));
        assert_eq!(None, apps()[5].follows(&s), "a group without a route has no leader");
        assert_eq!(None, app("chromium", "Chromium").follows(&s));
    }

    /// The table as the approved screenshot has it: every installed app by name, its route's mark and today's data.
    #[test]
    fn the_table_lists_every_app_with_its_route() {
        let v = page(&Table::default());
        assert_eq!("15 installed · 4 routed · 2 direct", v.counts);
        assert_eq!(
            vec![
                "alacarte-made-1",
                "chromium",
                "discord",
                "firefox",
                "org.gimp.GIMP",
                "libreoffice-startcenter",
                "libreoffice-writer",
                "firefox-private",
                "signal-desktop",
                "spotify",
                "steam",
                "org.gnome.Terminal",
                "thunderbird",
                "org.example.Tool",
                "code"
            ],
            keys(&v)
        );
        let firefox = row(&v, "firefox");
        assert_eq!(
            ("US", 1, true, false, "", "25 MB"),
            (
                firefox.code.as_str(),
                firefox.hue,
                firefox.filled,
                firefox.direct,
                firefox.note.as_str(),
                firefox.today.as_str()
            )
        );
        let private = row(&v, "firefox-private");
        assert_eq!(
            ("US", false, "Runs as Firefox", "—"),
            (private.code.as_str(), private.filled, private.note.as_str(), private.today.as_str())
        );
        assert_eq!("Runs as Firefox", row(&v, "alacarte-made-1").note);
        let steam = row(&v, "steam");
        assert_eq!(
            ("NL", 0, false, "Default only"),
            (steam.code.as_str(), steam.hue, steam.filled, steam.note.as_str())
        );
        assert_eq!("Default only", row(&v, "org.example.Tool").note);
        let terminal = row(&v, "org.gnome.Terminal");
        assert_eq!(("··", -1, true, true), (terminal.code.as_str(), terminal.hue, terminal.filled, terminal.direct));
        let writer = row(&v, "libreoffice-writer");
        assert_eq!(
            ("NL", false, ""),
            (writer.code.as_str(), writer.filled, writer.note.as_str()),
            "a group with no route: the default, no note"
        );
        assert_eq!(
            ("C", "App", ""),
            (
                row(&v, "chromium").letter.as_str(),
                row(&v, "chromium").kind.as_str(),
                row(&v, "chromium").unset.as_str()
            )
        );
        assert_eq!(
            vec!["NAME ▲", "KIND", "ROUTE", "TODAY"],
            v.heads.iter().map(|h| h.text.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(("Sort by Name", true), (v.heads[0].label.as_str(), v.heads[0].on));
        assert!(v.all && !v.system && v.disclosed && v.stats);
        assert_eq!(
            vec!["NL", "US", "IT", "WG", "Direct"],
            v.chips.iter().map(|c| c.label.as_str()).collect::<Vec<_>>()
        );
        assert_eq!((3, true), (v.chips[3].hue, v.chips[4].direct));
        assert_eq!(("", -1, ""), (v.selected.as_str(), v.selected_index, v.detail.key.as_str()));
        assert_eq!("", v.editing);
    }

    /// While statistics are off there is no Today column, and nothing about today in the panel.
    #[test]
    fn no_today_without_statistics() {
        let mut s = setup();
        s.prefs.stats = false;
        let v = view(&apps(), &s, None, true, &HashMap::new(), &selected("spotify"), program);
        assert_eq!(3, v.heads.len());
        assert!(!v.stats && v.rows.iter().all(|r| r.today.is_empty()));
        assert_eq!("", v.detail.today);
    }

    /// One that runs as another takes its route, and says so; Show takes you to it.
    #[test]
    fn an_app_that_runs_as_another_takes_its_route() {
        for key in ["firefox-private", "alacarte-made-1"] {
            let d = page(&selected(key)).detail;
            assert_eq!(
                "Takes Firefox's route: it runs as Firefox, and unbraid can't tell their traffic apart.",
                d.leader_note
            );
            assert_eq!(
                ("firefox", "Takes Firefox's route", "Show Firefox"),
                (d.leader.as_str(), d.leader_menu.as_str(), d.show_leader.as_str())
            );
            assert!(d.choices.is_empty() && !d.own && !d.default_only);
            assert_eq!("No traffic yet today", d.today);
        }
        let firefox = page(&selected("firefox")).detail;
        assert_eq!(
            vec![
                ("alacarte-made-1", "Browser", "runs as Firefox"),
                ("firefox-private", "Private Browsing", "runs as Firefox")
            ],
            firefox.also.iter().map(|a| (a.key.as_str(), a.label.as_str(), a.note.as_str())).collect::<Vec<_>>()
        );
        assert_eq!("25 MB through United States", firefox.today);
    }

    /// A script, an interpreter or an AppImage only follows the default route: no choices, in the panel or the menu.
    #[test]
    fn an_app_that_cannot_be_told_apart_follows_the_default() {
        let d = page(&selected("org.example.Tool")).detail;
        assert!(d.default_only && d.choices.is_empty() && d.leader.is_empty() && !d.own);
        assert_eq!("/tmp/unbraid-ui-test/opt/org.example.Tool/org.example.Tool", d.copy);
    }

    /// The routes to choose, the default's first, then Direct; the one in use checked, the default route's offered back.
    #[test]
    fn the_panel_and_the_menu_offer_every_route() {
        let d = page(&selected("spotify")).detail;
        let tiles: Vec<_> =
            d.choices.iter().map(|c| (c.id.as_str(), c.name.as_str(), c.sub.as_str(), c.menu.as_str(), c.on)).collect();
        assert_eq!(
            vec![
                ("nl", "Netherlands", "Default · Nord", "Netherlands (default)", false),
                ("us", "United States", "Nord", "United States", false),
                ("it", "Italy", "Nord", "Italy", true),
                ("lab", "Home lab", "WireGuard", "Home lab", false),
                (DIRECT, "Direct", "No VPN", "Direct", false),
            ],
            tiles
        );
        assert_eq!(
            ("WG", 3, -1, true),
            (d.choices[3].code.as_str(), d.choices[3].hue, d.choices[4].hue, d.choices[4].direct)
        );
        assert_eq!(
            ("Spotify", "S", "/tmp/unbraid-ui-test/opt/spotify/spotify"),
            (d.label.as_str(), d.letter.as_str(), d.program.as_str())
        );
        assert_eq!("/tmp/unbraid-ui-test/opt/spotify/spotify", d.copy);
        assert!(d.own && d.also.is_empty() && !d.lookups);
        assert_eq!("10 MB through Italy", d.today);
        let v = page(&selected("spotify"));
        assert_eq!((9, "spotify"), (v.selected_index, v.selected.as_str()));
        let chromium = page(&selected("chromium")).detail;
        assert!(!chromium.own, "it follows the default route: nothing to go back to");
        assert_eq!("16 MB through Netherlands", chromium.today);
        let terminal = page(&selected("org.gnome.Terminal")).detail;
        assert_eq!("No traffic yet today", terminal.today);
        let unknown = view(&apps(), &setup(), None, true, &today(), &selected("spotify"), |_| None).detail;
        assert_eq!(
            ("spotify", ""),
            (unknown.program.as_str(), unknown.copy.as_str()),
            "no program known: its key, and nothing to copy"
        );
    }

    /// A Direct app's lookups go through unbraid's filter or around it, while one is set and the profile in use is shown.
    #[test]
    fn a_direct_app_offers_its_lookups_switch() {
        let mut s = setup();
        assert!(!view(&apps(), &s, None, true, &today(), &selected("code"), program).detail.lookups, "no filter set");
        s.prefs.filter = Filter { id: Some("quad9".into()), ..Filter::default() };
        let d = view(&apps(), &s, None, true, &today(), &selected("code"), program).detail;
        assert_eq!(
            (true, false, "Outside unbraid, with the computer's DNS"),
            (d.lookups, d.lookups_on, d.lookups_sub.as_str())
        );
        s.prefs = filter_lookups(&s.prefs, "code");
        let d = view(&apps(), &s, None, true, &today(), &selected("code"), program).detail;
        assert_eq!(
            (true, "Through unbraid, with Quad9. The app can see a VPN is on"),
            (d.lookups_on, d.lookups_sub.as_str())
        );
        assert!(
            !view(&apps(), &s, None, true, &today(), &selected("spotify"), program).detail.lookups,
            "only for Direct apps"
        );
        s.profiles.push(Profile::with_apps("Solo", "nl", &[("code", DIRECT)]));
        let shown = s.view_as(Some("Solo"));
        assert!(
            !view(&apps(), &shown, Some("Solo"), true, &today(), &selected("code"), program).detail.lookups,
            "a setting of every profile"
        );
    }

    /// The switch flips an app's own choice, and drops it once it equals every Direct app's.
    #[test]
    fn the_lookups_switch_keeps_only_choices_that_differ() {
        let mut p = Prefs { filter: Filter { id: Some("quad9".into()), ..Filter::default() }, ..Prefs::default() };
        p = filter_lookups(&p, "code");
        assert_eq!(Some(&true), p.filter.apps.get("code"));
        p = filter_lookups(&p, "code");
        assert!(p.filter.apps.is_empty());
        p.filter.direct_apps = true;
        p = filter_lookups(&p, "code");
        assert_eq!(Some(&false), p.filter.apps.get("code"));
        assert!(!p.filter.through("code"));
    }

    /// A column head sorts by it; again, the other way round. Apps alike keep their order either way.
    #[test]
    fn the_heads_sort_the_table() {
        let mut t = Table::default();
        t.sort_by(Sort::Today);
        let v = page(&t);
        assert_eq!(
            vec!["firefox", "chromium", "spotify", "thunderbird", "discord", "signal-desktop", "alacarte-made-1"],
            keys(&v)[..7].to_vec()
        );
        assert_eq!(
            vec!["NAME", "KIND", "ROUTE", "TODAY ▲"],
            v.heads.iter().map(|h| h.text.as_str()).collect::<Vec<_>>()
        );
        t.sort_by(Sort::Today);
        let v = page(&t);
        assert_eq!("TODAY ▼", v.heads[3].text);
        assert_eq!(
            vec!["code", "org.example.Tool", "org.gnome.Terminal"],
            keys(&v)[..3].to_vec(),
            "least data first, then by name backwards"
        );
        assert_eq!("firefox", *keys(&v).last().unwrap());
        t.sort_by(Sort::Route);
        assert!(!t.down);
        let v = page(&t);
        assert_eq!(vec!["org.gnome.Terminal", "code"], keys(&v)[..2].to_vec(), "Direct sorts as \"Direct\"");
        assert_eq!(vec!["discord", "spotify"], keys(&v)[2..4].to_vec(), "then Italy");
        assert_eq!(
            vec!["alacarte-made-1", "firefox", "firefox-private", "thunderbird"],
            keys(&v)[11..].to_vec(),
            "United States, with the apps that take its route"
        );
        let mut kinds = apps();
        kinds[1].kind = "Flatpak";
        t.sort_by(Sort::Kind);
        let v = view(&kinds, &setup(), None, true, &today(), &t, program);
        assert_eq!(vec!["alacarte-made-1", "discord"], keys(&v)[..2].to_vec());
        assert_eq!("chromium", *keys(&v).last().unwrap(), "App before Flatpak");
    }

    /// The exits filter the table by where each app goes out, the search by name or key; system apps show on demand,
    /// and always once they have a route.
    #[test]
    fn filters_and_the_search_narrow_the_table() {
        let mut t = Table { filter: Some("us".into()), ..Table::default() };
        let v = page(&t);
        assert_eq!(vec!["alacarte-made-1", "firefox", "firefox-private", "thunderbird"], keys(&v));
        assert!(!v.all && v.chips[1].on && !v.chips[0].on);
        t.filter = Some(DIRECT.into());
        assert_eq!(vec!["org.gnome.Terminal", "code"], keys(&page(&t)));
        assert!(page(&t).chips[4].on);
        t.filter = Some("lab".into());
        assert!(page(&t).rows.is_empty());
        t.filter = None;
        t.query = "  OFFICE ".into();
        assert_eq!(vec!["libreoffice-startcenter", "libreoffice-writer"], keys(&page(&t)));
        t.query = "gnome".into();
        assert_eq!(vec!["org.gnome.Terminal"], keys(&page(&t)), "its key matches too");
        let mut listed = apps();
        listed.push(AppInfo { system: true, ..app("nm-applet", "Network") });
        listed.push(AppInfo { system: true, ..app("settings-daemon", "Settings Daemon") });
        let mut s = setup();
        s.apps.insert("settings-daemon".into(), "it".into());
        let t = Table::default();
        let v = view(&listed, &s, None, true, &today(), &t, program);
        assert!(!keys(&v).contains(&"nm-applet") && keys(&v).contains(&"settings-daemon"));
        let v = view(&listed, &s, None, true, &today(), &Table { system: true, ..t }, program);
        assert!(keys(&v).contains(&"nm-applet") && v.system);
    }

    /// Routes with one code are told apart by provider; an empty profile's apps have no exit, and a chip finds them.
    #[test]
    fn chips_and_marks_for_odd_setups() {
        let mut s = setup();
        s.routes.push(Route { hue: 4, ..Route::new("mnl", Location::country("mullvad", 153, "NL", "Netherlands")) });
        let v = view(&apps(), &s, None, true, &today(), &Table::default(), program);
        assert_eq!(
            vec!["NL · Nord", "US", "IT", "WG", "NL · Mullvad", "Direct"],
            v.chips.iter().map(|c| c.label.as_str()).collect::<Vec<_>>()
        );
        s.profiles.push(Profile::new("Travel", ""));
        let travel = s.view_as(Some("Travel"));
        let t = Table { filter: Some(String::new()), ..Table::default() };
        let v = view(&apps(), &travel, Some("Travel"), true, &today(), &t, program);
        assert_eq!(
            vec!["NL · Nord", "US", "IT", "WG", "NL · Mullvad", "Not set", "Direct"],
            v.chips.iter().map(|c| c.label.as_str()).collect::<Vec<_>>()
        );
        assert!(v.chips[5].on && v.chips[5].hue == -1);
        assert_eq!(15, v.rows.len(), "nothing has an exit yet");
        assert_eq!("Not set", v.rows[0].unset);
        assert_eq!(
            "0 installed · 0 routed · 0 direct",
            view(&[], &travel, Some("Travel"), true, &today(), &t, program).counts
        );
        s.apps.insert("chromium".into(), "gone".into());
        let v = view(&apps(), &s, None, true, &today(), &Table::default(), program);
        assert_eq!(
            ("··", -1, false),
            (row(&v, "chromium").code.as_str(), row(&v, "chromium").hue, row(&v, "chromium").direct),
            "a route that no longer exists"
        );
    }

    /// Showing a profile not in use says so, and how to go back or use it.
    #[test]
    fn a_profile_not_in_use_is_edited_apart() {
        let mut s = setup();
        s.profiles.push(Profile::new("Travel", ""));
        let v = view(&apps(), &s.view_as(Some("Home")), Some("Home"), true, &today(), &Table::default(), program);
        assert_eq!(
            ("Editing Home · not in use. No profile is in use.", "", "Back to current setup", "Use Home"),
            (v.editing.as_str(), v.editing_hint.as_str(), v.back_label.as_str(), v.use_label.as_str())
        );
        let work = s.use_profile("Work");
        let v =
            view(&apps(), &work.view_as(Some("Travel")), Some("Travel"), true, &today(), &Table::default(), program);
        assert_eq!(
            ("Editing Travel · not in use. Work is in use.", "Choose a default route on Routes", "Back to Work", ""),
            (v.editing.as_str(), v.editing_hint.as_str(), v.back_label.as_str(), v.use_label.as_str())
        );
        let v = view(&apps(), &work, Some("Work"), true, &today(), &Table::default(), program);
        assert_eq!("", v.editing, "the profile in use isn't a draft");
    }

    /// The arrow keys move the selection through the table, from the first row with none, and stop at its ends.
    #[test]
    fn the_arrow_keys_walk_the_table() {
        let mut t = Table::default();
        let rows = page(&t).rows;
        t.step(&rows, 1);
        assert_eq!(Some("alacarte-made-1"), t.selected.as_deref());
        t.step(&rows, -1);
        assert_eq!(Some("alacarte-made-1"), t.selected.as_deref());
        t.step(&rows, 1);
        assert_eq!(Some("chromium"), t.selected.as_deref());
        t.selected = Some("code".into());
        t.step(&rows, 1);
        assert_eq!(Some("code"), t.selected.as_deref());
        t.selected = Some("gone".into());
        t.step(&rows, 1);
        assert_eq!(Some("alacarte-made-1"), t.selected.as_deref(), "one no longer listed: the first");
        t.step(&[], 1);
        assert_eq!(Some("alacarte-made-1"), t.selected.as_deref());
    }

    /// Reselecting the page clears its selection and filter first; a program added shows, selected; the search stays
    /// when another profile is shown.
    #[test]
    fn the_table_starts_over_when_asked() {
        let mut t = Table {
            query: "fire".into(),
            filter: Some("us".into()),
            selected: Some("firefox".into()),
            ..Table::default()
        };
        assert!(!t.reselected());
        assert_eq!((None, None), (t.filter.clone(), t.selected.clone()));
        assert!(t.reselected());
        t.filter = Some("us".into());
        t.viewed();
        assert_eq!((None, "fire"), (t.filter.clone(), t.query.as_str()));
        t.filter = Some(DIRECT.into());
        t.added("/usr/bin/true");
        assert_eq!(Table { selected: Some("/usr/bin/true".into()), ..Table::default() }, t);
    }

    /// Data reads as on the Stats page, rounded half up.
    #[test]
    fn data_reads_as_on_the_stats_page() {
        assert_eq!("980 kB", bytes_text(980_400));
        assert_eq!("1000 kB", bytes_text(999_500));
        assert_eq!("3 MB", bytes_text(2_500_000));
        assert_eq!("16 MB", bytes_text(16_000_000));
        assert_eq!("1.3 GB", bytes_text(1_250_000_000));
        assert_eq!("0 kB", bytes_text(0));
    }

    /// An icon's initial is the label's first character people see, in capitals.
    #[test]
    fn the_initial_is_one_character() {
        assert_eq!("É", letter("éclair"));
        assert_eq!("", letter(""));
        assert_eq!("👩‍💻", letter("👩‍💻 Dev"));
    }
}
