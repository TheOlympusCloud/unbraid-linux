//! The Routes page: where each route goes out, the default route and the connection.

use crate::ui::picker::NORD_GROUPS;
use crate::ui::stats::rate;
use crate::exit_check::ExitReport;
use crate::model::{DIRECT, Route, Server, Setup};
use crate::providers;
use crate::stats;
use crate::ui::profiles::{UseBarView, use_bar};
use crate::vpn::{Ask, Phase, VpnState, vpn_on};
use indexmap::{IndexMap, IndexSet};
use std::collections::HashSet;

/// An installed app as Routes needs it: its key, its name, and the apps that run as one program with it (`group`,
/// empty when none).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct App {
    pub pkg: String,
    pub label: String,
    pub group: Vec<String>,
}

impl App {
    /// The app whose route this one takes in `s`: its group's first with an exception, when that isn't itself.
    pub fn follows(&self, s: &Setup) -> Option<&str> {
        self.group.iter().find(|g| s.apps.contains_key(*g)).filter(|g| **g != self.pkg).map(String::as_str)
    }
}

/// What Routes reads: the store's setup, the connection, and what the window keeps about them.
pub struct Inputs<'a> {
    pub setup: &'a Setup,
    /// The profile shown on Routes and Apps when it isn't the one in use; none = the one in use.
    pub viewing: Option<&'a str>,
    pub vpn: &'a VpnState,
    /// The newest start or stop the connection hasn't taken up yet ([`crate::vpn::Live::asked`]).
    pub asked: Option<Ask>,
    /// The profile being switched to, until the engine runs it.
    pub switching: Option<&'a str>,
    /// A switch the engine refused: the profile asked for, and the one still in use.
    pub refused: Option<(&'a str, Option<&'a str>)>,
    /// The installed apps, once listed (empty before).
    pub apps: &'a [App],
    /// What each route's exit reported, by route id.
    pub exits: &'a IndexMap<String, ExitReport>,
    /// Exits are still being asked: a route with no answer yet says it is being checked.
    pub asking: bool,
    /// Providers whose new key may not reach all their servers yet ([`providers::setting_up`]).
    pub setting_up: &'a HashSet<String>,
    /// Live speeds; read while statistics are recorded.
    pub live: Option<&'a stats::Live>,
    /// Now, in epoch ms: the connection's clock and a pause's ring.
    pub now: i64,
}

/// The address a route's exit reported, a check under way, or one that failed; empty `text` shows nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExitLine {
    pub text: String,
    /// `text` is an address.
    pub ip: bool,
    /// The check failed: said quietly, with an info mark.
    pub failed: bool,
}

/// What an item of a route's menu or sheet, or of the power sheet, does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Act {
    #[default]
    ChangeLocation,
    Rename,
    MakeDefault,
    MakeDirectDefault,
    AssignInApps,
    Remove,
    Drop,
    Pause,
    Disconnect,
}

/// One item of a menu or a sheet. `danger` ones are in the bad ink (and a menu sets them apart); `minutes` for a pause.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteAction {
    pub act: Act,
    pub text: String,
    pub danger: bool,
    pub minutes: i32,
}

/// A sheet: its title, a line above its actions (`lead`), the actions, and a note under them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sheet {
    pub title: String,
    pub lead: String,
    pub actions: Vec<RouteAction>,
    pub note: String,
}

/// An app in a route's stack of icons: its key, for its icon, and the initial shown without one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppMark {
    pub pkg: String,
    pub letter: String,
}

/// A route as Routes shows it: the default route's card, or an exception's row. Direct is no route: no code, no colour.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouteCard {
    /// The route's id, or [`DIRECT`].
    pub id: String,
    pub direct: bool,
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub place: String,
    /// The default route's server and its load while connected: "nl1256 · 9% load".
    pub server: String,
    /// Who it carries: "All other apps · 8" on the default route, the apps on an exception.
    pub apps_label: String,
    /// No app uses it: its label is dim.
    pub no_apps: bool,
    /// The first five apps' icons.
    pub apps: Vec<AppMark>,
    /// Apps past those five: "+N".
    pub more: i32,
    pub exit: ExitLine,
    /// An IPv6 exit address, which takes a line of its own under the row.
    pub wide: bool,
    /// What its right click offers.
    pub menu: Vec<RouteAction>,
    /// What a click on it opens.
    pub sheet: Sheet,
}

/// One exit in the Exits card: the route, its place, its download now (while recorded) and the address it reported.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExitRow {
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub place: String,
    pub speed: String,
    pub exit: ExitLine,
}

/// The home network's row: how it is reached and its subnets, and Tailscale's sign-in link while it asks for one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HomeRow {
    pub sub: String,
    pub login_url: String,
    /// Connected: its mark in its colour.
    pub lit: bool,
}

/// Everything Routes shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RoutesView {
    pub overline: String,
    pub phase: Phase,
    /// A profile switch is under way: the band and the button show it as a connect.
    pub switching: bool,
    /// The band's first line (the connection's clock while on), in the case written: the screen sets it in capitals.
    pub status: String,
    pub title: String,
    pub sub: String,
    /// `sub` is the connection's error.
    pub sub_bad: bool,
    /// What a click on the band or the power button does, for screen readers.
    pub label: String,
    /// The power button opens Pause and Disconnect; otherwise it connects.
    pub power_menu: bool,
    /// A timed pause: the ring and how much of it is left (1 to 0).
    pub paused_ring: bool,
    pub paused_left: f32,
    /// Live speeds while statistics are recorded: value and unit, down then up.
    pub speeds: bool,
    pub down: String,
    pub down_unit: String,
    pub up: String,
    pub up_unit: String,
    /// A switch the engine refused, said once with Try again; empty when none.
    pub refused: String,
    /// The profile Try again switches to.
    pub retry: String,
    /// A profile shown but not in use: what Use would switch to.
    pub use_bar: Option<UseBarView>,
    /// An empty profile's default route, not chosen yet.
    pub not_set: bool,
    pub default_route: RouteCard,
    pub exceptions: Vec<RouteCard>,
    /// No exception yet: the note that every app takes the default route.
    pub all_default: bool,
    /// Many Nord locations at once: the note on Nord's limit.
    pub nord_note: bool,
    /// Connected and showing the profile in use: routes in their colours, the exits' addresses.
    pub lit: bool,
    pub exits: Vec<ExitRow>,
    pub home: Option<HomeRow>,
    /// Pause or disconnect, from the power button.
    pub power: Sheet,
}

fn count(n: usize) -> String {
    if n == 1 { "1 app".into() } else { format!("{n} apps") }
}

/// Server name and, where the provider publishes it, its load: "nl1256 · 9% load".
pub fn server_id(r: &Route, s: &Server) -> String {
    let name = if r.loc.provider == "nord" { s.host.split('.').next().unwrap_or_default().to_string() } else { s.name.clone() };
    let load = s.load >= 0 && providers::get(&r.loc.provider).is_some_and(|p| p.has_load());
    if load { format!("{name} · {}% load", s.load) } else { name }
}

/// Where a route goes out, in words: its kind of own server, or "Nord · P2P · Amsterdam · OpenVPN TCP". `live` are the
/// servers in use, whose city tells where "Fastest" landed.
pub fn place(r: &Route, live: &IndexMap<String, Server>) -> String {
    if r.wg.is_some() {
        return "WireGuard".into();
    }
    if r.ovpn.is_some() {
        return "OpenVPN".into();
    }
    if r.ss.is_some() {
        return "Shadowsocks".into();
    }
    if r.ts_exit.is_some() {
        return "Tailscale exit".into();
    }
    let nord = r.loc.provider == "nord";
    // Standard servers say nothing.
    let group = NORD_GROUPS.iter().find(|(id, _)| nord && id.is_some() && r.loc.group.as_deref() == *id).map(|(_, label)| label.to_string());
    let city = r.loc.pinned.as_ref().map(|p| p.name.clone()).or_else(|| r.loc.city.clone()).or_else(|| live.get(&r.id).map(|s| s.city.clone()).filter(|c| !c.trim().is_empty()));
    let tech = match nord.then(|| providers::nord::tech(&r.loc)).as_deref() {
        Some("openvpn_udp") => Some("OpenVPN".to_string()),
        Some("openvpn_tcp") => Some("OpenVPN TCP".to_string()),
        _ => None,
    };
    [Some(r.source()), group, Some(city.unwrap_or_else(|| "Fastest".into())), tech].into_iter().flatten().collect::<Vec<_>>().join(" · ")
}

/// App names for a small group ("Signal", "Bank A, Bank B"), the app count for a larger one ("7 apps").
pub fn apps_label(pkgs: &[&str], labels: &IndexMap<&str, &str>) -> String {
    match pkgs.len() {
        0 => "No apps assigned".into(),
        1..=3 => pkgs.iter().map(|p| labels.get(p).map_or_else(|| p.rsplit('.').next().unwrap_or_default().to_string(), |l| l.to_string())).collect::<Vec<_>>().join(", "),
        n => count(n),
    }
}

/// The band's first line: the connection's state, its clock while on ("Connected · 01:02:03"), when a pause ends.
pub fn status_line(vpn: &VpnState, switching: bool, now: i64) -> String {
    if switching {
        return "Switching profile".into();
    }
    match vpn.phase {
        Phase::On => {
            let s = ((now - vpn.since) / 1000).max(0);
            format!("Connected · {:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
        }
        Phase::Connecting => "Connecting".into(),
        Phase::Off => "Not connected".into(),
        Phase::Paused if vpn.paused_until > 0 => format!("Paused · resumes {}{}", if vpn.paused_about { "about " } else { "" }, clock(vpn.paused_until)),
        Phase::Paused => "Paused".into(),
    }
}

/// A time of day, as the desktop's clock shows it: "14:30".
fn clock(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(|t| t.with_timezone(&chrono::Local).format("%H:%M").to_string()).unwrap_or_default()
}

/// How much of a timed pause is left, 1 to 0, for its ring.
pub fn paused_left(vpn: &VpnState, now: i64) -> f32 {
    if vpn.phase != Phase::Paused || vpn.paused_until <= vpn.paused_at {
        return 1.0;
    }
    ((vpn.paused_until - now) as f32 / (vpn.paused_until - vpn.paused_at) as f32).clamp(0.0, 1.0)
}

fn action(act: Act, text: impl Into<String>) -> RouteAction {
    RouteAction { act, text: text.into(), danger: matches!(act, Act::Remove | Act::Drop | Act::Disconnect), minutes: 0 }
}

/// The saved profiles, other than the one in use, that list route `id`: removing it takes it from them too.
fn also_in(s: &Setup, id: &str) -> Vec<String> {
    s.saved().into_iter().filter(|p| Some(&p.name) != s.profile.as_ref() && p.own().contains(id)).map(|p| p.name).collect()
}

/// What route `id`'s right click offers (`menu`) and what its sheet does, in `shown` (the setup as the profile shown
/// routes it). In a profile not in use (`draft`), nothing shared changes: no rename, and Remove only takes the route
/// out of that profile.
fn route_actions(s: &Setup, shown: &Setup, draft: Option<&str>, id: &str) -> (Vec<RouteAction>, Sheet) {
    let mut menu = vec![];
    let mut sheet = Sheet::default();
    if id == DIRECT {
        sheet.title = "Direct".into();
        sheet.lead = "Apps here skip the VPN. Assign them in Apps.".into();
        if shown.default_route != DIRECT {
            menu.push(action(Act::MakeDefault, "Make default"));
            sheet.actions.push(action(Act::MakeDefault, "Make default"));
        } else {
            menu.push(action(Act::AssignInApps, "Assign apps to Direct in Apps"));
        }
        return (menu, sheet);
    }
    sheet.title = shown.route(Some(id)).map(Route::name).unwrap_or_default();
    menu.push(action(Act::ChangeLocation, "Change location…"));
    sheet.actions.push(action(Act::ChangeLocation, "Change location"));
    if id == shown.default_route {
        menu.push(action(Act::MakeDirectDefault, "Make Direct the default"));
        sheet.actions.push(action(Act::MakeDirectDefault, "Make Direct the default"));
    }
    if let Some(d) = draft {
        if id != shown.default_route {
            menu.push(action(Act::MakeDefault, "Make default"));
            menu.push(action(Act::Drop, format!("Remove from {d}")));
            sheet.actions.push(action(Act::MakeDefault, "Make default"));
            sheet.actions.push(action(Act::Drop, format!("Remove from {d}")));
            sheet.note = format!("Its apps in {d} will use its default route. The route stays for other profiles.");
        }
        return (menu, sheet);
    }
    if s.route(Some(id)).is_some_and(Route::imported) {
        menu.push(action(Act::Rename, "Rename…"));
        sheet.actions.push(action(Act::Rename, "Rename"));
    }
    if id != s.default_route {
        let others = also_in(s, id).join(", ");
        menu.push(action(Act::MakeDefault, "Make default"));
        menu.push(action(Act::Remove, if others.is_empty() { "Remove route".into() } else { format!("Remove route, also from {others}") }));
        sheet.actions.push(action(Act::MakeDefault, "Make default"));
        sheet.actions.push(action(Act::Remove, "Remove route"));
        sheet.note = format!("Its apps will use the default route.{}", if others.is_empty() { String::new() } else { format!(" It also goes from {others}.") });
    }
    (menu, sheet)
}

/// Pause or disconnect: offered by the power button while connected. With blocking on, a pause takes every app offline.
fn power_sheet(lockdown: bool) -> Sheet {
    let what = if lockdown { "Pause internet for" } else { "Pause" };
    let mut actions: Vec<RouteAction> = [(5, "5 minutes"), (15, "15 minutes"), (60, "1 hour")].iter().map(|(m, label)| RouteAction { minutes: *m, ..action(Act::Pause, format!("{what} {label}")) }).collect();
    actions.push(action(Act::Disconnect, "Disconnect"));
    Sheet {
        title: "Pause or disconnect".into(),
        lead: if lockdown { "Blocking is on: every app, Direct apps included, is offline while paused." } else { "While paused, apps use your normal connection." }.into(),
        actions,
        note: String::new(),
    }
}

/// Up to five app icons for `pkgs`, and how many more there are.
fn marks(pkgs: &[&str], labels: &IndexMap<&str, &str>) -> (Vec<AppMark>, i32) {
    let apps = pkgs.iter().take(5).map(|p| AppMark { pkg: p.to_string(), letter: labels.get(p).copied().unwrap_or(*p).chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default() }).collect();
    (apps, pkgs.len().saturating_sub(5) as i32)
}

/// Routes as `i` has it: the connection, the default route, the exceptions and the exits.
pub fn view(i: &Inputs) -> RoutesView {
    let (s, vpn) = (i.setup, i.vpn);
    let on = vpn.phase == Phase::On;
    // A profile shown but not in use (a draft): the page shows its routes, the connection stays the live one's.
    let draft = i.viewing.filter(|n| Some(*n) != s.profile.as_deref() && s.profiles.iter().any(|p| p.name == *n));
    let shown = s.view_as(i.viewing);
    let lit = on && draft.is_none();
    let empty = IndexMap::new();
    let live = if lit { &vpn.servers } else { &empty };
    let mut by_route: IndexMap<&str, Vec<&str>> = IndexMap::new();
    for (pkg, route) in &shown.apps {
        by_route.entry(route.as_str()).or_default().push(pkg.as_str());
    }
    // A profile lists its own routes, and routes nothing uses yet (one just added), never another profile's.
    let hidden = s.hidden_routes(draft);
    // Direct is built in, not a route: listed once an app in this profile uses it (its default shows as the card above).
    let ids: Vec<&str> = shown.routes.iter().map(|r| r.id.as_str()).chain([DIRECT]).filter(|id| *id != shown.default_route && !hidden.contains(*id) && (*id != DIRECT || by_route.contains_key(DIRECT))).collect();
    let labels: IndexMap<&str, &str> = i.apps.iter().map(|a| (a.pkg.as_str(), a.label.as_str())).collect();
    // The default carries every app not sent elsewhere.
    let default_apps = i.apps.iter().filter(|a| shown.route_of(a.follows(&shown).unwrap_or(&a.pkg)) == shown.default_route).count();
    // A route's report holds only for the engine and server it was taken on. A route with a tunnel and no answer yet is
    // being checked, so its card keeps its size meanwhile; it couldn't be checked only once every attempt failed.
    let exit_of = |id: &str| -> ExitLine {
        if !lit {
            return ExitLine::default();
        }
        let report = i.exits.get(id).filter(|r| r.engine == vpn.engine && r.server.as_ref() == vpn.servers.get(id));
        let tunnel = vpn.servers.contains_key(id) || s.route(Some(id)).is_some_and(|r| r.ts_exit.is_some());
        match report.and_then(|r| r.ip.clone()) {
            Some(ip) => ExitLine { text: ip, ip: true, failed: false },
            None if report.is_none() && !tunnel => ExitLine::default(),
            None if i.asking => ExitLine { text: "Checking the exit…".into(), ..Default::default() },
            None => ExitLine { text: "Couldn't check this exit's address".into(), failed: true, ip: false },
        }
    };
    let card = |id: &str| -> RouteCard {
        let route = shown.route(Some(id));
        let pkgs = by_route.get(id).cloned().unwrap_or_default();
        let (apps, more) = marks(&pkgs, &labels);
        let (menu, sheet) = route_actions(s, &shown, draft, id);
        let exit = if route.is_some() { exit_of(id) } else { ExitLine::default() };
        RouteCard {
            id: id.into(),
            direct: route.is_none(),
            code: route.map(Route::code).unwrap_or_default(),
            hue: route.map_or(0, |r| r.hue),
            name: route.map_or_else(|| "Direct".into(), Route::name),
            place: route.map_or_else(|| "Skips the VPN".into(), |r| place(r, live)),
            server: String::new(),
            apps_label: apps_label(&pkgs, &labels),
            no_apps: pkgs.is_empty(),
            apps,
            more,
            wide: exit.ip && exit.text.contains(':'),
            exit,
            menu,
            sheet,
        }
    };
    let default_route = {
        let route = shown.route(Some(&shown.default_route));
        let server = route.and_then(|r| vpn.servers.get(&r.id).filter(|_| lit).map(|sv| server_id(r, sv))).unwrap_or_default();
        RouteCard {
            apps_label: format!("All other apps · {default_apps}"),
            place: route.map_or_else(|| "No VPN for these apps".into(), |r| place(r, live)),
            server,
            exit: exit_of(&shown.default_route),
            apps: vec![],
            more: 0,
            no_apps: false,
            ..card(&shown.default_route)
        }
    };
    let exceptions: Vec<RouteCard> = ids.iter().map(|id| card(id)).collect();
    let speeds = s.prefs.stats && on;
    let exits = [shown.default_route.as_str()].into_iter().chain(ids.iter().copied()).collect::<IndexSet<_>>().into_iter().filter_map(|id| shown.route(Some(id))).map(|r| ExitRow {
        code: r.code(),
        hue: r.hue,
        name: r.name(),
        place: place(r, live),
        speed: i.live.filter(|_| speeds).and_then(|l| l.down.get(&stats::id_of(r))).and_then(|d| d.last()).map(|b| rate(*b as i64)).map(|(v, u)| format!("{v} {u}")).unwrap_or_default(),
        exit: exit_of(&r.id),
    });
    let home = (s.home.tailscale || s.home.wg.is_some()).then(|| {
        let via = if s.home.tailscale { "Tailscale".into() } else { format!("WireGuard · {}", s.home.wg.as_ref().map(|w| w.endpoint.rsplit_once(':').map_or(w.endpoint.as_str(), |(host, _)| host)).unwrap_or_default()) };
        let subnets = s.home.subnets.join(", ");
        HomeRow {
            sub: if subnets.trim().is_empty() { via } else { format!("{via} · {subnets}") },
            login_url: vpn.ts_login_url.clone().filter(|_| s.home.tailscale).unwrap_or_default(),
            lit: on,
        }
    });
    // Right after a sign-in, a provider's new key may not reach all its servers for a minute: say so instead of nothing.
    let setting_up: Vec<String> = if on {
        s.active_routes().into_iter().filter(|r| !r.imported() && i.setting_up.contains(&r.loc.provider)).map(|r| r.loc.provider.clone()).collect::<IndexSet<_>>().into_iter().map(|p| providers::get(&p).map_or(p, |x| x.name().to_string())).collect()
    } else {
        vec![]
    };
    let sub = match () {
        _ if i.switching.is_some() => format!("To {} · apps reconnect for a moment", i.switching.unwrap_or_default()),
        _ if vpn.error.is_some() => vpn.error.clone().unwrap_or_default(),
        _ if !setting_up.is_empty() => format!("{} is setting up your key. Its routes can take a minute to work", setting_up.join(" and ")),
        _ => match vpn.phase {
            Phase::On => "Every app leaves through its own exit. Click to pause or disconnect.".into(),
            Phase::Paused if vpn.lockdown => "Apps are offline (Block connections without VPN) · click to resume".into(),
            Phase::Paused => "Apps skip the VPN · click to resume".into(),
            Phase::Connecting => "Setting up your routes".into(),
            Phase::Off => "Click to connect".into(),
        },
    };
    let (down, down_unit) = rate(i.live.map_or(0, |l| l.down_now));
    let (up, up_unit) = rate(i.live.map_or(0, |l| l.up_now));
    RoutesView {
        overline: match (draft, &s.profile) {
            (Some(d), _) => format!("Profile {d} · not in use"),
            (None, Some(p)) => format!("Profile {p} · in use"),
            (None, None) => "Every app, its own exit".into(),
        },
        phase: vpn.phase,
        switching: i.switching.is_some(),
        status: status_line(vpn, i.switching.is_some(), i.now),
        title: match vpn.phase {
            _ if i.switching.is_some() => "Switching",
            Phase::On if s.direct_only() => "Connected",
            Phase::On => "Protected",
            Phase::Paused => "Paused",
            Phase::Connecting => "Connecting",
            Phase::Off => "Unprotected",
        }
        .into(),
        sub,
        sub_bad: vpn.error.is_some(),
        label: match vpn.phase {
            Phase::On | Phase::Connecting => "Pause or disconnect",
            Phase::Paused => "Resume",
            Phase::Off => "Connect",
        }
        .into(),
        // A connect the connection hasn't taken up yet counts as on, so a second click offers to stop.
        power_menu: vpn_on(vpn.phase, i.asked),
        paused_ring: vpn.phase == Phase::Paused && vpn.paused_until > 0,
        paused_left: paused_left(vpn, i.now),
        speeds,
        down,
        down_unit,
        up,
        up_unit,
        refused: i.refused.map(|(to, kept)| format!("Couldn't switch to {to}.{}", kept.map(|k| format!(" {k} is still in use.")).unwrap_or_default())).unwrap_or_default(),
        retry: i.refused.map(|(to, _)| to.to_string()).unwrap_or_default(),
        use_bar: draft.map(|d| use_bar(d, s.profile.as_deref(), s.profiles.iter().any(|p| p.name == d && p.ready()))),
        not_set: shown.default_route.is_empty(),
        default_route,
        exceptions,
        all_default: shown.apps.is_empty() && !shown.default_route.is_empty(),
        nord_note: s.active_routes().iter().filter(|r| !r.imported() && r.loc.provider == "nord").count() > 6,
        lit,
        exits: exits.collect(),
        home,
        power: power_sheet(vpn.lockdown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, Profile, WgPeer};

    const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

    /// The set-up app of the approved screenshots: three Nord countries and a WireGuard server, apps on routes and Direct.
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
            profiles: vec![Profile::with_apps("Work", "nl", &[("firefox-private", "it")]), Profile::with_apps("Home", "nl", &[("firefox", "us"), ("firefox-private", "it")])],
            ..Setup::default()
        }
    }

    fn app(pkg: &str, label: &str, group: &[&str]) -> App {
        App { pkg: pkg.into(), label: label.into(), group: group.iter().map(|g| g.to_string()).collect() }
    }

    /// The apps the screenshots list, Firefox's private window and a launcher entry running as Firefox.
    fn listed() -> Vec<App> {
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

    struct Fixture {
        setup: Setup,
        vpn: VpnState,
        apps: Vec<App>,
        exits: IndexMap<String, ExitReport>,
        setting_up: HashSet<String>,
    }

    impl Fixture {
        fn new(setup: Setup) -> Self {
            Fixture { setup, vpn: VpnState::default(), apps: listed(), exits: IndexMap::new(), setting_up: HashSet::new() }
        }
        fn view(&self, viewing: Option<&str>) -> RoutesView {
            view(&Inputs { setup: &self.setup, viewing, vpn: &self.vpn, asked: None, switching: None, refused: None, apps: &self.apps, exits: &self.exits, asking: false, setting_up: &self.setting_up, live: None, now: 0 })
        }
    }

    /// The approved screenshot: Netherlands for every other app, the United States and Italy for two apps each, Direct for
    /// two more; the WireGuard route no profile uses stays hidden, and the exits list the three countries.
    #[test]
    fn set_up_app_as_approved() {
        let v = Fixture::new(set_up()).view(None);
        assert_eq!("Every app, its own exit", v.overline);
        assert_eq!(("NOT CONNECTED".to_string(), "Unprotected", "Click to connect", "Connect"), (v.status.to_uppercase(), v.title.as_str(), v.sub.as_str(), v.label.as_str()));
        assert!(!v.power_menu && !v.lit && !v.not_set && !v.all_default);
        assert_eq!(("All other apps · 8", "Netherlands", "Nord · Fastest", "NL"), (v.default_route.apps_label.as_str(), v.default_route.name.as_str(), v.default_route.place.as_str(), v.default_route.code.as_str()));
        let rows: Vec<_> = v.exceptions.iter().map(|r| (r.name.as_str(), r.place.as_str(), r.apps_label.as_str(), r.apps.iter().map(|a| a.letter.as_str()).collect::<String>())).collect();
        assert_eq!(
            vec![("United States", "Nord · Fastest", "Firefox, Thunderbird", "FT".into()), ("Italy", "Nord · Fastest", "Spotify, Discord", "SD".into()), ("Direct", "Skips the VPN", "Terminal, Visual Studio Code", "TV".into())],
            rows
        );
        assert!(v.exceptions[2].direct && !v.exceptions[0].direct);
        assert_eq!(vec!["Netherlands", "United States", "Italy"], v.exits.iter().map(|e| e.name.as_str()).collect::<Vec<_>>());
        assert!(v.home.is_none());
    }

    /// Before the apps are listed, apps go by their keys and the default counts none.
    #[test]
    fn apps_unknown_yet() {
        let mut f = Fixture::new(set_up());
        f.apps.clear();
        f.setup.apps.insert("org.example.Tool".into(), "us".into());
        f.setup.apps.move_index(6, 1);
        let v = f.view(None);
        assert_eq!("All other apps · 0", v.default_route.apps_label);
        assert_eq!("firefox, Tool, thunderbird", v.exceptions[0].apps_label);
        assert_eq!("FOT", v.exceptions[0].apps.iter().map(|a| a.letter.as_str()).collect::<String>());
        assert_eq!("Terminal, code", v.exceptions[2].apps_label);
    }

    /// The route menu offers what the sheet does: on the default route, Change location and Direct as the default; on
    /// another, its removal names the saved profiles it goes from too.
    #[test]
    fn menus_and_sheets() {
        let v = Fixture::new(set_up()).view(None);
        let texts = |a: &[RouteAction]| a.iter().map(|x| x.text.clone()).collect::<Vec<_>>();
        assert_eq!(vec!["Change location…", "Make Direct the default"], texts(&v.default_route.menu));
        assert_eq!(("Netherlands", vec!["Change location".to_string(), "Make Direct the default".into()]), (v.default_route.sheet.title.as_str(), texts(&v.default_route.sheet.actions)));
        assert_eq!(vec!["Change location…", "Make default", "Remove route, also from Home"], texts(&v.exceptions[0].menu));
        assert_eq!("Its apps will use the default route. It also goes from Home.", v.exceptions[0].sheet.note);
        assert!(v.exceptions[0].menu[2].danger);
        assert_eq!(vec!["Make default"], texts(&v.exceptions[2].menu));
        assert_eq!("Apps here skip the VPN. Assign them in Apps.", v.exceptions[2].sheet.lead);
        // An imported route can be renamed; Direct as the default sends its apps' choice to Apps.
        let mut s = set_up();
        s.apps.insert("steam".into(), "lab".into());
        s.default_route = DIRECT.into();
        let v = Fixture::new(s).view(None);
        assert_eq!("No VPN for these apps", v.default_route.place);
        assert_eq!(vec!["Assign apps to Direct in Apps"], texts(&v.default_route.menu));
        let lab = v.exceptions.iter().find(|r| r.id == "lab").unwrap();
        assert_eq!(("WireGuard", "WG"), (lab.place.as_str(), lab.code.as_str()));
        assert_eq!(vec!["Change location…", "Rename…", "Make default", "Remove route"], texts(&lab.menu));
        assert_eq!(vec!["Pause 5 minutes", "Pause 15 minutes", "Pause 1 hour", "Disconnect"], texts(&v.power.actions));
    }

    /// A profile not in use is shown as a draft: its overline says so, the use bar offers Use, its routes are its own,
    /// and its menus never reach what is shared.
    #[test]
    fn draft_profile() {
        let f = Fixture::new(set_up().save_as("Desk").add("Trip", true));
        let v = f.view(Some("Trip"));
        assert_eq!("Profile Trip · not in use", v.overline);
        assert!(v.not_set && v.exceptions.is_empty() && !v.all_default);
        let bar = v.use_bar.unwrap();
        assert_eq!(("Trip · not in use", "Choose a default route to use it", "Back", false), (bar.title.as_str(), bar.sub.as_str(), bar.back.as_str(), bar.ready));
        assert_eq!("Profile Desk · in use", f.view(None).overline);
        assert_eq!(None, f.view(Some("Desk")).use_bar, "the profile in use is no draft");
        let mut s = f.setup.clone();
        s = s.editing(Some("Trip"), |p| Profile { default_route: "nl".into(), apps: [("spotify".to_string(), "it".to_string())].into_iter().collect(), ..p });
        let v = Fixture::new(s).view(Some("Trip"));
        let it = &v.exceptions[0];
        assert_eq!(vec!["Change location…", "Make default", "Remove from Trip"], it.menu.iter().map(|a| a.text.as_str()).collect::<Vec<_>>());
        assert_eq!(Act::Drop, it.menu[2].act);
        assert_eq!("Its apps in Trip will use its default route. The route stays for other profiles.", it.sheet.note);
        assert!(v.use_bar.unwrap().ready);
    }

    /// Connected: the clock, the routes in colour, the default route's server and load, and each exit's address, being
    /// checked, or not checked; an address from another engine start no longer counts.
    #[test]
    fn connected() {
        let mut f = Fixture::new(set_up());
        let sv = Server { name: "Amsterdam #1256".into(), host: "nl1256.nordvpn.com".into(), load: 9, city: "Amsterdam".into(), ..Default::default() };
        f.vpn = VpnState { phase: Phase::On, since: 1_000, engine: 2, servers: [("nl".to_string(), sv.clone()), ("us".to_string(), Server { host: "us1.nordvpn.com".into(), load: -1, ..Default::default() })].into_iter().collect(), ..Default::default() };
        f.exits.insert("nl".into(), ExitReport { ip: Some("185.1.2.3".into()), at: 0, engine: 2, server: Some(sv) });
        f.exits.insert("it".into(), ExitReport { ip: Some("2a00::1".into()), at: 0, engine: 1, server: None });
        let v = view(&Inputs { setup: &f.setup, viewing: None, vpn: &f.vpn, asked: None, switching: None, refused: None, apps: &f.apps, exits: &f.exits, asking: true, setting_up: &f.setting_up, live: None, now: 3_723_000 + 1_000 });
        assert_eq!(("Connected · 01:02:03", "Protected", true, true), (v.status.as_str(), v.title.as_str(), v.lit, v.power_menu));
        assert_eq!(("Nord · Amsterdam", "nl1256 · 9% load"), (v.default_route.place.as_str(), v.default_route.server.as_str()));
        assert_eq!(ExitLine { text: "185.1.2.3".into(), ip: true, failed: false }, v.default_route.exit);
        assert_eq!("Checking the exit…", v.exceptions[0].exit.text);
        assert_eq!(ExitLine::default(), v.exceptions[1].exit, "no tunnel and an old report: nothing to say");
        assert_eq!(ExitLine::default(), v.exceptions[2].exit, "Direct has no exit to check");
        f.exits.insert("it".into(), ExitReport { ip: Some("2a00::1".into()), at: 0, engine: 2, server: None });
        let v = f.view(None);
        assert!(v.exceptions[1].wide);
        assert_eq!("Couldn't check this exit's address", v.exceptions[0].exit.text);
        assert!(v.exceptions[0].exit.failed);
    }

    /// The band says what is happening, most pressing first: a switch, an error, a key being set up, then the state.
    #[test]
    fn band_words() {
        let f = Fixture::new(set_up());
        let setting_up: HashSet<String> = ["nord".to_string()].into_iter().collect();
        let mut vpn = VpnState { phase: Phase::On, error: Some("NordVPN refused".into()), ..Default::default() };
        let refused = Some(("Home", Some("Work")));
        let at = |vpn: &VpnState, switching: Option<&str>| view(&Inputs { setup: &f.setup, viewing: None, vpn, asked: None, switching, refused, apps: &[], exits: &f.exits, asking: false, setting_up: &setting_up, live: None, now: 0 });
        let v = at(&vpn, Some("Home"));
        assert_eq!(("Switching profile", "Switching", "To Home · apps reconnect for a moment", true), (v.status.as_str(), v.title.as_str(), v.sub.as_str(), v.sub_bad));
        assert_eq!(("Couldn't switch to Home. Work is still in use.", "Home"), (v.refused.as_str(), v.retry.as_str()));
        assert_eq!("NordVPN refused", at(&vpn, None).sub);
        vpn.error = None;
        assert_eq!("NordVPN is setting up your key. Its routes can take a minute to work", at(&vpn, None).sub);
        vpn = VpnState { phase: Phase::Paused, lockdown: true, paused_until: 0, ..Default::default() };
        let v = at(&vpn, None);
        assert_eq!(("Paused", "Apps are offline (Block connections without VPN) · click to resume", "Resume"), (v.status.as_str(), v.sub.as_str(), v.label.as_str()));
        assert_eq!("Pause internet for 5 minutes", v.power.actions[0].text);
        assert_eq!("Blocking is on: every app, Direct apps included, is offline while paused.", v.power.lead);
    }

    /// A timed pause names when it ends and drains its ring.
    #[test]
    fn pause_ring() {
        let vpn = VpnState { phase: Phase::Paused, paused_at: 1_000, paused_until: 61_000, paused_about: true, ..Default::default() };
        assert_eq!(0.5, paused_left(&vpn, 31_000));
        assert_eq!(0.0, paused_left(&vpn, 90_000));
        assert_eq!(format!("Paused · resumes about {}", clock(61_000)), status_line(&vpn, false, 31_000));
        assert_eq!(1.0, paused_left(&VpnState { phase: Phase::Paused, ..Default::default() }, 31_000));
    }

    /// A route's place: its own server's kind, or the provider, Nord's group, the city or Fastest, and Nord's OpenVPN.
    #[test]
    fn places() {
        let mut r = Route::new("x", Location { group: Some("legacy_double_vpn".into()), city: Some("Paris".into()), ..Location::country("nord", 74, "FR", "France") });
        assert_eq!("Nord · Double VPN · Paris · OpenVPN", place(&r, &IndexMap::new()));
        r.loc = Location { protocol: Some("openvpn_tcp".into()), ..Location::country("nord", 74, "FR", "France") };
        assert_eq!("Nord · Fastest · OpenVPN TCP", place(&r, &IndexMap::new()));
        let live: IndexMap<String, Server> = [("x".to_string(), Server { city: "Lyon".into(), ..Default::default() })].into_iter().collect();
        r.loc = Location::country("mullvad", 1, "FR", "France");
        assert_eq!("Mullvad · Lyon", place(&r, &live));
        r.ts_exit = Some("100.64.0.1".into());
        assert_eq!("Tailscale exit", place(&r, &live));
    }

    /// Up to three apps by name, more as a count; the first five as icons, then +N.
    #[test]
    fn app_names_and_icons() {
        let labels: IndexMap<&str, &str> = [("a.b.Signal", "Signal")].into_iter().collect();
        assert_eq!("No apps assigned", apps_label(&[], &labels));
        assert_eq!("Signal, Bank", apps_label(&["a.b.Signal", "org.Bank"], &labels));
        assert_eq!("4 apps", apps_label(&["a", "b", "c", "d"], &labels));
        assert_eq!("1 app", count(1));
        let (icons, more) = marks(&["a", "b", "c", "d", "e", "f", "g"], &labels);
        assert_eq!((5, 2), (icons.len(), more));
    }

    /// Speeds read as the Stats page has them: kbps under 1 Mbps, one decimal under 100 Mbps.
    #[test]
    fn speeds() {
        assert_eq!(("0".to_string(), "kbps".to_string()), rate(99));
        assert_eq!(("0.1".to_string(), "kbps".to_string()), rate(100));
        assert_eq!(("1".to_string(), "kbps".to_string()), rate(500));
        assert_eq!(("12.3".to_string(), "Mbps".to_string()), rate(12_345_678));
        assert_eq!(("250".to_string(), "Mbps".to_string()), rate(250_600_000));
    }

    /// Many Nord locations at once: the note on Nord's limit. The home network shows its way in and subnets.
    #[test]
    fn notes_and_home() {
        let mut s = set_up();
        for (n, code) in ["DE", "FR", "SE", "CH", "JP"].iter().enumerate() {
            s.routes.push(Route::new(code, Location::country("nord", n as i32, code, code)));
            s.apps.insert(format!("app{n}"), code.to_string());
        }
        s.home.wg = Some(WgPeer::new("Home", KEY, vec![], KEY, "home.example.net:51820", vec![]));
        s.home.subnets = vec!["192.168.1.0/24".into()];
        let v = Fixture::new(s).view(None);
        assert!(v.nord_note);
        assert_eq!(Some(HomeRow { sub: "WireGuard · home.example.net · 192.168.1.0/24".into(), login_url: String::new(), lit: false }), v.home);
        let mut s = set_up();
        s.apps.clear();
        let v = Fixture::new(s).view(None);
        assert!(v.all_default && !v.nord_note);
    }
}
