//! Settings: its subjects on the left, the page of the one picked, every row's words and what its click does, and the
//! dialogs and sheets those rows open.

use crate::compiler::{canonical, is_private, official_ts};
use crate::desktop_settings::Theme;
use crate::limits::{self, LIMIT_OPT};
use crate::model::{Filter, OWN, Route, Setup, filters, own_dns};
use crate::providers::{self, Device, IMPORTS, MTU, Opt, PROTECT, Provider};
use crate::ui::status::{OLD_LIST_MS, Tone, provider_status, published_on};
use crate::vpn::{Phase, VpnState};
use crate::{APP, TITLE, VERSION_NAME};
use indexmap::IndexMap;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

pub const PRIVACY: &str = "https://unbraid.app/privacy";
pub const TERMS_URL: &str = "https://unbraid.app/terms";
const SOURCE: &str = "https://github.com/quiet-crafts/unbraid";

/// The file choosers' titles: the home tunnel's config.
pub const PICK_HOME_CONFIG: &str = "Choose your router's WireGuard config";

/// What the app re-uses, by name, licence and holder; the full texts are `notices.txt`.
const CREDITS: [(&str, &str); 16] = [
    ("sing-box 1.14.4", "GPL-3.0-or-later · nekohasekai (SagerNet). The engine (its Linux daemon), with small patches"),
    ("Tailscale", "BSD-3-Clause · Tailscale Inc. and contributors"),
    ("wireguard-go", "MIT · WireGuard LLC"),
    ("gVisor", "Apache-2.0 · The gVisor Authors"),
    ("Go and about 100 more modules", "BSD, MIT, Apache-2.0, ISC and MPL-2.0, each listed in the full texts"),
    ("Rust standard library", "Apache-2.0 or MIT · The Rust Project Developers"),
    ("About 350 more Rust crates", "MIT, Apache-2.0, Unicode-3.0, Zlib, BSD and ISC, each listed in the full texts"),
    ("Slint", "GPL-3.0 · SixtyFPS GmbH. Draws the app"),
    (
        "tokio, tonic, prost",
        "MIT and Apache-2.0 · Tokio Contributors, gRPC authors, Dan Burkert and others. The app's line to its engine",
    ),
    (
        "rustls, ring",
        "Apache-2.0, ISC and MIT · Joseph Birr-Pixton, Brian Smith and the BoringSSL authors. Secures the app's connections",
    ),
    ("rusqlite", "MIT · The rusqlite developers. Keeps the local statistics (SQLite is public domain)"),
    ("rqrr", "MIT and ISC · Moritz Wanzenböck, Daniel Beer. Reads QR codes at sign-in"),
    ("Material Symbols", "Apache-2.0 · Google"),
    ("Big Shoulders Display, Onest, Martian Mono", "SIL Open Font License 1.1 · their project authors"),
    ("gluetun", "MIT · Quentin McGaw. Server lists, and the ExpressVPN profile"),
    ("PIA manual-connections", "MIT · Private Internet Access, Inc."),
];
const MLAB: (&str, &str) = ("Measurement Lab (M-Lab)", "Speed-test servers, used under M-Lab's acceptable use policy");

fn trademarks() -> String {
    format!(
        "NordVPN, Mullvad, Proton VPN, Surfshark, ExpressVPN, Private Internet Access, IVPN, Windscribe, AirVPN, Tailscale, WireGuard, \
         sing-box and M-Lab are names or trademarks of their owners, used only to say what {APP} works with. {APP} is independent: none \
         of them made, endorse or support it. Your provider accounts stay under their own terms. \"WireGuard\" and the \"WireGuard\" \
         logo are registered trademarks of Jason A. Donenfeld."
    )
}

/// Every licence in full, as the licences require.
const NOTICES: &str = include_str!("../../notices.txt");

/// The Tailscale row while Tailscale is off.
const IDLE: &str = "Reach your tailnet from every app";

/// The Tailscale row's line: off, waiting for the connection, or what the tailnet says of itself.
pub fn tailscale_sub(enabled: bool, connected: bool, state: Option<&str>) -> String {
    match state {
        _ if !enabled => IDLE.into(),
        _ if !connected => format!("Connects with {APP}"),
        Some("NeedsLogin") => "Sign-in needed".into(),
        Some("NeedsMachineAuth") => "Waiting for approval in the Tailscale admin console".into(),
        Some("InUseOtherUser") => "In use by another user on this device".into(),
        None | Some("" | "Starting" | "NoState") => "Starting".into(),
        Some("Running") => "Connected".into(),
        Some("Stopped") => "Stopped".into(),
        _ => IDLE.into(),
    }
}

/// What a row, or a dialog's button, does when clicked; `arg` on the row says what it acts on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Act {
    /// Nothing: a row that only says something.
    #[default]
    None,
    /// Goes to page `arg`, on top of this one.
    Open,
    /// Shows subject `arg` on its own, as a click on the left does.
    Pick,
    /// Opens `arg` in the browser.
    Url,
    /// Opens dialog `arg`.
    Dialog,
    /// Opens or closes the page's Advanced settings.
    Advanced,
    Tailscale,
    /// Signs in to Tailscale at `arg`.
    TsLogin,
    /// Lets the tailnet's DNS answer for names under `arg`, or stops.
    Suffix,
    Lan,
    /// Picks the home tunnel's config file.
    HomeConfig,
    /// A provider setting, `arg` its key: a switch flips, a choice sets `value`.
    Opt,
    /// unbraid's filter is `arg` ("" none).
    Filter,
    FilterRoutes,
    FilterDirect,
    /// Apps set to Direct stay outside unbraid.
    Outside,
    /// Apps set to Direct pass through unbraid for the filter.
    Through,
    Stats,
    Login,
    Connect,
    Minimised,
    CloseToTray,
    RememberWindow,
    /// The theme named `arg`.
    Theme,
    Tour,
    AddProvider,
    /// Imports a config file: `arg` "wg", "ovpn" or "any", `value` the name it's prefixed with.
    ImportFile,
    Shadowsocks,
    /// Saves filter `arg` ("nextdns" or "own") with the typed value.
    SaveFilter,
    SignOutTailscale,
    TsServer,
    Subnets,
    DeleteStats,
    /// Provider `arg`'s own limit, as typed.
    Limit,
    /// Signs out of provider `arg`.
    SignOut,
    RenameServer,
    RemoveServer,
}

/// What ends a row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum End {
    #[default]
    None,
    Chevron,
    /// The provider's status dot, in its tone, then a chevron.
    Dot,
    Toggle,
    Radio,
    /// Opens in the browser.
    External,
    Delete,
    /// The route's mark: `value` its code, `hue` its colour.
    Mark,
    /// Key caps: `value`.
    Keys,
    /// A Remove button (`value` its text) beside the row's own click.
    Remove,
    /// The Advanced settings' arrow, turned while open.
    Expand,
}

/// A row's leading icon, in its squircle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Glyph {
    #[default]
    None,
    VpnKey,
    Hub,
    Home,
    Tunnel,
    Shield,
    Layers,
    Stats,
    Bolt,
    Info,
    File,
    Phone,
    Dns,
    Lan,
    Router,
    Power,
    Routes,
    Sliders,
}

/// One row of a group.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub act: Act,
    pub arg: String,
    pub title: String,
    pub sub: String,
    pub icon: Glyph,
    pub end: End,
    /// A switch's state, or whether this choice is the one picked.
    pub checked: bool,
    /// The title in the accent: a call to act.
    pub cta: bool,
    /// The title in the bad ink: it removes something.
    pub danger: bool,
    pub tone: Tone,
    pub value: String,
    pub hue: i32,
    /// The title starts with the logo, its slash in the accent: "un/braid by Quiet Crafts" is " by Quiet Crafts".
    pub wordmark: bool,
}

impl Default for Row {
    fn default() -> Self {
        row("", "")
    }
}

fn row(title: impl Into<String>, sub: impl Into<String>) -> Row {
    Row {
        act: Act::None,
        arg: String::new(),
        title: title.into(),
        sub: sub.into(),
        icon: Glyph::None,
        end: End::None,
        checked: false,
        cta: false,
        danger: false,
        tone: Tone::Idle,
        value: String::new(),
        hue: 0,
        wordmark: false,
    }
}

impl Row {
    fn act(self, act: Act, arg: impl Into<String>) -> Row {
        Row { act, arg: arg.into(), ..self }
    }
    fn icon(self, icon: Glyph) -> Row {
        Row { icon, ..self }
    }
    fn end(self, end: End) -> Row {
        Row { end, ..self }
    }
    fn switch(self, on: bool) -> Row {
        Row { end: End::Toggle, checked: on, ..self }
    }
    fn choice(self, on: bool) -> Row {
        Row { end: End::Radio, checked: on, ..self }
    }
    fn value(self, value: impl Into<String>) -> Row {
        Row { value: value.into(), ..self }
    }
    fn danger(self) -> Row {
        Row { danger: true, ..self }
    }
    /// A switch that can't be changed here: it shows the state, greyed.
    fn fixed(self) -> Row {
        Row { act: Act::None, ..self }
    }
}

/// Rows under a section's name ("" for a 16 px gap instead), then an error in the bad ink and a caption.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Group {
    pub label: String,
    pub rows: Vec<Row>,
    /// The collapsible Advanced settings: its first row is the head, the others show while it's open, the head then
    /// saying `open_sub`.
    pub advanced: bool,
    pub open_sub: String,
    /// The page's main action under the rows (Add connection), as a tonal button; "" none.
    pub button: String,
    pub error: String,
    pub caption: String,
}

fn group(label: &str, rows: Vec<Row>) -> Group {
    Group { label: label.into(), rows, ..Group::default() }
}

fn caption(text: impl Into<String>) -> Group {
    Group { caption: text.into(), ..Group::default() }
}

/// The same collapsible group on every page that has settings most people never need, just above its sign-out:
/// closed it sums up what's set, open it lists `rows` under a warning. None without rows.
fn advanced(summary: String, rows: Vec<Row>) -> Option<Group> {
    if rows.is_empty() {
        return None;
    }
    let head = row("Advanced settings", summary).act(Act::Advanced, "").icon(Glyph::Sliders).end(End::Expand);
    Some(Group {
        rows: std::iter::once(head).chain(rows).collect(),
        advanced: true,
        open_sub: "For when something doesn't work. A wrong choice can stop connections".into(),
        ..Group::default()
    })
}

/// A subject on the left: its page's key, its name and icon, and the name of the group it starts ("" if none).
#[derive(Clone, Debug, PartialEq)]
pub struct Subject {
    pub key: String,
    pub title: String,
    pub icon: Glyph,
    pub group: String,
}

const SUBJECTS: [(&str, &str, &str, Glyph); 10] = [
    ("Connections", "providers", "Providers & servers", Glyph::VpnKey),
    ("", "tailscale", "Tailscale", Glyph::Hub),
    ("", "local", "Local & home access", Glyph::Home),
    ("Safety", "behaviour", "VPN behaviour", Glyph::Tunnel),
    ("", "dns", "Protection", Glyph::Shield),
    ("This app", "desktop", "Desktop", Glyph::Layers),
    ("", "stats", "Statistics", Glyph::Stats),
    ("", "shortcuts", "Keyboard shortcuts", Glyph::Bolt),
    ("", "about", "About & support", Glyph::Info),
    ("", "legal", "Legal", Glyph::File),
];

/// A line of the licences page: a licence's title, or a paragraph of its text (the other one empty). Paragraphs are
/// apart, so the page lays out only those in view.
#[derive(Clone, Debug, PartialEq)]
pub struct Licence {
    pub title: String,
    pub text: String,
}

/// A dialog's text field: its name, the hint inside it, what it starts with, and whether it hides what's typed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Input {
    pub label: String,
    pub placeholder: String,
    pub value: String,
    pub secret: bool,
}

fn input(label: &str, placeholder: &str, value: impl Into<String>) -> Input {
    Input { label: label.into(), placeholder: placeholder.into(), value: value.into(), secret: false }
}

/// A dialog a page opens, by `key`: a prompt (its message, fields and confirm button), or a bottom sheet (`sheet`) of
/// rows. `confirm` is the confirm button (a sheet's primary button), `other` a second one (title "" none): their title is
/// the text. Under the fields, `hint` while what's typed is [`valid`], `error` while it isn't. `stays`: the sheet stays
/// open after its buttons.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dialog {
    pub key: String,
    pub sheet: bool,
    pub title: String,
    pub text: String,
    pub inputs: Vec<Input>,
    pub hint: String,
    pub error: String,
    pub rows: Vec<Row>,
    pub confirm: Row,
    pub other: Row,
    pub stays: bool,
}

fn prompt(key: impl Into<String>, title: impl Into<String>, text: impl Into<String>, confirm: Row) -> Dialog {
    Dialog { key: key.into(), title: title.into(), text: text.into(), confirm, ..Dialog::default() }
}

fn sheet(key: impl Into<String>, title: impl Into<String>, text: impl Into<String>, rows: Vec<Row>) -> Dialog {
    Dialog { key: key.into(), sheet: true, title: title.into(), text: text.into(), rows, ..Dialog::default() }
}

/// What Settings reads: the store's setup and accounts, the connection, and what the window keeps about them.
pub struct Inputs<'a> {
    pub setup: &'a Setup,
    pub vpn: &'a VpnState,
    /// Signed-in providers: id → account.
    pub accounts: &'a IndexMap<String, String>,
    /// The pages open, from the subject on the left to the one shown; empty = Providers & servers. It outlives the
    /// screen, so coming back from Add provider lands where the user left.
    pub stack: &'a [String],
    /// A failed action's message (a provider that couldn't release its device, a control server…).
    pub notice: Option<&'a str>,
    /// Providers whose saved server list is under a day old ([`crate::store::Store::countries_fresh`]).
    pub fresh: &'a HashSet<String>,
    /// When each gluetun list was published, epoch seconds ([`crate::store::Store::catalog_dates`]).
    pub list_dates: &'a IndexMap<String, i64>,
    /// Providers whose new key may not reach all their servers yet ([`providers::setting_up`]).
    pub setting_up: &'a HashSet<String>,
    /// The setup the engine runs, and its tunnel tags by route ([`crate::vpn::Live`]).
    pub running: Option<&'a Setup>,
    pub tags: &'a IndexMap<String, String>,
    /// The open provider page's settings ([`provider_opts`]), device slot and plan, read off the window's thread;
    /// empty until read.
    pub opts: &'a [Opt],
    pub device: Option<&'a Device>,
    pub plan: Option<&'a str>,
    /// A Tailscale node is still kept on this computer, even with Tailscale off.
    pub ts_stored: bool,
    /// Starting at login ([`crate::autostart::Autostart`]): whether, connecting too, and minimised to the tray.
    pub login: (bool, bool, bool),
    pub theme: Theme,
    pub close_to_tray: bool,
    pub remember_window: bool,
    /// The statistics file's size in bytes ([`crate::stats::size`]).
    pub stats_size: u64,
    /// Where the key that seals the setup sits in a file, home as "~" ([`crate::keyring::in_file`]); none in a keyring.
    pub key_file: Option<&'a str>,
    /// Why the home tunnel's config couldn't be imported.
    pub wg_error: Option<&'a str>,
    /// Now, epoch ms.
    pub now: i64,
}

/// The screen: the subjects, the page shown and the dialogs it can open.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SettingsView {
    /// "Version 2.8.2", over the subjects.
    pub version: String,
    pub subjects: Vec<Subject>,
    /// The subject picked on the left.
    pub subject: String,
    /// The page shown, the line above its title, its title, and whether it has Back.
    pub page: String,
    pub over: String,
    pub title: String,
    pub back: bool,
    /// The provider whose page this is, for its settings; "" elsewhere.
    pub provider: String,
    pub notice: String,
    pub groups: Vec<Group>,
    /// Licences, on their page.
    pub licences: Vec<Licence>,
    pub dialogs: Vec<Dialog>,
}

/// `stack` as it can show: a provider page whose account is gone falls back to the page under it.
pub fn shown(stack: &[String], accounts: &IndexMap<String, String>) -> Vec<String> {
    let mut s = stack.to_vec();
    if s.last()
        .and_then(|p| p.strip_prefix("provider:"))
        .is_some_and(|id| providers::get(id).is_none() || !accounts.contains_key(id))
    {
        s.pop();
    }
    s
}

/// A provider page's settings, in order: its own blocking, its options and, unless it's OpenVPN, the MTU. Blocks on
/// the provider's server list: call it off the window's thread.
pub fn provider_opts(p: &dyn Provider, account: &str) -> Vec<Opt> {
    p.protection()
        .into_iter()
        .chain(p.options(account))
        .chain((p.protocol() != "OpenVPN").then(|| MTU.clone()))
        .collect()
}

fn routes_word(n: usize) -> String {
    format!("{n} {}", if n == 1 { "route" } else { "routes" })
}

fn signed_in(i: &Inputs) -> Vec<&'static dyn Provider> {
    providers::all().into_iter().filter(|p| i.accounts.contains_key(p.id())).collect()
}

/// unbraid's filter on VPN routes replaces each provider's own blocking: those switches show off, their choice kept.
fn custom_dns(s: &Setup) -> bool {
    s.prefs.filter.server().is_some() && s.prefs.filter.routes
}

pub fn view(i: &Inputs) -> SettingsView {
    let stack = shown(i.stack, i.accounts);
    let page = stack.last().cloned().unwrap_or_else(|| "providers".into());
    let subject = stack.first().cloned().unwrap_or_else(|| "providers".into());
    let named = |key: &str| SUBJECTS.iter().find(|s| s.1 == key).map_or("", |s| s.2).to_string();
    let (over, title) = match page.as_str() {
        "notices" => ("Legal".to_string(), "Licences".to_string()),
        p if p.starts_with("provider:") => {
            ("Providers & servers".into(), providers::get(&p[9..]).map_or_else(String::new, |pr| pr.name().into()))
        }
        p => ("Settings".into(), named(p)),
    };
    let (groups, dialogs) = match page.as_str() {
        "providers" => providers_page(i),
        p if p.starts_with("provider:") => provider_page(i, &p[9..]),
        "tailscale" => tailscale_page(i),
        "local" => local_page(i),
        "behaviour" => behaviour_page(i),
        "dns" => dns_page(i),
        "stats" => stats_page(i),
        "legal" => (legal_page(), vec![]),
        "desktop" => (desktop_page(i), vec![]),
        "about" => (about_page(i), vec![]),
        // Shortcuts are the window's own list; licences are below.
        _ => (vec![], vec![]),
    };
    let quiet = ["legal", "notices", "desktop", "shortcuts"].contains(&page.as_str());
    SettingsView {
        version: format!("Version {VERSION_NAME}"),
        subjects: SUBJECTS
            .iter()
            .map(|(g, key, title, icon)| Subject {
                key: key.to_string(),
                title: title.to_string(),
                icon: *icon,
                group: g.to_string(),
            })
            .collect(),
        subject,
        back: stack.len() > 1,
        provider: page.strip_prefix("provider:").unwrap_or_default().into(),
        notice: if quiet { String::new() } else { i.notice.unwrap_or_default().into() },
        licences: if page == "notices" { notices() } else { vec![] },
        page,
        over,
        title,
        groups,
        dialogs,
    }
}

fn providers_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let s = i.setup;
    let on_phase = i.vpn.phase == Phase::On;
    let mut rows: Vec<Row> = signed_in(i)
        .into_iter()
        .map(|pr| {
            let id = pr.id();
            let n = s.routes.iter().filter(|r| !r.imported() && r.loc.provider == id).count();
            let active: Vec<&Route> =
                s.active_routes().into_iter().filter(|r| !r.imported() && r.loc.provider == id).collect();
            let on = on_phase && !active.is_empty();
            let stuck = i.vpn.stuck.get(id).copied();
            // Only the setup the engine runs counts: a route just moved to this provider isn't connected yet.
            let connected = on
                && active.iter().all(|r| {
                    i.vpn.servers.contains_key(&r.id)
                        && i.running.and_then(|run| run.route(Some(&r.id))).is_some_and(|x| x.loc == r.loc)
                });
            let unit = i.accounts.get(id).map_or_else(|| "connection".into(), |a| pr.limit(a).unit);
            let dropping = active
                .iter()
                .find(|r| i.vpn.dropping.contains(&r.id))
                .filter(|_| on)
                .map(|r| limits::dropping(&r.name(), pr.name(), &unit));
            let old = pr
                .list_source()
                .and_then(|c| i.list_dates.get(&c).copied())
                .filter(|t| i.now - t * 1000 > OLD_LIST_MS)
                .map(published_on);
            let (tone, words) = provider_status(
                pr.name(),
                n > 0,
                stuck == Some(true),
                on && i.setting_up.contains(id),
                on && stuck == Some(false),
                i.fresh.contains(id),
                connected,
                dropping.as_deref(),
                old.as_deref(),
            );
            let used = if n > 0 { format!(" · used by {}", routes_word(n)) } else { String::new() };
            Row { tone, ..row(pr.name(), words + &used).act(Act::Open, format!("provider:{id}")).end(End::Dot) }
        })
        .collect();
    if rows.is_empty() {
        rows.push(row("No provider yet", "Sign in to one with Add connection"));
    }
    let servers: Vec<Row> = s
        .servers
        .iter()
        .map(|sv| {
            let n = s.routes.iter().filter(|r| r.own.as_deref() == Some(&sv.id)).count();
            row(
                sv.name(),
                format!(
                    "{} · {}",
                    sv.kind(),
                    if n == 0 { "not used".into() } else { format!("used by {}", routes_word(n)) }
                ),
            )
            .act(Act::Dialog, format!("server:{}", sv.id))
            .end(End::Chevron)
        })
        .collect();
    let mine = Group {
        button: "Add connection".into(),
        caption: "A provider sign-in, a WireGuard or OpenVPN file, or a Shadowsocks link. Tailscale exit nodes are under Tailscale.".into(),
        ..group(if servers.is_empty() { "" } else { "My servers" }, servers)
    };
    (vec![group("VPN providers", rows), mine], providers_dialogs(i))
}

fn providers_dialogs(i: &Inputs) -> Vec<Dialog> {
    let s = i.setup;
    let others: Vec<&str> =
        providers::all().into_iter().filter(|p| !i.accounts.contains_key(p.id())).take(4).map(|p| p.name()).collect();
    let guides: Vec<&str> = IMPORTS.iter().map(|g| g.name).collect();
    let mut d = vec![
        sheet(
            "add",
            "Add connection",
            "",
            vec![
                row("Sign in to a provider", format!("{} and more", others.join(", ")))
                    .act(Act::AddProvider, "")
                    .end(End::Chevron),
                row("WireGuard or OpenVPN file", ".conf or .ovpn, from any provider or your own server")
                    .act(Act::ImportFile, "any")
                    .end(End::Chevron),
                row("Shadowsocks link", "Paste an ss:// access key").act(Act::Shadowsocks, "").end(End::Chevron),
                row("Provider without an app here?", format!("{}: download, then import", guides.join(", ")))
                    .act(Act::Dialog, "guides")
                    .end(End::Chevron),
            ],
        ),
        sheet(
            "guides",
            "From another provider",
            "",
            IMPORTS
                .iter()
                .map(|g| row(g.name, g.r#where).act(Act::Dialog, format!("guide:{}", g.id)).end(End::Chevron))
                .collect(),
        ),
    ];
    d.extend(IMPORTS.iter().map(|g| Dialog {
        confirm: row(format!("Download the config from {}", g.name), "").act(Act::Url, g.url),
        other: row("Import file", "").act(Act::ImportFile, if g.open_vpn { "ovpn" } else { "wg" }).value(g.name),
        stays: true,
        ..sheet(format!("guide:{}", g.id), g.name, g.r#where, vec![])
    }));
    for sv in &s.servers {
        let used = s.routes.iter().filter(|r| r.own.as_deref() == Some(&sv.id)).count();
        let line = if used > 0 { format!(" · used by {}", routes_word(used)) } else { String::new() };
        d.push(Dialog {
            inputs: vec![input("Name", "e.g. Home VPS", sv.name())],
            other: row("Remove server", "").act(Act::Dialog, format!("remove:{}", sv.id)).danger(),
            ..prompt(
                format!("server:{}", sv.id),
                sv.name(),
                format!("{}{line}", sv.kind()),
                row("Save", "").act(Act::RenameServer, &sv.id),
            )
        });
        let why = if used == 0 {
            "It isn't used by any route."
        } else {
            "The routes using it are removed too; their apps follow the default route."
        };
        d.push(prompt(
            format!("remove:{}", sv.id),
            format!("Remove {}?", sv.name()),
            why,
            row("Remove", "").act(Act::RemoveServer, &sv.id).danger(),
        ));
    }
    d
}

fn provider_page(i: &Inputs, id: &str) -> (Vec<Group>, Vec<Dialog>) {
    let (Some(pr), Some(acc)) = (providers::get(id), i.accounts.get(id)) else { return (vec![], vec![]) };
    let s = i.setup;
    let name = pr.name();
    let routes: Vec<&Route> = s.routes.iter().filter(|r| !r.imported() && r.loc.provider == id).collect();
    let running = matches!(i.vpn.phase, Phase::On | Phase::Paused);
    // Providers that count connections, not devices: each separate tunnel to one of its servers is one.
    let tunnels = if running {
        let mine = |route: &str| {
            i.running.and_then(|run| run.route(Some(route))).is_some_and(|r| !r.imported() && r.loc.provider == id)
        };
        i.tags.iter().filter(|(route, _)| mine(route)).map(|(_, tag)| tag).collect::<HashSet<_>>().len() as i32
    } else {
        0
    };
    // The same line for every provider: its limit (the user's own first), and what unbraid uses of it.
    let lim = pr.limit(acc);
    let counted = row(
        if lim.unit == "device" { "Devices" } else { "Connections" },
        limits::line(
            name,
            limits::effective(&lim, s.opt(id, LIMIT_OPT).as_deref()),
            &lim.unit,
            if lim.per_tunnel { tunnels } else { 1 },
            i.device.and_then(|d| d.used),
        ),
    )
    .act(Act::Dialog, format!("limit:{id}"))
    .icon(Glyph::Phone)
    .end(End::Chevron);
    // A provider whose only server list is gluetun's public one: how old it is.
    let list = pr.list_source().map(|c| {
        let date = i.list_dates.get(&c).map(|t| format!(", published {}", published_on(*t))).unwrap_or_default();
        row("Server list", format!("From gluetun's public list{date}")).icon(Glyph::Dns)
    });
    let plan = std::iter::once("Signed in").chain(i.plan).collect::<Vec<_>>().join(" · ");
    let device = i.device.map(|d| match &d.url {
        Some(u) => row("This computer", &d.line).act(Act::Url, u).icon(Glyph::Info).end(End::External),
        None => row("This computer", &d.line).icon(Glyph::Info),
    });
    let mut groups = vec![group(
        "",
        [Some(row("Account", plan).icon(Glyph::VpnKey)), Some(counted), list, device].into_iter().flatten().collect(),
    )];

    let opt_row = |o: &Opt| {
        let v = s.opt(id, &o.key);
        if o.choices.is_empty() {
            row(&o.label, &o.sub).act(Act::Opt, &o.key).switch(v.as_deref() == Some("on"))
        } else {
            let picked = o.choices.iter().find(|c| Some(&c.0) == v.as_ref()).map_or(o.sub.as_str(), |c| c.1.as_str());
            row(&o.label, picked).act(Act::Dialog, format!("opt:{id}:{}", o.key)).end(End::Chevron)
        }
    };
    // Every provider's own blocking under one name and in one place; unbraid's filter on VPN routes replaces it (shown
    // off, the choice kept). Without a switch the row leads to the filter.
    let custom = custom_dns(s);
    let protect = pr.protection();
    let blocking = match &protect {
        Some(p) => {
            let on = s.opt(id, PROTECT).as_deref() == Some("on") && !custom;
            let mut first = p.sub.chars();
            let sub = first.next().map_or_else(String::new, |c| c.to_lowercase().chain(first).collect());
            let r = row(
                format!("{name} blocking"),
                if custom {
                    format!("Off while {APP}'s filter is on for VPN routes")
                } else {
                    format!("{}: {sub}", p.label)
                },
            )
            .act(Act::Opt, PROTECT)
            .icon(Glyph::Shield)
            .switch(on);
            if custom { r.fixed() } else { r }
        }
        None => {
            let sub = if custom { format!("{APP}'s filter is on for VPN routes") } else { pr.blocking_note() };
            match pr.blocking_url().filter(|_| !custom) {
                Some(u) => row(format!("{name} blocking"), sub).act(Act::Url, u).icon(Glyph::Shield).end(End::External),
                None => {
                    row(format!("{name} blocking"), sub).act(Act::Open, "dns").icon(Glyph::Shield).end(End::Chevron)
                }
            }
        }
    };
    let shown_opts: Vec<&Opt> = i.opts.iter().filter(|o| o.key != PROTECT).collect();
    groups.push(group(
        &format!("{name} settings"),
        std::iter::once(blocking).chain(shown_opts.iter().filter(|o| !o.advanced).map(|o| opt_row(o))).collect(),
    ));
    if !routes.is_empty() {
        groups.push(group(
            "Used by",
            routes
                .iter()
                .map(|r| {
                    let apps = s.apps.values().filter(|v| **v == r.id).count();
                    // A route that turned the provider's blocking on or off for itself says so.
                    let own = r
                        .filter
                        .zip(protect.as_ref())
                        .map(|(on, p)| format!("{} {} here", p.label, if on { "on" } else { "off" }));
                    let uses = if r.id == s.default_route {
                        "Default route".to_string()
                    } else {
                        format!("{apps} {}", if apps == 1 { "app" } else { "apps" })
                    };
                    let line = [Some(uses), i.vpn.servers.get(&r.id).map(|sv| sv.name.clone()), own]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" · ");
                    Row { hue: r.hue, ..row(r.name(), line).end(End::Mark).value(r.code()) }
                })
                .collect(),
        ));
    }
    // How the key was made, read from its config, and where configs are managed: shown, never changed here.
    let adv: Vec<&Opt> = shown_opts.iter().copied().filter(|o| o.advanced).collect();
    let facts = pr.facts(acc);
    let summary = adv
        .iter()
        .map(|o| {
            let v = s.opt(id, &o.key).unwrap_or_default();
            format!("{}: {}", o.label, o.choices.iter().find(|c| c.0 == v).map_or(v.as_str(), |c| c.1.as_str()))
        })
        .chain(facts.as_ref().map(|f| format!("Set in your config: {}", if f.is_empty() { "not known" } else { f })))
        .collect::<Vec<_>>()
        .join(" · ");
    let extra = [
        facts.as_ref().map(|f| {
            row(
                "Set in your config",
                if f.is_empty() { "Not known: sign in with the whole .conf to see them" } else { f },
            )
        }),
        pr.config_help()
            .map(|(text, url)| row(format!("In your {name} account"), text).act(Act::Url, url).end(End::External)),
    ];
    groups.extend(advanced(summary, adv.iter().map(|o| opt_row(o)).chain(extra.into_iter().flatten()).collect()));
    let only =
        i.accounts.len() == 1 && s.servers.is_empty() && !s.routes.iter().any(Route::imported) && !s.home.tailscale;
    let out_sub = match () {
        _ if only => "It's your only connection: you'll be back at sign-in",
        _ if routes.is_empty() => "No route uses it",
        _ => "Apps on its routes are blocked until you sign in again or move them; other routes keep running",
    };
    groups.push(group(
        "",
        vec![row(format!("Sign out of {name}"), out_sub).act(Act::Dialog, format!("signout:{id}")).danger()],
    ));

    let mut dialogs: Vec<Dialog> = i
        .opts
        .iter()
        .filter(|o| !o.choices.is_empty())
        .map(|o| {
            let v = s.opt(id, &o.key);
            sheet(
                format!("opt:{id}:{}", o.key),
                &o.label,
                &o.sub,
                o.choices
                    .iter()
                    .map(|(value, label)| {
                        row(label, "").act(Act::Opt, &o.key).value(value).choice(Some(value) == v.as_ref())
                    })
                    .collect(),
            )
        })
        .collect();
    let unit = &lim.unit;
    let plural = format!(
        "{}{}s",
        unit.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default(),
        unit.chars().skip(1).collect::<String>()
    );
    let leave = lim.value.map_or_else(
        || format!("{name} doesn't tell {APP}, so leave empty if you don't know."),
        |v| format!("Leave empty for {name}'s own figure, {v}."),
    );
    dialogs.push(Dialog {
        inputs: vec![input(&plural, &lim.value.map_or_else(|| "e.g. 5".into(), |v| v.to_string()), s.opt(id, LIMIT_OPT).unwrap_or_default())],
        ..prompt(
            format!("limit:{id}"),
            "Your plan's limit",
            format!("How many {unit}s your {name} plan allows at once. {APP} warns before a change would go over it. {leave}"),
            row("Save", "").act(Act::Limit, id),
        )
    });
    dialogs.push(prompt(
        format!("signout:{id}"),
        format!("Sign out of {name}?"),
        "Routes and app choices stay on this computer. While connected, apps on its routes are blocked until you sign in again or move them to another route.",
        row("Sign out", "").act(Act::SignOut, id).danger(),
    ));
    (groups, dialogs)
}

fn tailscale_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let s = i.setup;
    let h = &s.home;
    let status = tailscale_sub(h.tailscale, i.vpn.phase == Phase::On, i.vpn.ts_state.as_deref());
    let reach_sub = if h.tailscale {
        status
    } else if s.ts_exit().is_some() {
        "Off · Tailscale still runs for your exit-node route".into()
    } else {
        "From apps routed through unbraid".into()
    };
    let login = i.vpn.ts_login_url.as_ref().filter(|_| s.tailscale()).map(|u| Row {
        cta: true,
        ..row("Sign in to Tailscale", "Opens your browser").act(Act::TsLogin, u).end(End::External)
    });
    let mut groups = vec![group(
        "",
        std::iter::once(
            row("Reach your tailnet", reach_sub).act(Act::Tailscale, "").icon(Glyph::Hub).switch(h.tailscale),
        )
        .chain(login)
        .collect(),
    )];
    if s.tailscale() && !i.vpn.ts_exit_nodes.is_empty() {
        let mut nodes = i.vpn.ts_exit_nodes.clone();
        nodes.sort_by_key(|n| !n.online);
        let rows = nodes
            .iter()
            .map(|n| {
                let used = s.routes.iter().filter(|r| r.ts_exit.as_deref() == Some(&n.ip)).count();
                row(
                    &n.name,
                    format!(
                        "{} · {}",
                        if n.online { "Online" } else { "Offline" },
                        if used == 0 { "not used".into() } else { format!("used by {}", routes_word(used)) }
                    ),
                )
            })
            .collect();
        groups.push(group("Exit nodes", rows));
    }
    if s.tailscale() {
        groups.push(caption("Pick an exit node for a route in Routes. Reaching your home network through Tailscale is under Local & home access."));
        // A Headscale server can name any domain: its devices' names answer apps only once the user allows that suffix.
        let suffix = i.vpn.ts_suffix.as_ref().filter(|_| h.tailscale && !official_ts(h)).map(|d| {
            let on = h.ts_suffix_allowed.as_ref() == Some(d);
            let sub = if on {
                format!("On · your server answers every lookup under {d}")
            } else {
                format!("Off · allow to reach devices by name; your server then answers every lookup under {d}")
            };
            row(format!("Device names under {d}"), sub).act(Act::Suffix, d).switch(on)
        });
        let server = row("Control server", h.ts_control_url.clone().unwrap_or_else(|| "Tailscale (default)".into()))
            .act(Act::Dialog, "tsserver")
            .icon(Glyph::Dns)
            .end(End::Chevron);
        groups.extend(advanced(
            format!("Control server: {}", h.ts_control_url.as_deref().unwrap_or("Tailscale")),
            std::iter::once(server).chain(suffix).collect(),
        ));
    }
    // Whatever the sign-in's state, and also with Tailscale off while its node is still kept on the computer.
    if s.tailscale() || i.ts_stored {
        groups.push(group(
            "",
            vec![
                row("Sign out of Tailscale", "Its exit routes are removed; their apps follow the default route")
                    .act(Act::Dialog, "tsout")
                    .danger(),
            ],
        ));
    }
    let dialogs = vec![
        prompt(
            "tsout",
            "Sign out of Tailscale?",
            "Tailscale exit routes are removed. Their apps follow the default route.",
            row("Sign out", "").act(Act::SignOutTailscale, "").danger(),
        ),
        Dialog {
            inputs: vec![
                input("Server URL", "https://headscale.example.com", h.ts_control_url.clone().unwrap_or_default()),
                Input { secret: true, ..input("Auth key (optional)", "Signs in without a browser", "") },
            ],
            error: "Use a full https:// address".into(),
            ..prompt(
                "tsserver",
                "Control server",
                "For a self-hosted Headscale. Changing it signs this computer out of the current tailnet.",
                row("Save", "").act(Act::TsServer, ""),
            )
        },
    ];
    (groups, dialogs)
}

fn local_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let s = i.setup;
    let h = &s.home;
    let status = if h.tailscale {
        tailscale_sub(h.tailscale, i.vpn.phase == Phase::On, i.vpn.ts_state.as_deref())
    } else {
        "Off".into()
    };
    let wg = match &h.wg {
        Some(w) => {
            row("Home WireGuard tunnel", format!("{} · {}", w.name, w.endpoint)).end(End::Remove).value("Remove")
        }
        None => row("Home WireGuard tunnel", "Not set up · import your router's .conf").end(End::Chevron),
    };
    let subnets = h.subnets.join(", ");
    let mut groups = vec![
        group(
            "This network",
            vec![
                row("Local network bypasses the VPN", "Printers, casting and NAS on this network stay reachable")
                    .act(Act::Lan, "")
                    .icon(Glyph::Lan)
                    .switch(s.prefs.lan),
            ],
        ),
        Group {
            error: i.wg_error.unwrap_or_default().into(),
            caption:
                "Reach home from anywhere through Tailscale, or a WireGuard tunnel to your router (e.g. a FRITZ!Box)."
                    .into(),
            ..group(
                "Home, from anywhere",
                vec![
                    row("Through Tailscale", status).act(Act::Open, "tailscale").icon(Glyph::Hub).end(End::Chevron),
                    wg.act(Act::HomeConfig, "").icon(Glyph::Tunnel),
                ],
            )
        },
    ];
    let line = format!(
        "{} · a WireGuard tunnel uses its own config's ranges",
        if subnets.is_empty() { "None" } else { &subnets }
    );
    groups.extend(advanced(
        format!("Home subnets through Tailscale: {}", if subnets.is_empty() { "none" } else { &subnets }),
        vec![
            row("Home subnets through Tailscale", line)
                .act(Act::Dialog, "subnets")
                .icon(Glyph::Router)
                .end(End::Chevron),
        ],
    ));
    let dialogs = vec![Dialog {
        inputs: vec![input("", "192.168.178.0/24", subnets)],
        hint: "Separate several with commas.".into(),
        error: "Private ranges only, in CIDR notation, e.g. 192.168.178.0/24".into(),
        ..prompt("subnets", "Home subnets", "", row("Save", "").act(Act::Subnets, ""))
    }];
    (groups, dialogs)
}

fn behaviour_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let (on, connects, _) = i.login;
    let title = if on {
        format!("Starts at login{}", if connects { " and connects" } else { "" })
    } else {
        "Doesn't start at login".into()
    };
    let at_login = Group {
        caption: format!(
            "Linux has no switch that keeps apps offline whenever {APP} isn't running: before you log in, while paused and if {APP} stops, apps use \
             your normal connection. While {APP} is on, nothing goes around it, and Direct apps use your normal connection."
        ),
        ..group(
            "At login",
            vec![
                row(title, "Set in Desktop, with the tray and the window")
                    .act(Act::Pick, "desktop")
                    .icon(Glyph::Power)
                    .end(End::Chevron),
            ],
        )
    };
    (vec![at_login], vec![])
}

fn dns_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let s = i.setup;
    let f = &s.prefs.filter;
    let dns = f.server();
    // Each filter once, alphabetical, with what it blocks in its own words; none is suggested.
    let mut rows = vec![
        row("None", "Each provider's own blocking, set on its page. Direct apps use the computer's DNS")
            .act(Act::Filter, "")
            .choice(f.id.is_none()),
    ];
    rows.extend(filters().into_iter().map(|d| {
        let on = f.id.as_deref() == Some(&d.id);
        if d.id == "nextdns" {
            let profile = if on { if f.value.trim().is_empty() { "not set" } else { &f.value } } else { "needed" };
            row(&d.name, format!("{} · profile {profile}", d.blocks)).act(Act::Dialog, "filter:nextdns").choice(on)
        } else {
            row(&d.name, &d.blocks).act(Act::Filter, &d.id).choice(on)
        }
    }));
    let own = f.id.as_deref() == Some(OWN);
    let plain = dns.as_ref().is_none_or(|d| d.tls.is_none() && d.path.is_none());
    let own_sub = if own {
        format!("{}{}", f.value, if plain { " · not encrypted" } else { "" })
    } else {
        "https://… (DNS over HTTPS) or tls://… (DNS over TLS)".into()
    };
    rows.push(row("Your own server", own_sub).act(Act::Dialog, "filter:own").choice(own));
    let mut groups = vec![group("unbraid's filter", rows)];
    if dns.is_some() {
        let blocking: Vec<String> = signed_in(i)
            .into_iter()
            .filter_map(|pr| {
                pr.protection().filter(|_| s.opt(pr.id(), PROTECT).as_deref() == Some("on")).map(|p| p.label)
            })
            .collect();
        let routes_sub = if f.routes {
            format!(
                "Replaces each provider's own blocking{}",
                if blocking.is_empty() { String::new() } else { format!(" ({})", blocking.join(", ")) }
            )
        } else {
            "Off · each route uses its provider's own DNS and blocking".into()
        };
        groups.push(group(
            "Where it applies",
            vec![
                row("VPN routes", routes_sub).act(Act::FilterRoutes, "").switch(f.routes),
                row(format!("Direct traffic through {APP}"), "Apps that follow a Direct default route")
                    .act(Act::FilterDirect, "")
                    .switch(f.direct),
            ],
        ));
        let notes = [
            f.routes.then_some("On VPN routes the filter is asked inside each route's own tunnel."),
            f.direct_apps
                .then_some("Apps that pass through can see a VPN is on, which some banking and streaming apps refuse."),
            Some("Each Direct app can be set on its own in Apps."),
        ];
        groups.push(Group {
            caption: notes.into_iter().flatten().collect::<Vec<_>>().join(" "),
            ..group(
                "Apps set to Direct",
                vec![
                    row(format!("Outside {APP}"), "They never touch the VPN and use the computer's DNS")
                        .act(Act::Outside, "")
                        .choice(!f.direct_apps),
                    row(format!("Through {APP}"), "Traffic still goes straight out; lookups use this filter")
                        .act(Act::Through, "")
                        .choice(f.direct_apps),
                ],
            )
        });
    }
    let filter_prompt = |id: &str, title: &str, text: &str, label: &str, placeholder: &str| Dialog {
        inputs: vec![input(
            label,
            placeholder,
            if f.id.as_deref() == Some(id) { f.value.clone() } else { String::new() },
        )],
        ..prompt(format!("filter:{id}"), title, text, row("Save", "").act(Act::SaveFilter, id))
    };
    let dialogs = vec![
        filter_prompt(
            "nextdns",
            "NextDNS profile",
            "The ID of your profile, as on my.nextdns.io (6 characters).",
            "Profile ID",
            "abc123",
        ),
        filter_prompt(
            OWN,
            "Your own server",
            "A DNS over HTTPS address (https://dns.example.com/dns-query), DNS over TLS (tls://dns.example.com), or a plain IPv4 address, which isn't encrypted.",
            "Server",
            "https://dns.example.com/dns-query",
        ),
    ];
    (groups, dialogs)
}

fn stats_page(i: &Inputs) -> (Vec<Group>, Vec<Dialog>) {
    let on = i.setup.prefs.stats;
    let mut rows = vec![
        row("Record usage statistics", "Only on this computer, never uploaded. Turning it off keeps what's saved.")
            .act(Act::Stats, "")
            .icon(Glyph::Stats)
            .switch(on),
    ];
    if i.stats_size > 0 {
        rows.push(row(
            "Saved history",
            format!("{:.1} MB · hourly for a week, daily for about a year", i.stats_size as f64 / 1e6),
        ));
        rows.push(
            row("Delete saved history", "Erase everything recorded so far")
                .act(Act::Dialog, "statsDelete")
                .end(End::Delete)
                .danger(),
        );
    }
    let text = format!(
        "All recorded data, sessions and speed tests are erased from this computer. This can't be undone.{}",
        if on { " Recording stays on." } else { "" }
    );
    (
        vec![group("", rows)],
        vec![prompt(
            "statsDelete",
            "Delete statistics?",
            text,
            row("Delete statistics", "").act(Act::DeleteStats, "").danger(),
        )],
    )
}

fn link(title: &str, url: &str) -> Row {
    row(title, url.trim_start_matches("https://")).act(Act::Url, url).end(End::External)
}

fn legal_page() -> Vec<Group> {
    let credits = CREDITS.iter().chain([&MLAB]).map(|(name, sub)| row(*name, *sub));
    vec![
        group(
            "",
            vec![
                row("Licence", "GNU GPL v3.0 or later: free to use, share and change. No warranty.")
                    .act(Act::Open, "notices")
                    .icon(Glyph::File)
                    .end(End::Chevron),
                link("Source code", SOURCE),
                link("Terms of use", TERMS_URL),
                link("Privacy policy", PRIVACY),
            ],
        ),
        Group {
            caption: trademarks(),
            ..group(
                "Built with",
                credits
                    .chain([row("All licence texts", "In full, as the licences require")
                        .act(Act::Open, "notices")
                        .end(End::Chevron)])
                    .collect(),
            )
        },
    ]
}

fn desktop_page(i: &Inputs) -> Vec<Group> {
    let (on, connects, minimised) = i.login;
    let unless_off = |r: Row| if on { r } else { r.fixed() };
    let minimised_sub = if minimised {
        "Only the tray icon at login; the window opens when you ask"
    } else {
        "The window opens at login too"
    };
    let tray_sub = if i.close_to_tray {
        "The connection stays up; the tray or the launcher brings the window back"
    } else {
        "Closing quits, and the connection ends"
    };
    let theme = |t: Theme, name: &str, sub: String| row(name, sub).act(Act::Theme, name).choice(i.theme == t);
    vec![
        group(
            "At login",
            vec![
                row(format!("Start {APP} when I log in"), "In the background, before your apps go online")
                    .act(Act::Login, "")
                    .switch(on),
                unless_off(
                    row("Connect when it starts", "The routes of the profile in use")
                        .act(Act::Connect, "")
                        .switch(connects),
                ),
                unless_off(row("Start minimised to the tray", minimised_sub).act(Act::Minimised, "").switch(minimised)),
            ],
        ),
        group(
            "Window",
            vec![
                row(format!("Closing the window keeps {APP} in the tray"), tray_sub)
                    .act(Act::CloseToTray, "")
                    .switch(i.close_to_tray),
                row("Remember the window's size and place", "It opens where you left it")
                    .act(Act::RememberWindow, "")
                    .switch(i.remember_window),
            ],
        ),
        Group {
            caption: format!(
                "The tray needs a desktop with a system tray. On GNOME, that's the AppIndicator extension; without one, the launcher's menu and \"{APP} connect\" do its job."
            ),
            ..group(
                "Theme",
                vec![
                    theme(Theme::System, "System", "Follows your desktop's light or dark setting".into()),
                    theme(Theme::Dark, "Dark", format!("{APP}'s own look")),
                    theme(Theme::Light, "Light", "A light ground, the same colours a shade deeper".into()),
                ],
            )
        },
    ]
}

fn about_page(i: &Inputs) -> Vec<Group> {
    // Without a desktop keyring the key is only as safe as the folder it seals: say so, where backups are thought of.
    let key = i.key_file.map(|dir| {
        row(
            "Your logins' key is in a file",
            format!("There was no desktop keyring, so the key that seals your setup is kept beside it, in {dir}. A backup of that folder holds both: keep it private."),
        )
        .icon(Glyph::VpnKey)
    });
    let first = [
        Some(
            row("Take the tour", format!("How {APP} works, in eight stops"))
                .act(Act::Tour, "")
                .icon(Glyph::Routes)
                .end(End::Chevron),
        ),
        Some(row(format!("{TITLE} {VERSION_NAME}"), "sing-box 1.14 · GPL-3.0").icon(Glyph::Info)),
        Some(
            row("Privacy policy", "No analytics, no ads, no account with us").act(Act::Url, PRIVACY).end(End::External),
        ),
        key,
        Some(link("Terms of use", TERMS_URL)),
    ];
    vec![
        group("", first.into_iter().flatten().collect()),
        group(
            "Credits",
            vec![
                Row { wordmark: true, ..row(" by Quiet Crafts", "Its design, its features and most of this code are theirs: this Linux version is based on their Android app").act(Act::Url, "https://unbraid.app").end(End::External) },
                row("The Android app's source", "github.com/Quiet-Crafts/unbraid").act(Act::Url, "https://github.com/Quiet-Crafts/unbraid").end(End::External),
            ],
        ),
        group("Support", vec![row("Free and open source", "Made by one person. A donation helps keep it going.").act(Act::Url, "https://unbraid.app/donate/").end(End::External)]),
    ]
}

/// Every notice in `notices.txt`, its title then its paragraphs, reflowed to the page.
fn notices() -> Vec<Licence> {
    static ALL: LazyLock<Vec<Licence>> = LazyLock::new(|| {
        let line = |title: &str, text: &str| Licence { title: title.into(), text: text.into() };
        NOTICES
            .split("\n=== ")
            .flat_map(|n| {
                let n = n.strip_prefix("=== ").unwrap_or(n);
                let (title, text) = n.split_once('\n').unwrap_or((n, ""));
                let paragraphs: Vec<Licence> = reflow(text.trim())
                    .split("\n\n")
                    .map(str::trim_end)
                    .filter(|p| !p.trim().is_empty())
                    .map(|p| line("", p))
                    .collect();
                std::iter::once(line(title, "")).chain(paragraphs)
            })
            .collect()
    });
    ALL.clone()
}

/// Licence files are hard-wrapped near 80 columns: a single line break inside a paragraph becomes a space, with the
/// spaces around it; a blank line stays, and so does a break before a list item ("* ", "- ", "• ", "1. ", "2) ", "(a) ").
pub fn reflow(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut from, mut j) = (0, 0);
    while j < c.len() {
        if c[j] == '\n' && (j == 0 || c[j - 1] != '\n') && !keeps_break(&c[j + 1..]) {
            let mut start = j;
            while start > from && matches!(c[start - 1], ' ' | '\t') {
                start -= 1;
            }
            out.extend(&c[from..start]);
            out.push(' ');
            j += 1;
            while j < c.len() && matches!(c[j], ' ' | '\t') {
                j += 1;
            }
            from = j;
        } else {
            j += 1;
        }
    }
    out.extend(&c[from..]);
    out
}

/// What follows a line break keeps it: a blank line, or a list item's mark and a space.
fn keeps_break(rest: &[char]) -> bool {
    if rest.first() == Some(&'\n') {
        return true;
    }
    let r = &rest[rest.iter().take_while(|ch| matches!(ch, ' ' | '\t')).count()..];
    let run = |from: usize, f: fn(&char) -> bool| r.iter().skip(from).take_while(|ch| f(ch)).count();
    let mark = match r.first() {
        Some('*' | '•' | '-') => 1,
        Some(d) if d.is_ascii_digit() => {
            let n = run(0, char::is_ascii_digit);
            if matches!(r.get(n), Some('.' | ')')) { n + 1 } else { 0 }
        }
        Some('(') => {
            let n = run(1, |ch| ch.is_ascii_lowercase() || ch.is_ascii_digit());
            if n > 0 && r.get(n + 1) == Some(&')') { n + 2 } else { 0 }
        }
        _ => 0,
    };
    mark > 0 && r.get(mark).is_some_and(|ch| matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C'))
}

static OCTET: &str = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)";
static CIDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"^{OCTET}(\.{OCTET}){{3}}/([12]?\d|3[0-2])$")).unwrap());
static HTTPS_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?(/.*)?$").unwrap());

/// The home subnets typed, as they're saved (each range's own start, once), or none while one isn't a private range in
/// CIDR notation. Empty clears them.
pub fn home_subnets(text: &str) -> Option<Vec<String>> {
    let l: Vec<&str> = text.split([',', ' ', '\t', '\n', '\r']).filter(|t| !t.is_empty()).collect();
    if l.iter().any(|c| !CIDR.is_match(c) || !is_private(c)) {
        return None;
    }
    Some(l.into_iter().filter_map(canonical).collect::<indexmap::IndexSet<_>>().into_iter().collect())
}

/// Whether dialog `key` can save `a`, what's typed in its first field.
pub fn valid(key: &str, a: &str) -> bool {
    match key {
        "filter:own" => own_dns(a).is_some(),
        "filter:nextdns" => {
            Filter { id: Some("nextdns".into()), value: a.into(), ..Filter::default() }.server().is_some()
        }
        "tsserver" => a.trim().is_empty() || HTTPS_URL.is_match(a.trim()),
        "subnets" => home_subnets(a).is_some(),
        k if k.starts_with("limit:") => a.is_empty() || a.parse::<i32>().is_ok_and(|n| (1..=999).contains(&n)),
        k if k.starts_with("server:") => !a.trim().is_empty(),
        _ => true,
    }
}

/// What a dialog's field keeps of what's typed: a limit's digits (three at most), a server's name (40 characters), a
/// filter's address (200).
pub fn clean(key: &str, text: &str) -> String {
    match key {
        k if k.starts_with("limit:") => text.chars().filter(char::is_ascii_digit).take(3).collect(),
        k if k.starts_with("server:") => text.chars().take(40).collect(),
        k if k.starts_with("filter:") => text.chars().take(200).collect(),
        _ => text.into(),
    }
}

/// Reaching the tailnet, on or off.
pub fn set_tailscale(s: &Setup, on: bool) -> Setup {
    let mut s = s.clone();
    s.home.tailscale = on;
    s
}

/// Lets the tailnet's DNS answer every lookup under `suffix`, or stops.
pub fn allow_suffix(s: &Setup, suffix: &str, on: bool) -> Setup {
    let mut s = s.clone();
    s.home.ts_suffix_allowed = on.then(|| suffix.into());
    s
}

pub fn set_lan(s: &Setup, on: bool) -> Setup {
    let mut s = s.clone();
    s.prefs.lan = on;
    s
}

pub fn remove_home_wg(s: &Setup) -> Setup {
    let mut s = s.clone();
    s.home.wg = None;
    s
}

/// Saves the home subnets typed; none while they aren't [`valid`].
pub fn set_subnets(s: &Setup, text: &str) -> Option<Setup> {
    let mut s = s.clone();
    s.home.subnets = home_subnets(text)?;
    Some(s)
}

/// Changes unbraid's filter with `f`: which one, where it applies.
fn with_filter(s: &Setup, f: impl FnOnce(&mut Filter)) -> Setup {
    let mut s = s.clone();
    f(&mut s.prefs.filter);
    s
}

/// The filter is `id` (none: each provider's own blocking).
pub fn set_filter(s: &Setup, id: Option<&str>) -> Setup {
    with_filter(s, |f| f.id = id.map(str::to_string))
}

/// NextDNS with its profile, or the user's own server (`id` [`OWN`]), as typed.
pub fn save_filter(s: &Setup, id: &str, value: &str) -> Setup {
    with_filter(s, |f| {
        f.id = Some(id.into());
        f.value = value.trim().into();
    })
}

pub fn set_filter_routes(s: &Setup, on: bool) -> Setup {
    with_filter(s, |f| f.routes = on)
}

pub fn set_filter_direct(s: &Setup, on: bool) -> Setup {
    with_filter(s, |f| f.direct = on)
}

/// Apps set to Direct pass through unbraid for the filter (`on`), or stay outside it.
pub fn set_filter_direct_apps(s: &Setup, on: bool) -> Setup {
    with_filter(s, |f| f.direct_apps = on)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, OwnServer, WgPeer};

    /// Tailscale's states read as what they are; no status yet while connected is starting, not idle.
    #[test]
    fn tailscale_status_text() {
        assert_eq!("Starting", tailscale_sub(true, true, None));
        assert_eq!("Starting", tailscale_sub(true, true, Some("")));
        assert_eq!("In use by another user on this device", tailscale_sub(true, true, Some("InUseOtherUser")));
        assert_eq!("Sign-in needed", tailscale_sub(true, true, Some("NeedsLogin")));
        assert_eq!("Connected", tailscale_sub(true, true, Some("Running")));
        assert_eq!("Connects with unbraid", tailscale_sub(true, false, None));
    }

    struct World {
        setup: Setup,
        accounts: IndexMap<String, String>,
        stack: Vec<String>,
        vpn: VpnState,
        opts: Vec<Opt>,
        login: (bool, bool, bool),
        size: u64,
    }

    impl World {
        fn new() -> World {
            let lab = WgPeer::new(
                "Home lab",
                "k",
                vec!["10.8.0.2/32".into()],
                "k",
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
                apps: [("firefox", "us"), ("spotify", "it")]
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                servers: vec![OwnServer { id: "s1".into(), wg: Some(lab), ovpn: None, ss: None }],
                ..Setup::default()
            };
            World {
                setup,
                accounts: [("nord".to_string(), "{}".to_string())].into_iter().collect(),
                stack: vec![],
                vpn: VpnState::default(),
                opts: vec![],
                login: (false, true, true),
                size: 0,
            }
        }

        fn at(mut self, stack: &[&str]) -> World {
            self.stack = stack.iter().map(|s| s.to_string()).collect();
            self
        }

        fn view(&self) -> SettingsView {
            let (fresh, dates, setting_up, tags) =
                (["nord".to_string()].into_iter().collect(), IndexMap::new(), HashSet::new(), IndexMap::new());
            view(&Inputs {
                setup: &self.setup,
                vpn: &self.vpn,
                accounts: &self.accounts,
                stack: &self.stack,
                notice: Some("Couldn't reach the control server"),
                fresh: &fresh,
                list_dates: &dates,
                setting_up: &setting_up,
                running: None,
                tags: &tags,
                opts: &self.opts,
                device: None,
                plan: None,
                ts_stored: false,
                login: self.login,
                theme: Theme::System,
                close_to_tray: true,
                remember_window: true,
                stats_size: self.size,
                key_file: None,
                wg_error: None,
                now: 0,
            })
        }
    }

    fn titles(g: &Group) -> Vec<&str> {
        g.rows.iter().map(|r| r.title.as_str()).collect()
    }

    /// The hub is Providers & servers: the providers with their status and use, the user's own servers, then Add connection.
    #[test]
    fn hub_lists_providers_and_servers() {
        let v = World::new().view();
        assert_eq!(
            ("providers", "providers", "Settings", "Providers & servers", false),
            (v.page.as_str(), v.subject.as_str(), v.over.as_str(), v.title.as_str(), v.back)
        );
        assert_eq!("Version 2.8.2", v.version);
        assert_eq!(["VPN providers", "My servers"], [v.groups[0].label.as_str(), v.groups[1].label.as_str()]);
        let nord = &v.groups[0].rows[0];
        assert_eq!(
            ("NordVPN", "Server list up to date · used by 3 routes", Tone::Good, Act::Open, "provider:nord"),
            (nord.title.as_str(), nord.sub.as_str(), nord.tone, nord.act, nord.arg.as_str())
        );
        assert_eq!("WireGuard · used by 1 route", v.groups[1].rows[0].sub);
        assert_eq!("Add connection", v.groups[1].button);
        assert_eq!("Couldn't reach the control server", v.notice);
        assert!(v.dialogs.iter().any(|d| d.key == "server:s1" && d.text == "WireGuard · used by 1 route"));
        let add = v.dialogs.iter().find(|d| d.key == "add").unwrap();
        assert_eq!("Mullvad, Private Internet Access, IVPN, Proton VPN and more", add.rows[0].sub);
        assert_eq!("PureVPN, CyberGhost: download, then import", add.rows[3].sub);
    }

    /// Signed in to nothing, the list says how to start; with no server of its own, Add connection stands alone.
    #[test]
    fn hub_without_providers() {
        let mut w = World::new();
        w.accounts.clear();
        w.setup.servers.clear();
        let v = w.view();
        assert_eq!("No provider yet", v.groups[0].rows[0].title);
        assert_eq!(Act::None, v.groups[0].rows[0].act);
        assert_eq!(
            ("", 0, "Add connection"),
            (v.groups[1].label.as_str(), v.groups[1].rows.len(), v.groups[1].button.as_str())
        );
    }

    /// Desktop: login's two choices grey out while it doesn't start at login, and the theme is one of three.
    #[test]
    fn desktop_choices() {
        let v = World::new().at(&["desktop"]).view();
        assert_eq!(("Desktop", "", false), (v.title.as_str(), v.notice.as_str(), v.back));
        let login = &v.groups[0].rows;
        assert_eq!(
            ("Start unbraid when I log in", Act::Login, false),
            (login[0].title.as_str(), login[0].act, login[0].checked)
        );
        assert_eq!(
            (Act::None, End::Toggle, true),
            (login[1].act, login[1].end, login[1].checked),
            "connecting can't change while it doesn't start"
        );
        assert_eq!(["System", "Dark", "Light"], titles(&v.groups[2])[..]);
        assert!(v.groups[2].rows[0].checked && !v.groups[2].rows[2].checked);
        assert_eq!("unbraid's own look", v.groups[2].rows[1].sub);
        let mut w = World::new().at(&["desktop"]);
        w.login = (true, false, false);
        let v = w.view();
        assert_eq!(
            (Act::Connect, "The window opens at login too"),
            (v.groups[0].rows[1].act, v.groups[0].rows[2].sub.as_str())
        );
    }

    /// A provider's page: its account, limit and blocking; the routes on it with their marks; Advanced settings; and
    /// the sign-out, which says what it leaves.
    #[test]
    fn provider_page() {
        let mut w = World::new().at(&["providers", "provider:nord"]);
        w.opts = provider_opts(providers::get("nord").unwrap(), "{}");
        let v = w.view();
        assert_eq!(
            ("Providers & servers", "NordVPN", true, "nord"),
            (v.over.as_str(), v.title.as_str(), v.back, v.provider.as_str())
        );
        assert_eq!(["Account", "Connections"], titles(&v.groups[0])[..]);
        assert_eq!("Signed in", v.groups[0].rows[0].sub);
        assert!(v.groups[0].rows[1].sub.starts_with("NordVPN allows 10 connections."), "{}", v.groups[0].rows[1].sub);
        assert_eq!("NordVPN settings", v.groups[1].label);
        assert_eq!(
            ("NordVPN blocking", Act::Opt, "protect"),
            (v.groups[1].rows[0].title.as_str(), v.groups[1].rows[0].act, v.groups[1].rows[0].arg.as_str())
        );
        let used = &v.groups[2];
        assert_eq!(
            ("Used by", ["Netherlands", "United States", "Italy"].as_slice()),
            (used.label.as_str(), &titles(used)[..])
        );
        assert_eq!(
            ("Default route", "1 app", "US", 1),
            (used.rows[0].sub.as_str(), used.rows[1].sub.as_str(), used.rows[1].value.as_str(), used.rows[1].hue)
        );
        let adv = v.groups.iter().find(|g| g.advanced).expect("Advanced settings");
        assert_eq!("Advanced settings", adv.rows[0].title);
        assert!(adv.rows[0].sub.contains("MTU: Default (1280)"), "{}", adv.rows[0].sub);
        let out = v.groups.last().unwrap();
        assert_eq!(
            (
                "Sign out of NordVPN",
                "Apps on its routes are blocked until you sign in again or move them; other routes keep running",
                true
            ),
            (out.rows[0].title.as_str(), out.rows[0].sub.as_str(), out.rows[0].danger)
        );
        assert!(v.dialogs.iter().any(|d| d.key == "limit:nord" && d.inputs[0].label == "Connections"));
        assert!(v.dialogs.iter().any(|d| d.key == "opt:nord:mtu" && d.rows.len() == 6));
        // Signed out meanwhile: the page under it shows.
        w.accounts.clear();
        assert_eq!("providers", w.view().page);
    }

    /// The device slot a provider reports is this computer's, and opens the provider's device list when it has one.
    #[test]
    fn device_row() {
        let w = World::new().at(&["providers", "provider:nord"]);
        let (fresh, dates, setting_up, tags) = (HashSet::new(), IndexMap::new(), HashSet::new(), IndexMap::new());
        let device = Device {
            line: "Named unbraid-7f3a in your account".into(),
            url: Some("https://my.example/devices".into()),
            used: Some(3),
        };
        let v = view(&Inputs {
            setup: &w.setup,
            vpn: &w.vpn,
            accounts: &w.accounts,
            stack: &w.stack,
            notice: None,
            fresh: &fresh,
            list_dates: &dates,
            setting_up: &setting_up,
            running: None,
            tags: &tags,
            opts: &[],
            device: Some(&device),
            plan: Some("Paid until 22 Nov 2026"),
            ts_stored: false,
            login: w.login,
            theme: Theme::System,
            close_to_tray: true,
            remember_window: true,
            stats_size: 0,
            key_file: None,
            wg_error: None,
            now: 0,
        });
        let rows = &v.groups[0].rows;
        assert_eq!("Signed in · Paid until 22 Nov 2026", rows[0].sub);
        assert!(rows[1].sub.contains("3 are in use"), "{}", rows[1].sub);
        let this = rows.iter().find(|r| r.icon == Glyph::Info).unwrap();
        assert_eq!(("This computer", Act::Url, End::External), (this.title.as_str(), this.act, this.end));
    }

    /// unbraid's filter on VPN routes turns each provider's blocking switch off, greyed, keeping its choice.
    #[test]
    fn filter_replaces_provider_blocking() {
        let mut w = World::new().at(&["providers", "provider:nord"]);
        w.setup = save_filter(&set_filter_routes(&w.setup, true), "quad9", "");
        w.setup = set_filter(&w.setup, Some("quad9"));
        let row = &w.view().groups[1].rows[0];
        assert_eq!(
            (Act::None, false, "Off while unbraid's filter is on for VPN routes"),
            (row.act, row.checked, row.sub.as_str())
        );
        let dns = w.at(&["dns"]).view();
        assert_eq!(
            ["unbraid's filter", "Where it applies", "Apps set to Direct"],
            dns.groups.iter().map(|g| g.label.as_str()).collect::<Vec<_>>()[..]
        );
        assert!(dns.groups[0].rows.iter().any(|r| r.title == "Quad9" && r.checked));
        assert_eq!(
            "On VPN routes the filter is asked inside each route's own tunnel. Each Direct app can be set on its own in Apps.",
            dns.groups[2].caption
        );
    }

    /// Saved statistics show their size and can be deleted; the stats page says nothing of them before there are any.
    #[test]
    fn stats_history() {
        let mut w = World::new().at(&["stats"]);
        assert_eq!(1, w.view().groups[0].rows.len());
        w.size = 2_345_678;
        let v = w.view();
        assert_eq!("2.3 MB · hourly for a week, daily for about a year", v.groups[0].rows[1].sub);
        assert_eq!(
            (Act::Dialog, "statsDelete", End::Delete),
            (v.groups[0].rows[2].act, v.groups[0].rows[2].arg.as_str(), v.groups[0].rows[2].end)
        );
    }

    /// About names the app as Unbraid by TheOlympus and keeps the Quiet Crafts credit; Legal credits what this app is
    /// built with, and Licences has every notice.
    #[test]
    fn about_and_licences() {
        let v = World::new().at(&["about"]).view();
        assert_eq!("Unbraid by TheOlympus 2.8.2", v.groups[0].rows[1].title);
        assert!(v.groups[1].rows[0].wordmark && v.groups[1].rows[0].title == " by Quiet Crafts");
        let legal = World::new().at(&["legal"]).view();
        let built = titles(&legal.groups[1]);
        assert!(
            built.contains(&"Slint")
                && built.contains(&"rqrr")
                && built.contains(&"sing-box 1.14.4")
                && !built.iter().any(|t| t.contains("Compose"))
        );
        assert_eq!(Some(&"All licence texts"), built.last());
        let notices = World::new().at(&["legal", "notices"]).view();
        assert_eq!(("Legal", "Licences", true), (notices.over.as_str(), notices.title.as_str(), notices.back));
        assert_eq!(("unbraid", ""), (notices.licences[0].title.as_str(), notices.licences[0].text.as_str()));
        assert!(
            notices.licences.iter().filter(|l| !l.title.is_empty()).count() > 400
                && notices.licences.iter().any(|l| l.title.starts_with("slint "))
        );
        assert!(
            notices.licences[1].text.contains("GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007"),
            "the GPL's head is one line"
        );
        assert!(
            notices.licences.iter().all(|l| l.title.is_empty() != l.text.is_empty()),
            "each line is a title or a paragraph"
        );
    }

    /// Single line breaks inside a paragraph become a space; blank lines and list items keep theirs.
    #[test]
    fn reflows_licence_paragraphs() {
        assert_eq!("a b", reflow("a\nb"));
        assert_eq!("a b", reflow("a  \n   b"));
        assert_eq!("a\n\nb", reflow("a\n\nb"));
        assert_eq!("a\n* b\n  - c\n2) d\n(iv) e\n• f", reflow("a\n* b\n  - c\n2) d\n(iv) e\n• f"));
        assert_eq!("terms of 1.5 times", reflow("terms of\n1.5 times"));
        assert_eq!("x (ab)c", reflow("x\n(ab)c"));
    }

    /// Home subnets: private ranges in CIDR notation only, saved as each range's start, once.
    #[test]
    fn home_subnets_typed() {
        assert_eq!(
            Some(vec!["192.168.178.0/24".to_string(), "10.0.0.0/8".to_string()]),
            home_subnets("192.168.178.7/24, 10.1.2.3/8 192.168.178.0/24")
        );
        assert_eq!(Some(vec![]), home_subnets(" "));
        assert_eq!(None, home_subnets("8.8.8.0/24"));
        assert_eq!(None, home_subnets("192.168.1.0"));
        assert_eq!(None, home_subnets("192.168.1.0/33"));
        let s = set_subnets(&Setup::default(), "192.168.178.1/24").unwrap();
        assert_eq!(vec!["192.168.178.0/24".to_string()], s.home.subnets);
    }

    /// What each dialog accepts, and keeps of what's typed.
    #[test]
    fn dialog_fields() {
        assert!(valid("limit:nord", "") && valid("limit:nord", "12") && !valid("limit:nord", "0"));
        assert_eq!("123", clean("limit:nord", "1a2b34"));
        assert!(
            valid("tsserver", "")
                && valid("tsserver", " https://hs.example.com:8080/x ")
                && !valid("tsserver", "http://hs.example.com")
        );
        assert!(valid("filter:own", "tls://dns.example.com") && !valid("filter:own", "dns.example.com"));
        assert!(valid("filter:nextdns", "abc123") && !valid("filter:nextdns", "abc 123"));
        assert!(!valid("server:s1", "  ") && valid("server:s1", "VPS"));
        assert_eq!(40, clean("server:s1", &"x".repeat(50)).len());
    }

    /// The page's own changes: Tailscale, LAN, the home tunnel, the device-name suffix and the filter's choices.
    #[test]
    fn changes() {
        let s = Setup::default();
        assert!(set_tailscale(&s, true).home.tailscale);
        assert!(!set_lan(&s, false).prefs.lan);
        assert_eq!(Some("hs.example".to_string()), allow_suffix(&s, "hs.example", true).home.ts_suffix_allowed);
        assert_eq!(
            None,
            allow_suffix(&allow_suffix(&s, "hs.example", true), "hs.example", false).home.ts_suffix_allowed
        );
        let f = save_filter(&s, "nextdns", " abc123 ").prefs.filter;
        assert_eq!((Some("nextdns"), "abc123"), (f.id.as_deref(), f.value.as_str()));
        assert!(set_filter_direct_apps(&set_filter_direct(&s, true), true).prefs.filter.direct_apps);
        assert_eq!(None, set_filter(&save_filter(&s, OWN, "9.9.9.9"), None).prefs.filter.id);
    }
}
