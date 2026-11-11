//! What a setup is: routes, exits, apps, profiles and settings, as the saved files hold them. The JSON is the one the
//! earlier (JVM) app wrote, field for field, so an existing setup opens unchanged: defaults and empty values are left
//! out, unknown keys are ignored.

use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use unicode_segmentation::UnicodeSegmentation;

pub const DIRECT: &str = "direct";
pub const MAX_PROFILES: usize = 20;
/// A profile name's length in characters people see: an emoji or an accented letter counts once.
pub const PROFILE_NAME: usize = 12;
/// The current [`Setup::version`].
pub const VERSION: i32 = 1;

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

/// Where a route exits. Only `provider` set = that provider's fastest server anywhere.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase", default)]
pub struct Location {
    #[serde(skip_serializing_if = "is_nord")]
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    /// Provider-specific region/city id (e.g. Mullvad "se-got", PIA "de-frankfurt").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// NordVPN only: none = NordLynx, else openvpn_udp / openvpn_tcp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned: Option<Server>,
}

fn is_nord(p: &str) -> bool {
    p == "nord"
}

impl Default for Location {
    fn default() -> Self {
        Location { provider: "nord".into(), country_id: None, country_code: None, country: None, city_id: None, city: None, region: None, group: None, protocol: None, pinned: None }
    }
}

impl Location {
    /// A provider's country, as the Kotlin `Location(provider, countryId, countryCode, country)` constructor made one.
    pub fn country(provider: &str, id: i32, code: &str, name: &str) -> Self {
        Location { provider: provider.into(), country_id: Some(id), country_code: Some(code.into()), country: Some(name.into()), ..Default::default() }
    }

    pub fn of(provider: &str) -> Self {
        Location { provider: provider.into(), ..Default::default() }
    }

    pub fn label(&self) -> String {
        if let Some(p) = &self.pinned {
            return p.name.clone();
        }
        match (&self.city, &self.country) {
            (Some(city), country) => format!("{} · {}", country.as_deref().unwrap_or("null"), city),
            (None, Some(country)) => country.clone(),
            (None, None) => "Fastest".into(),
        }
    }

    pub fn code(&self) -> String {
        self.country_code.clone().unwrap_or_else(|| "··".into())
    }

    /// What makes two locations the same place: Nord ids are Nord's own; other providers' ids are derived and changed
    /// once (positions → [`stable_id`]), so those compare by code, city and region instead. Pins compare by server name.
    pub fn ident(&self) -> Location {
        let nord = self.provider == "nord";
        Location {
            country_id: self.country_id.filter(|_| nord),
            city_id: self.city_id.filter(|_| nord),
            pinned: self.pinned.as_ref().map(|p| Server { name: p.name.clone(), host: String::new(), ip: String::new(), public_key: String::new(), load: -1, city: String::new(), country: String::new() }),
            ..self.clone()
        }
    }

    /// How a location is remembered as a favourite: its [`Location::ident`], without server type or protocol.
    pub fn fav_key(&self) -> Location {
        Location { group: None, protocol: None, ..self.ident() }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub name: String,
    pub host: String,
    pub ip: String,
    pub public_key: String,
    pub load: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
}

/// A plain WireGuard peer, e.g. a FRITZ!Box export.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct WgPeer {
    pub name: String,
    pub private_key: String,
    pub address: Vec<String>,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(default = "default_mtu", skip_serializing_if = "is_default_mtu")]
    pub mtu: i32,
    /// Seconds between keepalives as an imported config asks (0 = none); none = unbraid's 25.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<i32>,
}

fn default_mtu() -> i32 {
    1420
}
fn is_default_mtu(m: &i32) -> bool {
    *m == 1420
}

impl WgPeer {
    pub fn new(name: &str, private_key: &str, address: Vec<String>, public_key: &str, endpoint: &str, allowed_ips: Vec<String>) -> Self {
        WgPeer { name: name.into(), private_key: private_key.into(), address, public_key: public_key.into(), preshared_key: None, endpoint: endpoint.into(), allowed_ips, dns: vec![], mtu: 1420, keepalive: None }
    }
}

/// An imported OpenVPN profile (ExpressVPN, CyberGhost…): the raw .ovpn plus its login.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct OvpnProfile {
    pub name: String,
    pub config: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
}

/// A Shadowsocks server (e.g. an Outline access key).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SsProfile {
    pub name: String,
    pub server: String,
    pub port: i32,
    pub method: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
}

/// One exit. Exactly one source: a provider `loc`, an imported `wg`/`ovpn`/`ss` server, or `ts_exit`, a Tailscale
/// exit node (name or 100.x address) reached through the built-in Tailscale client.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub id: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub loc: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovpn: Option<OvpnProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ss: Option<SsProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_exit: Option<String>,
    /// Display name of the `ts_exit` node; `ts_exit` itself holds its tailnet IP so similarly named nodes can't be confused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_name: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub hue: i32,
    /// The provider's own blocking for this route only: none follows the provider's page ([`Setup::protects`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<bool>,
    /// The saved [`OwnServer`] whose config `wg`/`ovpn`/`ss` is a copy of, so renaming or removing it reaches this route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own: Option<String>,
}

impl Route {
    pub fn new(id: &str, loc: Location) -> Self {
        Route { id: id.into(), loc, wg: None, ovpn: None, ss: None, ts_exit: None, ts_name: None, hue: 0, filter: None, own: None }
    }

    pub fn name(&self) -> String {
        if let Some(w) = &self.wg {
            return w.name.clone();
        }
        if let Some(o) = &self.ovpn {
            return o.name.clone();
        }
        if let Some(s) = &self.ss {
            return s.name.clone();
        }
        self.ts_name.clone().or_else(|| self.ts_exit.clone()).or_else(|| self.loc.country.clone()).unwrap_or_else(|| "Fastest".into())
    }

    pub fn code(&self) -> String {
        if self.wg.is_some() {
            "WG".into()
        } else if self.ovpn.is_some() {
            "OV".into()
        } else if self.ss.is_some() {
            "SS".into()
        } else if self.ts_exit.is_some() {
            "TS".into()
        } else {
            self.loc.code()
        }
    }

    /// Not tied to a provider account.
    pub fn imported(&self) -> bool {
        self.wg.is_some() || self.ovpn.is_some() || self.ss.is_some() || self.ts_exit.is_some()
    }

    /// Who carries this route: the provider, or the kind of own server.
    pub fn source(&self) -> String {
        if self.wg.is_some() {
            "WireGuard".into()
        } else if self.ovpn.is_some() {
            "OpenVPN".into()
        } else if self.ss.is_some() {
            "Shadowsocks".into()
        } else if self.ts_exit.is_some() {
            "Tailscale".into()
        } else {
            crate::providers::short(&self.loc.provider)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Home {
    #[serde(skip_serializing_if = "is_default")]
    pub tailscale: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_auth_key: Option<String>,
    /// Self-hosted coordination server (Headscale); none = Tailscale's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_control_url: Option<String>,
    /// LANs behind a Tailscale subnet router, e.g. 192.168.178.0/24. Reached through Tailscale even on other Wi-Fi.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subnets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgPeer>,
    /// A Headscale server's DNS suffix the user allowed to answer every app's lookups under it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_suffix_allowed: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Prefs {
    /// Moved to NordVPN's page ([`Setup::opts`]); read only to carry an older choice over ([`Setup::migrated`]).
    #[serde(skip_serializing_if = "is_true")]
    pub threat_protection: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub custom_dns: Vec<String>,
    #[serde(skip_serializing_if = "is_true")]
    pub lan: bool,
    /// Local statistics; off until the user agrees, and nothing is recorded while off.
    #[serde(skip_serializing_if = "is_default")]
    pub stats: bool,
    /// unbraid's own DNS filter and where it applies.
    #[serde(skip_serializing_if = "is_default")]
    pub filter: Filter,
}

fn is_true(b: &bool) -> bool {
    *b
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { threat_protection: true, custom_dns: vec![], lan: true, stats: false, filter: Filter::default() }
    }
}

/// One of the user's own servers, added in Settings and picked for any route (which keeps a copy of the config).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OwnServer {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovpn: Option<OvpnProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ss: Option<SsProfile>,
}

impl OwnServer {
    pub fn name(&self) -> String {
        self.wg.as_ref().map(|w| w.name.clone()).or_else(|| self.ovpn.as_ref().map(|o| o.name.clone())).or_else(|| self.ss.as_ref().map(|s| s.name.clone())).unwrap_or_default()
    }
    pub fn kind(&self) -> &'static str {
        if self.wg.is_some() {
            "WireGuard"
        } else if self.ovpn.is_some() {
            "OpenVPN"
        } else {
            "Shadowsocks"
        }
    }
    pub fn code(&self) -> &'static str {
        if self.wg.is_some() {
            "WG"
        } else if self.ovpn.is_some() {
            "OVPN"
        } else {
            "SS"
        }
    }
}

/// A saved setup: a default exit and app exceptions. Routes are shared by every profile. An empty profile has no
/// `default_route` yet ("") and can't be used until it gets one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub name: String,
    pub default_route: String,
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub apps: IndexMap<String, String>,
    /// Routes added to this profile, which it lists even while no app uses them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
}

impl Profile {
    pub fn new(name: &str, default_route: &str) -> Self {
        Profile { name: name.into(), default_route: default_route.into(), apps: IndexMap::new(), added: vec![] }
    }
    pub fn with_apps(name: &str, default_route: &str, apps: &[(&str, &str)]) -> Self {
        Profile { apps: apps.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ..Profile::new(name, default_route) }
    }
    pub fn ready(&self) -> bool {
        !self.default_route.is_empty()
    }
    /// The routes this profile lists: its default, those its apps use, and those added to it.
    pub fn own(&self) -> IndexSet<String> {
        let mut s = IndexSet::new();
        s.insert(self.default_route.clone());
        s.extend(self.apps.values().cloned());
        s.extend(self.added.iter().cloned());
        s
    }
}

/// Bidirectional controls and line separators, refused in profile names.
const BIDI: &[char] = &['\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{061C}', '\u{2028}', '\u{2029}'];

/// Characters people see in `s` ([`PROFILE_NAME`] counts these, not bytes).
pub fn graphemes(s: &str) -> usize {
    s.graphemes(true).count()
}

/// The first `n` characters people see of `s`, never splitting one.
pub fn take_graphemes(s: &str, n: usize) -> String {
    s.graphemes(true).take(n).collect()
}

/// An id that stays the same when a provider adds or drops places, so saved routes and favourites keep matching. It is
/// Java's `String.hashCode` of the lower-cased key (UTF-16 units), as the earlier app saved them.
pub fn stable_id(key: &str) -> i32 {
    let mut h: i32 = 0;
    for u in key.to_lowercase().encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(u as i32);
    }
    h & 0x7fff_ffff
}

/// Case-insensitive equality as Kotlin's `equals(ignoreCase = true)` does it, character by character.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    let (mut x, mut y) = (a.chars(), b.chars());
    loop {
        match (x.next(), y.next()) {
            (None, None) => return true,
            (Some(c), Some(d)) => {
                if c != d && !c.to_uppercase().eq(d.to_uppercase()) && !c.to_lowercase().eq(d.to_lowercase()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Setup {
    pub routes: Vec<Route>,
    pub default_route: String,
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub apps: IndexMap<String, String>,
    /// Starred countries, cities or pinned servers, shown first in the picker.
    pub favorites: Vec<Location>,
    #[serde(skip_serializing_if = "is_default")]
    pub home: Home,
    #[serde(skip_serializing_if = "is_default_prefs")]
    pub prefs: Prefs,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<OwnServer>,
    /// Saved format: 1 = provider pages and unbraid's filter. New setups start at the current one ([`crate::store`]).
    #[serde(skip_serializing_if = "is_default")]
    pub version: i32,
    /// Each provider's page settings: provider id → option key → value. Unset keys take the provider's defaults.
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub opts: IndexMap<String, IndexMap<String, String>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<Profile>,
    /// The profile in use's `added`, kept live like `default_route` and `apps`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    /// The profile in use; its saved copy follows every edit ([`Setup::saved`]). None = none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Routes without apps connected only for a combined speed test; never saved.
    #[serde(skip)]
    pub testing: IndexSet<String>,
}

fn is_default_prefs(p: &Prefs) -> bool {
    *p == Prefs::default()
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            routes: vec![Route::new("nl", Location::country("nord", 153, "NL", "Netherlands"))],
            default_route: "nl".into(),
            apps: IndexMap::new(),
            favorites: vec![Location::country("nord", 228, "US", "United States"), Location::country("nord", 106, "IT", "Italy"), Location::country("nord", 153, "NL", "Netherlands")],
            home: Home::default(),
            prefs: Prefs::default(),
            servers: vec![],
            version: 0,
            opts: IndexMap::new(),
            profiles: vec![],
            added: vec![],
            profile: None,
            testing: IndexSet::new(),
        }
    }
}

impl Setup {
    pub fn route(&self, id: Option<&str>) -> Option<&Route> {
        let id = id?;
        self.routes.iter().find(|r| r.id == id)
    }

    /// `profiles` as they stand: the one in use with the current default and exceptions.
    pub fn saved(&self) -> Vec<Profile> {
        self.profiles
            .iter()
            .map(|p| if Some(&p.name) == self.profile.as_ref() { Profile { default_route: self.default_route.clone(), apps: self.apps.clone(), added: self.added.clone(), ..p.clone() } } else { p.clone() })
            .collect()
    }

    /// The live setup as a profile: what is in use.
    fn live(&self) -> Profile {
        Profile { name: self.profile.clone().unwrap_or_default(), default_route: self.default_route.clone(), apps: self.apps.clone(), added: self.added.clone() }
    }

    /// Switches to profile `name` (not an empty one); the one in use keeps what it has now.
    pub fn use_profile(&self, name: &str) -> Setup {
        if Some(name) == self.profile.as_deref() {
            return self.clone();
        }
        match self.profiles.iter().find(|p| p.name == name && p.ready()) {
            Some(p) => Setup { profiles: self.saved(), profile: Some(p.name.clone()), default_route: p.default_route.clone(), apps: p.apps.clone(), added: p.added.clone(), ..self.clone() },
            None => self.clone(),
        }
    }

    /// Saves the current setup as profile `name`, now in use (nothing changes on the connection).
    pub fn save_as(&self, name: &str) -> Setup {
        // The first profile keeps every route shown until now; a later one, what the setup in use lists.
        let keep: Vec<String> = if self.profiles.is_empty() {
            let own = self.live().own();
            let mut v: Vec<String> = self.added.clone();
            v.extend(self.routes.iter().map(|r| r.id.clone()).filter(|id| !own.contains(id)));
            let mut seen = IndexSet::new();
            v.into_iter().filter(|x| seen.insert(x.clone())).collect()
        } else {
            self.added.clone()
        };
        let mut profiles = self.saved();
        profiles.push(Profile { name: name.into(), default_route: self.default_route.clone(), apps: self.apps.clone(), added: keep.clone() });
        Setup { profiles, profile: Some(name.into()), added: keep, ..self.clone() }
    }

    /// Adds profile `name`, not in use: a copy of the current setup, or `empty`.
    pub fn add(&self, name: &str, empty: bool) -> Setup {
        let mut profiles = self.saved();
        profiles.push(if empty { Profile::new(name, "") } else { Profile { name: name.into(), ..self.live() } });
        Setup { profiles, ..self.clone() }
    }

    /// The setup as profile `name` routes it (its default and exceptions), for showing it; itself for the one in use or none.
    pub fn view_as(&self, name: Option<&str>) -> Setup {
        match self.profiles.iter().find(|p| name.is_some() && Some(p.name.as_str()) == name && name != self.profile.as_deref()) {
            Some(p) => Setup { default_route: p.default_route.clone(), apps: p.apps.clone(), added: p.added.clone(), ..self.clone() },
            None => self.clone(),
        }
    }

    /// Routes a page leaves out when showing profile `name` (none = the setup in use): every route that profile doesn't
    /// use or keep ([`Profile::own`]). With no profiles yet, none: every route shows.
    pub fn hidden_routes(&self, name: Option<&str>) -> IndexSet<String> {
        if self.profiles.is_empty() {
            return IndexSet::new();
        }
        let own = self.view_as(name).live().own();
        self.routes.iter().map(|r| r.id.clone()).filter(|id| !own.contains(id)).collect()
    }

    /// Changes the default and exceptions of profile `name` with `f`: only its saved copy, unless it is the one in use (or none).
    pub fn editing(&self, name: Option<&str>, f: impl Fn(Profile) -> Profile) -> Setup {
        let in_use = name.is_none() || name == self.profile.as_deref() || !self.profiles.iter().any(|p| Some(p.name.as_str()) == name);
        if in_use {
            let p = f(self.live());
            return Setup { default_route: p.default_route, apps: p.apps, added: p.added, ..self.clone() };
        }
        Setup { profiles: self.profiles.iter().map(|p| if Some(p.name.as_str()) == name { f(p.clone()) } else { p.clone() }).collect(), ..self.clone() }
    }

    pub fn rename(&self, old: &str, new: &str) -> Setup {
        Setup {
            profiles: self.profiles.iter().map(|p| if p.name == old { Profile { name: new.into(), ..p.clone() } } else { p.clone() }).collect(),
            profile: if self.profile.as_deref() == Some(old) { Some(new.into()) } else { self.profile.clone() },
            ..self.clone()
        }
    }

    /// Deletes profile `name`. The current routes stay as they are, even when it was the one in use.
    pub fn forget(&self, name: &str) -> Setup {
        Setup { profiles: self.profiles.iter().filter(|p| p.name != name).cloned().collect(), profile: self.profile.clone().filter(|p| p != name), ..self.clone() }
    }

    /// Back to what `ran` (the setup the engine still runs after refusing a switch) uses: its profile when still saved,
    /// its default and exceptions as far as their routes still exist. The refused profile keeps what it had.
    pub fn back(&self, ran: &Setup) -> Setup {
        let ok = |id: &str| id == DIRECT || self.route(Some(id)).is_some();
        // Its profile again only if still as it ran: one edited meanwhile keeps those edits, the routes run unprofiled.
        let same = self.profiles.iter().find(|p| Some(&p.name) == ran.profile.as_ref()).filter(|p| p.default_route == ran.default_route && p.apps == ran.apps && p.added == ran.added);
        Setup {
            profiles: self.saved(),
            profile: same.map(|p| p.name.clone()),
            default_route: if ok(&ran.default_route) { ran.default_route.clone() } else { self.default_route.clone() },
            apps: ran.apps.iter().filter(|(_, v)| ok(v)).map(|(k, v)| (k.clone(), v.clone())).collect(),
            added: ran.added.iter().filter(|a| ok(a)).cloned().collect(),
            ..self.clone()
        }
    }

    /// Moves profile `name` `by` places (negative = earlier).
    pub fn move_profile(&self, name: &str, by: i32) -> Setup {
        let Some(i) = self.profiles.iter().position(|p| p.name == name) else { return self.clone() };
        let mut profiles = self.profiles.clone();
        let p = profiles.remove(i);
        let to = (i as i64 + by as i64).clamp(0, profiles.len() as i64) as usize;
        profiles.insert(to, p);
        Setup { profiles, ..self.clone() }
    }

    /// `raw` trimmed, if it can name a profile: not blank, at most [`PROFILE_NAME`] characters, not taken (but by `except`).
    pub fn profile_name(&self, raw: &str, except: Option<&str>) -> Option<String> {
        let n = raw.trim();
        // No control or direction-override characters: a name shows in tiles and shortcuts, where they could disguise it.
        let ok = !n.is_empty()
            && graphemes(n) <= PROFILE_NAME
            && !n.chars().any(|c| c.is_control() || BIDI.contains(&c))
            && !self.profiles.iter().any(|p| Some(p.name.as_str()) != except && eq_ignore_case(&p.name, n));
        ok.then(|| n.to_string())
    }

    /// Profiles left pointing at a removed route: its apps follow the profile's default, a removed default becomes the first route.
    pub fn tidy(&self) -> Setup {
        let ok = |id: &str| id == DIRECT || id.is_empty() || self.routes.iter().any(|r| r.id == id);
        if self.added.iter().all(|a| ok(a)) && self.profiles.iter().all(|p| ok(&p.default_route) && p.apps.values().all(|v| ok(v)) && p.added.iter().all(|a| ok(a))) {
            return self.clone();
        }
        let first = self.routes.first().map(|r| r.id.clone()).unwrap_or_else(|| DIRECT.into());
        Setup {
            added: self.added.iter().filter(|a| ok(a)).cloned().collect(),
            profiles: self
                .profiles
                .iter()
                .map(|p| {
                    let d = if ok(&p.default_route) { p.default_route.clone() } else { first.clone() };
                    Profile { apps: p.apps.iter().filter(|(_, v)| ok(v) && **v != d).map(|(k, v)| (k.clone(), v.clone())).collect(), added: p.added.iter().filter(|a| ok(a)).cloned().collect(), default_route: d, name: p.name.clone() }
                })
                .collect(),
            ..self.clone()
        }
    }

    pub fn route_of(&self, pkg: &str) -> String {
        self.apps.get(pkg).cloned().unwrap_or_else(|| self.default_route.clone())
    }

    /// Routes that carry traffic right now: the default plus any with apps (and those up for a speed test).
    pub fn active_routes(&self) -> Vec<&Route> {
        self.routes.iter().filter(|r| r.id == self.default_route || self.testing.contains(&r.id) || self.apps.values().any(|v| *v == r.id)).collect()
    }

    /// The Tailscale exit node in use, if any active route goes out through one (Tailscale allows one at a time).
    pub fn ts_exit(&self) -> Option<String> {
        self.active_routes().into_iter().find_map(|r| r.ts_exit.clone())
    }

    /// Tailscale runs for home access or for an exit-node route.
    pub fn tailscale(&self) -> bool {
        self.home.tailscale || self.ts_exit().is_some()
    }

    /// Nothing goes through a VPN (Direct default, no app on a route, no home tunnel): running protects nothing.
    pub fn direct_only(&self) -> bool {
        self.default_route == DIRECT && self.apps.values().all(|v| v == DIRECT) && self.home.wg.is_none() && !self.home.tailscale
    }

    /// `provider`'s page setting `key`, or its default.
    pub fn opt(&self, provider: &str, key: &str) -> Option<String> {
        self.opts.get(provider).and_then(|m| m.get(key)).cloned().or_else(|| crate::providers::default_opt(provider, key))
    }

    /// Whether route `r` uses its provider's own blocking: its own choice, else the provider page's.
    pub fn protects(&self, r: &Route) -> bool {
        !r.imported() && r.filter.unwrap_or_else(|| self.opt(&r.loc.provider, crate::providers::PROTECT).as_deref() == Some("on"))
    }

    /// Older saves kept Threat Protection Lite in [`Prefs`] (it now lives on NordVPN's page) and a custom DNS server for
    /// every route (now unbraid's filter set to that server, on VPN routes).
    pub fn migrated(&self) -> Setup {
        if self.version >= VERSION {
            return self.clone();
        }
        // NordVPN routes had no blocking switch of their own: a flag one kept from another provider meant nothing then.
        let mut s = Setup { version: VERSION, routes: self.routes.iter().map(|r| if !r.imported() && r.loc.provider == "nord" { Route { filter: None, ..r.clone() } } else { r.clone() }).collect(), ..self.clone() };
        if !self.prefs.threat_protection {
            let mut nord = self.opts.get("nord").cloned().unwrap_or_default();
            nord.insert(crate::providers::PROTECT.into(), "off".into());
            s.opts.insert("nord".into(), nord);
            s.prefs.threat_protection = true;
        }
        if let Some(first) = self.prefs.custom_dns.first() {
            let filter = if s.prefs.filter.id.is_some() { s.prefs.filter.clone() } else { Filter { id: Some(OWN.into()), value: first.clone(), routes: true, ..Default::default() } };
            s.prefs.custom_dns = vec![];
            s.prefs.filter = filter;
        }
        s
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct City {
    pub id: i32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct Country {
    pub id: i32,
    pub name: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub server_count: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cities: Vec<City>,
}

/// A ready tunnel for one exit, produced at connect time. Tagged as the earlier app's polymorphic JSON was.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(tag = "type")]
pub enum Link {
    /// `ports`: the server's other ports, best first, for a network that blocks the one in the peer's endpoint.
    /// `entries`: the server's entry addresses in the order its provider page numbers them; empty = only the endpoint's.
    #[serde(rename = "app.unbraid.data.WgLink", rename_all = "camelCase")]
    Wg {
        server: Server,
        peer: WgPeer,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ports: Vec<i32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        entries: Vec<String>,
    },
    #[serde(rename = "app.unbraid.data.OvpnLink")]
    Ovpn { server: Server, profile: OvpnProfile },
    #[serde(rename = "app.unbraid.data.SsLink")]
    Ss { server: Server, profile: SsProfile },
    /// Goes out through the built-in Tailscale client's exit node.
    #[serde(rename = "app.unbraid.data.TsLink")]
    Ts { server: Server },
}

impl Link {
    pub fn server(&self) -> &Server {
        match self {
            Link::Wg { server, .. } | Link::Ovpn { server, .. } | Link::Ss { server, .. } | Link::Ts { server } => server,
        }
    }
}

// ---- unbraid's own DNS filter ------------------------------------------------------------------------------------

/// The user's own filter server ([`Filter::id`]).
pub const OWN: &str = "own";

/// unbraid's own DNS filter, and where it applies. `id` is one of [`filters`] or [`OWN`]; none = no filter, so every
/// route keeps its provider's own blocking and Direct traffic the computer's DNS.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// NextDNS: the profile ID. Own server: https://host/path (DoH), tls://host (DoT) or a plain IPv4 address.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// VPN routes ask the filter, through their own tunnel, instead of their provider's resolver or blocking.
    #[serde(skip_serializing_if = "is_default")]
    pub routes: bool,
    /// Apps that follow a Direct default route ask the filter instead of the computer's DNS.
    #[serde(skip_serializing_if = "is_default")]
    pub direct: bool,
    /// Apps set to Direct pass through unbraid (still straight out) so their lookups use the filter.
    #[serde(skip_serializing_if = "is_default")]
    pub direct_apps: bool,
    /// Apps set to Direct that differ from `direct_apps`: app → through unbraid.
    #[serde(skip_serializing_if = "IndexMap::is_empty")]
    pub apps: IndexMap<String, bool>,
}

impl Filter {
    /// Whether Direct app `pkg` passes through unbraid for the filter.
    pub fn through(&self, pkg: &str) -> bool {
        self.server().is_some() && self.apps.get(pkg).copied().unwrap_or(self.direct_apps)
    }

    /// The resolver to ask, or none when none is set or it can't be used.
    pub fn server(&self) -> Option<Dns> {
        match self.id.as_deref() {
            None => None,
            Some(OWN) => own_dns(&self.value),
            Some("nextdns") => {
                let p = self.value.trim();
                if !NEXTDNS.is_match(p) {
                    return None;
                }
                filter_by_id("nextdns").map(|d| Dns { path: Some(format!("/{p}")), private_dns: Some(format!("{p}.dns.nextdns.io")), ..d })
            }
            Some(id) => filter_by_id(id),
        }
    }
}

/// A filtering resolver: `ip` port `port`; `path` none = DNS over TLS, else over HTTPS; `tls` none with no path = plain
/// DNS. `private_dns`: Android's Private DNS name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dns {
    pub id: String,
    pub name: String,
    pub blocks: String,
    pub ip: String,
    pub tls: Option<String>,
    pub path: Option<String>,
    pub port: i32,
    pub private_dns: Option<String>,
}

impl Dns {
    /// As the Kotlin constructor's defaults made one: DNS over HTTPS at /dns-query, its port from the kind.
    fn public(id: &str, name: &str, blocks: &str, ip: &str, tls: &str) -> Dns {
        Dns { id: id.into(), name: name.into(), blocks: blocks.into(), ip: ip.into(), tls: Some(tls.into()), path: Some("/dns-query".into()), port: 443, private_dns: Some(tls.into()) }
    }
}

/// Public filtering resolvers, alphabetical, each reached by its address with its TLS name, so no lookup is needed to find it.
pub fn filters() -> Vec<Dns> {
    vec![
        Dns::public("adguard", "AdGuard DNS", "Ads and trackers", "94.140.14.14", "dns.adguard-dns.com"),
        Dns::public("adguard-family", "AdGuard DNS Family", "Ads, trackers and adult sites", "94.140.14.15", "family.adguard-dns.com"),
        Dns::public("cloudflare-security", "Cloudflare 1.1.1.2", "Malware", "1.1.1.2", "security.cloudflare-dns.com"),
        Dns::public("cloudflare-family", "Cloudflare 1.1.1.3", "Malware and adult sites", "1.1.1.3", "family.cloudflare-dns.com"),
        Dns { private_dns: None, ..Dns::public("nextdns", "NextDNS", "What your NextDNS profile blocks", "45.90.28.0", "dns.nextdns.io") },
        Dns::public("quad9", "Quad9", "Malware", "9.9.9.9", "dns.quad9.net"),
    ]
}

pub fn filter_by_id(id: &str) -> Option<Dns> {
    filters().into_iter().find(|d| d.id == id)
}

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$").unwrap());
// The Kotlin pattern's "(?=.{1,253}$)" look-ahead is the length check in host_name().
static HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$").unwrap());
static OWN_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(https|tls)://([A-Za-z0-9.-]+)(?::(\d{1,5}))?(/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*)?$").unwrap());
static NEXTDNS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9]{1,32}$").unwrap());

pub fn is_ipv4(s: &str) -> bool {
    IPV4.is_match(s)
}

fn host_name(s: &str) -> bool {
    (1..=253).contains(&s.chars().count()) && HOST.is_match(s)
}

/// The user's own server: "https://host[:port]/path", "tls://host[:port]" or a plain IPv4 address (not encrypted). A host
/// name is looked up through the same route (see the compiler); none when it isn't one of these.
pub fn own_dns(text: &str) -> Option<Dns> {
    let t = text.trim();
    if is_ipv4(t) {
        return Some(Dns { id: OWN.into(), name: t.into(), blocks: String::new(), ip: t.into(), tls: None, path: None, port: 53, private_dns: None });
    }
    let m = OWN_URL.captures(t)?;
    let group = |i: usize| m.get(i).map(|g| g.as_str()).unwrap_or("");
    let (scheme, raw_host, port, path) = (group(1), group(2), group(3), group(4));
    let host = raw_host.to_lowercase().trim_end_matches('.').to_string();
    if !is_ipv4(&host) && !host_name(&host) {
        return None;
    }
    let https = scheme == "https";
    let p = if port.is_empty() {
        if https { 443 } else { 853 }
    } else {
        match port.parse::<i32>() {
            Ok(n) if (1..=65535).contains(&n) => n,
            _ => return None,
        }
    };
    if !https && !path.is_empty() {
        return None;
    }
    Some(Dns {
        id: OWN.into(),
        name: t.into(),
        blocks: String::new(),
        ip: host.clone(),
        tls: if is_ipv4(&host) && https { None } else { Some(host.clone()) },
        path: if https { Some(if path.is_empty() { "/dns-query".into() } else { path.into() }) } else { None },
        port: p,
        private_dns: if !https && !is_ipv4(&host) { Some(host.clone()) } else { None },
    })
}

/// Whether `d` is reached by name, so it needs a lookup first.
pub fn by_name(d: &Dns) -> bool {
    !is_ipv4(&d.ip)
}
