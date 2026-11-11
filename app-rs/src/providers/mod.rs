//! VPN providers unbraid signs in to, and what every provider page shares.

pub mod key_provider;
pub mod nord_api;
pub mod nord;
pub mod mullvad;
pub mod pia;
pub mod proton;
pub mod airvpn;
pub mod ivpn;
pub mod surfshark;
pub mod expressvpn;
pub mod windscribe;

use crate::error::Result;
use crate::model::{Country, Link, Location, Server};
use indexmap::IndexMap;

/// Key of a provider's own blocking switch on its page ("on"/"off"); a route can override it ([`crate::model::Route::filter`]).
pub const PROTECT: &str = "protect";
/// Key of a WireGuard provider's port setting: [`AUTO`] or a port number.
pub const PORT_OPT: &str = "port";
pub const AUTO: &str = "auto";
/// Key of every WireGuard provider's MTU setting: [`AUTO`] is 1280, as in Mullvad's Android app; else up to 1420.
pub const MTU_OPT: &str = "mtu";
pub const MTU_MIN: i32 = 1280;
pub const MTU_MAX: i32 = 1420;
/// Key of a provider's entry address setting: the number of one of a server's entries, from 1.
pub const ENTRY_OPT: &str = "entry";

/// Settings every provider page has, with their defaults.
pub fn common_default(key: &str) -> Option<String> {
    (key == MTU_OPT).then(|| AUTO.to_string())
}

/// The MTU a provider's tunnels use, from its page's [`MTU_OPT`].
pub fn mtu(value: Option<&str>) -> i32 {
    value.and_then(|v| v.parse::<i32>().ok()).filter(|m| (MTU_MIN..=MTU_MAX).contains(m)).unwrap_or(MTU_MIN)
}

/// One sign-in form field. `file` = can hold a whole config file; `qr` = can be filled by scanning a QR code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub secret: bool,
    pub hint: String,
    pub file: bool,
    pub qr: bool,
}

impl Field {
    pub fn new(key: &str, label: &str) -> Self {
        Field { key: key.into(), label: label.into(), secret: true, hint: String::new(), file: false, qr: false }
    }
}

/// A setting on a provider's page, saved in the setup's opts. No `choices` = an on/off switch ("on"/"off").
/// `advanced`: one most people never need, listed under the page's Advanced settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub key: String,
    pub label: String,
    pub sub: String,
    pub choices: Vec<(String, String)>,
    pub advanced: bool,
}

/// What a provider says about the device slot this computer holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub line: String,
    pub url: Option<String>,
    pub used: Option<i32>,
}

/// How many `unit`s ("connection" or "device") an account may use at once, and how unbraid counts its own: one per
/// separate tunnel (`per_tunnel`), or one for the whole account. `value` none = unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub unit: String,
    pub per_tunnel: bool,
    pub value: Option<i32>,
}

/// A VPN provider unbraid can sign in to. Every call may block on the network and runs off the window's thread.
/// `account` is the opaque, sealed blob [`Provider::sign_in`] returned.
pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn fields(&self) -> Vec<Field>;
    /// Where the user finds what `fields` ask for.
    fn help(&self) -> String;
    /// Validates credentials (talking to the provider) and returns what `connect` needs later.
    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String>;
    /// Countries with cities, sorted by name.
    fn countries(&self, account: &str) -> Result<Vec<Country>>;
    /// Picks the best server for `loc` and returns a ready tunnel.
    fn connect(&self, loc: &Location, account: &str) -> Result<Link>;
    /// Up to `limit` servers for a manual pick, best first.
    fn servers(&self, _loc: &Location, _account: &str, _limit: usize) -> Result<Vec<Server>> {
        Ok(vec![])
    }
    fn has_load(&self) -> bool {
        false
    }
    fn one_key(&self) -> bool {
        false
    }
    fn protocol(&self) -> String {
        "WireGuard".into()
    }
    fn sign_out(&self, _account: &str) -> bool {
        true
    }
    fn revoked(&self, _account: &str) -> bool {
        false
    }
    fn trusts(&self, _link: &Link, _account: &str) -> bool {
        true
    }
    fn protection(&self) -> Option<Opt> {
        None
    }
    fn facts(&self, _account: &str) -> Option<String> {
        None
    }
    fn config_help(&self) -> Option<(String, String)> {
        None
    }
    fn list_source(&self) -> Option<String> {
        None
    }
    fn blocking_note(&self) -> String {
        format!("{} can't turn it on or off. Use {}'s Protection filter instead", crate::APP, crate::APP)
    }
    fn blocking_url(&self) -> Option<String> {
        None
    }
    fn options(&self, _account: &str) -> Vec<Opt> {
        vec![]
    }
    fn defaults(&self) -> IndexMap<String, String> {
        IndexMap::new()
    }
    fn blocking_dns(&self, _opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        None
    }
    fn device(&self, _account: &str) -> Option<Device> {
        None
    }
    fn plan(&self, _account: &str) -> Option<String> {
        None
    }
    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "connection".into(), per_tunnel: true, value: None }
    }
    fn key_setup_ms(&self) -> u64 {
        0
    }
}

/// Every provider, in the order the sign-in list shows them.
pub fn all() -> Vec<&'static dyn Provider> {
    vec![]
}

pub fn get(id: &str) -> Option<&'static dyn Provider> {
    all().into_iter().find(|p| p.id() == id)
}

/// Name short enough for a route label: "Nord", "PIA", "Proton".
pub fn short(id: &str) -> String {
    match id {
        "nord" => "Nord".into(),
        "pia" => "PIA".into(),
        "proton" => "Proton".into(),
        "proton-free" => "Proton Free".into(),
        _ => get(id).map(|p| p.name().to_string()).unwrap_or_else(|| id.to_string()),
    }
}

/// A provider page setting's default: the provider's own, else every page's.
pub fn default_opt(provider: &str, key: &str) -> Option<String> {
    get(provider).and_then(|p| p.defaults().get(key).cloned()).or_else(|| common_default(key))
}
