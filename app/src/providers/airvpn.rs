//! AirVPN over WireGuard. AirVPN issues the key per *device* (Client Area → Devices), together with a device-specific
//! tunnel address and a preshared key; one device's key, address and preshared key serve every server, and every
//! server shares one [Peer] key (kept in the account and used for every server).
//!
//! Sign-in takes either an API key or a whole generated .conf (bare keys are refused). With an API key (Client Area → API,
//! sent as the `API-KEY` header) unbraid makes a device of its own, like other providers' device slots:
//! `GET airvpn.org/api/devices/?action=add` (any name is ignored, it starts as "New device"), `action=modify` names it,
//! `list` shows it `ready` with its key and addresses after about 20 s; sign-out removes it (`action=delete`). Only when
//! AirVPN refuses a new device (all 10 in use, say) does the user pick one of theirs. Then
//! `GET /api/generator/?protocols=wireguard_1_udp_1637&servers=<name>&device=<name>` returns that device's .conf. The
//! generator falls back to the Default device for an unknown name, so the name is always one from the list and the
//! config's address must be the device's own. API errors come back as HTTP 200 with `{"error": …}`.
//! Servers: AirVPN's own status API `GET airvpn.org/api/status/` (no login; the gluetun updater reads it): healthy
//! servers' `ip_v4_in1` is the WireGuard entry and `ip_v4_in3` the alternative one, hostname `<cc>.vpn.airdns.org`.
//! Fallback: gluetun's catalogue, for addresses only: the key is always the account's own, never the catalogue's.
//! WireGuard answers at entries 1 and 3 on ports 1637 and 47107; entry 3 also takes 51820, left out so every port works
//! at either entry (entries 2 and 4 have no WireGuard). DNS 10.128.0.1 (the in-tunnel DNS in AirVPN's configs; a pasted
//! .conf overrides it and the port). Every plan allows 5 connections at once, each to a different server: two tunnels to
//! the *same* server need two devices' keys.

use super::key_provider::{self, Account, KeyProvider};
use super::surfshark::Source;
use super::{AUTO, Device, ENTRY_OPT, Field, Limit, Opt, PORT_OPT, Provider, encode, is_io, plans};
use crate::APP;
use crate::catalog::{self, Entry};
use crate::error::{Challenge, Error, Result};
use crate::http;
use crate::manual::require;
use crate::model::{Country, Link, Location, Server, eq_ignore_case};
use indexmap::IndexMap;
use regex::Regex;
use serde::Deserialize;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

#[derive(Deserialize, Default)]
#[serde(default)]
struct Node {
    #[serde(rename = "public_name")]
    name: String,
    #[serde(rename = "country_name")]
    country: String,
    #[serde(rename = "country_code")]
    code: String,
    location: String,
    continent: String,
    #[serde(rename = "ip_v4_in1")]
    ip: String,
    #[serde(rename = "ip_v4_in3")]
    ip3: String,
    health: String,
    #[serde(rename = "currentload")]
    load: Option<i32>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Status {
    servers: Vec<Node>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub(crate) struct DeviceInfo {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) status: String,
    /// None while AirVPN is still making the device.
    #[serde(rename = "wireguard_public_key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "wireguard_ipv4")]
    pub(crate) ipv4: Option<String>,
}

/// The `devices` reply: the list, or the `id` of a device just added, or an `error`.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Devices {
    devices: Option<Vec<DeviceInfo>>,
    id: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct User {
    premium: bool,
    #[serde(rename = "expiration_unix")]
    expires: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct UserInfo {
    user: Option<User>,
}

const API: &str = "https://airvpn.org/api/";
const DEVICES: &str = "https://airvpn.org/devices/";
const KEYS: &str = "https://airvpn.org/apisettings/";
const DNS_LISTS: &str = "https://airvpn.org/dns/";
const DEVICE: &str = "device";
const PORTS: [i32; 2] = [1637, 47107];
static API_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[0-9a-fA-F]{64}$").unwrap());
/// AmneziaWG obfuscation keys: the engine would drop them silently, so such a config is refused.
static AMNEZIA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?imR)^[[:space:]]*(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5])[[:space:]]*=").unwrap());

fn device_field() -> Field {
    Field { secret: false, hint: "As listed in the Client Area".into(), ..Field::new(DEVICE, "Device name") }
}

/// An AirVPN API call: the service, the API key and the query.
pub(crate) type Api = Arc<dyn Fn(&str, &str, &[(&str, &str)]) -> Result<String> + Send + Sync>;
/// A wait of so many milliseconds.
pub(crate) type Pause = Arc<dyn Fn(u64) + Send + Sync>;

pub(crate) static CATALOGUE: LazyLock<RwLock<Source<Vec<Entry>>>> = LazyLock::new(|| RwLock::new(Arc::new(|| catalog::fetch("airvpn", "wireguard"))));
pub(crate) static STATUS: LazyLock<RwLock<Source<String>>> = LazyLock::new(|| RwLock::new(Arc::new(|| http::get(&format!("{API}status/"), &[], None, None))));
pub(crate) static PAUSE: LazyLock<RwLock<Pause>> = LazyLock::new(|| RwLock::new(Arc::new(|ms| std::thread::sleep(std::time::Duration::from_millis(ms)))));
pub(crate) static API_CALL: LazyLock<RwLock<Api>> = LazyLock::new(|| {
    RwLock::new(Arc::new(|service, key, query| {
        let query = if query.is_empty() { String::new() } else { format!("?{}", query.iter().map(|(k, v)| http::enc(k) + "=" + &http::enc(v)).collect::<Vec<_>>().join("&")) };
        http::get(&format!("{API}{service}/{query}"), &[("API-KEY", key)], None, None)
    }))
});

fn api(service: &str, key: &str, query: &[(&str, &str)]) -> Result<String> {
    let f = API_CALL.read().unwrap_or_else(PoisonError::into_inner).clone();
    f(service, key, query)
}

fn status() -> Result<String> {
    let f = STATUS.read().unwrap_or_else(PoisonError::into_inner).clone();
    f()
}

fn pause(ms: u64) {
    let f = PAUSE.read().unwrap_or_else(PoisonError::into_inner).clone();
    f(ms)
}

pub struct AirVpn;

impl Provider for AirVpn {
    fn id(&self) -> &'static str {
        "airvpn"
    }

    fn name(&self) -> &'static str {
        "AirVPN"
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "The API key, or the whole generated file".into(), file: true, ..Field::new("key", "API key or WireGuard .conf") }]
    }

    fn help(&self) -> String {
        format!(
            "Easiest: in the AirVPN Client Area open API (airvpn.org/apisettings), add an API key and paste it here. {APP} then adds a device of its own to your account, which takes about half a minute, and removes it when you sign out. Or open Config Generator, choose WireGuard, a device and any server, then generate the .conf and paste the whole file."
        )
    }

    /// `currentload` of the status API is the server's load in percent.
    fn has_load(&self) -> bool {
        true
    }

    fn defaults(&self) -> IndexMap<String, String> {
        IndexMap::from([(PORT_OPT.to_string(), AUTO.to_string()), (ENTRY_OPT.to_string(), "1".to_string())])
    }

    fn options(&self, _account: &str) -> Vec<Opt> {
        let ports = std::iter::once((AUTO.to_string(), "Automatic".to_string())).chain(PORTS.map(|p| (p.to_string(), format!("UDP {p}")))).collect();
        vec![
            Opt { choices: ports, advanced: true, ..Opt::new(PORT_OPT, "Port", "Automatic tries one, then the other when a network blocks it") },
            Opt {
                choices: vec![("1".into(), "Standard".into()), ("2".into(), "Alternative".into())],
                advanced: true,
                ..Opt::new(ENTRY_OPT, "Entry address", "Alternative reaches each server on another address, for networks that block the standard one")
            },
        ]
    }

    /// Shown in the Client Area for every plan.
    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "connection".into(), per_tunnel: true, value: Some(5) }
    }

    /// Block lists and anti-geolocation are set only in the Client Area and work through AirVPN's own DNS.
    fn blocking_note(&self) -> String {
        format!("Set in the AirVPN Client Area. It works through AirVPN's DNS, so not while {APP}'s filter is on")
    }

    fn blocking_url(&self) -> Option<String> {
        Some(DNS_LISTS.into())
    }

    fn config_help(&self) -> Option<(String, String)> {
        Some(("Forwarded ports and dynamic DNS are set in the AirVPN Client Area and apply on their own".into(), "https://airvpn.org/ports/".into()))
    }

    /// The device an API sign-in uses; a pasted .conf doesn't say which one it is.
    fn device(&self, blob: &str) -> Option<Device> {
        let a = key_provider::account(blob).ok()?;
        let name = a.device?;
        let line = if a.own_device { format!("Its own device, {name}, removed when you sign out") } else { format!("Uses your device {name}") };
        Some(Device { line: format!("{line}. See all your devices in the AirVPN Client Area"), url: Some(DEVICES.into()), used: None })
    }

    fn plan(&self, blob: &str) -> Option<String> {
        let key = key_provider::account(blob).ok()?.api_key?;
        let body = api("userinfo", &key, &[]).ok()?;
        let u = http::parsed("AirVPN", || serde_json::from_str::<UserInfo>(&body)).ok()?.user?;
        Some(plans::line(Some(u.expires).filter(|e| u.premium && *e > 0), chrono::Utc::now().timestamp()))
    }

    /// With an API key: the device was deleted, or renewed (a new key), in the Client Area.
    fn revoked(&self, blob: &str) -> bool {
        let check = || -> Result<bool> {
            let a = key_provider::account(blob)?;
            let Some(key) = &a.api_key else { return Ok(false) };
            let mine = |d: &DeviceInfo| a.device_id.as_ref().map_or(Some(&d.name) == a.device.as_ref(), |id| d.id == *id) && d.key == a.device_key;
            Ok(!devices(key)?.iter().any(mine))
        };
        check().unwrap_or(false)
    }

    /// Removes the device unbraid made; one of the user's own stays. A device already gone counts as removed.
    fn sign_out(&self, blob: &str) -> bool {
        let release = || -> Result<bool> {
            let a = key_provider::account(blob)?;
            match (a.own_device, &a.api_key, &a.device_id) {
                (true, Some(key), Some(id)) => remove(key, id),
                _ => Ok(true),
            }
        };
        release().unwrap_or(false)
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let text = input.get("key").map_or("", |k| k.trim());
        if API_KEY.is_match(text) {
            return from_api(text, input.get(DEVICE).map(|d| d.trim()));
        }
        require!(
            !AMNEZIA.is_match(text),
            "This config uses Amnezia obfuscation (Jc, S1, H1 and similar lines), which {APP} can't apply. Generate a standard WireGuard config in the AirVPN Config Generator."
        );
        key_provider::sign_in(self, input)
    }

    fn facts(&self, account: &str) -> Option<String> {
        key_provider::facts(self, account)
    }

    fn trusts(&self, link: &Link, account: &str) -> bool {
        key_provider::trusts(self, link, account)
    }

    fn countries(&self, account: &str) -> Result<Vec<Country>> {
        key_provider::countries(self, account)
    }

    fn connect(&self, loc: &Location, account: &str) -> Result<Link> {
        key_provider::connect(self, loc, account)
    }

    fn servers(&self, loc: &Location, account: &str, limit: usize) -> Result<Vec<Server>> {
        key_provider::servers(self, loc, account, limit)
    }
}

impl KeyProvider for AirVpn {
    fn default_address(&self) -> Option<Vec<String>> {
        None
    }

    fn default_dns(&self) -> Vec<String> {
        vec!["10.128.0.1".into()]
    }

    fn default_port(&self) -> i32 {
        1637
    }

    fn preshared_required(&self) -> bool {
        true
    }

    fn ports(&self) -> Vec<i32> {
        PORTS.to_vec()
    }

    /// Entry 1, then entry 3 ([`parse`] keeps both only when the status API lists both).
    fn addresses(&self, e: &Entry) -> Vec<String> {
        if e.ips.len() == 2 { e.ips.clone() } else { vec![] }
    }

    fn entries(&self, a: &Account) -> Result<Vec<Entry>> {
        let listed = status().and_then(|body| parse(&body, a.public_key.as_deref().unwrap_or_default())).and_then(|l| {
            if l.is_empty() { Err(Error::Io("Empty AirVPN server list".into())) } else { Ok(l) }
        });
        match (listed, &a.public_key) {
            (Ok(l), _) => Ok(l),
            // Addresses only, and just the first: the catalogue doesn't say which of a server's addresses is which entry.
            (Err(e), Some(key)) if is_io(&e) => {
                let catalogue = CATALOGUE.read().unwrap_or_else(PoisonError::into_inner).clone();
                Ok(catalogue()?.into_iter().map(|e| Entry { wgpubkey: Some(key.clone()), ips: e.ipv4().map(String::from).into_iter().collect(), ..e }).collect())
            }
            (Err(e), _) => Err(e),
        }
    }

    /// Every AirVPN server shares the account's [Peer] key: no list, pinned server or saved tunnel can change it.
    fn peer_key(&self, sv: &Server, a: &Account) -> String {
        a.public_key.clone().unwrap_or_else(|| sv.public_key.clone())
    }
}

/// A device of unbraid's own; when AirVPN won't add one, the device `wanted` (the user's answer, none before asking) or
/// the only one. The config comes from the generator, kept with the API key that made it.
fn from_api(key: &str, wanted: Option<&str>) -> Result<String> {
    let all = devices(key)?;
    if wanted.is_none()
        && let Some(made) = own(key, &all)?
    {
        return Ok(made);
    }
    let names = all.iter().map(|d| d.name.chars().take(40).collect::<String>()).collect::<Vec<_>>().join(", ");
    let ask = |message: String| Error::Challenge(Box::new(Challenge { message, field: device_field(), image: None, keep: IndexMap::new() }));
    let d = match wanted {
        Some(w) if !w.is_empty() => {
            all.iter().find(|d| eq_ignore_case(&d.name, w)).ok_or_else(|| ask(format!("You have no AirVPN device named {}. Yours: {names}.", w.chars().take(40).collect::<String>())))?
        }
        _ if all.len() == 1 => &all[0],
        _ if all.is_empty() => {
            return Err(Error::Auth {
                message: format!("AirVPN didn't add a device for {APP} and your account has none. Add one in the Client Area, then try again"),
                url: Some(DEVICES.into()),
            });
        }
        _ => {
            return Err(ask(format!(
                "AirVPN didn't add a device for {APP}, maybe because all yours are in use. Which one should it use? Yours: {names}. Or remove one in the Client Area and try again."
            )));
        }
    };
    signed(key, d, false)
}

/// Adds a device, names it and waits until it is ready; none when AirVPN refuses to add one. Only a device AirVPN's
/// reply names is unbraid's: after a lost reply the new one in the list could be another app's, so none is taken over.
/// One that doesn't become ready is removed again ([`remove`]), or the user is told it is left.
fn own(key: &str, before: &[DeviceInfo]) -> Result<Option<String>> {
    let added = api("devices", key, &[("action", "add")]).and_then(|body| reply(&body)).and_then(|r| {
        if r.error.is_some() {
            return Ok(None);
        }
        r.id.filter(|id| !id.trim().is_empty()).map(Some).ok_or_else(|| Error::Io("No device id from AirVPN".into()))
    });
    let id = match added {
        Ok(Some(id)) => id,
        Ok(None) => return Ok(None),
        Err(e @ Error::Auth { .. }) => return Err(e),
        Err(e) if is_io(&e) => {
            return Err(Error::Fail("AirVPN didn't answer while adding a device. If a new device appeared in the Client Area, remove it, then try again".into()));
        }
        Err(e) => return Err(e),
    };
    let mut name = "New device".to_string();
    let mut finish = || -> Result<String> {
        let free = (1..).map(|i| if i == 1 { APP.to_string() } else { format!("{APP} {i}") }).find(|n| !before.iter().any(|d| eq_ignore_case(&d.name, n))).unwrap_or_default();
        failed(&api("devices", key, &[("action", "modify"), ("id", &id), ("name", &free), ("description", &format!("Removed when you sign out of {APP}"))])?)?;
        name = free;
        for _ in 1..=30 {
            pause(2_000);
            if let Some(d) = devices(key)?.into_iter().find(|d| d.id == id && d.name == name && d.status == "ready" && d.key.as_deref().is_some_and(|k| !k.trim().is_empty())) {
                return signed(key, &d, true);
            }
        }
        Err(Error::Fail("AirVPN is still setting up the new device. Try again in a minute".into()))
    };
    match finish() {
        Ok(made) => Ok(Some(made)),
        Err(e) if remove(key, &id).unwrap_or(false) => Err(e),
        Err(_) => Err(Error::Fail(format!(
            "Signing in didn't finish, and {APP} couldn't remove the device it added, {name}. Remove it in the AirVPN Client Area, then try again"
        ))),
    }
}

/// Removes device `id`, once it is no longer being made (AirVPN can undo a delete sent while it still is). True when
/// it is gone or going; false when it couldn't be removed.
fn remove(key: &str, id: &str) -> Result<bool> {
    for _ in 1..=30 {
        let Some(d) = devices(key)?.into_iter().find(|d| d.id == id) else { return Ok(true) };
        if d.status == "deleted" {
            return Ok(true);
        }
        if d.status != "create" {
            let r = reply(&api("devices", key, &[("action", "delete"), ("id", id)])?)?;
            return Ok(r.error.is_none_or(|e| e.to_lowercase().contains("unknown")));
        }
        pause(2_000);
    }
    Ok(false)
}

/// Device `d`'s config from the generator, as an account.
fn signed(key: &str, d: &DeviceInfo, own: bool) -> Result<String> {
    let listed = parse(&status()?, "")?;
    let server = listed.iter().min_by_key(|e| e.load).and_then(|e| e.server_name.clone()).ok_or_else(|| Error::Io("Empty AirVPN server list".into()))?;
    let protocols = format!("wireguard_1_udp_{}", AirVpn.default_port());
    let query: [(&str, &str); 7] = [
        ("protocols", &protocols),
        ("servers", &server),
        ("device", &d.name),
        ("system", "linux"),
        ("resolve", "on"),
        ("iplayer_entry", "ipv4"),
        ("iplayer_exit", "ipv4"),
    ];
    let conf = api("generator", key, &query)?;
    if conf.trim_start().starts_with('{') {
        failed(&conf)?;
        return Err(Error::Fail(format!("AirVPN didn't make a config for {}. Try again later", d.name)));
    }
    let a = key_provider::account(&key_provider::sign_in(&AirVpn, &IndexMap::from([("key".to_string(), conf)]))?)?;
    // A device AirVPN doesn't know gets the Default device's config: the address must be this device's own.
    if let Some(ip) = d.ipv4.as_deref().filter(|ip| !ip.is_empty())
        && !a.address.iter().any(|a| a.split('/').next() == Some(ip))
    {
        return Err(Error::Fail("AirVPN sent another device's config. Try again".into()));
    }
    let device_id = Some(d.id.clone()).filter(|id| !id.is_empty());
    encode(&Account { api_key: Some(key.into()), device: Some(d.name.clone()), device_key: d.key.clone(), device_id, own_device: own, ..a })
}

pub(crate) fn devices(key: &str) -> Result<Vec<DeviceInfo>> {
    let body = api("devices", key, &[])?;
    failed(&body)?;
    Ok(reply(&body)?.devices.unwrap_or_default().into_iter().filter(|d| !d.name.trim().is_empty()).collect())
}

/// A `devices` reply; a refused key fails, any other error is left in [`Devices::error`].
fn reply(body: &str) -> Result<Devices> {
    let r: Devices = http::parsed("AirVPN", || serde_json::from_str(body))?;
    if r.error.as_ref().is_some_and(|e| e.to_lowercase().contains("authoriz")) {
        failed(body)?;
    }
    Ok(r)
}

/// An API reply that is an error: a refused key needs a new one; anything else is a passing failure.
fn failed(body: &str) -> Result<()> {
    let Some(error) = serde_json::from_str::<Devices>(body).ok().and_then(|d| d.error) else { return Ok(()) };
    if error.to_lowercase().contains("authoriz") {
        return Err(Error::Auth { message: "AirVPN didn't accept that API key. Check it in the Client Area under API".into(), url: Some(KEYS.into()) });
    }
    Err(Error::Fail("AirVPN couldn't answer right now. Try again later".into()))
}

pub(crate) fn parse(body: &str, server_key: &str) -> Result<Vec<Entry>> {
    let s: Status = http::parsed("AirVPN", || serde_json::from_str(body))?;
    Ok(s.servers
        .into_iter()
        .filter(|n| n.health == "ok" && n.ip.contains('.') && !n.country.trim().is_empty() && !n.code.trim().is_empty())
        .map(|n| Entry {
            vpn: "wireguard".into(),
            hostname: format!("{}.vpn.airdns.org", n.code),
            city: Some(n.location.replace(", ", " ").replace(',', "")).filter(|c| !c.trim().is_empty()),
            country: Some(n.country),
            region: Some(n.continent),
            server_name: Some(n.name),
            wgpubkey: Some(server_key.into()),
            ips: std::iter::once(n.ip).chain(Some(n.ip3).filter(|ip| ip.contains('.'))).collect(),
            load: n.load.map_or(-1, |l| l.clamp(0, 100)),
            ..Entry::default()
        })
        .collect())
}
