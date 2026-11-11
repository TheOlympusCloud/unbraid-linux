//! Mullvad over WireGuard. Account blob: account number, WireGuard private key, assigned tunnel address and device id.
//!
//! Sign-in follows mullvad-api (github.com/mullvad/mullvadvpn-app): `POST auth/v1/token {account_number}` gives an
//! `access_token`; `POST accounts/v1/devices {pubkey, hijack_dns}` with `Authorization: Bearer` returns 201 with the
//! device `id` and `ipv4_address`. One device (one of the account's 5) serves every relay.
//! Server list: `GET /public/relays/wireguard/v2`; port 51820 and DNS 10.64.0.1 as in Mullvad's own mullvad-wg.sh.
//! Every relay takes WireGuard on any port in the list's `port_ranges`; [`PORTS`] are the ones Automatic tries.
//! Blocking DNS is 100.64.0.N, N the sum of the categories (ads 1, trackers 2, malware 4, adult 8, gambling 16, social 32).
//! Sign-out frees the slot: `DELETE accounts/v1/devices/{id}` (204) with a fresh token. A device reply lost in transit
//! would orphan a slot, so a transport failure on the POST is reconciled by listing `GET accounts/v1/devices` and adopting
//! the entry with our public key.
//! INVALID_ACCOUNT / MAX_DEVICES_REACHED are matched on the response body, not the HTTP status.
//! Its page reads the paid-until date from `GET accounts/v1/accounts/me` and the device count from the device list.

use super::{AUTO, Device, Field, Limit, Opt, PORT_OPT, PROTECT, Provider, encode, is_io, plans, unless_io};
use crate::error::{Error, Result};
use crate::manual::require;
use crate::model::{City, Country, Link, Location, Server, WgPeer, eq_ignore_case, stable_id};
use crate::{APP, http, limits};
use indexmap::{IndexMap, IndexSet};
use rand::Rng;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;

/// Curve25519 key pairs in WireGuard's base64 form, for providers that register our own public key.
pub(crate) mod wg_keys {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use x25519_dalek::{PublicKey, StaticSecret};

    pub(crate) struct Keys {
        pub private: String,
        pub public: String,
    }

    pub(crate) fn generate() -> Keys {
        keys(rand::random())
    }

    /// The pair for 32 random bytes, the private key clamped as WireGuard writes it.
    pub(crate) fn keys(mut raw: [u8; 32]) -> Keys {
        raw[0] &= 248;
        raw[31] = (raw[31] & 127) | 64;
        let public = PublicKey::from(&StaticSecret::from(raw));
        Keys { private: STANDARD.encode(raw), public: STANDARD.encode(public.as_bytes()) }
    }
}

/// POSTs JSON and returns status and body without failing on 4xx: Mullvad and IVPN report why a sign-in failed in the
/// error body, which [`http`] discards. The request is sent once, never replayed (a registration whose reply was lost
/// must not be made twice); any error therefore means no HTTP status was seen.
pub(crate) fn post_json_raw(url: &str, body: &str, headers: &[(&str, &str)]) -> Result<(u16, String)> {
    let io = |e: reqwest::Error| Error::Io(e.without_url().to_string());
    let client = reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(http::named(None, None)?)
        .https_only(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(io)?;
    let mut request = client.post(url).header("Accept", "application/json").header("Content-Type", "application/json").body(body.to_string());
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let reply = request.send().map_err(io)?;
    let code = reply.status().as_u16();
    let mut text = Vec::new();
    reply.take(1 << 20).read_to_end(&mut text)?;
    Ok((code, String::from_utf8_lossy(&text).into_owned()))
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account: String,
    pub private_key: String,
    pub ipv4_address: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceReply {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) pubkey: String,
    pub(crate) ipv4_address: String,
    #[serde(default)]
    pub(crate) name: String,
}

#[derive(Deserialize)]
struct AccountReply {
    #[serde(default)]
    expiry: Option<String>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Loc {
    pub(crate) country: String,
    pub(crate) city: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Relay {
    pub(crate) hostname: String,
    pub(crate) location: String,
    #[serde(default = "yes")]
    pub(crate) active: bool,
    #[serde(rename = "ipv4_addr_in")]
    pub(crate) ip: String,
    pub(crate) public_key: String,
    #[serde(rename = "include_in_country", default = "yes")]
    pub(crate) in_country: bool,
    #[serde(default)]
    pub(crate) weight: i32,
    #[serde(default)]
    pub(crate) owned: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Wireguard {
    #[serde(default)]
    pub(crate) relays: Vec<Relay>,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RelayList {
    #[serde(default)]
    pub(crate) locations: IndexMap<String, Loc>,
    #[serde(default)]
    pub(crate) wireguard: Wireguard,
}

impl RelayList {
    /// Active relays whose location is known.
    pub(crate) fn usable(&self) -> impl Iterator<Item = &Relay> {
        self.wireguard.relays.iter().filter(|r| r.active && self.locations.contains_key(&r.location))
    }
}

const API: &str = "https://api.mullvad.net";
const DNS: &str = "10.64.0.1";
const PORT: i32 = 51820;
/// Automatic's order: the standard port, then ones restrictive networks tend to leave open. All inside Mullvad's ranges.
const PORTS: [i32; 4] = [PORT, 53, 123, 4500];
const OWNED: &str = "owned";
/// Categories added to the base ads, trackers and malware (7), with their bit in the blocking address.
const EXTRA: [(&str, i32, &str); 3] = [("adult", 8, "Adult content"), ("gambling", 16, "Gambling"), ("social", 32, "Social media")];
const SLOTS: i32 = 5;
const DEVICES: &str = "https://mullvad.net/account/devices";

pub struct Mullvad;

impl Provider for Mullvad {
    fn id(&self) -> &'static str {
        "mullvad"
    }

    fn name(&self) -> &'static str {
        "Mullvad"
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "16 digits".into(), ..Field::new("account", "Account number") }]
    }

    fn help(&self) -> String {
        format!(
            "Your 16-digit account number: shown when you created the account, and at mullvad.net/account after logging in. Each account has 5 device slots; {APP} uses one."
        )
    }

    fn protection(&self) -> Option<Opt> {
        Some(Opt::new(PROTECT, "DNS content blocking", "Ads, trackers and malware"))
    }

    fn defaults(&self) -> IndexMap<String, String> {
        [(PROTECT, "off"), (PORT_OPT, AUTO), (OWNED, "off")].into_iter().chain(EXTRA.map(|(k, ..)| (k, "off"))).map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn blocking_dns(&self, opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        Some(format!("100.64.0.{}", 7 + EXTRA.iter().map(|(k, bit, _)| if opts(k).as_deref() == Some("on") { *bit } else { 0 }).sum::<i32>()))
    }

    fn options(&self, _account: &str) -> Vec<Opt> {
        let ports = std::iter::once((AUTO.to_string(), "Automatic".to_string())).chain(PORTS.map(|p| (p.to_string(), format!("UDP {p}")))).collect();
        EXTRA
            .iter()
            .map(|(k, _, label)| Opt::new(k, label, "Also blocked while Mullvad blocking is on"))
            .chain([
                Opt::new(OWNED, "Mullvad-owned servers only", "Leaves out servers Mullvad rents. Servers you pinned stay"),
                Opt { choices: ports, advanced: true, ..Opt::new(PORT_OPT, "Port", "Automatic tries 51820 first, then other ports when a network blocks it") },
            ])
            .collect()
    }

    /// Five device slots per account; unbraid registers one.
    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "device".into(), per_tunnel: false, value: Some(SLOTS) }
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let n: String = input.get("account").map_or("", String::as_str).chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
        require!(n.len() == 16 && n.bytes().all(|b| b.is_ascii_digit()), "A Mullvad account number has 16 digits");
        let token = access_token(&n)?;
        let keys = wg_keys::generate();
        let reply = match post_json_raw(&format!("{API}/accounts/v1/devices"), &format!(r#"{{"pubkey":"{}","hijack_dns":false}}"#, keys.public), &[("Authorization", &bearer(&token))]) {
            Ok(reply) => reply,
            Err(e) if is_io(&e) => return adopted(&token, &n, &keys).ok_or(e),
            Err(e) => return Err(e),
        };
        device(reply, &n, &keys.private)
    }

    fn sign_out(&self, blob: &str) -> bool {
        let release = || -> Result<()> {
            let a = account(blob)?;
            let token = access_token(&a.account)?;
            match http::delete(&format!("{API}/accounts/v1/devices/{}", http::enc(&a.device_id)), &[("Authorization", &bearer(&token))]) {
                Err(Error::Status { code: 404 }) | Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        };
        release().is_ok()
    }

    /// Mullvad answers 404 for a device removed from the account.
    fn revoked(&self, blob: &str) -> bool {
        let check = || -> Result<String> {
            let a = account(blob)?;
            http::get(&format!("{API}/accounts/v1/devices/{}", http::enc(&a.device_id)), &[("Authorization", &bearer(&access_token(&a.account)?))], None, None)
        };
        match check() {
            Ok(_) => false,
            Err(Error::Status { code }) => code == 404,
            Err(Error::Auth { .. }) => true,
            Err(_) => false,
        }
    }

    /// This computer's device and how many of the slots are taken (the page's device count); offline, the name saved at
    /// sign-in.
    fn device(&self, blob: &str) -> Option<Device> {
        let a = account(blob).ok()?;
        let list = access_token(&a.account)
            .and_then(|token| http::get(&format!("{API}/accounts/v1/devices"), &[("Authorization", &bearer(&token))], None, None))
            .and_then(|body| devices(&body))
            .ok();
        Some(device_line(&a, list.as_deref()))
    }

    fn plan(&self, blob: &str) -> Option<String> {
        let token = access_token(&account(blob).ok()?.account).ok()?;
        let body = http::get(&format!("{API}/accounts/v1/accounts/me"), &[("Authorization", &bearer(&token))], None, None).ok()?;
        expiry(&body).ok()?.map(|t| plans::line(Some(t), chrono::Utc::now().timestamp()))
    }

    fn countries(&self, _account: &str) -> Result<Vec<Country>> {
        Ok(countries(&fetch()?, owned_only()))
    }

    /// A pinned server is looked up in the fresh list so a changed IP or key is picked up; if the list is unreachable the
    /// pinned values are used.
    fn connect(&self, loc: &Location, blob: &str) -> Result<Link> {
        let list = if loc.pinned.is_none() { Some(fetch()?) } else { unless_io(fetch())? };
        link(list.as_ref(), loc, &account(blob)?, &mut rand::rng(), owned_only())
    }

    fn servers(&self, loc: &Location, _account: &str, limit: usize) -> Result<Vec<Server>> {
        let l = fetch()?;
        let mut rs = matching(&l, loc, owned_only());
        rs.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.hostname.cmp(&b.hostname)));
        Ok(rs.into_iter().take(limit).map(|r| server(r, &l)).collect())
    }
}

pub(crate) fn devices(body: &str) -> Result<Vec<DeviceReply>> {
    http::parsed("Mullvad", || serde_json::from_str(body))
}

pub(crate) fn device_line(a: &Account, list: Option<&[DeviceReply]>) -> Device {
    let name = list.and_then(|l| l.iter().find(|d| d.id == a.device_id)).map_or(a.device.as_str(), |d| d.name.as_str());
    let name = name.split(' ').map(capitalized).collect::<Vec<_>>().join(" ");
    Device {
        line: format!("Its own device{}, removed when you sign out", if name.trim().is_empty() { String::new() } else { format!(", {name}") }),
        url: Some(DEVICES.into()),
        used: list.map(|l| l.len() as i32),
    }
}

fn capitalized(word: &str) -> String {
    let mut chars = word.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// The paid-until time (epoch seconds) from an `accounts/me` reply, e.g. "2026-11-22T12:00:00+00:00".
pub(crate) fn expiry(body: &str) -> Result<Option<i64>> {
    let reply: AccountReply = http::parsed("Mullvad", || serde_json::from_str(body))?;
    Ok(reply.expiry.and_then(|e| chrono::DateTime::parse_from_rfc3339(&e).ok()).map(|t| t.timestamp()))
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn access_token(account: &str) -> Result<String> {
    token(post_json_raw(&format!("{API}/auth/v1/token"), &format!(r#"{{"account_number":"{account}"}}"#), &[])?)
}

/// The device Mullvad registered for `keys` although its reply never arrived, if the account lists one.
fn adopted(token: &str, account: &str, keys: &wg_keys::Keys) -> Option<String> {
    http::get(&format!("{API}/accounts/v1/devices"), &[("Authorization", &bearer(token))], None, None).and_then(|list| adopt(&list, account, keys)).ok().flatten()
}

pub(crate) fn adopt(list: &str, account: &str, keys: &wg_keys::Keys) -> Result<Option<String>> {
    devices(list)?.into_iter().find(|d| d.pubkey == keys.public).map(|d| blob(account, &keys.private, d)).transpose()
}

pub(crate) fn token((code, body): (u16, String)) -> Result<String> {
    if code == 400 && body.contains("INVALID_ACCOUNT") || code == 401 || code == 403 {
        return Err(Error::Auth { message: "Mullvad doesn't recognise that account number".into(), url: None });
    }
    if !(200..=299).contains(&code) {
        return Err(Error::Status { code });
    }
    Ok(http::parsed("Mullvad", || serde_json::from_str::<TokenReply>(&body))?.access_token)
}

pub(crate) fn device((code, body): (u16, String), account: &str, private_key: &str) -> Result<String> {
    if body.contains("MAX_DEVICES_REACHED") {
        return Err(Error::Auth { message: limits::full("Mullvad", Some(SLOTS), "device"), url: Some(DEVICES.into()) });
    }
    if code == 401 || code == 403 {
        return Err(Error::Auth { message: "Mullvad refused the device registration".into(), url: None });
    }
    if code != 201 {
        return Err(Error::Status { code });
    }
    blob(account, private_key, http::parsed("Mullvad", || serde_json::from_str(&body))?)
}

fn blob(account: &str, private_key: &str, d: DeviceReply) -> Result<String> {
    encode(&Account { account: account.into(), private_key: private_key.into(), ipv4_address: d.ipv4_address, device_id: d.id, device: d.name })
}

pub fn account(blob: &str) -> Result<Account> {
    http::parsed("Mullvad", || serde_json::from_str(blob))
}

fn owned_only() -> bool {
    super::opt("mullvad", OWNED).as_deref() == Some("on")
}

fn fetch() -> Result<RelayList> {
    parse(&http::get(&format!("{API}/public/relays/wireguard/v2"), &[], None, None)?)
}

pub(crate) fn parse(body: &str) -> Result<RelayList> {
    http::parsed("Mullvad", || serde_json::from_str(body))
}

pub(crate) fn countries(l: &RelayList, owned_only: bool) -> Vec<Country> {
    let mut groups: IndexMap<&str, Vec<&Relay>> = IndexMap::new();
    for r in l.usable().filter(|r| r.owned || !owned_only) {
        groups.entry(r.location.split('-').next().unwrap_or_default()).or_default().push(r);
    }
    let country = |r: &Relay| l.locations[&r.location].country.clone();
    let mut groups: Vec<(&str, Vec<&Relay>)> = groups.into_iter().collect();
    groups.sort_by_key(|(_, rs)| country(rs[0]));
    groups
        .into_iter()
        .map(|(cc, rs)| {
            let mut cities: Vec<(&str, &str)> =
                rs.iter().map(|r| r.location.as_str()).collect::<IndexSet<_>>().into_iter().map(|code| (code, l.locations[code].city.as_str())).collect();
            cities.sort_by_key(|(_, city)| *city);
            Country {
                id: stable_id(cc),
                name: country(rs[0]),
                code: cc.to_uppercase(),
                server_count: rs.len() as i32,
                cities: cities.into_iter().map(|(code, city)| City { id: stable_id(code), name: city.into(), key: Some(code.into()) }).collect(),
            }
        })
        .collect()
}

/// Relays for `loc`: a city if [`Location::region`] is set, else its country; `include_in_country = false` relays only by city.
pub(crate) fn matching<'a>(l: &'a RelayList, loc: &Location, owned_only: bool) -> Vec<&'a Relay> {
    l.usable()
        .filter(|r| {
            (r.owned || !owned_only)
                && match (&loc.region, &loc.country_code, &loc.country) {
                    (Some(region), ..) => r.location == *region,
                    (None, Some(cc), _) => r.in_country && eq_ignore_case(r.location.split('-').next().unwrap_or_default(), cc),
                    (None, None, Some(country)) => r.in_country && l.locations.get(&r.location).is_some_and(|x| x.country == *country),
                    (None, None, None) => r.in_country,
                }
        })
        .collect()
}

pub(crate) fn link(l: Option<&RelayList>, loc: &Location, a: &Account, rnd: &mut impl Rng, owned_only: bool) -> Result<Link> {
    let sv = match (&loc.pinned, l) {
        (Some(p), None) => p.clone(),
        (Some(p), Some(l)) => current(l, p)?,
        // A list is always read when nothing is pinned.
        (None, None) => return Err(Error::State(String::new())),
        (None, Some(l)) => {
            let rs = matching(l, loc, owned_only);
            if rs.is_empty() {
                return Err(Error::Io(format!("No active {} server for {}", if owned_only { "Mullvad-owned" } else { "Mullvad" }, loc.label())));
            }
            server(pick(&rs, rnd), l)
        }
    };
    let address = format!("{}/32", a.ipv4_address.split('/').next().unwrap_or_default());
    let peer = WgPeer { dns: vec![DNS.into()], ..WgPeer::new(&sv.name, &a.private_key, vec![address], &sv.public_key, &format!("{}:{PORT}", sv.ip), vec!["0.0.0.0/0".into()]) };
    Ok(Link::Wg { server: sv, peer, ports: PORTS.to_vec(), entries: vec![] })
}

/// `p` as the fresh list has it, found by host name, else by IP.
fn current(l: &RelayList, p: &Server) -> Result<Server> {
    let r = l.usable().find(|r| r.hostname == p.host).or_else(|| l.usable().find(|r| r.ip == p.ip)).ok_or_else(|| Error::NoLongerOffered(p.name.clone()))?;
    Ok(server(r, l))
}

/// Mullvad's `weight` is a selection weight (higher = preferred), not a load; the app picks weighted at random.
fn pick<'a>(rs: &[&'a Relay], rnd: &mut impl Rng) -> &'a Relay {
    let total: i64 = rs.iter().map(|r| r.weight as i64).sum();
    if total <= 0 {
        return rs.choose(rnd).copied().unwrap_or(rs[0]);
    }
    let mut t = rnd.random_range(0..total);
    rs.iter()
        .find(|r| {
            t -= r.weight as i64;
            t < 0
        })
        .copied()
        .unwrap_or(rs[0])
}

fn server(r: &Relay, l: &RelayList) -> Server {
    let city = l.locations.get(&r.location).map(|x| x.city.clone()).unwrap_or_default();
    Server { name: r.hostname.clone(), host: r.hostname.clone(), ip: r.ip.clone(), public_key: r.public_key.clone(), load: 0, city, country: String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::tests::{by_code, fixture, input, peer, pinned_to};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::collections::HashSet;
    use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

    fn list() -> RelayList {
        parse(&fixture("providers/mullvad_relays.json")).unwrap()
    }

    fn acct() -> Account {
        Account {
            account: "1234567890123456".into(),
            private_key: "cHJpdmF0ZS1wcml2YXRlLXByaXZhdGUtcHJpdmF0ZTE=".into(),
            ipv4_address: "10.66.12.34/32".into(),
            device_id: "dev-1".into(),
            device: String::new(),
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// X25519 public key = scalar times the base point (u = 9).
    fn derive(private: &[u8]) -> [u8; 32] {
        x25519(private.try_into().unwrap(), X25519_BASEPOINT_BYTES)
    }

    fn seeded(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    #[test]
    fn derivation_matches_rfc7748() {
        let public = derive(&hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
        assert_eq!(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), public);
    }

    #[test]
    fn generated_keys_are_wire_guard_format() {
        let k = wg_keys::generate();
        assert_eq!(44, k.private.len());
        assert_eq!(44, k.public.len());
        let private = STANDARD.decode(&k.private).unwrap();
        assert_eq!(0, private[0] & 7);
        assert_eq!(64, private[31] & 0xC0);
        assert_eq!(STANDARD.decode(&k.public).unwrap(), derive(&private));
        assert_ne!(k.private, wg_keys::generate().private);
    }

    /// Raw bytes that still need clamping, as another key generator can give them, come out in the same format.
    #[test]
    fn xdh_fallback_produces_the_same_format() {
        let k = wg_keys::keys([0xff; 32]);
        assert_eq!(44, k.private.len());
        let private = STANDARD.decode(&k.private).unwrap();
        assert_eq!(0, private[0] & 7);
        assert_eq!(64, private[31] & 0xC0);
        assert_eq!(STANDARD.decode(&k.public).unwrap(), derive(&private));
    }

    #[test]
    fn countries_are_grouped_and_keyed() {
        let cs = countries(&list(), false);
        assert_eq!(vec!["Netherlands", "Sweden", "USA"], cs.iter().map(|c| c.name.as_str()).collect::<Vec<_>>());
        assert_eq!(vec!["NL", "SE", "US"], cs.iter().map(|c| c.code.as_str()).collect::<Vec<_>>());
        assert_eq!(cs.len(), cs.iter().map(|c| c.id).collect::<HashSet<_>>().len());
        let se = cs.iter().find(|c| c.code == "SE").unwrap();
        let mut keys: Vec<&str> = se.cities.iter().map(|c| c.key.as_deref().unwrap()).collect();
        keys.sort();
        assert_eq!(vec!["se-got", "se-mma", "se-sto"], keys);
        let names: Vec<&str> = se.cities.iter().map(|c| c.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, names);
        assert!(cs.iter().all(|c| c.server_count > 0 && c.cities.iter().all(|city| city.key.as_deref().unwrap().starts_with(&format!("{}-", c.code.to_lowercase())))));
    }

    #[test]
    fn inactive_relays_are_dropped() {
        let list = list();
        assert!(list.wireguard.relays.iter().any(|r| !r.active));
        assert!(list.usable().all(|r| r.active));
        let nl = countries(&list, false).into_iter().find(|c| c.code == "NL").unwrap();
        assert_eq!(list.usable().filter(|r| r.location == "nl-ams").count() as i32, nl.server_count);
    }

    #[test]
    fn relay_keys_are_wire_guard_keys() {
        let list = list();
        assert!(!list.wireguard.relays.is_empty());
        assert!(list.wireguard.relays.iter().all(|r| r.public_key.len() == 44 && STANDARD.decode(&r.public_key).unwrap().len() == 32));
    }

    #[test]
    fn country_link_uses_an_active_relay_in_that_country() {
        let (list, acct) = (list(), acct());
        let eligible: HashSet<&str> = list.usable().filter(|r| r.location.starts_with("se-") && r.in_country).map(|r| r.hostname.as_str()).collect();
        let seen: Vec<Link> = (1..=60).map(|i| link(Some(&list), &by_code("mullvad", "SE"), &acct, &mut seeded(i), false).unwrap()).collect();
        for l in &seen {
            assert!(eligible.contains(l.server().host.as_str()));
            let p = peer(l);
            assert_eq!(l.server().public_key, p.public_key);
            assert_eq!(format!("{}:51820", l.server().ip), p.endpoint);
            assert_eq!(vec!["10.66.12.34/32"], p.address);
            assert_eq!(vec!["0.0.0.0/0"], p.allowed_ips);
            assert_eq!(vec!["10.64.0.1"], p.dns);
            assert_eq!(acct.private_key, p.private_key);
        }
        assert!(!seen.iter().any(|l| l.server().host == "se-mma-wg-004"));
    }

    #[test]
    fn city_link_includes_relays_hidden_from_the_country() {
        let (list, acct) = (list(), acct());
        let malmo = Location { region: Some("se-mma".into()), ..by_code("mullvad", "SE") };
        let picks: Vec<Server> = (1..=60).map(|i| link(Some(&list), &malmo, &acct, &mut seeded(i), false).unwrap().server().clone()).collect();
        assert!(picks.iter().all(|s| s.host.starts_with("se-mma-") && s.city == "Malmö"));
        assert!(picks.iter().any(|s| s.host == "se-mma-wg-004"));
    }

    #[test]
    fn weight_decides_the_pick() {
        let rs = parse(
            r#"{"locations":{"xx-aaa":{"country":"X","city":"A"}},"wireguard":{"relays":[
            {"hostname":"xx-aaa-wg-001","location":"xx-aaa","active":true,"ipv4_addr_in":"1.1.1.1","public_key":"k","weight":0},
            {"hostname":"xx-aaa-wg-002","location":"xx-aaa","active":true,"ipv4_addr_in":"1.1.1.2","public_key":"k","weight":100}]}}"#,
        )
        .unwrap();
        assert!((1..=30).all(|i| link(Some(&rs), &by_code("mullvad", "XX"), &acct(), &mut seeded(i), false).unwrap().server().host == "xx-aaa-wg-002"));
    }

    #[test]
    fn pinned_server_needs_no_relay_list() {
        let sv = link(Some(&list()), &by_code("mullvad", "NL"), &acct(), &mut rand::rng(), false).unwrap().server().clone();
        let l = link(None, &pinned_to("mullvad", sv.clone()), &acct(), &mut rand::rng(), false).unwrap();
        assert_eq!(&sv, l.server());
        assert_eq!(format!("{}:51820", sv.ip), peer(&l).endpoint);
    }

    #[test]
    fn missing_pinned_relay_is_no_longer_offered() {
        let list = list();
        let sv = link(Some(&list), &by_code("mullvad", "NL"), &acct(), &mut rand::rng(), false).unwrap().server().clone();
        let gone = Server { host: "gone".into(), ip: "203.0.113.99".into(), ..sv };
        assert!(matches!(link(Some(&list), &pinned_to("mullvad", gone), &acct(), &mut rand::rng(), false), Err(Error::NoLongerOffered(_))));
    }

    #[test]
    fn owned_only_leaves_out_rented_servers() {
        let list = list();
        let us = |owned: bool| countries(&list, owned).into_iter().find(|c| c.code == "US").unwrap().cities.into_iter().map(|c| c.key.unwrap()).collect::<Vec<_>>();
        assert_eq!(vec!["us-lax", "us-nyc"], us(false));
        assert_eq!(vec!["us-nyc"], us(true));
        assert!((1..=30).all(|i| link(Some(&list), &by_code("mullvad", "US"), &acct(), &mut seeded(i), true).unwrap().server().host.starts_with("us-nyc-")));
        let lax = Location { region: Some("us-lax".into()), ..by_code("mullvad", "US") };
        match link(Some(&list), &lax, &acct(), &mut rand::rng(), true) {
            Err(e) if is_io(&e) => assert!(e.to_string().contains("Mullvad-owned")),
            other => panic!("{other:?}"),
        }
        let rented = link(Some(&list), &lax, &acct(), &mut rand::rng(), false).unwrap().server().clone();
        assert_eq!(&rented, link(Some(&list), &pinned_to("mullvad", rented.clone()), &acct(), &mut rand::rng(), true).unwrap().server());
    }

    #[test]
    fn automatic_ports_and_blocking_categories() {
        let l = link(Some(&list()), &by_code("mullvad", "NL"), &acct(), &mut rand::rng(), false).unwrap();
        let Link::Wg { ports, .. } = &l else { panic!("not WireGuard") };
        assert_eq!(&vec![51820, 53, 123, 4500], ports);
        assert_eq!(Some("100.64.0.7".to_string()), Mullvad.blocking_dns(&|_| None));
        assert_eq!(Some("100.64.0.47".to_string()), Mullvad.blocking_dns(&|k| Some(if k == "adult" || k == "social" { "on" } else { "off" }.into())));
        assert_eq!(Some("100.64.0.63".to_string()), Mullvad.blocking_dns(&|_| Some("on".into())));
        assert_eq!(vec!["adult", "gambling", "social", "owned", "port"], Mullvad.options("").iter().map(|o| o.key.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn unknown_country_fails() {
        assert!(link(Some(&list()), &by_code("mullvad", "ZZ"), &acct(), &mut rand::rng(), false).is_err_and(|e| is_io(&e)));
    }

    #[test]
    fn account_blob_round_trips() {
        let reply = r#"{"id":"7e0cb5c6-0a0f-4f4a-9a61-0d2f0f0c0b8e","name":"x","pubkey":"k","ipv4_address":"10.68.1.2/32","ipv6_address":"fc00::2/128","hijack_dns":false,"created":"2026-10-18T00:00:00Z"}"#;
        let blob = device((201, reply.into()), "1234567890123456", "priv").unwrap();
        let expected = Account {
            account: "1234567890123456".into(),
            private_key: "priv".into(),
            ipv4_address: "10.68.1.2/32".into(),
            device_id: "7e0cb5c6-0a0f-4f4a-9a61-0d2f0f0c0b8e".into(),
            device: "x".into(),
        };
        assert_eq!(expected, account(&blob).unwrap());
    }

    #[test]
    fn token_and_device_errors() {
        assert_eq!("tok", token((200, r#"{"access_token":"tok","expiry":"2026-10-19T00:00:00Z"}"#.into())).unwrap());
        for (code, body) in [(400, r#"{"code":"INVALID_ACCOUNT","error":"Bad account number"}"#), (401, "")] {
            assert!(matches!(token((code, body.into())), Err(Error::Auth { .. })));
        }
        match device((400, r#"{"code":"MAX_DEVICES_REACHED","error":"x"}"#.into()), "1", "p") {
            Err(Error::Auth { message, .. }) => assert!(message.contains("All 5 Mullvad devices are in use"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert!(device((500, String::new()), "1", "p").is_err_and(|e| is_io(&e) && !matches!(e, Error::Auth { .. })));
    }

    #[test]
    fn lost_registration_reply_is_reconciled_by_public_key() {
        let keys = wg_keys::Keys { private: "priv".into(), public: "ourpub".into() };
        let devices = r#"[{"id":"d-1","name":"a","pubkey":"other","ipv4_address":"10.68.0.1/32"},{"id":"d-2","name":"b","pubkey":"ourpub","ipv4_address":"10.68.0.2/32","hijack_dns":false}]"#;
        let expected = Account { account: "1234567890123456".into(), private_key: "priv".into(), ipv4_address: "10.68.0.2/32".into(), device_id: "d-2".into(), device: "b".into() };
        assert_eq!(expected, account(&adopt(devices, "1234567890123456", &keys).unwrap().unwrap()).unwrap());
        assert_eq!(None, adopt("[]", "1234567890123456", &keys).unwrap());
        assert_eq!(None, adopt(devices, "1234567890123456", &wg_keys::Keys { private: "p".into(), public: "unknown".into() }).unwrap());
    }

    #[test]
    fn old_blob_without_device_name_still_loads() {
        assert_eq!("", account(r#"{"account":"1","privateKey":"p","ipv4Address":"10.0.0.1/32","deviceId":"d"}"#).unwrap().device);
    }

    #[test]
    fn device_line_counts_slots_and_names_ours() {
        let list = devices(r#"[{"id":"d-1","name":"tidy cat","pubkey":"a","ipv4_address":"10.68.0.1/32"},{"id":"dev-1","name":"rapid otter","pubkey":"b","ipv4_address":"10.68.0.2/32"}]"#).unwrap();
        let url = Some("https://mullvad.net/account/devices".to_string());
        assert_eq!(Device { line: "Its own device, Rapid Otter, removed when you sign out".into(), url: url.clone(), used: Some(2) }, device_line(&acct(), Some(&list)));
        assert_eq!(Device { line: "Its own device, Old Name, removed when you sign out".into(), url, used: None }, device_line(&Account { device: "old name".into(), ..acct() }, None));
        assert_eq!("Its own device, removed when you sign out", device_line(&acct(), None).line);
    }

    #[test]
    fn expiry_is_read_from_account_reply() {
        assert_eq!(Some(1795334400), expiry(r#"{"id":"x","expiry":"2026-11-22T08:00:00+00:00","max_devices":5}"#).unwrap());
        assert_eq!(Some(1795334400), expiry(r#"{"expiry":"2026-11-22T08:00:00Z"}"#).unwrap());
        assert_eq!(None, expiry(r#"{"id":"x"}"#).unwrap());
        assert_eq!(None, expiry(r#"{"expiry":"soon"}"#).unwrap());
    }

    #[test]
    fn parse_failures_do_not_quote_the_reply() {
        let bad = r#"{"access_token": SECRET-TOKEN"#;
        let failures = [token((200, bad.into())).err(), device((201, bad.into()), "1", "p").err(), account(r#"{"account":"SECRET-ACCT" "#).err(), parse("SECRET-LIST").err()];
        for e in failures {
            let e = e.expect("refused");
            assert!(is_io(&e) && !e.to_string().contains("SECRET"), "{e}");
        }
    }

    #[test]
    fn bad_account_number_is_rejected_before_any_request() {
        for bad in ["", "1234", "12345678901234567", "abcd1234abcd1234"] {
            assert!(matches!(Mullvad.sign_in(&input(&[("account", bad)])), Err(Error::Invalid(_))), "{bad}");
        }
    }
}
