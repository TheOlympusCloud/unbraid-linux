//! IVPN over WireGuard. Account blob: account ID, session token, WireGuard private key and the tunnel address IVPN assigned.
//!
//! Sign-in follows the official client (github.com/ivpn/desktop-app, daemon/api): `POST https://api.ivpn.net/v4/session/new`
//! with `{username, force, wg_public_key}`. The reply carries its own `status` (200, 401 bad ID, 602 session limit,
//! 702 inactive account, 70001 captcha, 70011 2FA), `token` and `wireguard.ip_address`. One session and one key serve every host.
//! Server list: `GET /v5/servers.json`. Port 2049 and DNS = the host's in-tunnel `local_ip` (172.16.0.1) as in IVPN's WireGuard FAQ
//! and the client's DefaultDNS. `ip_address` is taken as a bare IPv4 (a mask is stripped if present). Accounts with 2FA,
//! or ones IVPN answers with a captcha, get one more question ([`Error::Challenge`]) and the same sign-in again.
//!
//! Sign-out frees the session: `POST /v4/session/delete {"session_token"}`. Limitation: IVPN has no API to list sessions,
//! so a `session/new` whose reply is lost in transit leaves an orphaned session (one of the account's device slots) that
//! only the user can remove in the IVPN client area; it cannot be reconciled here.

use super::mullvad::{post_json_raw, wg_keys};
use super::{AUTO, Device, Field, Limit, Opt, PORT_OPT, PROTECT, Provider, encode};
use crate::error::{Challenge, Error, Result};
use crate::manual::require;
use crate::model::{City, Country, Link, Location, Server, WgPeer, eq_ignore_case, stable_id};
use crate::{APP, compiler, http, limits};
use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub account_id: String,
    pub session_token: String,
    pub private_key: String,
    pub ip_address: String,
    /// The name IVPN gave this session, as its client area lists it, and the plan's device limit (0 = unknown).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub limit: i32,
}

fn is_zero(n: &i32) -> bool {
    *n == 0
}

#[derive(Deserialize)]
struct WgReply {
    #[serde(default)]
    ip_address: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Plan {
    name: String,
    device_limit: i32,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Status {
    current_plan: String,
    available_plans: Vec<Plan>,
    limit: i32,
}

impl Status {
    /// The device limit: the 602 reply's own, else the current plan's ("IVPN Standard" is plan "Standard").
    fn device_limit(&self) -> i32 {
        if self.limit > 0 {
            return self.limit;
        }
        let plan = self.current_plan.to_lowercase();
        // The longest matching name, the first of equals.
        let named =
            self.available_plans.iter().filter(|p| !p.name.trim().is_empty() && plan.contains(&p.name.to_lowercase()));
        named.rev().max_by_key(|p| p.name.chars().count()).map_or(0, |p| p.device_limit)
    }
}

#[derive(Deserialize)]
struct SessionReply {
    #[serde(default)]
    status: Option<i64>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    wireguard: Option<WgReply>,
    #[serde(default, rename = "device_name")]
    device: Option<String>,
    #[serde(default, rename = "service_status")]
    service: Option<Status>,
    #[serde(default)]
    data: Option<Status>,
    #[serde(default)]
    captcha_id: Option<String>,
    #[serde(default)]
    captcha_image: Option<String>,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Host {
    pub(crate) hostname: String,
    pub(crate) host: String,
    pub(crate) public_key: String,
    pub(crate) local_ip: String,
    #[serde(default)]
    pub(crate) load: f64,
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct Gateway {
    pub(crate) gateway: String,
    pub(crate) country_code: String,
    pub(crate) country: String,
    pub(crate) city: String,
    #[serde(default)]
    pub(crate) hosts: Vec<Host>,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct Port {
    pub(crate) r#type: String,
    pub(crate) port: Option<i32>,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct Ports {
    pub(crate) wireguard: Vec<Port>,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct Blocklist {
    #[serde(rename = "Description")]
    pub(crate) name: String,
    #[serde(rename = "Normal")]
    pub(crate) normal: String,
    #[serde(rename = "Hardcore")]
    pub(crate) hardcore: String,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct AntiTracker {
    #[serde(rename = "DnsServers")]
    pub(crate) lists: Vec<Blocklist>,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct Config {
    pub(crate) ports: Ports,
    #[serde(rename = "antitracker_plus")]
    pub(crate) antitracker: AntiTracker,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub(crate) struct ServerList {
    pub(crate) wireguard: Vec<Gateway>,
    pub(crate) config: Config,
}

impl ServerList {
    /// The single UDP ports IVPN's WireGuard servers take (its list also has ranges, left out here).
    pub(crate) fn ports(&self) -> Vec<i32> {
        let udp = self.config.ports.wireguard.iter().filter(|p| eq_ignore_case(&p.r#type, "UDP"));
        udp.filter_map(|p| p.port).collect::<IndexSet<_>>().into_iter().collect()
    }

    /// Hosts for `loc`: a city (gateway) if [`Location::region`] is set, else its country, else everything.
    pub(crate) fn matching(&self, loc: &Location) -> Vec<(&Gateway, &Host)> {
        let gateways = self.wireguard.iter().filter(|g| match (&loc.region, &loc.country_code, &loc.country) {
            (Some(region), ..) => g.gateway == *region,
            (None, Some(cc), _) => eq_ignore_case(&g.country_code, cc),
            (None, None, Some(country)) => g.country == *country,
            (None, None, None) => true,
        });
        gateways.flat_map(|g| g.hosts.iter().map(move |h| (g, h))).collect()
    }
}

const API: &str = "https://api.ivpn.net";
const PORT: i32 = 2049;
/// Automatic port: the default first, then the ones restrictive networks most often let through. Only those IVPN lists.
const FALLBACK: [i32; 9] = [PORT, 443, 53, 80, 123, 2050, 1194, 500, 4500];
const DNS: &str = "172.16.0.1";
// AntiTracker's block list until one is picked: OISD Big, the one IVPN's plain AntiTracker uses.
const OISD: &str = "10.0.254.2|10.0.254.3";
const LIST: &str = "list";
const HARDCORE: &str = "hardcore";
const CLIENT_AREA: &str = "https://www.ivpn.net/account/";
const CODE: &str = "confirmation";
const CAPTCHA: &str = "captcha";
const CAPTCHA_ID: &str = "captcha_id";

static ACCOUNT_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^(?:i-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}|ivpn[A-Za-z0-9]{7,8})$").unwrap());
static CAPTCHA_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9_-]{1,128}$").unwrap());
/// Base64 as a MIME decoder reads it: padding optional, bits left over at the end ignored.
const B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

fn code_field() -> Field {
    Field { secret: false, hint: "6 digits".into(), ..Field::new(CODE, "Two-factor code") }
}

fn captcha_field() -> Field {
    Field { secret: false, ..Field::new(CAPTCHA, "Characters in the picture") }
}

pub struct Ivpn;

impl Provider for Ivpn {
    fn id(&self) -> &'static str {
        "ivpn"
    }

    /// Every host in IVPN's list carries its load, and the app picks the lowest.
    fn has_load(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "IVPN"
    }

    fn protection(&self) -> Option<Opt> {
        Some(Opt::new(PROTECT, "AntiTracker", "Ads and trackers"))
    }

    fn defaults(&self) -> IndexMap<String, String> {
        [(PROTECT, "off"), (LIST, OISD), (HARDCORE, "off"), (PORT_OPT, AUTO)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// One session serves every IVPN route, so this computer is always one device.
    fn device(&self, blob: &str) -> Option<Device> {
        let a = account(blob).ok()?;
        // The status check names the session and plan as they are now; offline, as at sign-in.
        let now = post_json_raw(&format!("{API}/v4/session/status"), &session_body(&a.session_token), &[])
            .ok()
            .and_then(|(_, body)| serde_json::from_str::<SessionReply>(&body).ok())
            .filter(|r| r.status == Some(200));
        let name = now.and_then(|r| r.device).unwrap_or(a.device);
        Some(Device {
            line: format!(
                "{}See all your devices in the IVPN client area",
                if name.trim().is_empty() { String::new() } else { format!("Named {name}. ") }
            ),
            url: Some(CLIENT_AREA.into()),
            used: None,
        })
    }

    /// The plan's device limit as read at sign-in; unbraid always holds one session.
    fn limit(&self, blob: &str) -> Limit {
        Limit {
            unit: "device".into(),
            per_tunnel: false,
            value: Some(account(blob).map_or(0, |a| a.limit)).filter(|n| *n > 0),
        }
    }

    /// A block list is saved as its two resolvers, "normal|hardcore", so a route needs no server list to use it.
    fn blocking_dns(&self, opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        let list = opts(LIST).unwrap_or_else(|| OISD.into());
        let pick = list
            .split('|')
            .nth(if opts(HARDCORE).as_deref() == Some("on") { 1 } else { 0 })
            .filter(|ip| compiler::ipv4(ip).is_some_and(|(_, len)| len == 32) && !ip.contains('/'));
        Some(pick.unwrap_or(OISD.split('|').next().unwrap_or_default()).to_string())
    }

    /// A new key reaches every IVPN server within about a minute of the sign-in.
    fn key_setup_ms(&self) -> u64 {
        90_000
    }

    fn options(&self, _account: &str) -> Vec<Opt> {
        fetch().map(|l| options(&l)).unwrap_or_default()
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "i-XXXX-XXXX-XXXX".into(), qr: true, ..Field::new("account", "Account ID") }]
    }

    fn help(&self) -> String {
        format!(
            "Your account ID (i-XXXX-XXXX-XXXX, or ivpn plus 8 characters on older accounts): in the IVPN client area, or on any device already logged in. Signed up with an email? Log in at ivpn.net with it: the account ID is at the top of the client area, with a QR code you can scan. {APP} uses one of your devices."
        )
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let acct: String =
            input.get("account").map_or("", String::as_str).chars().filter(|c| !c.is_whitespace()).collect();
        require!(ACCOUNT_ID.is_match(&acct), "Account ID must look like i-XXXX-XXXX-XXXX or ivpnXXXXXXXX");
        let keys = wg_keys::generate();
        let mut body: IndexMap<&str, Value> = IndexMap::from([
            ("username", acct.clone().into()),
            ("force", false.into()),
            ("wg_public_key", keys.public.clone().into()),
        ]);
        // The answers to an earlier reply's two-factor or captcha question.
        for k in [CODE, CAPTCHA, CAPTCHA_ID] {
            let answer: String =
                input.get(k).map_or("", String::as_str).chars().filter(|c| !c.is_whitespace()).collect();
            if !answer.is_empty() {
                body.insert(k, answer.into());
            }
        }
        session(post_json_raw(&format!("{API}/v4/session/new"), &encode(&body)?, &[])?, &acct, &keys.private)
    }

    fn sign_out(&self, blob: &str) -> bool {
        account(blob)
            .and_then(|a| post_json_raw(&format!("{API}/v4/session/delete"), &session_body(&a.session_token), &[]))
            .is_ok_and(|(code, _)| (200..=299).contains(&code))
    }

    /// IVPN's session status answers 601 (session not found) once the session was logged out elsewhere.
    fn revoked(&self, blob: &str) -> bool {
        account(blob)
            .and_then(|a| post_json_raw(&format!("{API}/v4/session/status"), &session_body(&a.session_token), &[]))
            .is_ok_and(|reply| session_gone(&reply))
    }

    fn countries(&self, _account: &str) -> Result<Vec<Country>> {
        Ok(countries(&fetch()?))
    }

    // A pinned server is looked up in the current list (its address and key may have changed); the saved one only offline.
    fn connect(&self, loc: &Location, blob: &str) -> Result<Link> {
        let list = if loc.pinned.is_none() { Some(fetch()?) } else { fetch().ok() };
        link(list.as_ref(), loc, &account(blob)?)
    }

    fn servers(&self, loc: &Location, _account: &str, limit: usize) -> Result<Vec<Server>> {
        let l = fetch()?;
        let mut hosts = l.matching(loc);
        hosts.sort_by(|a, b| a.1.load.total_cmp(&b.1.load));
        Ok(hosts.into_iter().take(limit).map(|(g, h)| server(g, h)).collect())
    }
}

fn session_body(token: &str) -> String {
    serde_json::json!({ "session_token": token }).to_string()
}

pub(crate) fn options(l: &ServerList) -> Vec<Opt> {
    let lists: Vec<(String, String)> =
        l.config.antitracker.lists.iter().map(|b| (format!("{}|{}", b.normal, b.hardcore), b.name.clone())).collect();
    let mut ports = l.ports();
    ports.sort();
    let ports = std::iter::once((AUTO.to_string(), "Automatic".to_string()))
        .chain(ports.into_iter().map(|p| (p.to_string(), format!("UDP {p}"))))
        .collect();
    let list = Opt { choices: lists, ..Opt::new(LIST, "Block list", "What AntiTracker blocks, from IVPN's own lists") };
    (!list.choices.is_empty())
        .then_some(list)
        .into_iter()
        .chain([
            Opt {
                advanced: true,
                ..Opt::new(HARDCORE, "Hardcore mode", "Also blocks Google and Facebook, and sites that need them")
            },
            Opt {
                choices: ports,
                advanced: true,
                ..Opt::new(PORT_OPT, "Port", "Automatic tries 2049 first, then other ports when a network blocks it")
            },
        ])
        .collect()
}

pub(crate) fn session_gone((code, body): &(u16, String)) -> bool {
    let status = serde_json::from_str::<SessionReply>(body).ok().and_then(|r| r.status).unwrap_or(*code as i64);
    status == 601 || status == 401
}

pub(crate) fn session((code, body): (u16, String), account: &str, private_key: &str) -> Result<String> {
    let o: SessionReply = http::parsed("IVPN", || serde_json::from_str(&body))?;
    let auth = |message: String, url: Option<&str>| Error::Auth { message, url: url.map(String::from) };
    let challenge = |message: &str, field: Field, image: Option<Vec<u8>>, keep: IndexMap<String, String>| {
        Error::Challenge(Box::new(Challenge { message: message.into(), field, image, keep }))
    };
    match o.status.unwrap_or(code as i64) {
        200 => {}
        401 => return Err(auth("IVPN doesn't recognise that account ID".into(), None)),
        602 => {
            return Err(auth(
                limits::full("IVPN", o.data.as_ref().map(Status::device_limit).filter(|n| *n > 0), "device"),
                Some(CLIENT_AREA),
            ));
        }
        702 => return Err(auth("This IVPN account isn't active. Renew it first.".into(), None)),
        status @ (70001 | 70002) => {
            let Some(id) = o.captcha_id.filter(|id| CAPTCHA_KEY.is_match(id)) else {
                return Err(auth(
                    "IVPN is asking for a captcha. Log in once on ivpn.net or in the IVPN app, then try again.".into(),
                    None,
                ));
            };
            let image = o.captcha_image.unwrap_or_default();
            let b64: String = image
                .split_once("base64,")
                .map_or(image.as_str(), |(_, b)| b)
                .chars()
                .take_while(|c| *c != '=')
                .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
                .collect();
            let message = if status == 70001 {
                "IVPN wants to check you're a person. Type the characters in the picture."
            } else {
                "That didn't match. Try this picture."
            };
            return Err(challenge(
                message,
                captcha_field(),
                B64.decode(b64).ok(),
                IndexMap::from([(CAPTCHA_ID.to_string(), id)]),
            ));
        }
        70011 => {
            return Err(challenge(
                "Two-factor authentication is on for this account. Enter the code from your authenticator app.",
                code_field(),
                None,
                IndexMap::new(),
            ));
        }
        70012 => {
            return Err(challenge(
                "That code didn't work. Enter the current one.",
                code_field(),
                None,
                IndexMap::new(),
            ));
        }
        status => return Err(Error::Status { code: u16::try_from(status).unwrap_or(u16::MAX) }),
    }
    let ip = o
        .wireguard
        .and_then(|w| w.ip_address)
        .ok_or_else(|| Error::Fail("IVPN didn't assign a WireGuard address. Try again later".into()))?;
    let token = o.token.ok_or_else(|| Error::Fail("IVPN didn't return a session. Try again later".into()))?;
    encode(&Account {
        account_id: account.into(),
        session_token: token,
        private_key: private_key.into(),
        ip_address: ip.split('/').next().unwrap_or_default().into(),
        device: o.device.unwrap_or_default().chars().take(64).collect(),
        limit: o.service.as_ref().map_or(0, Status::device_limit),
    })
}

pub fn account(blob: &str) -> Result<Account> {
    http::parsed("IVPN", || serde_json::from_str(blob))
}

fn fetch() -> Result<ServerList> {
    parse(&http::get(&format!("{API}/v5/servers.json"), &[], None, None)?)
}

pub(crate) fn parse(body: &str) -> Result<ServerList> {
    http::parsed("IVPN", || serde_json::from_str(body))
}

pub(crate) fn countries(l: &ServerList) -> Vec<Country> {
    let mut by_code: IndexMap<&str, Vec<&Gateway>> = IndexMap::new();
    for g in l.wireguard.iter().filter(|g| !g.hosts.is_empty()) {
        by_code.entry(g.country_code.as_str()).or_default().push(g);
    }
    let mut groups: Vec<Vec<&Gateway>> = by_code.into_values().collect();
    groups.sort_by(|a, b| a[0].country.cmp(&b[0].country));
    groups
        .into_iter()
        .map(|mut gs| {
            gs.sort_by(|a, b| a.city.cmp(&b.city));
            let first = gs[0];
            Country {
                id: stable_id(&first.country_code),
                name: first.country.clone(),
                code: first.country_code.to_uppercase(),
                server_count: gs.iter().map(|g| g.hosts.len() as i32).sum(),
                cities: gs
                    .iter()
                    .map(|g| City { id: stable_id(&g.gateway), name: g.city.clone(), key: Some(g.gateway.clone()) })
                    .collect(),
            }
        })
        .collect()
}

pub(crate) fn link(l: Option<&ServerList>, loc: &Location, a: &Account) -> Result<Link> {
    let (sv, dns) = match (l, &loc.pinned) {
        (None, Some(p)) => (p.clone(), DNS.to_string()),
        // A list is always read when nothing is pinned.
        (None, None) => return Err(Error::State(String::new())),
        (Some(l), pinned) => {
            let (g, h) = match pinned {
                Some(p) => l
                    .wireguard
                    .iter()
                    .flat_map(|g| g.hosts.iter().map(move |h| (g, h)))
                    .find(|(_, h)| h.hostname == p.host)
                    .ok_or_else(|| Error::NoLongerOffered(p.name.clone()))?,
                None => l
                    .matching(loc)
                    .into_iter()
                    .min_by(|a, b| a.1.load.total_cmp(&b.1.load))
                    .ok_or_else(|| Error::Io(format!("No IVPN server for {}", loc.label())))?,
            };
            (server(g, h), h.local_ip.split('/').next().unwrap_or_default().to_string())
        }
    };
    let ports = l
        .map(|l| l.ports())
        .map(|listed| FALLBACK.into_iter().filter(|p| listed.contains(p)).collect())
        .unwrap_or_default();
    let address = format!("{}/32", a.ip_address.split('/').next().unwrap_or_default());
    let peer = WgPeer {
        dns: vec![dns],
        ..WgPeer::new(
            &sv.name,
            &a.private_key,
            vec![address],
            &sv.public_key,
            &format!("{}:{PORT}", sv.ip),
            vec!["0.0.0.0/0".into()],
        )
    };
    Ok(Link::Wg { server: sv, peer, ports, entries: vec![] })
}

fn server(g: &Gateway, h: &Host) -> Server {
    Server {
        name: h.hostname.clone(),
        host: h.hostname.clone(),
        ip: h.host.clone(),
        public_key: h.public_key.clone(),
        load: h.load.round() as i32,
        city: g.city.clone(),
        country: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::is_io;
    use crate::providers::tests::{by_code, fixture, input, peer, pinned_to};
    use std::collections::HashSet;

    fn list() -> ServerList {
        parse(&fixture("providers/ivpn_servers.json")).unwrap()
    }

    fn acct() -> Account {
        Account {
            account_id: "i-ABCD-EFGH-IJKL".into(),
            session_token: "session".into(),
            private_key: "cHJpdmF0ZS1wcml2YXRlLXByaXZhdGUtcHJpdmF0ZTE=".into(),
            ip_address: "172.16.34.56".into(),
            device: String::new(),
            limit: 0,
        }
    }

    fn ports(l: &Link) -> &[i32] {
        match l {
            Link::Wg { ports, .. } => ports,
            _ => panic!("not WireGuard"),
        }
    }

    #[test]
    fn countries_are_grouped_and_keyed() {
        let list = list();
        let cs = countries(&list);
        assert_eq!(
            vec!["Argentina", "Netherlands", "Sweden", "United States"],
            cs.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(vec!["AR", "NL", "SE", "US"], cs.iter().map(|c| c.code.as_str()).collect::<Vec<_>>());
        assert_eq!(cs.len(), cs.iter().map(|c| c.id).collect::<HashSet<_>>().len());
        let us = cs.iter().find(|c| c.code == "US").unwrap();
        assert!(us.cities.len() > 5);
        assert!(us.cities.iter().all(|c| c.key.as_deref().unwrap().ends_with(".wg.ivpn.net")));
        let names: Vec<&str> = us.cities.iter().map(|c| c.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, names);
        assert_eq!(us.cities.len(), us.cities.iter().map(|c| c.key.clone()).collect::<HashSet<_>>().len());
        assert_eq!(
            list.wireguard.iter().filter(|g| g.country_code == "US").map(|g| g.hosts.len() as i32).sum::<i32>(),
            us.server_count
        );
    }

    #[test]
    fn host_keys_are_wire_guard_keys() {
        let list = list();
        let hosts: Vec<&Host> = list.wireguard.iter().flat_map(|g| &g.hosts).collect();
        assert!(!hosts.is_empty());
        assert!(hosts.iter().all(|h| h.public_key.len() == 44 && crate::wg_conf::valid_wg_key(&h.public_key)));
    }

    #[test]
    fn country_link_picks_the_least_loaded_host() {
        let (list, acct) = (list(), acct());
        let l = link(Some(&list), &by_code("ivpn", "NL"), &acct).unwrap();
        let best = list
            .wireguard
            .iter()
            .filter(|g| g.country_code == "NL")
            .flat_map(|g| &g.hosts)
            .min_by(|a, b| a.load.total_cmp(&b.load))
            .unwrap();
        assert_eq!(best.hostname, l.server().host);
        let p = peer(&l);
        assert_eq!(best.public_key, p.public_key);
        assert_eq!(format!("{}:2049", best.host), p.endpoint);
        assert_eq!(vec!["172.16.34.56/32"], p.address);
        assert_eq!(vec!["172.16.0.1"], p.dns);
        assert_eq!(vec!["0.0.0.0/0"], p.allowed_ips);
        assert_eq!(acct.private_key, p.private_key);
        assert_eq!("Amsterdam", l.server().city);
    }

    /// Automatic tries 2049, then the ports restrictive networks let through, all from IVPN's own list; offline only the default.
    #[test]
    fn links_carry_the_fallback_ports_ivpn_lists() {
        let (list, acct) = (list(), acct());
        let l = link(Some(&list), &by_code("ivpn", "NL"), &acct).unwrap();
        assert_eq!(&[2049, 443, 53, 80, 123, 2050, 1194, 500, 4500], ports(&l));
        assert!(ports(&l).iter().all(|p| list.ports().contains(p)));
        assert!(ports(&link(None, &pinned_to("ivpn", l.server().clone()), &acct).unwrap()).is_empty());
        let port = |kind: &str, port: i32| Port { r#type: kind.into(), port: Some(port) };
        let few = ServerList {
            config: Config {
                ports: Ports { wireguard: vec![port("UDP", 53), port("TCP", 443), port("UDP", 2049)] },
                ..Config::default()
            },
            ..list
        };
        assert_eq!(&[2049, 53], ports(&link(Some(&few), &by_code("ivpn", "NL"), &acct).unwrap()));
    }

    /// Every host of a country can be picked by hand (the US has more than twenty).
    #[test]
    fn every_server_of_a_country_is_listed() {
        let list = list();
        let us: usize = list.wireguard.iter().filter(|g| g.country_code == "US").map(|g| g.hosts.len()).sum();
        assert_eq!(us, list.matching(&by_code("ivpn", "US")).len());
    }

    /// AntiTracker's lists come from IVPN's list, saved as both resolvers; Hardcore picks the second; nonsense falls back.
    #[test]
    fn anti_tracker_lists_and_hardcore() {
        fn dns(o: &[(&str, &str)]) -> String {
            Ivpn.blocking_dns(&|k: &str| {
                o.iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.to_string())
                    .or_else(|| Ivpn.defaults().get(k).cloned())
            })
            .unwrap()
        }
        let opts = options(&list());
        let lists = opts.iter().find(|o| o.key == "list").unwrap();
        assert_eq!(10, lists.choices.len());
        let pro = lists.choices.iter().find(|(_, name)| name == "Hagezi Pro").unwrap().0.as_str();
        assert_eq!("10.0.254.10|10.0.254.11", pro);
        assert_eq!("10.0.254.2", dns(&[]));
        assert_eq!("10.0.254.3", dns(&[("hardcore", "on")]));
        assert_eq!("10.0.254.10", dns(&[("list", pro)]));
        assert_eq!("10.0.254.11", dns(&[("list", pro), ("hardcore", "on")]));
        assert_eq!("10.0.254.2", dns(&[("list", "1.2.3.4/0|x"), ("hardcore", "on")]));
    }

    #[test]
    fn city_link_stays_in_that_gateway() {
        let l = link(
            Some(&list()),
            &Location { region: Some("us-ny.wg.ivpn.net".into()), ..by_code("ivpn", "US") },
            &acct(),
        )
        .unwrap();
        assert_eq!("New York, NY", l.server().city);
        assert!(l.server().host.starts_with("us-ny"));
    }

    /// Only IVPN's own "session not found" (or a refused login) counts as removed; anything unclear doesn't.
    #[test]
    fn a_session_logged_out_elsewhere_is_seen() {
        assert!(session_gone(&(200, r#"{"status":601,"message":"Session not found"}"#.into())));
        assert!(session_gone(&(401, "not json".into())));
        assert!(!session_gone(&(200, r#"{"status":200}"#.into())));
        assert!(!session_gone(&(500, "<html>".into())));
        assert!(!session_gone(&(429, r#"{"status":429}"#.into())));
    }

    #[test]
    fn pinned_server_needs_no_list() {
        let sv = link(Some(&list()), &by_code("ivpn", "SE"), &acct()).unwrap().server().clone();
        assert_eq!(&sv, link(None, &pinned_to("ivpn", sv.clone()), &acct()).unwrap().server());
    }

    /// With the list readable, a pinned server takes its current address and key; gone from the list, it is final.
    #[test]
    fn pinned_server_is_refreshed_from_the_list() {
        let list = list();
        let sv = link(Some(&list), &by_code("ivpn", "SE"), &acct()).unwrap().server().clone();
        let stale = Server { ip: "203.0.113.9".into(), public_key: format!("{}=", "x".repeat(43)), ..sv.clone() };
        let l = link(Some(&list), &pinned_to("ivpn", stale), &acct()).unwrap();
        assert_eq!(sv.ip, l.server().ip);
        assert_eq!(sv.public_key, peer(&l).public_key);
        assert_eq!(sv.host, l.server().host);
        let gone = Server { host: "gone.wg.ivpn.net".into(), ..sv };
        assert!(matches!(link(Some(&list), &pinned_to("ivpn", gone), &acct()), Err(Error::NoLongerOffered(_))));
    }

    #[test]
    fn unknown_country_fails() {
        assert!(link(Some(&list()), &by_code("ivpn", "ZZ"), &acct()).is_err_and(|e| is_io(&e)));
    }

    #[test]
    fn session_replies() {
        let ok = r#"{"status":200,"token":"tok","vpn_username":"u","vpn_password":"p","service_status":{"is_active":true},"wireguard":{"status":200,"message":"Success","ip_address":"172.16.1.2"}}"#;
        let expected = Account {
            account_id: "i-ABCD-EFGH-IJKL".into(),
            session_token: "tok".into(),
            private_key: "priv".into(),
            ip_address: "172.16.1.2".into(),
            device: String::new(),
            limit: 0,
        };
        assert_eq!(expected, account(&session((200, ok.into()), "i-ABCD-EFGH-IJKL", "priv").unwrap()).unwrap());
        // The device name and the plan's limit, for the IVPN page.
        let named = r#"{"status":200,"token":"tok","device_name":"Brave Owl","service_status":{"current_plan":"IVPN Standard","available_plans":[{"name":"Pro","device_limit":10},{"name":"Standard","device_limit":5}]},"wireguard":{"ip_address":"172.16.1.2"}}"#;
        let a = account(&session((200, named.into()), "a", "p").unwrap()).unwrap();
        assert_eq!(("Brave Owl", 5), (a.device.as_str(), a.limit));
        // A full account says how many devices and links to where they are listed.
        let full =
            r#"{"status":602,"message":"You've reached the maximum number of connected devices","data":{"limit":5}}"#;
        match session((400, full.into()), "a", "p") {
            Err(Error::Auth { message, url }) => {
                assert_eq!("All 5 IVPN devices are in use. Sign out another device, then try again.", message);
                assert!(url.unwrap().starts_with("https://www.ivpn.net/"));
            }
            other => panic!("{other:?}"),
        }
        for body in [
            r#"{"status":401,"message":"The provided Account ID is not valid"}"#,
            r#"{"status":702,"message":"inactive"}"#,
            r#"{"status":70001}"#,
        ] {
            assert!(matches!(session((400, body.into()), "a", "p"), Err(Error::Auth { .. })), "{body}");
        }
        // Two-factor and captcha are one more question, then the same sign-in again.
        for status in [70011, 70012] {
            match session((400, format!(r#"{{"status":{status}}}"#)), "a", "p") {
                Err(Error::Challenge(c)) => assert!(c.field.key == "confirmation" && c.image.is_none()),
                other => panic!("{other:?}"),
            }
        }
        let png = [0x89, 80, 78, 71];
        let captcha = format!(
            r#"{{"status":70002,"captcha_id":"c-1","captcha_image":"data:image/png;base64,{}"}}"#,
            B64.encode(png)
        );
        match session((400, captcha), "a", "p") {
            Err(Error::Challenge(c)) => {
                assert_eq!("captcha", c.field.key);
                assert_eq!(IndexMap::from([("captcha_id".to_string(), "c-1".to_string())]), c.keep);
                assert_eq!(Some(png.to_vec()), c.image);
            }
            other => panic!("{other:?}"),
        }
        assert!(
            session((502, "<html>".into()), "a", "p").is_err_and(|e| is_io(&e) && !matches!(e, Error::Auth { .. }))
        );
    }

    #[test]
    fn parse_failures_do_not_quote_the_reply() {
        let failures = [
            session((200, r#"{"status":200,"token":"SECRET-TOKEN" "#.into()), "a", "p").err(),
            account(r#"{"sessionToken":"SECRET" "#).err(),
            parse("SECRET-LIST").err(),
        ];
        for e in failures {
            let e = e.expect("refused");
            assert!(is_io(&e) && !e.to_string().contains("SECRET"), "{e}");
        }
        assert!(
            session((200, r#"{"status":200,"token":"t"}"#.into()), "a", "p")
                .is_err_and(|e| is_io(&e) && !matches!(e, Error::Auth { .. }))
        );
        assert!(
            session((400, r#"{"status":999,"message":"echoes SECRET"}"#.into()), "a", "p")
                .is_err_and(|e| is_io(&e) && !e.to_string().contains("SECRET"))
        );
    }

    #[test]
    fn bad_account_id_is_rejected_before_any_request() {
        for bad in ["", "i-ABCD", "x-ABCD-EFGH-IJKL", "1234567890"] {
            assert!(matches!(Ivpn.sign_in(&input(&[("account", bad)])), Err(Error::Invalid(_))), "{bad}");
        }
    }
}
