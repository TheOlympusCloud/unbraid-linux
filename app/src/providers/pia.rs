//! Private Internet Access over WireGuard, following PIA's official scripts
//! (https://github.com/pia-foss/manual-connections): `get_token.sh`, `get_region.sh` and
//! `connect_to_wireguard_with_token.sh`. Account blob: [`Account`] (login, last token, WireGuard key pair).
//! TLS to a WireGuard server is by IP, pinned to PIA's CA, with the server's `cn` as host name.

use super::mullvad::wg_keys;
use super::{Field, Opt, PROTECT, Provider, encode, is_io};
use crate::error::{Error, Result};
use crate::http;
use crate::manual::require;
use crate::model::{City, Country, Link, Location, Server, WgPeer, eq_ignore_case, stable_id};
use indexmap::IndexMap;
use regex::Regex;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};

/// "US Denver" → "Denver": compiled once, it runs inside sort comparators.
static COUNTRY_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Z]{2} .").unwrap());
static CN: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9._-]+$").unwrap());
static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[0-9.]+$").unwrap());

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub username: String,
    pub password: String,
    pub token: String,
    pub token_time: i64,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wg {
    pub(crate) ip: String,
    pub(crate) cn: String,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Servers {
    #[serde(default)]
    pub(crate) wg: Vec<Wg>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Region {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) country: String,
    #[serde(default)]
    pub(crate) geo: bool,
    #[serde(default)]
    pub(crate) port_forward: bool,
    #[serde(default)]
    pub(crate) offline: bool,
    #[serde(default)]
    pub(crate) servers: Servers,
}

impl Region {
    /// `name` without the country prefix PIA puts on some regions ("DE Berlin" → "Berlin").
    pub(crate) fn city(&self) -> String {
        if COUNTRY_PREFIX.is_match(&self.name) { self.name[3..].to_string() } else { self.name.clone() }
    }
}

#[derive(Deserialize)]
struct ServerList {
    regions: Vec<Region>,
}

pub(crate) struct AddKey {
    pub(crate) server_key: String,
    pub(crate) server_port: i32,
    pub(crate) peer_ip: String,
    pub(crate) dns: Vec<String>,
}

#[derive(Deserialize)]
struct TokenReply {
    #[serde(default)]
    token: Option<String>,
}

#[derive(Deserialize)]
struct AddKeyReply {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    server_key: Option<String>,
    #[serde(default)]
    server_port: Option<i32>,
    #[serde(default)]
    peer_ip: Option<String>,
    #[serde(default, rename = "dns_servers")]
    dns: Vec<String>,
}

#[derive(Clone)]
struct Token {
    value: String,
    at: i64,
}

const TOKEN_URL: &str = "https://www.privateinternetaccess.com/api/client/v2/token";
const LIST_URL: &str = "https://serverlist.piaservers.net/vpninfo/servers/v6";
const TOKEN_REFRESH_MS: i64 = 20 * 3_600_000;
const TRIES: usize = 3;

/// The newest token per username, refreshed in this process.
static TOKENS: LazyLock<Mutex<HashMap<String, Token>>> = LazyLock::new(Default::default);

pub struct Pia;

impl Provider for Pia {
    fn id(&self) -> &'static str {
        "pia"
    }

    fn name(&self) -> &'static str {
        "Private Internet Access"
    }

    fn protection(&self) -> Option<Opt> {
        Some(Opt::new(PROTECT, "MACE", "Ads, trackers and malware"))
    }

    fn defaults(&self) -> IndexMap<String, String> {
        IndexMap::from([(PROTECT.to_string(), "off".to_string())])
    }

    fn blocking_dns(&self, _opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        Some("10.0.0.244".into())
    }

    fn fields(&self) -> Vec<Field> {
        vec![
            Field { secret: false, hint: "p1234567".into(), ..Field::new("username", "Username") },
            Field { hint: "PIA password".into(), ..Field::new("password", "Password") },
        ]
    }

    fn help(&self) -> String {
        "Your PIA login, not your email: a username like p1234567 and its password (PIA website → Account → Client Control Panel).".into()
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let user = input.get("username").map_or("", |u| u.trim()).to_string();
        let pass = input.get("password").cloned().unwrap_or_default();
        require!(!user.is_empty() && !pass.is_empty(), "Enter your PIA username and password");
        let keys = wg_keys::generate();
        let token = fetch_token(&user, &pass)?;
        let now = now();
        TOKENS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(user.clone(), Token { value: token.clone(), at: now });
        encode(&Account {
            username: user,
            password: pass,
            token,
            token_time: now,
            private_key: keys.private,
            public_key: keys.public,
        })
    }

    fn countries(&self, _account: &str) -> Result<Vec<Country>> {
        Ok(countries(&regions()?))
    }

    fn connect(&self, loc: &Location, blob: &str) -> Result<Link> {
        let a = account(blob)?;
        let targets: Vec<(Wg, Server)> = match &loc.pinned {
            Some(p) => vec![(Wg { ip: p.ip.clone(), cn: p.host.clone() }, p.clone())],
            None => {
                let list = regions()?;
                let r = pick(&list, loc)?;
                let base = |w: &Wg| Server {
                    name: r.name.clone(),
                    host: w.cn.clone(),
                    ip: w.ip.clone(),
                    public_key: String::new(),
                    load: 0,
                    city: r.city(),
                    country: String::new(),
                };
                r.servers.wg.iter().take(TRIES).map(|w| (w.clone(), base(w))).collect()
            }
        };
        let mut failure = None;
        for (sv, base) in targets {
            match register(&sv, &a) {
                Ok(k) => {
                    let server = Server { public_key: k.server_key.clone(), ..base };
                    return Ok(Link::Wg {
                        peer: peer(&server, &k, &a.private_key),
                        server,
                        ports: vec![],
                        entries: vec![],
                    });
                }
                Err(e @ Error::Auth { .. }) => return Err(e),
                Err(e) if is_io(&e) => failure = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(failure.unwrap_or_else(|| Error::Io("PIA has no WireGuard server for this location".into())))
    }

    fn servers(&self, loc: &Location, _account: &str, limit: usize) -> Result<Vec<Server>> {
        let list = regions()?;
        let mut rs: Vec<&Region> = match (&loc.region, &loc.country_code) {
            (Some(id), _) => list.iter().filter(|r| r.id == *id).collect(),
            (None, Some(c)) => list.iter().filter(|r| eq_ignore_case(&r.country, c)).collect(),
            (None, None) => list.iter().collect(),
        };
        rs.sort_by_key(|r| r.geo);
        let servers = rs.iter().flat_map(|r| {
            r.servers.wg.iter().map(|w| Server {
                name: w.cn.clone(),
                host: w.cn.clone(),
                ip: w.ip.clone(),
                public_key: String::new(),
                load: 0,
                city: r.city(),
                country: String::new(),
            })
        });
        Ok(servers.take(limit).collect())
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn account(blob: &str) -> Result<Account> {
    http::parsed("PIA", || serde_json::from_str(blob))
}

fn peer(sv: &Server, k: &AddKey, private_key: &str) -> WgPeer {
    let endpoint = format!("{}:{}", sv.ip, k.server_port);
    WgPeer {
        dns: k.dns.clone(),
        ..WgPeer::new(
            &sv.name,
            private_key,
            vec![format!("{}/32", k.peer_ip)],
            &k.server_key,
            &endpoint,
            vec!["0.0.0.0/0".into()],
        )
    }
}

fn regions() -> Result<Vec<Region>> {
    parse_regions(&http::get(LIST_URL, &[], None, None)?)
}

fn pick<'a>(list: &'a [Region], loc: &Location) -> Result<&'a Region> {
    if let Some(id) = &loc.region {
        return list
            .iter()
            .find(|r| r.id == *id)
            .ok_or_else(|| Error::Io(format!("PIA region {id} is no longer available")));
    }
    let mut pool: Vec<&Region> = match &loc.country_code {
        Some(c) => list.iter().filter(|r| eq_ignore_case(&r.country, c)).collect(),
        None => list.iter().collect(),
    };
    pool.sort_by_key(|r| r.geo);
    pool.first().copied().ok_or_else(|| Error::Io(format!("PIA has no WireGuard server for {}", loc.label())))
}

/// The server list is one line of JSON, then a blank line and a signature (not checked here, as in PIA's scripts).
pub(crate) fn parse_regions(body: &str) -> Result<Vec<Region>> {
    let list: ServerList = http::parsed("PIA", || serde_json::from_str(body.split('\n').next().unwrap_or_default()))?;
    Ok(list.regions.into_iter().filter(|r| !r.offline && !r.servers.wg.is_empty()).collect())
}

pub(crate) fn countries(regions: &[Region]) -> Vec<Country> {
    let mut by_code: IndexMap<String, Vec<&Region>> = IndexMap::new();
    for r in regions {
        by_code.entry(r.country.to_uppercase()).or_default().push(r);
    }
    let mut all: Vec<Country> = by_code
        .into_iter()
        .map(|(code, mut rs)| {
            rs.sort_by_key(|r| r.city());
            Country {
                id: code.encode_utf16().fold(0i32, |n, c| n.wrapping_mul(256).wrapping_add(c as i32)),
                name: crate::catalog::name(&code)
                    .filter(|n| !n.trim().is_empty())
                    .map_or_else(|| code.clone(), String::from),
                server_count: rs.iter().map(|r| r.servers.wg.len() as i32).sum(),
                cities: rs
                    .iter()
                    .map(|r| City { id: stable_id(&r.id), name: r.city(), key: Some(r.id.clone()) })
                    .collect(),
                code,
            }
        })
        .collect();
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all
}

fn fetch_token(user: &str, pass: &str) -> Result<String> {
    let refused = || Error::Auth { message: "PIA refused that username or password".into(), url: None };
    let body = match http::post_form(TOKEN_URL, &[("username", user), ("password", pass)], &[]) {
        Err(Error::Auth { .. }) => return Err(refused()),
        body => body?,
    };
    let reply: TokenReply = http::parsed("PIA", || serde_json::from_str(&body))?;
    reply.token.filter(|t| !t.trim().is_empty()).ok_or_else(refused)
}

/// A token younger than ~20 h (the blob's or the newest refreshed one), else a new one. PIA tokens last 24 h.
fn token(a: &Account, force: bool) -> Result<String> {
    let saved = Token { value: a.token.clone(), at: a.token_time };
    let known = match TOKENS.lock().unwrap_or_else(PoisonError::into_inner).get(&a.username) {
        Some(t) if t.at > saved.at => t.clone(),
        _ => saved,
    };
    if !force && now() - known.at < TOKEN_REFRESH_MS {
        return Ok(known.value);
    }
    let fresh = fetch_token(&a.username, &a.password)?;
    TOKENS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(a.username.clone(), Token { value: fresh.clone(), at: now() });
    Ok(fresh)
}

fn register(sv: &Wg, a: &Account) -> Result<AddKey> {
    match token(a, false).and_then(|t| add_key(sv, &t, &a.public_key)) {
        Err(Error::Auth { .. }) => token(a, true).and_then(|t| add_key(sv, &t, &a.public_key)),
        k => k,
    }
}

/// `curl --connect-to cn::ip: --cacert ca.rsa.4096.crt https://cn:1337/addKey?pt=..&pubkey=..`
fn add_key(sv: &Wg, token: &str, pub_key: &str) -> Result<AddKey> {
    require!(CN.is_match(&sv.cn) && IP.is_match(&sv.ip), "Unexpected PIA server {}", sv.cn);
    let url = format!("https://{}:1337/addKey?pt={}&pubkey={}", sv.ip, http::enc(token), http::enc(pub_key));
    parse_add_key(&http::get(&url, &[], Some(&TLS), Some(&sv.cn))?)
}

pub(crate) fn parse_add_key(body: &str) -> Result<AddKey> {
    let r: AddKeyReply = http::parsed("PIA", || serde_json::from_str(body))?;
    if r.status.as_deref() != Some("OK") {
        return Err(Error::Io("PIA refused the key".into()));
    }
    let missing = |field: &str| Error::Io(format!("PIA's reply has no {field}"));
    Ok(AddKey {
        server_key: r.server_key.ok_or_else(|| missing("server_key"))?,
        server_port: r.server_port.ok_or_else(|| missing("server_port"))?,
        peer_ip: r.peer_ip.ok_or_else(|| missing("peer_ip"))?,
        dns: r.dns,
    })
}

/// TLS trust limited to PIA's own CA, as the scripts do with `--cacert`.
pub(crate) static TLS: LazyLock<RootCertStore> = LazyLock::new(ca_store);

pub(crate) fn ca_store() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    // Built in and checked by a test: it always reads.
    roots.add(CertificateDer::from_pem_slice(CA.as_bytes()).expect("PIA's CA")).expect("PIA's CA");
    roots
}

/// PIA's CA, ca.rsa.4096.crt from its manual-connections scripts.
const CA: &str = "-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----
";
#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::is_io;
    use crate::providers::tests::fixture;
    use std::collections::HashSet;

    fn list() -> String {
        fixture("providers/pia_servers_v6.txt")
    }

    #[test]
    fn server_list_with_signature_tail_parses() {
        let list = list();
        assert!(list.split_once('\n').unwrap().1.starts_with('\n'));
        let rs = parse_regions(&list).unwrap();
        assert_eq!(
            vec![
                "us_denver",
                "nl_amsterdam",
                "nl_netherlands-so",
                "dz",
                "de_berlin",
                "de-frankfurt",
                "uk",
                "uk_manchester"
            ],
            rs.iter().map(|r| r.id.as_str()).collect::<Vec<_>>()
        );
        let denver = rs.iter().find(|r| r.id == "us_denver").unwrap();
        assert_eq!(
            vec!["denver425", "denver429", "denver431"],
            denver.servers.wg.iter().map(|w| w.cn.as_str()).collect::<Vec<_>>()
        );
        assert_eq!("181.41.206.151", denver.servers.wg[0].ip);
        assert!(denver.country == "US" && !denver.geo && !denver.port_forward);
        assert!(rs.iter().find(|r| r.id == "dz").unwrap().geo);
    }

    #[test]
    fn regions_without_wireguard_or_offline_are_skipped() {
        let body = concat!(
            r#"{"regions":[{"id":"a","name":"A","country":"NL","servers":{"meta":[{"ip":"1.1.1.1","cn":"x"}]}},"#,
            r#"{"id":"b","name":"B","country":"NL","offline":true,"servers":{"wg":[{"ip":"1.1.1.2","cn":"y"}]}},"#,
            r#"{"id":"c","name":"C","country":"NL","servers":{"wg":[{"ip":"1.1.1.3","cn":"z"}]}}]}"#,
            "\n\nc2ln"
        );
        assert_eq!(vec!["c"], parse_regions(body).unwrap().iter().map(|r| r.id.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn garbage_list_is_an_io_error() {
        assert!(parse_regions("<html>nope</html>").is_err_and(|e| is_io(&e)));
    }

    #[test]
    fn countries_and_cities() {
        let cs = countries(&parse_regions(&list()).unwrap());
        assert_eq!(
            vec!["Algeria", "Germany", "Netherlands", "United Kingdom", "United States"],
            cs.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
        let de = cs.iter().find(|c| c.code == "DE").unwrap();
        assert_eq!(vec!["Berlin", "Frankfurt"], de.cities.iter().map(|c| c.name.as_str()).collect::<Vec<_>>());
        assert_eq!(
            vec![Some("de_berlin"), Some("de-frankfurt")],
            de.cities.iter().map(|c| c.key.as_deref()).collect::<Vec<_>>()
        );
        assert_eq!(4, de.server_count);
        let nl = cs.iter().find(|c| c.code == "NL").unwrap();
        assert_eq!(
            vec!["Netherlands", "Netherlands Streaming Optimized"],
            nl.cities.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
        // Ids come from the region id, so they survive PIA adding or dropping regions.
        assert_eq!(
            nl.cities.iter().map(|c| stable_id(c.key.as_deref().unwrap())).collect::<Vec<_>>(),
            nl.cities.iter().map(|c| c.id).collect::<Vec<_>>()
        );
        assert_eq!(2, nl.cities.iter().map(|c| c.id).collect::<HashSet<_>>().len());
        assert_eq!(cs.len(), cs.iter().map(|c| c.id).collect::<HashSet<_>>().len());
    }

    #[test]
    fn add_key_response_parses() {
        let k = parse_add_key(&fixture("providers/pia_addkey.json")).unwrap();
        assert_eq!("eo8n2+EwTSaTW8R/q9uJ813QuBY8uaF+vccoM5WNDEs=", k.server_key);
        assert_eq!(1337, k.server_port);
        assert_eq!("10.30.128.2", k.peer_ip);
        assert_eq!(vec!["10.0.0.243", "10.0.0.242"], k.dns);
    }

    #[test]
    fn add_key_errors_are_io_errors() {
        assert!(
            parse_add_key(r#"{"status":"ERROR","message":"Login failed!"}"#)
                .is_err_and(|e| is_io(&e) && !e.to_string().contains("Login failed!"))
        );
        assert!(parse_add_key(r#"{"status":"OK"}"#).is_err_and(|e| is_io(&e)));
        assert!(parse_add_key("not json").is_err_and(|e| is_io(&e)));
    }

    /// The built-in CA is PIA's own, and makes a working TLS setup.
    #[test]
    fn ca_loads_into_key_store() {
        let roots = ca_store();
        assert_eq!(1, roots.len());
        assert!(roots.roots[0].subject.as_ref().windows(23).any(|w| w == b"Private Internet Access"));
        assert!(http::named(Some(&TLS), Some("denver425")).is_ok());
    }

    #[test]
    fn account_blob_round_trips() {
        let a = Account {
            username: "p1234567".into(),
            password: "pw".into(),
            token: "tok".into(),
            token_time: 1,
            private_key: "k1".into(),
            public_key: "k2".into(),
        };
        assert_eq!(a, account(&serde_json::to_string(&a).unwrap()).unwrap());
    }

    #[test]
    fn parse_failures_do_not_quote_the_reply() {
        let failures = [
            parse_add_key(r#"{"status":"OK","server_key":"SECRET-KEY","server_port":"nope" "#).err(),
            parse_regions(r#"{"regions":"SECRET-LIST" "#).err(),
            account(r#"{"username":"SECRET-USER" "#).err(),
        ];
        for e in failures {
            let e = e.expect("refused");
            assert!(is_io(&e) && !e.to_string().contains("SECRET"), "{e}");
        }
    }
}
