//! Surfshark over WireGuard. Sign-in is local: the key pair is generated (or registered) at my.surfshark.com → VPN →
//! Manual setup → Desktop or mobile → WireGuard, and one registered key works on every location.
//! Servers: Surfshark's own public list `GET api.surfshark.com/v4/server/clusters/generic` (country, city, hostname and
//! WireGuard key per cluster, no login; the updater of gluetun reads the same URL). It carries no IPs: gluetun's catalogue
//! supplies the addresses for the same host names ([`addresses`]), never keys (a swapped catalogue key would make another
//! server the trusted one), minus the Static-IP `-stNNN` servers a normal key may not be registered on. No host name is
//! looked up on the computer's own network, whose resolver would see which city each route uses. Keys only ever come
//! from Surfshark's list: if it can't be read, the last copy read ([`SNAPSHOT`]) stands in.
//! Parameters from Surfshark's manual Linux guide (support.surfshark.com/hc/en-us/articles/19262406140306): address
//! 10.14.0.2/16, DNS 162.252.172.57 and 149.154.159.92, endpoint `<host>:51820`, MTU 1280. A pasted .conf overrides them.
//! Surfshark assigns the address per key, so pasting the whole .conf is the safe route; the preshared key is not used.

use super::key_provider::{self, Account, KeyProvider};
use super::{Field, Provider, unless_io};
use crate::catalog::{self, Entry};
use crate::compiler;
use crate::error::{Error, Result};
use crate::http;
use crate::model::{Country, Link, Location, Server};
use crate::snapshot::Snapshot;
use indexmap::IndexMap;
use regex::Regex;
use serde::Deserialize;
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Cluster {
    country: String,
    region: Option<String>,
    location: Option<String>,
    connection_name: String,
    pub_key: Option<String>,
    load: Option<i32>,
}

const API: &str = "https://api.surfshark.com/v4/server/clusters/generic";
static STATIC_IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-st[0-9]+\.").unwrap());
static KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$").unwrap());

pub(crate) type Source<T> = Arc<dyn Fn() -> Result<T> + Send + Sync>;

/// Host name → IPv4 addresses.
type Book = IndexMap<String, Vec<String>>;

static CATALOGUE: LazyLock<RwLock<Source<Vec<Entry>>>> =
    LazyLock::new(|| RwLock::new(Arc::new(|| catalog::fetch("surfshark", "wireguard"))));

/// Where the addresses come from; another source is read afresh.
#[cfg(test)]
pub(crate) fn set_catalogue(f: impl Fn() -> Result<Vec<Entry>> + Send + Sync + 'static) {
    *CATALOGUE.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(f);
    let mut a = ADDRESSES.lock().unwrap_or_else(PoisonError::into_inner);
    a.list = None;
    a.tried_at = 0;
}

/// The last address list read, kept for when the catalogue can't be read.
pub(crate) static ADDRESS_BOOK: LazyLock<RwLock<Snapshot>> =
    LazyLock::new(|| RwLock::new(Snapshot::file("addresses-surfshark.json")));

struct Addresses {
    list: Option<Book>,
    at: i64,
    tried_at: i64,
}

static ADDRESSES: Mutex<Addresses> = Mutex::new(Addresses { list: None, at: 0, tried_at: 0 });

/// The last list read from Surfshark's own API: its keys still apply when the API can't be reached.
pub(crate) static SNAPSHOT: LazyLock<RwLock<Snapshot>> =
    LazyLock::new(|| RwLock::new(Snapshot::file("servers-surfshark.json")));

pub(crate) static LIVE: LazyLock<RwLock<Source<String>>> =
    LazyLock::new(|| RwLock::new(Arc::new(|| http::get(API, &[], None, None))));

fn snapshot() -> Option<String> {
    SNAPSHOT.read().unwrap_or_else(PoisonError::into_inner).read()
}

/// Host name → IPv4 addresses from gluetun's catalogue, read at most once a day; the last copy when it can't be read,
/// then asked again only after 15 minutes. Only literal addresses count: a name here would be looked up after all.
pub(crate) fn addresses(now: i64) -> Result<Book> {
    let mut a = ADDRESSES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(list) = a.list.as_ref().filter(|_| now - a.at < 86_400_000) {
        return Ok(list.clone());
    }
    let unreadable = || Error::Io("Surfshark's server addresses can't be read right now".into());
    // A failed read waits 15 minutes before the next, also with nothing kept to fall back on.
    if a.list.is_none() && now - a.tried_at < 15 * 60_000 {
        return Err(unreadable());
    }
    a.tried_at = now;
    let catalogue = CATALOGUE.read().unwrap_or_else(PoisonError::into_inner).clone();
    let fresh =
        unless_io(catalogue())?.map(|all| literal(fallback(all).into_iter().map(|e| (e.hostname, e.ips)).collect()));
    match fresh.filter(|f| !f.is_empty()) {
        Some(fresh) => {
            if let Ok(text) = serde_json::to_string(&fresh) {
                ADDRESS_BOOK.read().unwrap_or_else(PoisonError::into_inner).write(&text);
            }
            a.list = Some(fresh);
            a.at = now;
        }
        None => {
            if a.list.is_none() {
                let kept = ADDRESS_BOOK.read().unwrap_or_else(PoisonError::into_inner).read();
                a.list = kept.and_then(|text| serde_json::from_str::<Book>(&text).ok()).map(literal);
            }
            a.at = now - 86_400_000 + 15 * 60_000;
        }
    }
    a.list.clone().ok_or_else(unreadable)
}

fn literal(m: Book) -> Book {
    let literal = |ip: &String| !ip.contains('/') && compiler::ipv4(ip).is_some();
    m.into_iter()
        .map(|(host, ips)| (host, ips.into_iter().filter(literal).collect::<Vec<_>>()))
        .filter(|(_, ips)| !ips.is_empty())
        .collect()
}

pub(crate) fn parse(body: &str) -> Result<Vec<Entry>> {
    let all: Vec<Cluster> = http::parsed("Surfshark", || serde_json::from_str(body))?;
    Ok(all
        .into_iter()
        .filter(|c| {
            !c.country.trim().is_empty()
                && !c.connection_name.trim().is_empty()
                && c.pub_key.as_deref().is_some_and(|k| KEY.is_match(k))
        })
        .map(|c| Entry {
            vpn: "wireguard".into(),
            country: Some(c.country),
            region: c.region,
            city: c.location.filter(|l| !l.trim().is_empty()),
            hostname: c.connection_name,
            wgpubkey: c.pub_key,
            load: c.load.map_or(-1, |l| l.clamp(0, 100)),
            ..Entry::default()
        })
        .collect())
}

pub(crate) fn fallback(all: Vec<Entry>) -> Vec<Entry> {
    all.into_iter().filter(|e| !STATIC_IP.is_match(&e.hostname)).collect()
}

pub struct Surfshark;

impl Provider for Surfshark {
    fn id(&self) -> &'static str {
        "surfshark"
    }

    fn name(&self) -> &'static str {
        "Surfshark"
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field {
            hint: "Paste the whole file, or the private key".into(),
            file: true,
            ..Field::new("key", "WireGuard key or .conf")
        }]
    }

    fn help(&self) -> String {
        "Sign in at my.surfshark.com → VPN → Manual setup → Desktop or mobile → WireGuard → \"I don't have a key pair\" → name it → Generate a new key pair. The private key is shown only once, so also pick any location and Download the .conf, then paste that whole file here (it carries your private key and address). The same key works on every Surfshark location.".into()
    }

    /// Each cluster in the live list carries its load in percent; the catalogue fallback has none.
    fn has_load(&self) -> bool {
        true
    }

    fn facts(&self, account: &str) -> Option<String> {
        key_provider::facts(self, account)
    }

    fn trusts(&self, link: &Link, account: &str) -> bool {
        key_provider::trusts(self, link, account)
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        key_provider::sign_in(self, input)
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

impl KeyProvider for Surfshark {
    fn default_address(&self) -> Option<Vec<String>> {
        Some(vec!["10.14.0.2/16".into()])
    }

    fn default_dns(&self) -> Vec<String> {
        vec!["162.252.172.57".into(), "149.154.159.92".into()]
    }

    fn default_port(&self) -> i32 {
        51820
    }

    fn default_mtu(&self) -> i32 {
        1280
    }

    /// A saved or pinned key is reused only if Surfshark's own list (the last copy read) still has it, or it is the server
    /// key of the user's own downloaded .conf (it came from Surfshark too).
    fn trusts_key(&self, key: &str, a: &Account) -> bool {
        a.public_key.as_deref() == Some(key)
            || snapshot()
                .and_then(|s| parse(&s).ok())
                .is_some_and(|l| l.iter().any(|e| e.wgpubkey.as_deref() == Some(key)))
    }

    fn entries(&self, _a: &Account) -> Result<Vec<Entry>> {
        let live = LIVE.read().unwrap_or_else(PoisonError::into_inner).clone();
        let fresh = unless_io(live().and_then(|body| Ok((parse(&body)?, body))))?.filter(|(l, _)| !l.is_empty());
        if let Some((l, body)) = fresh {
            SNAPSHOT.read().unwrap_or_else(PoisonError::into_inner).write(&body);
            return Ok(l);
        }
        snapshot()
            .and_then(|s| parse(&s).ok())
            .filter(|l| !l.is_empty())
            .ok_or_else(|| Error::Io("Surfshark's server list can't be reached right now".into()))
    }

    /// Each of the location's hosts once, with its catalogue addresses and Surfshark's own key; hosts without one are skipped.
    fn usable(&self, all: &[Entry], loc: &Location) -> Result<Vec<Entry>> {
        let picked = catalog::pick(all, loc);
        if all.iter().any(|e| e.ipv4().is_some()) {
            return Ok(picked); // already has addresses
        }
        let ips = addresses(chrono::Utc::now().timestamp_millis())?;
        Ok(picked.into_iter().filter_map(|e| ips.get(&e.hostname).map(|ips| Entry { ips: ips.clone(), ..e })).collect())
    }
}
