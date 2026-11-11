//! Windscribe over WireGuard. Windscribe has no API to register a key, so the user generates one config at
//! windscribe.com (Config generators → WireGuard, a paid-plan feature) and pastes it once. Account blob: that config's
//! private key, tunnel address, preshared key, DNS, MTU and port.
//!
//! One config serves every server: the private key, address and preshared key are "specific by user and the same for all
//! servers" (gluetun wiki, setup/providers/windscribe.md, which also says the preshared key MUST be set). A
//! Build-a-Plan account can only use the locations it paid for (windscribe.com/knowledge-base/articles/where-do-i-access-my-wireguard-configs).
//!
//! Servers: Windscribe's public server list, the one gluetun's updater reads without a login
//! (internal/provider/windscribe/updater/api.go: `https://assets.windscribe.com/serverlist/mob-v2/1/<unix time>`).
//! Per gluetun's updater/servers.go, a node's WireGuard endpoint is its third address `ip3` and the server's public key
//! is its group's `wg_pubkey`. Port: the one in the pasted config when it is one gluetun allows for Windscribe
//! (53, 80, 123, 443, 1194, 65142; internal/configuration/settings/wireguardselection.go), else 1194, gluetun's default
//! (internal/provider/windscribe/connection.go: `NewConnectionDefaults(443, 1194, 1194)`). DNS is the pasted config's.
//! `health` in the server list is read as a load figure (lower = better) and only used to order servers.

use super::{Field, Provider, encode};
use crate::error::{Error, Result};
use crate::http;
use crate::manual::{invalid, require};
use crate::model::{City, Country, Link, Location, Server, WgPeer, eq_ignore_case, stable_id};
use crate::wg_conf::{self, valid_wg_key};
use indexmap::IndexMap;
use rand::Rng;
use rand::seq::SliceRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Account {
    pub(crate) private_key: String,
    pub(crate) address: Vec<String>,
    pub(crate) preshared_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) dns: Vec<String>,
    #[serde(default = "default_mtu", skip_serializing_if = "is_default_mtu")]
    pub(crate) mtu: i32,
    #[serde(default = "default_port", skip_serializing_if = "is_default_port")]
    pub(crate) port: i32,
}

fn default_mtu() -> i32 {
    1420
}
fn is_default_mtu(m: &i32) -> bool {
    *m == 1420
}
fn default_port() -> i32 {
    DEFAULT_PORT
}
fn is_default_port(p: &i32) -> bool {
    *p == DEFAULT_PORT
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct Node {
    pub(crate) hostname: String,
    pub(crate) ip3: String,
    pub(crate) health: i32,
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct Group {
    pub(crate) city: String,
    #[serde(rename = "wg_pubkey")]
    pub(crate) public_key: String,
    pub(crate) nodes: Vec<Node>,
    /// The host Windscribe's Config Generator writes as Endpoint for this location.
    pub(crate) wg_endpoint: String,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct Region {
    pub(crate) name: String,
    #[serde(rename = "country_code")]
    pub(crate) code: String,
    pub(crate) status: i32,
    pub(crate) groups: Vec<Group>,
}

impl Default for Region {
    fn default() -> Self {
        Region { name: String::new(), code: String::new(), status: 1, groups: vec![] }
    }
}

#[derive(Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(default)]
pub(crate) struct ServerList {
    pub(crate) data: Vec<Region>,
}

/// One WireGuard-capable node with its place.
#[derive(Clone, Debug)]
pub(crate) struct Row {
    pub(crate) region: String,
    pub(crate) code: String,
    pub(crate) city: String,
    pub(crate) node: Node,
    pub(crate) public_key: String,
}

const LIST: &str = "https://assets.windscribe.com/serverlist/mob-v2/1/";
const DEFAULT_PORT: i32 = 1194;
const PORTS: [i32; 6] = [53, 80, 123, 443, 1194, 65142];
static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$").unwrap());
static HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$").unwrap());

pub(crate) type Hosts = Arc<dyn Fn() -> Option<HashSet<String>> + Send + Sync>;

/// Host names of the ordinary locations (each group's WireGuard host, as generated configs name it, and its nodes),
/// also of locations down right now; none if the list can't be read (then only the endpoint's form is checked).
pub(crate) static NODE_HOSTS: LazyLock<RwLock<Hosts>> =
    LazyLock::new(|| RwLock::new(Arc::new(|| list().ok().map(|l| hosts(&l)))));

pub(crate) fn hosts(l: &ServerList) -> HashSet<String> {
    let names = l
        .data
        .iter()
        .flat_map(|r| r.groups.iter().flat_map(|g| g.nodes.iter().map(|n| &n.hostname).chain([&g.wg_endpoint])));
    names.filter(|h| !h.trim().is_empty()).map(|h| h.to_lowercase()).collect()
}

/// A Static IP config points at one purchased address or host that is not in the node list.
fn is_static(endpoint: &str) -> bool {
    let host = endpoint.rsplit_once(':').map_or(endpoint, |(host, _)| host);
    let node_hosts = NODE_HOSTS.read().unwrap_or_else(PoisonError::into_inner).clone();
    IPV4.is_match(host)
        || !HOST.is_match(host)
        || host.to_lowercase().contains("static")
        || node_hosts().is_some_and(|known| !known.contains(&host.to_lowercase()))
}

pub struct Windscribe;

impl Provider for Windscribe {
    fn id(&self) -> &'static str {
        "windscribe"
    }

    fn name(&self) -> &'static str {
        "Windscribe"
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "Paste the whole file".into(), file: true, ..Field::new("config", "WireGuard config") }]
    }

    fn help(&self) -> String {
        "A paid plan is needed. Sign in at windscribe.com, open My Account, Config Generator, WireGuard tab, pick any location and a port (443 if unsure), keep \"Generate new keypair\", then Download Config. Open the file in a text editor and paste all of it here. The key works for every location your plan covers. Build-a-Plan accounts can only connect to the locations they paid for. Static IP configs are tied to one server: import those under \"Your own servers\" instead.".into()
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let p = wg_conf::parse(input.get("config").map_or("", |c| c.trim()), self.name())?;
        require!(
            !is_static(&p.endpoint),
            "This looks like a Static IP config, which is tied to one server. Import it under \"Your own servers\" instead."
        );
        let psk = p.preshared_key.ok_or_else(|| {
            invalid("This config has no PresharedKey. Generate a WireGuard config at windscribe.com and paste that")
        })?;
        let port = p
            .endpoint
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .filter(|port| PORTS.contains(port))
            .unwrap_or(DEFAULT_PORT);
        encode(&Account {
            private_key: p.private_key,
            address: p.address,
            preshared_key: psk,
            dns: p.dns,
            mtu: p.mtu,
            port,
        })
    }

    fn countries(&self, _account: &str) -> Result<Vec<Country>> {
        Ok(countries(&fetch()?))
    }

    // A pinned node is looked up in the current list (its address and group key may have changed); the saved one only offline.
    fn connect(&self, loc: &Location, blob: &str) -> Result<Link> {
        let rows = if loc.pinned.is_none() { Some(fetch()?) } else { fetch().ok() };
        link(rows.as_deref(), loc, &account(blob)?, &mut rand::rng())
    }

    fn servers(&self, loc: &Location, _account: &str, limit: usize) -> Result<Vec<Server>> {
        let rows = fetch()?;
        let mut rs = matching(&rows, loc);
        rs.sort_by(|a, b| a.node.health.cmp(&b.node.health).then_with(|| a.node.hostname.cmp(&b.node.hostname)));
        Ok(rs.into_iter().take(limit).map(server).collect())
    }
}

pub(crate) fn account(blob: &str) -> Result<Account> {
    http::parsed("Windscribe", || serde_json::from_str(blob))
}

fn list() -> Result<ServerList> {
    parse(&http::get(&format!("{LIST}{}", chrono::Utc::now().timestamp()), &[], None, None)?)
}

fn fetch() -> Result<Vec<Row>> {
    Ok(rows(&list()?))
}

pub(crate) fn parse(body: &str) -> Result<ServerList> {
    http::parsed("Windscribe", || serde_json::from_str(body))
}

/// Nodes that have a WireGuard address and a valid group key, in regions that are up.
pub(crate) fn rows(l: &ServerList) -> Vec<Row> {
    l.data
        .iter()
        .filter(|r| r.status == 1 && !r.name.trim().is_empty())
        .flat_map(|r| {
            r.groups.iter().filter(|g| valid_wg_key(&g.public_key) && !g.city.trim().is_empty()).flat_map(move |g| {
                g.nodes.iter().filter(|n| IPV4.is_match(&n.ip3) && !n.hostname.trim().is_empty()).map(move |n| Row {
                    region: r.name.clone(),
                    code: r.code.to_uppercase(),
                    city: g.city.clone(),
                    node: n.clone(),
                    public_key: g.public_key.clone(),
                })
            })
        })
        .collect()
}

/// Windscribe's own locations: "US East", "Canada West", "Japan"…, with the cities in them.
pub(crate) fn countries(rows: &[Row]) -> Vec<Country> {
    let mut by_region: IndexMap<&str, Vec<&Row>> = IndexMap::new();
    for r in rows {
        by_region.entry(r.region.as_str()).or_default().push(r);
    }
    by_region.sort_keys();
    by_region
        .into_iter()
        .map(|(region, rs)| {
            let mut cities: Vec<&str> = rs.iter().map(|r| r.city.as_str()).collect();
            cities.sort();
            cities.dedup();
            Country {
                id: stable_id(region),
                name: region.into(),
                code: rs[0].code.clone(),
                server_count: rs.len() as i32,
                cities: cities
                    .into_iter()
                    .map(|c| City { id: stable_id(c), name: c.into(), key: Some(c.into()) })
                    .collect(),
            }
        })
        .collect()
}

/// Nodes for `loc`: a location by name (several share one country code), else by country code; [`Location::region`]
/// narrows to a city.
pub(crate) fn matching<'a>(rows: &'a [Row], loc: &Location) -> Vec<&'a Row> {
    rows.iter()
        .filter(|r| {
            let place = match (&loc.country, &loc.country_code) {
                (None, None) => true,
                (Some(country), _) => r.region == *country,
                (None, Some(cc)) => eq_ignore_case(&r.code, cc),
            };
            place && loc.region.as_ref().is_none_or(|city| r.city == *city)
        })
        .collect()
}

pub(crate) fn link(rows: Option<&[Row]>, loc: &Location, a: &Account, rnd: &mut impl Rng) -> Result<Link> {
    let sv = match (rows, &loc.pinned) {
        (None, Some(pinned)) => pinned.clone(),
        // A list is always read when nothing is pinned.
        (None, None) => return Err(Error::State(String::new())),
        (Some(rows), Some(pinned)) => rows
            .iter()
            .find(|r| r.node.hostname == pinned.host)
            .map(server)
            .ok_or_else(|| Error::NoLongerOffered(pinned.name.clone()))?,
        (Some(rows), None) => {
            let mut rs = matching(rows, loc);
            if rs.is_empty() {
                return Err(Error::Io(format!("No Windscribe server for {}", loc.label())));
            }
            rs.shuffle(rnd);
            rs.into_iter().min_by_key(|r| r.node.health).map(server).ok_or_else(|| Error::State(String::new()))?
        }
    };
    let peer = WgPeer {
        preshared_key: Some(a.preshared_key.clone()),
        dns: a.dns.clone(),
        mtu: a.mtu,
        ..WgPeer::new(
            &sv.name,
            &a.private_key,
            a.address.clone(),
            &sv.public_key,
            &format!("{}:{}", sv.ip, a.port),
            vec!["0.0.0.0/0".into()],
        )
    };
    Ok(Link::Wg { server: sv, peer, ports: vec![], entries: vec![] })
}

fn server(r: &Row) -> Server {
    Server {
        name: r.node.hostname.split('.').next().unwrap_or_default().into(),
        host: r.node.hostname.clone(),
        ip: r.node.ip3.clone(),
        public_key: r.public_key.clone(),
        load: r.node.health,
        city: r.city.clone(),
        country: r.code.clone(),
    }
}
