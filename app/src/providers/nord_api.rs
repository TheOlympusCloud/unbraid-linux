//! The handful of NordVPN endpoints unbraid needs. Every call blocks; run them off the window's thread.

use crate::error::{Error, Result};
use crate::http;
use crate::model::{Country, Location, Server};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::NaiveDateTime;
use indexmap::IndexSet;
use serde::Deserialize;
use std::collections::HashSet;

const BASE: &str = "https://api.nordvpn.com/v1";
const DEDICATED_IP_SERVICE: i64 = 11;

fn get(path: &str, token: Option<&str>) -> Result<String> {
    let auth = token.map(|t| format!("Basic {}", STANDARD.encode(format!("token:{t}"))));
    let headers: Vec<(&str, &str)> = auth.iter().map(|a| ("Authorization", a.as_str())).collect();
    http::get(&format!("{BASE}{path}"), &headers, None, None).map_err(|e| match e {
        Error::Auth { .. } => Error::Auth { message: "NordVPN rejected the token. Sign in again.".into(), url: None },
        e => e,
    })
}

#[derive(Deserialize)]
struct Credentials {
    nordlynx_private_key: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

/// NordLynx private key plus the service username and password OpenVPN needs.
pub fn credentials(token: &str) -> Result<(String, String, String)> {
    let body = get("/users/services/credentials", Some(token))?;
    let c: Credentials = http::parsed("NordVPN", || serde_json::from_str(&body))?;
    match (c.nordlynx_private_key, c.username, c.password) {
        (Some(key), Some(user), Some(pass)) => Ok((key, user, pass)),
        _ => Err(Error::Fail("Unexpected reply from NordVPN. Try again later".into())),
    }
}

pub fn countries() -> Result<Vec<Country>> {
    let body = get("/servers/countries", None)?;
    http::parsed("NordVPN", || serde_json::from_str(&body))
}

/// Lowest-load servers for a location, best first. `tech`: wireguard_udp, openvpn_udp or openvpn_tcp.
pub fn recommend(loc: &Location, limit: usize, tech: &str) -> Result<Vec<Server>> {
    let mut q = vec![("filters[servers_technologies][identifier]", tech.to_string())];
    q.extend(loc.country_id.map(|id| ("filters[country_id]", id.to_string())));
    q.extend(loc.city_id.map(|id| ("filters[country_city_id]", id.to_string())));
    q.extend(loc.group.clone().map(|g| ("filters[servers_groups][identifier]", g)));
    q.push(("limit", limit.to_string()));
    let q = q.iter().map(|(k, v)| http::enc(k) + "=" + v).collect::<Vec<_>>().join("&");
    parse_servers(&get(&format!("/servers/recommendations?{q}"), None)?, tech == "wireguard_udp")
}

fn query(pairs: &[(&str, Option<&str>)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| http::enc(k) + &v.map(|v| format!("={v}")).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("&")
}

/// The `/servers` list of `place` for `tech`, cut down to the given response `fields`.
fn servers(place: (&str, &str), tech: &str, fields: &[&str]) -> Result<String> {
    let fields: Vec<String> = fields.iter().map(|f| format!("fields[servers.{f}]")).collect();
    let mut pairs = vec![
        (place.0, Some(place.1)),
        ("filters[servers_technologies][identifier]", Some(tech)),
        ("limit", Some("20000")),
    ];
    pairs.extend(fields.iter().map(|f| (f.as_str(), None)));
    get(&format!("/servers?{}", query(&pairs)), None)
}

/// The whole `/servers` list of a specialty `group` for `tech`, cut down to the given response `fields`.
fn group_servers(group: &str, tech: &str, fields: &[&str]) -> Result<String> {
    servers(("filters[servers_groups][identifier]", group), tech, fields)
}

/// A city's servers for `tech`, or a country's without a city (the API can't look one up by host name), cut down to
/// what a [`Server`] needs: a few hundred at most per city, some thousands for a whole large country.
pub fn in_place(country_id: i32, city_id: Option<i32>, tech: &str) -> Result<Vec<Server>> {
    let place = match city_id {
        Some(city) => ("filters[country_city_id]", city.to_string()),
        None => ("filters[country_id]", country_id.to_string()),
    };
    let fields = [
        "name",
        "hostname",
        "station",
        "load",
        "locations.country.code",
        "locations.country.city.name",
        "technologies.identifier",
        "technologies.metadata",
    ];
    parse_servers(&servers((place.0, &place.1), tech, &fields)?, tech == "wireguard_udp")
}

/// Country codes with servers in a specialty `group`. `/servers/recommendations` is distance-sorted and cuts a long
/// list short (P2P came back as 4 countries); the full `/servers` list with two fields is complete and small.
pub fn group_countries(group: &str, tech: &str) -> Result<IndexSet<String>> {
    country_codes(&group_servers(group, tech, &["locations.country.code", "hostname"])?)
}

#[derive(Deserialize)]
struct Located {
    #[serde(default)]
    locations: Vec<Place>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Place {
    country: Option<Where>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Where {
    code: Option<String>,
    city: Option<Named>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Named {
    name: Option<String>,
}

pub(crate) fn country_codes(body: &str) -> Result<IndexSet<String>> {
    let all: Vec<Located> = http::parsed("NordVPN", || serde_json::from_str(body))?;
    Ok(all.into_iter().flat_map(|s| s.locations).filter_map(|p| p.country?.code).collect())
}

/// The servers of the account's active Dedicated IP services, as nordvpn-linux does it (daemon/serverpicker/dip.go):
/// `/users/services` lists them (service id 11, `details.servers[].id`), and the ids are looked up in the Dedicated IP group.
pub fn dedicated(token: &str, tech: &str) -> Result<Vec<Server>> {
    let ids = dedicated_ids(&get("/users/services", Some(token))?, chrono::Utc::now().naive_utc())?;
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let fields = [
        "id",
        "name",
        "hostname",
        "station",
        "load",
        "locations.country.code",
        "locations.country.city.name",
        "technologies.identifier",
        "technologies.metadata",
    ];
    with_ids(&group_servers("legacy_dedicated_ip", tech, &fields)?, &ids, tech == "wireguard_udp")
}

pub(crate) fn with_ids(body: &str, ids: &HashSet<i64>, need_key: bool) -> Result<Vec<Server>> {
    let all: Vec<Listed> = http::parsed("NordVPN", || serde_json::from_str(body))?;
    Ok(all
        .into_iter()
        .filter(|s| s.id.is_some_and(|id| ids.contains(&id)))
        .filter_map(|s| s.server(need_key))
        .collect())
}

#[derive(Deserialize)]
struct Service {
    #[serde(default)]
    service: Option<Id>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    details: Option<Details>,
}

#[derive(Deserialize)]
struct Id {
    #[serde(default)]
    id: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Details {
    servers: Vec<Id>,
}

pub(crate) fn dedicated_ids(body: &str, now: NaiveDateTime) -> Result<HashSet<i64>> {
    let all: Vec<Service> = http::parsed("NordVPN", || serde_json::from_str(body))?;
    Ok(all
        .into_iter()
        .filter(|s| {
            // A service whose end date can't be read is kept.
            let ends = s.expires_at.as_ref().and_then(|e| e.replace(' ', "T").parse::<NaiveDateTime>().ok());
            s.service.as_ref().and_then(|x| x.id) == Some(DEDICATED_IP_SERVICE) && ends.is_none_or(|t| t >= now)
        })
        .flat_map(|s| s.details.unwrap_or_default().servers)
        .filter_map(|x| x.id)
        .collect())
}

/// A server as `/servers` lists it, with the fields asked for.
#[derive(Deserialize)]
struct Listed {
    #[serde(default)]
    id: Option<i64>,
    name: String,
    hostname: String,
    station: String,
    #[serde(default)]
    load: Option<i32>,
    #[serde(default)]
    locations: Vec<Place>,
    #[serde(default)]
    technologies: Vec<Tech>,
}

#[derive(Deserialize)]
struct Tech {
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    metadata: Vec<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

impl Listed {
    /// As a [`Server`]; none without a WireGuard key when `need_key`.
    fn server(self, need_key: bool) -> Option<Server> {
        let key = self
            .technologies
            .iter()
            .find(|t| t.identifier.as_deref() == Some("wireguard_udp"))
            .and_then(|t| t.metadata.iter().find(|m| m.name.as_deref() == Some("public_key")))
            .and_then(|m| m.value.clone());
        let key = match key {
            Some(k) => k,
            None if need_key => return None,
            None => String::new(),
        };
        let place = self.locations.into_iter().next().and_then(|p| p.country);
        Some(Server {
            name: self.name,
            host: self.hostname,
            ip: self.station,
            public_key: key,
            load: self.load.unwrap_or(0),
            city: place.as_ref().and_then(|p| p.city.as_ref()?.name.clone()).unwrap_or_default(),
            country: place.and_then(|p| p.code).unwrap_or_default(),
        })
    }
}

pub(crate) fn parse_servers(body: &str, need_key: bool) -> Result<Vec<Server>> {
    let all: Vec<Listed> = http::parsed("NordVPN", || serde_json::from_str(body))?;
    Ok(all.into_iter().filter_map(|s| s.server(need_key)).collect())
}
