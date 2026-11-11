//! NordVPN: NordLynx (WireGuard), or OpenVPN UDP/TCP, which Double VPN and Onion over VPN need.

use super::{Field, Limit, Opt, PROTECT, Provider, as_listed, encode, nord_api};
use crate::error::{Error, Result};
use crate::manual::{self, require};
use crate::model::{Country, Link, Location, Server, WgPeer, eq_ignore_case};
use crate::{compiler, http};
use indexmap::{IndexMap, IndexSet};
use rand::seq::IndexedRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub token: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pass: String,
}

/// Groups only served over OpenVPN.
pub const OPEN_VPN_ONLY: [&str; 2] = ["legacy_double_vpn", "legacy_onion_over_vpn"];
pub const DEDICATED_IP: &str = "legacy_dedicated_ip";

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9]{32,128}$").unwrap());
static HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9-]+\.nordvpn\.com$").unwrap());

/// Nord's profiles rely on `cipher AES-256-CBC`, which OpenVPN 2.6 (and the engine) ignore for negotiation; Nord's
/// servers still need CBC offered, so the 2.6-style equivalent is spelled out (verified live: without it the tunnel
/// never comes up).
const LEGACY_CIPHERS: &str = "\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC\ndata-ciphers-fallback AES-256-CBC\n";

pub struct Nord;

impl Provider for Nord {
    fn id(&self) -> &'static str {
        "nord"
    }

    fn name(&self) -> &'static str {
        "NordVPN"
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "Paste token".into(), ..Field::new("token", "Access token") }]
    }

    fn help(&self) -> String {
        "Nord Account → NordVPN → Manual setup → Generate new token.".into()
    }

    fn protection(&self) -> Option<Opt> {
        Some(Opt::new(PROTECT, "Threat Protection Lite", "Ads and malicious domains"))
    }

    fn defaults(&self) -> IndexMap<String, String> {
        IndexMap::from([(PROTECT.to_string(), "on".to_string())])
    }

    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "connection".into(), per_tunnel: true, value: Some(10) }
    }

    fn blocking_dns(&self, _opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        Some(compiler::NORD_TP.into())
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        let t: String = input.get("token").map_or("", String::as_str).chars().filter(|c| !c.is_whitespace()).collect();
        require!(TOKEN.is_match(&t), "That doesn't look like a NordVPN token");
        let (key, user, pass) = nord_api::credentials(&t)?;
        encode(&Account { token: t, key, user, pass })
    }

    fn countries(&self, _account: &str) -> Result<Vec<Country>> {
        let mut all = nord_api::countries()?;
        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all)
    }

    /// Every NordVPN server carries its load, and the recommendations come lowest load first.
    fn has_load(&self) -> bool {
        true
    }

    fn one_key(&self) -> bool {
        true
    }

    fn connect(&self, loc: &Location, blob: &str) -> Result<Link> {
        let a = account(blob)?;
        let tech = tech(loc);
        let dedicated_ip = loc.group.as_deref() == Some(DEDICATED_IP);
        let sv = match &loc.pinned {
            // A pinned server as Nord lists it now (address and key can change); as saved when the list can't be read.
            Some(p) => {
                // A Dedicated IP server comes from the account's own list, which a refused login must not hide.
                let list = if dedicated_ip { nord_api::dedicated(&a.token, &tech).map(Some) } else { loc.country_id.map(|c| nord_api::in_place(c, loc.city_id, &tech)).transpose() };
                let list = match list {
                    Err(e @ Error::Auth { .. }) => return Err(e),
                    list => list.ok().flatten(),
                };
                as_listed(p, list)?
            }
            None if dedicated_ip => dedicated(&a, loc, &tech)?.into_iter().next().ok_or_else(|| Error::Io(format!("Your Dedicated IP isn't in {}", loc.label())))?,
            // One of the three least loaded, not always the first: Nord gives an account one WireGuard key for every
            // device, and two devices with one key on one server knock each other off. Every device at the same place
            // (and Nord's own apps) is told the same first choice.
            None => nord_api::recommend(loc, 3, &tech)?.choose(&mut rand::rng()).cloned().ok_or_else(|| Error::Io(format!("No NordVPN server for {}", loc.label())))?,
        };
        if tech == "wireguard_udp" {
            return Ok(Link::Wg { peer: peer(&sv, &a.key), server: sv, ports: vec![], entries: vec![] });
        }
        // OpenVPN: Nord publishes one profile per server; the login is the account's service credentials.
        let (user, pass) = if !a.user.is_empty() {
            (a.user, a.pass)
        } else {
            let (_, user, pass) = nord_api::credentials(&a.token)?;
            (user, pass)
        };
        let proto = tech.strip_prefix("openvpn_").unwrap_or(&tech);
        require!(HOST.is_match(&sv.host), "Unexpected server name");
        let text = http::get(&format!("https://downloads.nordcdn.com/configs/files/ovpn_{proto}/servers/{}.{proto}.ovpn", sv.host), &[], None, None)?;
        let profile = manual::parse_ovpn(&with_legacy_ciphers(&text), &sv.name, &user, &pass)?;
        Ok(Link::Ovpn { server: sv, profile })
    }

    fn servers(&self, loc: &Location, blob: &str, limit: usize) -> Result<Vec<Server>> {
        if loc.group.as_deref() == Some(DEDICATED_IP) {
            return Ok(dedicated(&account(blob)?, loc, &tech(loc))?.into_iter().take(limit).collect());
        }
        nord_api::recommend(&Location { pinned: None, ..loc.clone() }, limit, &tech(loc))
    }
}

pub fn account(blob: &str) -> Result<Account> {
    http::parsed("the account store", || serde_json::from_str(blob))
}

pub fn tech(loc: &Location) -> String {
    if loc.group.as_deref().is_some_and(|g| OPEN_VPN_ONLY.contains(&g)) {
        loc.protocol.clone().filter(|p| p.starts_with("openvpn")).unwrap_or_else(|| "openvpn_udp".into())
    } else {
        loc.protocol.clone().unwrap_or_else(|| "wireguard_udp".into())
    }
}

/// Country codes that have servers in a specialty `group` (P2P, Double VPN, Onion…).
pub fn group_countries(group: &str) -> Result<IndexSet<String>> {
    nord_api::group_countries(group, if OPEN_VPN_ONLY.contains(&group) { "openvpn_udp" } else { "wireguard_udp" })
}

/// The servers of the account's own Dedicated IP, narrowed to `loc`'s country; an account without one is told so.
fn dedicated(a: &Account, loc: &Location, tech: &str) -> Result<Vec<Server>> {
    let mine = nord_api::dedicated(&a.token, tech)?;
    if mine.is_empty() {
        return Err(Error::Io("This NordVPN account has no Dedicated IP. Add one in your Nord Account, or pick another server group.".into()));
    }
    Ok(mine.into_iter().filter(|s| loc.country_code.as_ref().is_none_or(|c| eq_ignore_case(&s.country, c))).collect())
}

pub(crate) fn with_legacy_ciphers(profile: &str) -> String {
    format!("{profile}{LEGACY_CIPHERS}")
}

pub fn peer(sv: &Server, key: &str) -> WgPeer {
    WgPeer::new(&sv.name, key, vec!["10.5.0.2/32".into()], &sv.public_key, &format!("{}:51820", sv.ip), vec!["0.0.0.0/0".into()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::tests::fixture;
    use serde_json::Value;
    use std::path::Path;

    fn ovpn(name: &str) -> String {
        fixture(&format!("providers/ovpn/{name}"))
    }

    #[test]
    fn nord_double_vpn_profiles_parse_and_validate() {
        for n in ["nord-double.udp.ovpn", "nord-double.tcp.ovpn"] {
            let p = manual::parse_ovpn(&ovpn(n), "UK-NL #19", "user", "pass").unwrap();
            let ep = manual::ovpn_endpoint("r-nord", &p).unwrap();
            assert_eq!(Some("openvpn-client"), ep["type"].as_str());
            assert_eq!(Some(true), ep["ping_restart_disabled"].as_bool());
            assert!(!ep.contains_key("ping_restart"));
            assert_eq!(Some("15s"), ep["ping_interval"].as_str());
            let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/manual");
            std::fs::create_dir_all(&dir).unwrap();
            let cfg = format!(r#"{{"log":{{"level":"warn"}},"endpoints":[{}],"route":{{"final":"r-nord"}}}}"#, Value::Object(ep));
            std::fs::write(dir.join(format!("nord-{n}.json")), cfg).unwrap();
        }
    }

    #[test]
    fn nord_profiles_still_offer_the_cbc_cipher_nord_servers_need() {
        let p = manual::parse_ovpn(&with_legacy_ciphers(&ovpn("nord-double.udp.ovpn")), "dv", "user", "pass").unwrap();
        let ep = manual::ovpn_endpoint("r", &p).unwrap();
        let ciphers: Vec<String> = ep["data_ciphers"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_uppercase()).collect();
        assert!(ciphers.contains(&"AES-256-CBC".to_string()) && ciphers.contains(&"AES-256-GCM".to_string()), "{ciphers:?}");
        assert_eq!("AES-256-CBC", ep["data_ciphers_fallback"].as_str().unwrap().to_uppercase());
    }
}
