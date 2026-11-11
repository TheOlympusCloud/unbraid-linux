//! Providers where the user downloads one WireGuard key (or .conf) from the website and that single key serves every
//! server: sign-in is local, with no API to check it against (AirVPN's can also fetch the .conf with an API key). The
//! tunnel settings come from the pasted .conf when there is one, else from the provider's documented defaults; the
//! server list comes from [`KeyProvider::entries`].
//!
//! Each key provider implements [`Provider`] with the functions here, and [`KeyProvider`] for what differs.

use super::{Provider, encode, is_io, unless_io};
use crate::catalog::{self, Entry};
use crate::error::{Error, Result};
use crate::http;
use crate::manual::{invalid, require};
use crate::model::{Country, Link, Location, Server, WgPeer};
use crate::wg_conf;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub private_key: String,
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub port: i32,
    pub mtu: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// The [Peer] key of a pasted .conf; only meaningful for providers whose servers all share one key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Settings the provider wrote into a pasted .conf as comments ([`KeyProvider::config_facts`]); none when only a key
    /// was pasted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<IndexMap<String, String>>,
    /// For a key the provider's API made: the API key, and the name, public key and id of the device it belongs to;
    /// `own_device` when the app made that device itself, so signing out removes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub own_device: bool,
}

impl Account {
    pub fn new(private_key: &str, address: Vec<String>, dns: Vec<String>, port: i32, mtu: i32) -> Self {
        Account {
            private_key: private_key.into(),
            address,
            dns,
            port,
            mtu,
            preshared_key: None,
            public_key: None,
            facts: None,
            api_key: None,
            device: None,
            device_key: None,
            device_id: None,
            own_device: false,
        }
    }
}

/// What a key provider decides for itself.
pub trait KeyProvider: Provider {
    /// Comment lines ("# NetShield = 0") a provider writes into its configs that say how the key was made, to show them.
    fn config_facts(&self) -> &'static [&'static str] {
        &[]
    }
    /// How one of `config_facts` reads on the page.
    fn fact(&self, key: &str, value: &str) -> String {
        format!("{key} {value}")
    }
    /// Tunnel address when only a bare key is pasted; none if the provider assigns it per device (the .conf is then required).
    fn default_address(&self) -> Option<Vec<String>>;
    fn default_dns(&self) -> Vec<String>;
    fn default_port(&self) -> i32;
    fn default_mtu(&self) -> i32 {
        1420
    }
    fn preshared_required(&self) -> bool {
        false
    }
    /// Every port its servers take, best first; the account's own port is always tried first.
    fn ports(&self) -> Vec<i32> {
        vec![]
    }
    /// A server's entry addresses for a tunnel's `entries`; none unless the provider has an entry setting.
    fn addresses(&self, _e: &Entry) -> Vec<String> {
        vec![]
    }
    fn entries(&self, a: &Account) -> Result<Vec<Entry>>;
    /// Whether a server key from an earlier list (a pinned or saved server) may still be used.
    fn trusts_key(&self, _key: &str, _a: &Account) -> bool {
        true
    }
    /// The server key a tunnel uses: the list's, unless the provider takes it from the account.
    fn peer_key(&self, sv: &Server, _a: &Account) -> String {
        sv.public_key.clone()
    }
    /// The servers of `all` that suit `loc`, best first, each complete enough to connect to. Providers whose list lacks
    /// addresses (Surfshark's live one) override this to resolve them.
    fn usable(&self, all: &[Entry], loc: &Location) -> Result<Vec<Entry>> {
        Ok(catalog::pick(all, loc))
    }
}

static KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[A-Za-z0-9+/]{43}=$").unwrap());
static MTU: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?imR)^[[:space:]]*mtu[[:space:]]*=").unwrap());
static FACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?mR)^[[:space:]]*#[[:space:]]*([A-Za-z][A-Za-z ()-]{0,40}?)[[:space:]]*=[[:space:]]*([A-Za-z0-9 .-]{1,40})[[:space:]]*$").unwrap()
});

pub fn facts<P: KeyProvider + ?Sized>(p: &P, blob: &str) -> Option<String> {
    let keys = p.config_facts();
    if keys.is_empty() {
        return None;
    }
    let Some(f) = account(blob).ok().and_then(|a| a.facts) else { return Some(String::new()) };
    let shown: Vec<String> = keys.iter().filter_map(|k| f.get(*k).map(|v| p.fact(k, v))).collect();
    Some(if shown.is_empty() { "None in your config".into() } else { shown.join(" · ") })
}

pub fn trusts<P: KeyProvider + ?Sized>(p: &P, link: &Link, blob: &str) -> bool {
    match link {
        Link::Wg { server, peer, .. } => account(blob).is_ok_and(|a| peer.public_key == p.peer_key(server, &a) && p.trusts_key(&peer.public_key, &a)),
        _ => true,
    }
}

pub fn sign_in<P: KeyProvider + ?Sized>(p: &P, input: &IndexMap<String, String>) -> Result<String> {
    let text = input.get("key").map_or("", |k| k.trim());
    let a = if text.contains('[') { from_conf(p, text)? } else { from_key(p, &text.chars().filter(|c| !c.is_whitespace()).collect::<String>())? };
    encode(&a)
}

fn from_key<P: KeyProvider + ?Sized>(p: &P, key: &str) -> Result<Account> {
    require!(KEY.is_match(key), "That doesn't look like a WireGuard private key");
    let address = p.default_address().ok_or_else(|| invalid(format!("{} needs the whole downloaded .conf file: it holds this device's address and preshared key", p.name())))?;
    Ok(Account::new(key, address, p.default_dns(), p.default_port(), p.default_mtu()))
}

fn from_conf<P: KeyProvider + ?Sized>(p: &P, text: &str) -> Result<Account> {
    let c = wg_conf::parse(text, p.name())?;
    require!(!p.preshared_required() || c.preshared_key.is_some(), "That {} config has no PresharedKey line", p.name());
    let keys = p.config_facts();
    let facts = (!keys.is_empty()).then(|| {
        FACT.captures_iter(text)
            .filter_map(|m| {
                let key = m[1].trim();
                keys.contains(&key).then(|| (key.to_string(), m[2].trim().chars().take(24).collect()))
            })
            .collect()
    });
    Ok(Account {
        address: c.address.iter().map(|a| if a.contains('/') { a.clone() } else { format!("{a}/32") }).collect(),
        dns: if c.dns.is_empty() { p.default_dns() } else { c.dns },
        port: c.endpoint.rsplit(':').next().and_then(|port| port.parse().ok()).ok_or_else(|| invalid("Endpoint needs host:port"))?,
        mtu: if MTU.is_match(text) { c.mtu } else { p.default_mtu() },
        preshared_key: c.preshared_key,
        public_key: Some(c.public_key),
        facts,
        ..Account::new(&c.private_key, vec![], vec![], 0, 0)
    })
}

pub fn account(blob: &str) -> Result<Account> {
    http::parsed("the account store", || serde_json::from_str(blob))
}

pub fn countries<P: KeyProvider + ?Sized>(p: &P, blob: &str) -> Result<Vec<Country>> {
    Ok(catalog::countries(&p.entries(&account(blob)?)?))
}

pub fn connect<P: KeyProvider + ?Sized>(p: &P, loc: &Location, blob: &str) -> Result<Link> {
    let a = account(blob)?;
    link(p, loc, &a, || p.entries(&a))
}

pub fn servers<P: KeyProvider + ?Sized>(p: &P, loc: &Location, blob: &str, limit: usize) -> Result<Vec<Server>> {
    p.usable(&p.entries(&account(blob)?)?, loc)?.iter().take(limit).map(|e| catalog::server(e, None)).collect()
}

/// The current address and key of a pinned server, found by host name and name (AirVPN shares one host name per
/// country), else by IP. The pinned values stand in only when the list can't be read; a server the list no longer has
/// is an error rather than a stale endpoint.
fn refreshed<P: KeyProvider + ?Sized>(
    p: &P,
    pinned: &Server,
    loc: &Location,
    a: &Account,
    entries: impl Fn() -> Result<Vec<Entry>>,
) -> Result<(Server, Option<Entry>)> {
    let all = match entries() {
        Ok(all) => all,
        Err(e) if is_io(&e) && p.trusts_key(&p.peer_key(pinned, a), a) => return Ok((pinned.clone(), None)),
        Err(e) => return Err(e),
    };
    let name = |e: &Entry| e.server_name.clone().unwrap_or_else(|| e.hostname.split('.').next().unwrap_or_default().to_string());
    let named: Vec<Entry> = all.iter().filter(|e| e.hostname == pinned.host && name(e) == pinned.name).cloned().collect();
    let found: Vec<Entry> = if named.is_empty() { all.into_iter().filter(|e| e.ips.contains(&pinned.ip)).collect() } else { named };
    let Some(first) = found.first() else { return Err(Error::NoLongerOffered(pinned.name.clone())) };
    let live = unless_io(p.usable(&found, &Location::of(&loc.provider)))?.and_then(|u| u.into_iter().find(|e| e.hostname == first.hostname));
    match live {
        Some(live) => Ok((catalog::server(&live, Some(&pinned.name))?, Some(live))),
        // No address for it now: keep the pinned one, but with the list's current key.
        None => Ok((first.wgpubkey.as_ref().map_or_else(|| pinned.clone(), |k| Server { public_key: k.clone(), ..pinned.clone() }), None)),
    }
}

pub(crate) fn link<P: KeyProvider + ?Sized>(p: &P, loc: &Location, a: &Account, entries: impl Fn() -> Result<Vec<Entry>>) -> Result<Link> {
    let (sv, e) = match &loc.pinned {
        Some(pinned) => refreshed(p, pinned, loc, a, entries)?,
        None => match p.usable(&entries()?, loc)?.into_iter().next() {
            Some(e) => (catalog::server(&e, None)?, Some(e)),
            None => return Err(Error::Io(format!("No {} server for {}", p.name(), loc.label()))),
        },
    };
    let ports = p.ports();
    let ports = if ports.is_empty() { vec![] } else { std::iter::once(a.port).chain(ports).collect::<IndexSet<_>>().into_iter().collect() };
    let peer = WgPeer {
        preshared_key: a.preshared_key.clone(),
        dns: a.dns.clone(),
        mtu: a.mtu,
        ..WgPeer::new(&sv.name, &a.private_key, a.address.clone(), &p.peer_key(&sv, a), &format!("{}:{}", sv.ip, a.port), vec!["0.0.0.0/0".into()])
    };
    Ok(Link::Wg { entries: e.map(|e| p.addresses(&e)).unwrap_or_default(), server: sv, peer, ports })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::airvpn::{self, AirVpn};
    use crate::providers::proton::{PROTON, PROTON_FREE};
    use crate::providers::surfshark::{self, Surfshark};
    use crate::providers::tests::{by_code, by_country, fixture, input, offline, peer, pinned_to, sing_box_check, sing_box_config, surfshark_at, wg};
    use crate::snapshot::Snapshot;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    fn entry(country: &str, host: &str, key: &str, ips: &[&str]) -> Entry {
        Entry {
            vpn: "wireguard".into(),
            country: Some(country.into()),
            hostname: host.into(),
            wgpubkey: Some(key.into()),
            ips: ips.iter().map(|ip| ip.to_string()).collect(),
            ..Entry::default()
        }
    }

    fn catalogue(name: &str) -> Vec<Entry> {
        catalog::parse(&fixture(&format!("catalog/catalog_{name}.json")), "wireguard").unwrap()
    }

    fn clusters() -> Vec<Entry> {
        surfshark::parse(&fixture("providers/surfshark_clusters.json")).unwrap()
    }

    /// Proton, Surfshark and AirVPN.
    mod key_providers {
        use super::*;

        const PRIV: &str = "dW5icmFpZC10ZXN0LXByaXZhdGUta2V5LTAwMDAwMDE=";
        const PSK: &str = "dW5icmFpZC10ZXN0LXByZXNoYXJlZC1rZXktMDAwMDE=";
        const SERVER_KEY: &str = "vOgsnvam/Xc6w8zfQeGcynOr8RMxYzpki3b0EaOkEoI=";

        /// Two capital letters, as a country code.
        fn iso(code: &str) -> bool {
            code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
        }

        fn conf(address: &str, dns: &str, endpoint: &str, preshared: bool, extra: &str) -> String {
            let psk = if preshared { format!("PresharedKey = {PSK}") } else { String::new() };
            format!(
                "[Interface]\n# Key for Android\nPrivateKey = {PRIV}\nAddress = {address}\nDNS = {dns}\n{extra}\n\n[Peer]\nPublicKey = {SERVER_KEY}\n{psk}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}"
            )
        }

        fn air_conf() -> String {
            conf("10.164.20.6/32, fd7d:76ee:e68f:a993:1:2:3:4/128", "10.128.0.1", "at.vpn.airdns.org:1637", true, "")
        }

        fn signed(p: &dyn KeyProvider, key: &str) -> Account {
            account(&p.sign_in(&input(&[("key", key)])).unwrap()).unwrap()
        }

        fn assert_rejected(p: &dyn KeyProvider, key: &str) {
            match p.sign_in(&input(&[("key", key)])) {
                Err(Error::Invalid(m)) => assert!(!m.contains(PRIV), "{m}"),
                _ => panic!("accepted: {}", key.chars().take(8).collect::<String>()),
            }
        }

        fn city_loc(provider: &str, entries: &[Entry]) -> Location {
            let c = catalog::countries(entries).into_iter().find(|c| !c.cities.is_empty()).unwrap();
            let city = &c.cities[0];
            Location { country_code: Some(c.code.clone()), country: Some(c.name.clone()), city: Some(city.name.clone()), region: city.key.clone(), ..Location::of(provider) }
        }

        fn place_of<'a>(entries: &'a [Entry], ip: &str) -> &'a str {
            entries.iter().find(|e| e.ipv4() == Some(ip)).unwrap().place()
        }

        fn static_host() -> Entry {
            Entry { region: Some("Europe".into()), city: Some("Frankfurt".into()), ..entry("Germany", "de-fra-st001.prod.surfshark.com", SERVER_KEY, &["5.5.5.5"]) }
        }

        // ---- Proton

        /// Proton's options are read from a pasted .conf's comments, allowlisted and short; a bare key says where to see them.
        #[test]
        fn proton_config_facts() {
            let conf = format!(
                "[Interface]\n# Key for test\n# Bouncing = 3\n# NetShield = 0\n# Moderate NAT = off\n# NAT-PMP (Port Forwarding) = off\n# VPN Accelerator = on\n# Secret = {PRIV}\nPrivateKey = {PRIV}\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n[Peer]\nPublicKey = {SERVER_KEY}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:51820"
            );
            let a = PROTON_FREE.sign_in(&input(&[("key", &conf)])).unwrap();
            assert_eq!(Some("VPN Accelerator on · NetShield off · Moderate NAT off · Port forwarding off".to_string()), PROTON_FREE.facts(&a));
            assert!(!a.contains("Bouncing") && !a.contains("Secret"));
            assert_eq!(Some(String::new()), PROTON_FREE.facts(&PROTON_FREE.sign_in(&input(&[("key", PRIV)])).unwrap())); // a bare key: not known
            assert_eq!(None, Surfshark.facts(&a));
        }

        #[test]
        fn proton_drops_secure_core_and_tor() {
            let secure_core = Regex::new(r"^(CH|IS|SE)-[A-Z]{2}#[0-9]+$").unwrap();
            let raw = catalogue("protonvpn");
            let kept = PROTON.filtered(raw.clone());
            assert!(raw.iter().any(|e| secure_core.is_match(e.server_name.as_deref().unwrap())));
            assert!(!kept.is_empty() && kept.len() < raw.len());
            assert!(kept.iter().all(|e| {
                let n = e.server_name.as_deref().unwrap();
                !secure_core.is_match(n) && !n.ends_with("-TOR")
            }));
            let cs = catalog::countries(&kept);
            assert!(!cs.is_empty());
            assert!(cs.iter().all(|c| iso(&c.code) && c.server_count > 0));
        }

        #[test]
        fn proton_bare_key_connects_to_a_country_and_a_city() {
            let a = signed(&PROTON, PRIV);
            let entries = PROTON.filtered(catalogue("protonvpn"));
            let l = link(&PROTON, &Location { country_code: Some("DE".into()), ..by_country("proton", "Germany") }, &a, || Ok(entries.clone())).unwrap();
            let ips: Vec<Option<&str>> = entries.iter().filter(|e| e.place() == "Germany").map(|e| e.ipv4()).collect();
            let p = peer(&l);
            assert!(ips.contains(&p.endpoint.split(':').next()));
            assert_eq!("Germany", place_of(&entries, &l.server().ip));
            assert_eq!(l.server().public_key, p.public_key);
            assert_eq!(vec!["10.2.0.2/32"], p.address);
            assert_eq!(vec!["10.2.0.1"], p.dns);
            assert!(p.endpoint.ends_with(":51820"));
            assert_eq!(vec!["0.0.0.0/0"], p.allowed_ips);
            assert_eq!(None, p.preshared_key);
            assert_eq!(PRIV, p.private_key);

            let coded = link(&PROTON, &by_code("proton", "DE"), &a, || Ok(entries.clone())).unwrap();
            assert_eq!("Germany", place_of(&entries, &coded.server().ip));
            assert_eq!("DE", coded.server().country);

            let city = city_loc("proton", &entries);
            let lc = link(&PROTON, &city, &a, || Ok(entries.clone())).unwrap();
            assert_eq!(city.region.as_deref(), Some(lc.server().city.as_str()));
            assert_eq!(city.country.as_deref(), Some(place_of(&entries, &lc.server().ip)));
        }

        #[test]
        fn proton_free_offers_only_free_servers() {
            let raw: Vec<Entry> = catalogue("protonvpn").into_iter().map(|e| if e.place() == "Austria" { Entry { free: true, ..e } } else { e }).collect();
            let free = PROTON_FREE.filtered(raw.clone());
            assert!(!free.is_empty() && free.iter().all(|e| e.free && e.place() == "Austria"));
            let all = PROTON.filtered(raw);
            assert!(free.iter().all(|e| all.contains(e)) && all.iter().any(|e| !e.free));
            assert_eq!(vec!["Austria"], catalog::countries(&free).iter().map(|c| c.name.as_str()).collect::<Vec<_>>());
            assert_eq!("proton-free", PROTON_FREE.id());
            assert_eq!("Proton VPN Free", PROTON_FREE.name());
            assert_eq!("proton", PROTON.id());
            assert!(PROTON_FREE.help().contains("free-vpn/server"));

            let a = signed(&PROTON_FREE, PRIV);
            let l = link(&PROTON_FREE, &by_code("proton-free", "AT"), &a, || Ok(free.clone())).unwrap();
            assert_eq!("Austria", place_of(&free, &l.server().ip));
            match link(&PROTON_FREE, &by_country("proton-free", "Germany"), &a, || Ok(free.clone())) {
                Err(e) if is_io(&e) => assert!(e.to_string().contains("Germany")),
                _ => panic!("Germany has no free server"),
            }
        }

        #[test]
        fn proton_conf_overrides_defaults() {
            let a = signed(&PROTON, &conf("10.2.0.2/32, 2a07:b944::2:2/128", "10.2.0.1", "79.135.105.1:51820", false, "MTU = 1400"));
            assert_eq!(PRIV, a.private_key);
            assert_eq!(vec!["10.2.0.2/32"], a.address);
            assert_eq!(vec!["10.2.0.1"], a.dns);
            assert_eq!(1400, a.mtu);
            let b = signed(&PROTON, &conf("10.3.0.2/32", "10.3.0.1", "79.135.105.1:51820", false, ""));
            assert_eq!(vec!["10.3.0.2/32"], b.address);
            assert_eq!(vec!["10.3.0.1"], b.dns);
            assert_eq!(1420, b.mtu);
        }

        #[test]
        fn proton_pinned_server_needs_no_list() {
            let a = signed(&PROTON, PRIV);
            let sv = link(&PROTON, &by_country("proton", "Germany"), &a, || Ok(PROTON.filtered(catalogue("protonvpn")))).unwrap().server().clone();
            let l = link(&PROTON, &pinned_to("proton", sv.clone()), &a, || Err(Error::Io("offline".into()))).unwrap();
            assert_eq!(&sv, l.server());
            assert_eq!(format!("{}:51820", sv.ip), peer(&l).endpoint);
        }

        #[test]
        fn bad_keys_are_rejected() {
            for p in [&PROTON as &dyn KeyProvider, &PROTON_FREE, &Surfshark, &AirVpn] {
                assert_rejected(p, "");
                assert_rejected(p, "hello");
                // 64 hex digits are an AirVPN API key, sent to AirVPN rather than refused here.
                if p.id() != "airvpn" {
                    assert_rejected(p, &"a".repeat(64));
                }
                assert_rejected(p, &PRIV[..PRIV.len() - 1]);
                assert_rejected(p, &format!("!{}", &PRIV[1..]));
                assert_rejected(p, &conf("10.2.0.2/32", "10.2.0.1", "1.2.3.4:51820", false, "").replace(PRIV, "short"));
                assert_rejected(p, &conf("10.2.0.2/32", "10.2.0.1", "1.2.3.4:51820", false, "").replace("[Peer]", ""));
            }
        }

        // ---- Surfshark

        #[test]
        fn surfshark_live_list_has_countries_and_keys_but_no_ips() {
            let clusters = clusters();
            assert!(!clusters.is_empty());
            assert!(clusters.iter().all(|e| e.ips.is_empty() && e.hostname.ends_with(".prod.surfshark.com") && e.wgpubkey.as_ref().unwrap().len() == 44));
            let cs = catalog::countries(&clusters);
            assert!(cs.iter().any(|c| c.name == "Netherlands" && c.code == "NL" && c.cities.iter().any(|city| city.name == "Amsterdam")));
            assert!(cs.iter().all(|c| iso(&c.code)));
        }

        /// The chosen host's address comes from the catalogue, its key from Surfshark's own list; nothing is looked up.
        #[test]
        fn surfshark_takes_the_chosen_hosts_address_from_the_catalogue() {
            let _held = offline();
            let clusters = clusters();
            surfshark_at(&clusters, "203.0.113.7");
            let a = signed(&Surfshark, PRIV);
            let l = link(&Surfshark, &by_country("surfshark", "Netherlands"), &a, || Ok(clusters.clone())).unwrap();
            let p = peer(&l);
            assert!(l.server().host.starts_with("nl-"));
            assert_eq!("203.0.113.7:51820", p.endpoint);
            assert_eq!(vec!["10.14.0.2/16"], p.address);
            assert_eq!(vec!["162.252.172.57", "149.154.159.92"], p.dns);
            assert_eq!(1280, p.mtu);
            assert_eq!(clusters.iter().find(|e| e.hostname == l.server().host).unwrap().wgpubkey.as_deref(), Some(p.public_key.as_str()));
            assert_eq!("Amsterdam", l.server().city);

            let coded = link(&Surfshark, &by_code("surfshark", "DE"), &a, || Ok(clusters.clone())).unwrap();
            assert_eq!("DE", coded.server().country);
            assert!(coded.server().host.starts_with("de-"));

            let city = city_loc("surfshark", &clusters);
            let lc = link(&Surfshark, &city, &a, || Ok(clusters.clone())).unwrap();
            assert_eq!(city.region.as_deref(), Some(lc.server().city.as_str()));
        }

        #[test]
        fn surfshark_falls_back_to_catalogue_ips_of_the_same_location() {
            let _held = offline();
            let clusters = clusters();
            let mut cat = catalogue("surfshark");
            cat.push(static_host());
            let de: Vec<String> = surfshark::fallback(cat.clone()).into_iter().filter(|e| e.place() == "Germany").flat_map(|e| e.ips).collect();
            assert!(!de.is_empty());
            let listed = cat.clone();
            surfshark::set_catalogue(move || Ok(listed.clone()));
            let a = signed(&Surfshark, PRIV);
            let l = link(&Surfshark, &by_country("surfshark", "Germany"), &a, || Ok(clusters.clone())).unwrap();
            assert!(de.iter().any(|ip| Some(ip.as_str()) == peer(&l).endpoint.split(':').next()));
            assert_eq!("DE", l.server().country);
            assert!(!peer(&l).endpoint.starts_with("5.5.5.5:"));

            let city = city_loc("surfshark", &surfshark::fallback(cat));
            let lc = link(&Surfshark, &city, &a, || Ok(clusters.clone())).unwrap();
            assert_eq!(city.region.as_deref(), Some(lc.server().city.as_str()));
            assert_eq!(city.country_code.as_deref(), Some(lc.server().country.as_str()));
        }

        /// Each host once, also when the list is asked for more than it has; the catalogue is read once a day, its last copy offline.
        #[test]
        fn surfshark_lists_each_host_once_and_reads_the_catalogue_once_a_day() {
            let _held = offline();
            let reads = Arc::new(Mutex::new(0));
            let nl: Vec<Entry> = clusters().into_iter().filter(|e| e.place() == "Netherlands").collect();
            let host = nl[0].hostname.clone();
            let (counted, at) = (reads.clone(), nl.iter().map(|e| entry("Netherlands", &e.hostname, "unused", &["203.0.113.7"])).collect::<Vec<_>>());
            surfshark::set_catalogue(move || {
                *counted.lock().unwrap() += 1;
                Ok(at.clone())
            });
            *surfshark::LIVE.write().unwrap() = Arc::new(|| Ok(fixture("providers/surfshark_clusters.json")));
            *surfshark::SNAPSHOT.write().unwrap() = Snapshot::memory(None);
            let acc = Surfshark.sign_in(&input(&[("key", PRIV)])).unwrap();
            let listed = Surfshark.servers(&by_country("surfshark", "Netherlands"), &acc, 200).unwrap();
            assert_eq!(nl.len(), listed.len());
            assert_eq!(listed.len(), listed.iter().map(|s| &s.host).collect::<HashSet<_>>().len());
            Surfshark.servers(&by_country("surfshark", "Netherlands"), &acc, 200).unwrap();
            assert_eq!(1, *reads.lock().unwrap());
            let now = chrono::Utc::now().timestamp_millis();
            assert_eq!(Some(&vec!["203.0.113.7".to_string()]), surfshark::addresses(now).unwrap().get(&host));
            // Two days later, the catalogue unreachable and nothing in memory (a new process): the copy kept on disk, and no
            // second try within 15 minutes.
            let counted = reads.clone();
            surfshark::set_catalogue(move || {
                *counted.lock().unwrap() += 1;
                Err(Error::Io("offline".into()))
            });
            let later = now + 2 * 86_400_000;
            assert_eq!(Some(&vec!["203.0.113.7".to_string()]), surfshark::addresses(later).unwrap().get(&host));
            surfshark::addresses(later + 60_000).unwrap();
            assert_eq!(2, *reads.lock().unwrap());
            // A host name in the catalogue's addresses is never used (it would be looked up on the computer's network).
            let named = host.clone();
            surfshark::set_catalogue(move || Ok(vec![entry("Netherlands", &named, "unused", &["evil.example.com", "203.0.113.8"])]));
            assert_eq!(Some(&vec!["203.0.113.8".to_string()]), surfshark::addresses(chrono::Utc::now().timestamp_millis()).unwrap().get(&host));
        }

        /// With nothing kept and the catalogue down, it is asked again only after 15 minutes.
        #[test]
        fn surfshark_waits_before_asking_a_failed_catalogue_again() {
            let _held = offline();
            let reads = Arc::new(Mutex::new(0));
            let counted = reads.clone();
            surfshark::set_catalogue(move || {
                *counted.lock().unwrap() += 1;
                Err(Error::Io("offline".into()))
            });
            let t = chrono::Utc::now().timestamp_millis();
            for i in 0..3 {
                assert!(surfshark::addresses(t + i * 60_000).is_err_and(|e| is_io(&e)));
            }
            assert_eq!(1, *reads.lock().unwrap());
            let _ = surfshark::addresses(t + 16 * 60_000);
            assert_eq!(2, *reads.lock().unwrap());
        }

        #[test]
        fn surfshark_skips_hosts_without_an_address() {
            let _held = offline();
            let clusters = clusters();
            let wanted = clusters.iter().rfind(|e| e.place() == "Germany").unwrap().hostname.clone();
            surfshark::set_catalogue(move || Ok(vec![entry("Germany", &wanted, "unused", &["198.51.100.9"])]));
            let a = signed(&Surfshark, PRIV);
            let l = link(&Surfshark, &by_country("surfshark", "Germany"), &a, || Ok(clusters.clone())).unwrap();
            assert_eq!("198.51.100.9:51820", peer(&l).endpoint);
            surfshark::set_catalogue(|| Ok(vec![entry("Germany", "elsewhere.prod.surfshark.com", "unused", &["198.51.100.9"])]));
            match link(&Surfshark, &by_country("surfshark", "Germany"), &a, || Ok(clusters.clone())) {
                Err(e) if is_io(&e) => assert!(e.to_string().contains("Germany")),
                _ => panic!("no server has an address"),
            }
        }

        #[test]
        fn surfshark_catalogue_fallback_has_ips_and_no_static_servers() {
            let mut raw = catalogue("surfshark");
            raw.push(static_host());
            let kept = surfshark::fallback(raw.clone());
            let static_ip = Regex::new(r"-st[0-9]+\.").unwrap();
            assert!(raw.iter().filter(|e| static_ip.is_match(&e.hostname)).count() >= 1);
            assert_eq!(raw.iter().filter(|e| !static_ip.is_match(&e.hostname)).cloned().collect::<Vec<_>>(), kept);
            let l = link(&Surfshark, &by_country("surfshark", "Netherlands"), &signed(&Surfshark, PRIV), || Ok(kept.clone())).unwrap();
            let ip = peer(&l).endpoint.split(':').next().unwrap().to_string();
            assert!(kept.iter().filter(|e| e.place() == "Netherlands").any(|e| e.ips.contains(&ip)));
            assert!(peer(&l).endpoint.ends_with(":51820"));
        }

        #[test]
        fn surfshark_conf_is_used_as_pasted() {
            let a = signed(&Surfshark, &conf("10.14.0.2/16", "162.252.172.57, 149.154.159.92", "nl-ams.prod.surfshark.com:51820", false, ""));
            assert_eq!(vec!["10.14.0.2/16"], a.address);
            assert_eq!(vec!["162.252.172.57", "149.154.159.92"], a.dns);
            assert_eq!(51820, a.port);
            assert_eq!(1280, a.mtu);
            assert_eq!(None, a.preshared_key);
            let b = signed(&Surfshark, &conf("10.64.222.21/16", "1.1.1.1", "nl-ams.prod.surfshark.com:51820", false, ""));
            assert_eq!(vec!["10.64.222.21/16"], b.address);
            assert_eq!(vec!["1.1.1.1"], b.dns);
        }

        // ---- AirVPN

        fn nodes() -> Vec<Entry> {
            airvpn::parse(&fixture("providers/airvpn_status.json"), SERVER_KEY).unwrap()
        }

        #[test]
        fn airvpn_live_list_uses_healthy_ipv4_entries() {
            let nodes = nodes();
            assert!(!nodes.is_empty());
            assert!(nodes.iter().all(|e| e.vpn == "wireguard"
                && e.ips.len() == 2
                && e.ips.iter().all(|ip| ip.contains('.'))
                && e.wgpubkey.as_deref() == Some(SERVER_KEY)
                && e.hostname.ends_with(".vpn.airdns.org")));
            let cs = catalog::countries(&nodes);
            assert!(cs.iter().any(|c| c.name == "Netherlands" && c.code == "NL"));
            assert!(cs.iter().all(|c| iso(&c.code)));
            assert!(nodes.iter().filter_map(|e| e.city.as_ref()).all(|c| !c.contains(',')));
            let body = r#"{"servers":[{"public_name":"A","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.4","health":"warning"},
                {"public_name":"B","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.5","health":"ok"}]}"#;
            let healthy = airvpn::parse(body, SERVER_KEY).unwrap();
            assert_eq!(vec![vec!["1.2.3.5".to_string()]], healthy.into_iter().map(|e| e.ips).collect::<Vec<_>>());
        }

        #[test]
        fn airvpn_needs_the_whole_conf() {
            assert_rejected(&AirVpn, PRIV);
            assert_rejected(&AirVpn, &conf("10.164.20.6/32", "10.128.0.1", "at.vpn.airdns.org:1637", false, ""));
            let a = signed(&AirVpn, &air_conf());
            assert_eq!(vec!["10.164.20.6/32"], a.address);
            assert_eq!(Some(PSK), a.preshared_key.as_deref());
            assert_eq!(Some(SERVER_KEY), a.public_key.as_deref());
            assert_eq!(1637, a.port);
            assert_eq!(vec!["10.128.0.1"], a.dns);
        }

        #[test]
        fn airvpn_connects_with_preshared_key_on_port1637() {
            let a = signed(&AirVpn, &air_conf());
            let entries = airvpn::parse(&fixture("providers/airvpn_status.json"), a.public_key.as_deref().unwrap()).unwrap();
            let l = link(&AirVpn, &by_country("airvpn", "Netherlands"), &a, || Ok(entries.clone())).unwrap();
            let p = peer(&l);
            let nl: Vec<Option<&str>> = entries.iter().filter(|e| e.place() == "Netherlands").map(|e| e.ipv4()).collect();
            assert!(nl.contains(&p.endpoint.split(':').next()));
            assert!(p.endpoint.ends_with(":1637"));
            assert_eq!(Some(PSK), p.preshared_key.as_deref());
            assert_eq!(SERVER_KEY, p.public_key);
            assert_eq!(vec!["10.164.20.6/32"], p.address);
            assert_eq!(vec!["10.128.0.1"], p.dns);

            let coded = link(&AirVpn, &by_code("airvpn", "NL"), &a, || Ok(entries.clone())).unwrap();
            assert_eq!("NL", coded.server().country);
            assert_eq!("Netherlands", place_of(&entries, &coded.server().ip));

            let city = city_loc("airvpn", &entries);
            assert_eq!(city.region.as_deref(), Some(link(&AirVpn, &city, &a, || Ok(entries.clone())).unwrap().server().city.as_str()));
        }

        #[test]
        fn airvpn_catalogue_fallback_uses_the_account_key() {
            let entries = catalogue("airvpn");
            assert!(!entries.is_empty() && entries.iter().all(|e| e.ipv4().unwrap().contains('.')));
            let l = link(&AirVpn, &by_country("airvpn", "Germany"), &signed(&AirVpn, &air_conf()), || Ok(entries.clone())).unwrap();
            // The key is the account's own [Peer] key (every AirVPN server shares it), never the catalogue's.
            assert_eq!(SERVER_KEY, peer(&l).public_key);
            assert!(peer(&l).endpoint.ends_with(":1637"));
        }

        // ---- sing-box

        #[test]
        fn sing_box_accepts_every_link() {
            let _held = offline();
            let clusters = clusters();
            surfshark_at(&clusters, "203.0.113.7");
            let pe = PROTON.filtered(catalogue("protonvpn"));
            let (pa, sa, aa) = (signed(&PROTON, PRIV), signed(&Surfshark, PRIV), signed(&AirVpn, &air_conf()));
            let ae = airvpn::parse(&fixture("providers/airvpn_status.json"), aa.public_key.as_deref().unwrap()).unwrap();
            let links = [
                ("proton-country", link(&PROTON, &by_country("proton", "Germany"), &pa, || Ok(pe.clone()))),
                ("proton-city", link(&PROTON, &city_loc("proton", &pe), &pa, || Ok(pe.clone()))),
                ("surfshark-country", link(&Surfshark, &by_country("surfshark", "Netherlands"), &sa, || Ok(clusters.clone()))),
                ("surfshark-city", link(&Surfshark, &city_loc("surfshark", &clusters), &sa, || Ok(clusters.clone()))),
                ("airvpn-country", link(&AirVpn, &by_country("airvpn", "Germany"), &aa, || Ok(ae.clone()))),
                ("airvpn-city", link(&AirVpn, &city_loc("airvpn", &ae), &aa, || Ok(ae.clone()))),
            ];
            for (name, l) in links {
                sing_box_check(&sing_box_config(name, name, wg(name, peer(&l.unwrap()))));
            }
        }
    }

    /// Server keys come only from the provider (or the user's .conf), never from gluetun's catalogue.
    mod key_sources {
        use super::*;
        use crate::providers::plans;

        const PRIV: &str = "dW5icmFpZC10ZXN0LXByaXZhdGUta2V5LTAwMDAwMDE=";
        const PSK: &str = "dW5icmFpZC10ZXN0LXByZXNoYXJlZC1rZXktMDAwMDE=";
        const ACCOUNT_KEY: &str = "vOgsnvam/Xc6w8zfQeGcynOr8RMxYzpki3b0EaOkEoI=";
        const EVIL_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        const API_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        fn live_body() -> String {
            fixture("providers/surfshark_clusters.json")
        }

        fn signed(p: &dyn KeyProvider, key: &str) -> String {
            p.sign_in(&input(&[("key", key)])).unwrap()
        }

        fn conf(address: &str, port: i32) -> String {
            format!("[Interface]\nPrivateKey = {PRIV}\nAddress = {address}\n\n[Peer]\nPublicKey = {ACCOUNT_KEY}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = at.vpn.airdns.org:{port}")
        }

        #[test]
        fn surfshark_takes_only_addresses_from_the_catalogue() {
            let _held = offline();
            let live = clusters();
            let first = live[0].clone();
            // A swapped catalogue: same host name, an attacker's address and key.
            let (country, host) = (first.country.clone().unwrap(), first.hostname.clone());
            surfshark::set_catalogue(move || Ok(vec![entry(&country, &host, EVIL_KEY, &["198.51.100.66"])]));
            let l = link(&Surfshark, &by_country("surfshark", first.place()), &account(&signed(&Surfshark, PRIV)).unwrap(), || Ok(live.clone())).unwrap();
            assert_eq!("198.51.100.66:51820", peer(&l).endpoint);
            assert_eq!(first.wgpubkey.as_deref(), Some(peer(&l).public_key.as_str()));
        }

        /// A pinned server with no address to be had (catalogue down, nothing kept) keeps its saved address, with Surfshark's current key.
        #[test]
        fn surfshark_pinned_server_keeps_its_address_when_none_can_be_read() {
            let _held = offline();
            let live = clusters();
            let e = &live[0];
            let pin = Server { name: e.hostname.split('.').next().unwrap().into(), host: e.hostname.clone(), ip: "203.0.113.5".into(), public_key: "stale".into(), load: 0, ..Server::default() };
            let loc = Location { pinned: Some(pin), ..by_country("surfshark", e.place()) };
            let l = link(&Surfshark, &loc, &account(&signed(&Surfshark, PRIV)).unwrap(), || Ok(live.clone())).unwrap();
            assert_eq!("203.0.113.5:51820", peer(&l).endpoint);
            assert_eq!(e.wgpubkey.as_deref(), Some(peer(&l).public_key.as_str()));
        }

        #[test]
        fn surfshark_ignores_catalogue_hosts_it_does_not_list() {
            let _held = offline();
            let live = clusters();
            let country = live[0].country.clone().unwrap();
            surfshark::set_catalogue(move || Ok(vec![entry(&country, "nl-evil.prod.surfshark.com", EVIL_KEY, &["198.51.100.66"])]));
            let used = link(&Surfshark, &by_country("surfshark", live[0].place()), &account(&signed(&Surfshark, PRIV)).unwrap(), || Ok(live.clone()));
            assert!(used.is_err_and(|e| is_io(&e)), "a host only the catalogue lists must not be used");
        }

        #[test]
        fn surfshark_keeps_its_last_list_and_uses_it_when_the_api_is_down() {
            let _held = offline();
            let blob = signed(&Surfshark, PRIV);
            *surfshark::LIVE.write().unwrap() = Arc::new(|| Ok(fixture("providers/surfshark_clusters.json")));
            let fresh = Surfshark.countries(&blob).unwrap();
            assert_eq!(Some(live_body()), surfshark::SNAPSHOT.read().unwrap().read());
            *surfshark::LIVE.write().unwrap() = Arc::new(|| Err(Error::Io("down".into())));
            surfshark::set_catalogue(|| Err(Error::State("the catalogue must not be read for keys".into())));
            assert_eq!(fresh, Surfshark.countries(&blob).unwrap());
        }

        #[test]
        fn surfshark_without_any_own_list_fails_instead_of_trusting_the_catalogue() {
            let _held = offline();
            surfshark::set_catalogue(|| Err(Error::State("the catalogue must not be read for keys".into())));
            match Surfshark.countries(&signed(&Surfshark, PRIV)) {
                Err(e) if is_io(&e) => assert!(e.to_string().contains("Surfshark")),
                _ => panic!("no list should be available"),
            }
        }

        #[test]
        fn surfshark_keeps_the_old_copy_when_the_api_sends_nothing_usable() {
            let _held = offline();
            *surfshark::SNAPSHOT.write().unwrap() = Snapshot::memory(Some(&live_body()));
            *surfshark::LIVE.write().unwrap() = Arc::new(|| Ok("[]".into()));
            assert!(!Surfshark.countries(&signed(&Surfshark, PRIV)).unwrap().is_empty());
            assert_eq!(Some(live_body()), surfshark::SNAPSHOT.read().unwrap().read());
        }

        #[test]
        fn airvpn_fallback_uses_the_account_key_not_the_catalogues() {
            let _held = offline();
            let conf = format!(
                "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.164.20.6/32\nDNS = 10.128.0.1\n\n[Peer]\nPublicKey = {ACCOUNT_KEY}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = at.vpn.airdns.org:1637"
            );
            let cat: Vec<Entry> = catalogue("airvpn").into_iter().map(|e| Entry { wgpubkey: Some(EVIL_KEY.into()), ..e }).collect();
            let listed = cat.clone();
            *airvpn::CATALOGUE.write().unwrap() = Arc::new(move || Ok(listed.clone()));
            let a = account(&signed(&AirVpn, &conf)).unwrap();
            let l = AirVpn.connect(&by_country("airvpn", cat[0].place()), &signed(&AirVpn, &conf)).unwrap();
            assert_eq!(ACCOUNT_KEY, peer(&l).public_key);
            assert_eq!(a.preshared_key, peer(&l).preshared_key);
            assert!(cat.iter().flat_map(|e| &e.ips).any(|ip| Some(ip.as_str()) == peer(&l).endpoint.split(':').next()));
        }

        // ---- AirVPN API sign-in

        struct Dev {
            id: String,
            name: String,
            status: String,
            key: String,
            ip: String,
            ready_at: usize,
        }

        /// An AirVPN account as its API behaves: devices by id; an added one starts as "New device" and turns ready after
        /// `ready_after` lists, also when it was deleted before (AirVPN undoes such a delete); the generator answers a
        /// device's own address, or the first (Default) device's for a name it doesn't know.
        #[derive(Default)]
        struct Air {
            devices: Vec<Dev>,
            calls: Vec<(String, IndexMap<String, String>)>,
            refuse_add: bool,
            lose_add: bool,
            ready_after: usize,
            generated: Option<String>,
            lists: usize,
        }

        impl Air {
            fn names(&self) -> Vec<String> {
                self.devices.iter().map(|d| d.name.clone()).collect()
            }

            fn actions(&self, action: &str) -> usize {
                self.calls.iter().filter(|(_, q)| q.get("action").map(String::as_str) == Some(action)).count()
            }

            fn answer(&mut self, service: &str, q: IndexMap<String, String>) -> Result<String> {
                self.calls.push((service.into(), q.clone()));
                match service {
                    "devices" => match q.get("action").map(String::as_str) {
                        None => {
                            self.lists += 1;
                            let lists = self.lists;
                            for (i, d) in self.devices.iter_mut().enumerate().filter(|(_, d)| d.status == "create" && lists >= d.ready_at) {
                                d.status = "ready".into();
                                d.key = format!("k-{}", d.id);
                                d.ip = format!("10.171.9.{i}");
                            }
                            let text = |s: &str| if s.is_empty() { "null".to_string() } else { format!("\"{s}\"") };
                            let list: Vec<String> = self
                                .devices
                                .iter()
                                .map(|d| format!(r#"{{"id":"{}","name":"{}","status":"{}","wireguard_public_key":{},"wireguard_ipv4":{}}}"#, d.id, d.name, d.status, text(&d.key), text(&d.ip)))
                                .collect();
                            Ok(format!(r#"{{"action":"list","devices":[{}],"result":"ok"}}"#, list.join(",")))
                        }
                        Some("add") => {
                            if self.refuse_add {
                                return Ok(r#"{"error":"Too many devices"}"#.into());
                            }
                            let id = format!("new{}", self.devices.len());
                            self.devices.push(Dev { id: id.clone(), name: "New device".into(), status: "create".into(), key: String::new(), ip: String::new(), ready_at: self.lists + self.ready_after });
                            if self.lose_add {
                                return Err(Error::Io("reply lost".into()));
                            }
                            Ok(format!(r#"{{"action":"add","id":"{id}","result":"ok"}}"#))
                        }
                        Some("modify") => {
                            self.devices.iter_mut().find(|d| Some(&d.id) == q.get("id")).unwrap().name = q["name"].clone();
                            Ok(r#"{"action":"modify","result":"ok"}"#.into())
                        }
                        Some("delete") => match self.devices.iter().position(|d| Some(&d.id) == q.get("id")) {
                            None => Ok(r#"{"error":"Device unknown"}"#.into()),
                            Some(i) => {
                                // A delete sent while the device is still being made is undone.
                                if self.devices[i].status != "create" {
                                    self.devices.remove(i);
                                }
                                Ok(r#"{"action":"delete","result":"ok"}"#.into())
                            }
                        },
                        other => panic!("action {other:?}"),
                    },
                    "generator" => Ok(self.generated.clone().unwrap_or_else(|| {
                        let ip = &self.devices.iter().find(|d| Some(&d.name) == q.get("device")).unwrap_or(&self.devices[0]).ip;
                        format!(
                            "[Interface]\nAddress = {ip}/32\nPrivateKey = {PRIV}\nMTU = 1320\nDNS = 10.128.0.1\n\n[Peer]\nPublicKey = {ACCOUNT_KEY}\nPresharedKey = {PSK}\nEndpoint = 198.51.100.9:1637\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15"
                        )
                    })),
                    "userinfo" => Ok(r#"{"user":{"login":"x","premium":true,"expiration_unix":1795348998},"result":"ok"}"#.into()),
                    other => panic!("service {other}"),
                }
            }
        }

        /// A fake AirVPN account with `names`' devices behind the API; the status list is the fixture and nothing waits.
        fn fake_air(names: &[&str]) -> Arc<Mutex<Air>> {
            let devices = names
                .iter()
                .enumerate()
                .map(|(i, n)| Dev { id: format!("id{i}"), name: n.to_string(), status: "ready".into(), key: format!("k{i}"), ip: format!("10.171.0.{}", i + 1), ready_at: 0 })
                .collect();
            let air = Arc::new(Mutex::new(Air { devices, ready_after: 2, ..Air::default() }));
            *airvpn::STATUS.write().unwrap() = Arc::new(|| Ok(fixture("providers/airvpn_status.json")));
            *airvpn::PAUSE.write().unwrap() = Arc::new(|_| {});
            let behind = air.clone();
            *airvpn::API_CALL.write().unwrap() = Arc::new(move |service, key, query| {
                assert_eq!(API_KEY, key);
                behind.lock().unwrap().answer(service, query.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
            });
            air
        }

        fn air_sign_in(device: Option<&str>) -> Result<String> {
            let key = format!(" {API_KEY}\n");
            let mut form = vec![("key", key.as_str())];
            form.extend(device.map(|d| ("device", d)));
            AirVpn.sign_in(&input(&form))
        }

        /// Like other providers' device slots: added, named, used, removed again on sign-out; the user's devices untouched.
        #[test]
        fn airvpn_api_key_makes_its_own_device_and_removes_it_on_sign_out() {
            let _held = offline();
            let air = fake_air(&["Default"]);
            let blob = air_sign_in(None).unwrap();
            let a = account(&blob).unwrap();
            assert_eq!(vec!["Default", "unbraid"], air.lock().unwrap().names());
            let (made_ip, made_key, made_id) = {
                let air = air.lock().unwrap();
                let made = air.devices.last().unwrap();
                (made.ip.clone(), made.key.clone(), made.id.clone())
            };
            assert_eq!(vec![format!("{made_ip}/32")], a.address);
            assert_eq!(
                (Some(API_KEY), Some("unbraid"), Some(made_key.as_str()), Some(made_id.as_str()), true),
                (a.api_key.as_deref(), a.device.as_deref(), a.device_key.as_deref(), a.device_id.as_deref(), a.own_device)
            );
            assert_eq!((Some(ACCOUNT_KEY), Some(PSK), 1637), (a.public_key.as_deref(), a.preshared_key.as_deref(), a.port));
            assert_eq!(1, air.lock().unwrap().actions("add"));
            let calls = air.lock().unwrap().calls.clone();
            let generated: Vec<&IndexMap<String, String>> = calls.iter().filter(|(s, _)| s == "generator").map(|(_, q)| q).collect();
            assert_eq!(1, generated.len());
            assert_eq!((Some("unbraid"), Some("wireguard_1_udp_1637")), (generated[0].get("device").map(String::as_str), generated[0].get("protocols").map(String::as_str)));
            let servers: Vec<Option<String>> = airvpn::parse(&fixture("providers/airvpn_status.json"), "").unwrap().into_iter().map(|e| e.server_name).collect();
            assert!(servers.contains(&generated[0].get("servers").cloned()));
            assert_eq!(Some("Its own device, unbraid, removed when you sign out. See all your devices in the AirVPN Client Area".to_string()), AirVpn.device(&blob).map(|d| d.line));
            assert!(AirVpn.sign_out(&blob));
            assert_eq!(vec!["Default"], air.lock().unwrap().names());
            // Already gone (removed on the website): still released.
            assert!(AirVpn.sign_out(&blob));
        }

        #[test]
        fn airvpn_own_device_gets_a_free_name() {
            let _held = offline();
            let air = fake_air(&["Default", "unbraid"]);
            assert_eq!(Some("unbraid 2".to_string()), account(&air_sign_in(None).unwrap()).unwrap().device);
            assert_eq!(vec!["Default", "unbraid", "unbraid 2"], air.lock().unwrap().names());
        }

        /// After a lost reply the new device could be another app's: never renamed, used or removed. One that doesn't get
        /// ready is removed again, or the user is told it is left.
        #[test]
        fn airvpn_own_device_is_never_guessed_and_is_cleaned_up_when_not_ready() {
            let _held = offline();
            let air = fake_air(&["Default"]);
            air.lock().unwrap().lose_add = true;
            match air_sign_in(None) {
                Err(Error::Fail(m)) => assert!(m.contains("Client Area"), "{m}"),
                other => panic!("{other:?}"),
            }
            assert_eq!(vec!["Default", "New device"], air.lock().unwrap().names());
            let touched = air.lock().unwrap().actions("modify");
            assert_eq!(0, touched + air.lock().unwrap().actions("delete"));

            // Ready only after unbraid gave up: removed once it is, not before (a delete then would be undone).
            let slow = fake_air(&["Default"]);
            slow.lock().unwrap().ready_after = 35;
            assert!(matches!(air_sign_in(None), Err(Error::Fail(_))));
            assert_eq!(vec!["Default"], slow.lock().unwrap().names());
            assert_eq!(1, slow.lock().unwrap().actions("delete"));

            let broken = fake_air(&["Default"]);
            broken.lock().unwrap().generated = Some(r#"{"error": "Unexpected, zero files in package. Contact our staff, thanks."}"#.into());
            assert!(matches!(air_sign_in(None), Err(Error::Fail(_))));
            assert_eq!(vec!["Default"], broken.lock().unwrap().names());

            // Removing it fails too: the user is told which device is left.
            let stuck = fake_air(&["Default"]);
            stuck.lock().unwrap().generated = Some(r#"{"error": "Unexpected"}"#.into());
            let real = airvpn::API_CALL.read().unwrap().clone();
            *airvpn::API_CALL.write().unwrap() =
                Arc::new(move |s, k, q| if q.contains(&("action", "delete")) { Ok(r#"{"error":"Try later"}"#.into()) } else { real(s, k, q) });
            match air_sign_in(None) {
                Err(Error::Fail(m)) => assert!(m.contains("unbraid") && m.contains("Client Area"), "{m}"),
                other => panic!("{other:?}"),
            }
            assert_eq!(vec!["Default", "unbraid"], stuck.lock().unwrap().names());
        }

        /// Only when AirVPN refuses a new device: the user picks one of theirs, which sign-out leaves alone.
        #[test]
        fn airvpn_refused_device_asks_which_of_theirs_to_use() {
            let _held = offline();
            let air = fake_air(&["Default", "Phone"]);
            air.lock().unwrap().refuse_add = true;
            match air_sign_in(None) {
                Err(Error::Challenge(c)) => assert!(c.field.key == "device" && c.message.contains("Default, Phone"), "{}", c.message),
                other => panic!("{other:?}"),
            }
            assert!(matches!(air_sign_in(Some("Tablet")), Err(Error::Challenge(_))));
            assert!(matches!(air_sign_in(Some("")), Err(Error::Challenge(_))));
            air.lock().unwrap().calls.clear();
            let blob = air_sign_in(Some("phone")).unwrap();
            let a = account(&blob).unwrap();
            assert_eq!(vec!["10.171.0.2/32"], a.address);
            assert_eq!((Some("Phone"), Some("k1"), Some("id1"), false), (a.device.as_deref(), a.device_key.as_deref(), a.device_id.as_deref(), a.own_device));
            // Answering the question never tries to add a device again.
            assert_eq!(0, air.lock().unwrap().actions("add"));
            assert_eq!(Some("Uses your device Phone. See all your devices in the AirVPN Client Area".to_string()), AirVpn.device(&blob).map(|d| d.line));
            assert!(AirVpn.sign_out(&blob));
            assert_eq!(vec!["Default", "Phone"], air.lock().unwrap().names());

            fake_air(&["Default"]).lock().unwrap().refuse_add = true;
            assert_eq!(Some("Default".to_string()), account(&air_sign_in(None).unwrap()).unwrap().device);
        }

        /// The generator quietly answers with the Default device for a name it doesn't know: such a config is refused.
        #[test]
        fn airvpn_config_must_be_the_devices_own() {
            let _held = offline();
            let air = fake_air(&["Default", "Phone"]);
            air.lock().unwrap().refuse_add = true;
            air.lock().unwrap().devices[1].name = "Phone".into();
            let real = airvpn::API_CALL.read().unwrap().clone();
            *airvpn::API_CALL.write().unwrap() = Arc::new(move |s, k, q| {
                if s != "generator" {
                    return real(s, k, q);
                }
                let renamed: Vec<(&str, &str)> = q.iter().map(|&(k, v)| if k == "device" { (k, "renamed") } else { (k, v) }).collect();
                real(s, k, &renamed)
            });
            assert!(matches!(air_sign_in(Some("Phone")), Err(Error::Fail(_))));
        }

        #[test]
        fn airvpn_api_errors_say_what_to_do() {
            let _held = offline();
            fake_air(&[]).lock().unwrap().refuse_add = true;
            assert!(matches!(air_sign_in(None), Err(Error::Auth { .. })));
            *airvpn::API_CALL.write().unwrap() = Arc::new(|_, _, _| Ok(r#"{"error": "Not authorized"}"#.into()));
            match air_sign_in(None) {
                Err(Error::Auth { message, .. }) => assert!(message.contains("API key"), "{message}"),
                other => panic!("{other:?}"),
            }
        }

        /// Revoked only when the list was read and the device is gone or has a new key; a pasted .conf is never checked.
        #[test]
        fn airvpn_device_deleted_or_renewed_is_revoked() {
            let _held = offline();
            let air = fake_air(&["Default"]);
            let blob = air_sign_in(None).unwrap();
            assert!(!AirVpn.revoked(&blob));
            air.lock().unwrap().devices.last_mut().unwrap().key = "renewed".into();
            assert!(AirVpn.revoked(&blob));
            air.lock().unwrap().devices.remove(1);
            assert!(AirVpn.revoked(&blob));
            *airvpn::API_CALL.write().unwrap() = Arc::new(|_, _, _| Err(Error::Io("offline".into())));
            assert!(!AirVpn.revoked(&blob));
            *airvpn::API_CALL.write().unwrap() = Arc::new(|_, _, _| Ok(r#"{"error": "Not authorized"}"#.into()));
            assert!(!AirVpn.revoked(&blob));
            *airvpn::API_CALL.write().unwrap() = Arc::new(|_, _, _| panic!("a pasted config has no API key"));
            let address = account(&blob).unwrap().address;
            assert_eq!(1, address.len());
            let pasted = signed(&AirVpn, &conf(&address[0], 1637));
            assert!(!AirVpn.revoked(&pasted));
            assert!(AirVpn.sign_out(&pasted));
            assert_eq!(None, AirVpn.plan(&pasted));
        }

        #[test]
        fn airvpn_plan_comes_from_the_account() {
            let _held = offline();
            fake_air(&["Default"]);
            let now = chrono::Utc::now().timestamp();
            assert_eq!(Some(plans::line(Some(1795348998), now)), AirVpn.plan(&air_sign_in(None).unwrap()));
            assert!(plans::line(Some(1795348998), 0).starts_with("Paid until "));
            assert!(plans::line(Some(1795348998), 1795348999).starts_with("Ended on "));
            assert_eq!("No active plan", plans::line(None, now));
        }

        /// Both ports, the account's first; both entries from AirVPN's list, none from the catalogue's.
        #[test]
        fn airvpn_tunnels_carry_ports_and_entries() {
            let _held = offline();
            let entries = airvpn::parse(&fixture("providers/airvpn_status.json"), ACCOUNT_KEY).unwrap();
            let l = link(&AirVpn, &by_country("airvpn", "Netherlands"), &account(&signed(&AirVpn, &conf("10.164.20.6/32", 1637))).unwrap(), || Ok(entries.clone())).unwrap();
            let Link::Wg { server, ports, entries: at, .. } = &l else { panic!("not WireGuard") };
            assert_eq!(&vec![1637, 47107], ports);
            let e = entries.iter().find(|e| e.ipv4() == Some(server.ip.as_str())).unwrap();
            assert_eq!(&e.ips, at);
            assert!(at.len() == 2 && at[0] == server.ip && at[1] != server.ip);
            let other = link(&AirVpn, &by_country("airvpn", "Netherlands"), &account(&signed(&AirVpn, &conf("10.164.20.6/32", 47107))).unwrap(), || Ok(entries.clone())).unwrap();
            let Link::Wg { ports, .. } = &other else { panic!("not WireGuard") };
            assert_eq!(&vec![47107, 1637], ports);
            *airvpn::CATALOGUE.write().unwrap() = Arc::new(|| catalog::parse(&fixture("catalog/catalog_airvpn.json"), "wireguard"));
            let unlisted = AirVpn.connect(&Location::of("airvpn"), &signed(&AirVpn, &conf("10.164.20.6/32", 1637))).unwrap();
            let Link::Wg { entries: none, .. } = &unlisted else { panic!("not WireGuard") };
            assert!(none.is_empty());
        }

        #[test]
        fn surfshark_drops_malformed_keys_before_keeping_a_list() {
            let live = clusters();
            let bad = live_body().replace(live[0].wgpubkey.as_deref().unwrap(), "not-a-key");
            assert!(surfshark::parse(&bad).unwrap().iter().all(|e| e.hostname != live[0].hostname));
        }

        #[test]
        fn saved_tunnels_need_a_trusted_key() {
            let _held = offline();
            let live = clusters();
            let blob = signed(&Surfshark, PRIV);
            surfshark_at(&live, "203.0.113.7");
            let good = link(&Surfshark, &by_country("surfshark", live[0].place()), &account(&blob).unwrap(), || Ok(live.clone())).unwrap();
            // No own list kept yet: a saved Surfshark tunnel can't be vouched for.
            assert!(!Surfshark.trusts(&good, &blob));
            *surfshark::SNAPSHOT.write().unwrap() = Snapshot::memory(Some(&live_body()));
            assert!(Surfshark.trusts(&good, &blob));
            let Link::Wg { server, peer: p, ports, entries } = good else { panic!("not WireGuard") };
            let swapped = Link::Wg { server: Server { public_key: EVIL_KEY.into(), ..server }, peer: WgPeer { public_key: EVIL_KEY.into(), ..p }, ports, entries };
            assert!(!Surfshark.trusts(&swapped, &blob));
        }

        #[test]
        fn airvpn_saved_tunnels_must_use_the_account_key() {
            let blob = signed(&AirVpn, &conf("10.164.20.6/32", 1637));
            let entries = airvpn::parse(&fixture("providers/airvpn_status.json"), ACCOUNT_KEY).unwrap();
            let place = entries[0].place().to_string();
            let l = link(&AirVpn, &by_country("airvpn", &place), &account(&blob).unwrap(), || Ok(entries.clone())).unwrap();
            assert!(AirVpn.trusts(&l, &blob));
            let Link::Wg { server, peer: p, ports, entries: at } = l else { panic!("not WireGuard") };
            let old = Link::Wg { server: Server { public_key: EVIL_KEY.into(), ..server.clone() }, peer: WgPeer { public_key: EVIL_KEY.into(), ..p }, ports, entries: at };
            assert!(!AirVpn.trusts(&old, &blob));
            // A pinned server whose saved key is the catalogue's still connects with the account key.
            let pinned = Location { pinned: Some(Server { public_key: EVIL_KEY.into(), ..server }), ..by_country("airvpn", &place) };
            assert_eq!(ACCOUNT_KEY, peer(&link(&AirVpn, &pinned, &account(&blob).unwrap(), || Ok(entries.clone())).unwrap()).public_key);
        }

        #[test]
        fn surfshark_trusts_the_server_key_of_the_users_own_conf() {
            let _held = offline();
            let live = clusters();
            let conf = format!(
                "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.14.0.2/16\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {}:51820",
                live[0].wgpubkey.as_deref().unwrap(),
                live[0].hostname
            );
            let blob = signed(&Surfshark, &conf);
            surfshark_at(&live, "203.0.113.7");
            let l = link(&Surfshark, &by_country("surfshark", live[0].place()), &account(&blob).unwrap(), || Ok(live.clone())).unwrap();
            // Right after an upgrade, with no own list kept yet: the .conf's own server is still trusted.
            assert!(Surfshark.trusts(&l, &blob));
        }

        #[test]
        fn a_snapshot_that_cant_be_saved_is_still_held_in_memory() {
            let s = Snapshot::new(Box::new(|| None), Box::new(|_| Err(std::io::Error::other("disk full"))));
            s.write("list");
            assert_eq!(Some("list".to_string()), s.read());
        }
    }
}
