//! The engine's config for a setup: one tunnel per exit, apps routed by their program, DNS through each exit.
//!
//! Order of decisions for every connection: DNS → home networks → LAN → the app's route → default route. Written as
//! for Android, where apps on Direct are left out of the VPN by the system; under lockdown (no app left out, as on
//! Linux) they are routed through `direct` instead. [`crate::linux_pass`] then makes it the config the Linux engine runs.

use crate::error::{Error, Result};
use crate::manual::{self, require};
use crate::model::{DIRECT, Dns, Home, Link, Route, Setup, WgPeer, by_name};
use crate::providers::{MTU_MAX, MTU_MIN};
use crate::wg_conf::valid_wg_key;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

pub const NORD_DNS: &str = "103.86.96.100";
pub const NORD_TP: &str = "103.86.96.108";
pub const TS_TAG: &str = "home-ts";
/// Inbound tag of the app's own way into a chosen exit, for speed and health tests: a proxy on 127.0.0.1 whose user
/// name is the exit's tunnel tag. The app itself leaves the VPN directly, so this is its only path into a tunnel; the
/// password is random per connection, so no other app on the computer can use it.
pub const PROBE: &str = "probe";
pub const CLASH: &str = "Another of your WireGuard connections uses this key on the same server with other settings. Use one config for both.";
/// Apps set to Direct that pass through unbraid for its filter, as one group of app rules.
const FILTERED: &str = "direct+filter";
const LAN: [&str; 6] =
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"];
const TAILNET: &str = "100.64.0.0/10";
/// Private ranges only: a home tunnel must never capture public traffic meant for an exit.
const PRIVATE: [&str; 4] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];
const OPENVPN_ROUTING: [&str; 7] = [
    "route ",
    "route-ipv6 ",
    "route-metric",
    "redirect-gateway",
    "redirect-private",
    "block-ipv6",
    "block-outside-dns",
];

static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$").unwrap());
/// Two or more DNS labels: letters, digits and inner hyphens, 63 characters each at most (and 253 in all, see `ts_suffix`).
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$").unwrap()
});
static SCHEME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*$").unwrap());

/// What a config is compiled from.
#[derive(Clone, Debug)]
pub struct Input {
    pub setup: Setup,
    pub links: IndexMap<String, Link>,
    pub self_package: String,
    pub lockdown: bool,
    pub ts_dir: String,
    pub cache_file: String,
    /// The tailnet's MagicDNS domain, if known.
    pub ts_suffix: Option<String>,
    /// Loopback port and password of the app's own way into each exit ([`PROBE`]); none = none.
    pub probe: Option<(u16, String)>,
    /// Index into [`fake_ranges`] of the block this engine hands out; the others are refused.
    pub fake_block: i32,
    /// Routes with no tunnel right now (signed out, unreachable): their apps' traffic and lookups are refused.
    pub blocked: IndexSet<String>,
    /// Tailscale asks the user to sign in (it gave a login link): only then do its sign-in pages skip the exit.
    pub ts_login_pending: bool,
}

impl Input {
    /// An input without a tailnet suffix, probe, blocked routes or pending sign-in, on the first fake-IP block.
    pub fn new(
        setup: Setup,
        links: IndexMap<String, Link>,
        self_package: &str,
        lockdown: bool,
        ts_dir: &str,
        cache_file: &str,
    ) -> Input {
        Input {
            setup,
            links,
            self_package: self_package.into(),
            lockdown,
            ts_dir: ts_dir.into(),
            cache_file: cache_file.into(),
            ts_suffix: None,
            probe: None,
            fake_block: 0,
            blocked: IndexSet::new(),
            ts_login_pending: false,
        }
    }
}

/// An IPv4 address or range as its address (in a u64, as the earlier app kept it) and prefix length; none if not IPv4.
pub fn ipv4(cidr: &str) -> Option<(u64, u32)> {
    let g = IPV4.captures(cidr.trim())?;
    let part = |i: usize| g.get(i).map(|m| m.as_str()).unwrap_or("");
    let octets: Vec<u64> = (1..5).map(|i| part(i).parse::<u64>().unwrap_or(999)).collect();
    let len_text = if part(5).is_empty() { "32" } else { part(5) };
    let len: u32 = len_text.parse().ok()?;
    // Leading zeros ("010") read as octal in some parsers and are refused by the engine's.
    if octets.iter().any(|o| *o > 255) || len > 32 || (1..6).any(|i| part(i).len() > 1 && part(i).starts_with('0')) {
        return None;
    }
    Some((octets.iter().fold(0u64, |a, v| (a << 8) | v), len))
}

/// The fake-IP pool (198.18.0.0/15) in eight blocks: each new domain table takes the next one and refuses the other
/// seven, so an address an app kept from an old table names nothing until eight tables later. Each holds 16,381 addresses.
pub fn fake_ranges() -> Vec<String> {
    (0..8).map(|i| format!("198.{}.{}.0/18", 18 + i / 4, i % 4 * 64)).collect()
}

/// The block a new table takes after `last`; a reload of the `open` table keeps its own.
pub fn next_block(last: i32, open: bool) -> i32 {
    (if open { last } else { last + 1 }).rem_euclid(8)
}

/// Older versions alternated two /16 halves: count the last one as its final block, so the next table starts in the
/// other half and nothing an app kept from it is handed out again.
pub fn block_after_half(half: Option<i32>) -> i32 {
    if half == Some(1) { 8 - 1 } else { 8 / 2 - 1 }
}

/// Route id → the tunnel tag it runs on: routes that resolve to one server with one login share a tunnel.
pub fn shared(
    s: &Setup,
    links: &IndexMap<String, Link>,
    blocked: &IndexSet<String>,
) -> Result<IndexMap<String, String>> {
    let mut owners: IndexMap<String, String> = IndexMap::new();
    require!(clashes(s, links).is_empty(), "{CLASH}"); // the link picker blocks them first
    let mut out = IndexMap::new();
    for r in s.active_routes().into_iter().filter(|r| r.ts_exit.is_none() && !blocked.contains(&r.id)) {
        let link = links.get(&r.id).ok_or_else(|| Error::State(format!("No server for {}", r.name())))?;
        let tag = owners.entry(link_key(link)).or_insert_with(|| format!("r-{}", r.id)).clone();
        out.insert(r.id.clone(), tag);
    }
    Ok(out)
}

pub fn compile(i: &Input) -> Result<String> {
    let s = &i.setup;
    // Blocked routes get no tunnel, DNS server or probe; their apps still match, to be refused.
    let active: Vec<&Route> = s.active_routes().into_iter().filter(|r| !i.blocked.contains(&r.id)).collect();
    let default_blocked = i.blocked.contains(&s.default_route);
    let exits: HashSet<&String> = active.iter().filter_map(|r| r.ts_exit.as_ref()).collect();
    require!(
        exits.len() <= 1,
        "Tailscale allows one exit node at a time. Use the same node for every Tailscale route."
    );
    // Tailscale-exit routes have no tunnel of their own: they ride the Tailscale endpoint, whose exit node is set below.
    // Routes that resolve to the same server with the same credentials share one tunnel: two with one key would fight over it.
    let shared = shared(s, &i.links, &i.blocked)?;
    let on_ts = |id: &str| s.route(Some(id)).is_some_and(|r| r.ts_exit.is_some());
    let tag = |id: &str| -> String {
        if id == DIRECT || id == FILTERED {
            "direct".into()
        } else if on_ts(id) {
            TS_TAG.into()
        } else {
            shared.get(id).cloned().unwrap_or_else(|| format!("r-{id}"))
        }
    };
    let ts_domains: Vec<String> = ["ts.net".to_string()]
        .into_iter()
        .filter(|_| official_ts(&s.home))
        .chain(trusted_suffix(i.ts_suffix.as_deref(), &s.home))
        .collect::<IndexSet<_>>()
        .into_iter()
        .collect();
    // OpenVPN routes use the DNS their server pushes, except NordVPN's own routes: those keep Nord's (Threat Protection)
    // resolvers through the tunnel.
    // unbraid's filter, when set: on VPN routes (through each route's tunnel) it replaces their own DNS and blocking.
    let filter = s.prefs.filter.server();
    let filter_routes = filter.is_some() && s.prefs.filter.routes;
    let pushed_dns = |r: &Route| !filter_routes && (r.imported() || r.loc.provider != "nord");
    let mut direct: Vec<&String> = s.apps.iter().filter(|(_, v)| *v == DIRECT).map(|(k, _)| k).collect();
    direct.sort();
    // Direct apps that pass through unbraid for the filter: still straight out, but not left out of the VPN.
    let through: HashSet<&String> = direct.iter().copied().filter(|k| s.prefs.filter.through(k)).collect();
    let home_wg = s.home.wg.as_ref();
    let ts = s.tailscale();
    // An exit keeps the endpoint running, but only the home toggle grants every app tailnet access.
    let home_ts = s.home.tailscale;
    let is_ovpn = |id: &str| matches!(i.links.get(id), Some(Link::Ovpn { .. }));
    // A route on its OpenVPN server's pushed DNS asks that tunnel's one DNS server (the engine allows one per tunnel).
    let ovpn_dns = |id: &str| is_ovpn(id) && s.route(Some(id)).is_some_and(pushed_dns);
    // A filter reached by name, on an imported OpenVPN route, is looked up with that tunnel's pushed DNS (it may only be known there).
    let ovpn_boot = |id: &str| {
        filter_routes
            && filter.as_ref().is_some_and(by_name)
            && is_ovpn(id)
            && s.route(Some(id)).is_some_and(Route::imported)
    };
    let dns_for = |id: &str| -> String {
        if id == FILTERED {
            "dns-filter".into()
        } else if id == DIRECT {
            "local".into()
        } else if ovpn_dns(id) {
            format!("dns-ovpn-{}", tag(id))
        } else {
            format!("dns-r-{id}")
        }
    };
    let direct_filtered = filter.is_some() && s.prefs.filter.direct && s.default_route == DIRECT;
    let default_dns = if direct_filtered && !default_blocked {
        "dns-filter".to_string()
    } else if s.default_route == DIRECT || default_blocked || active.is_empty() {
        "local".to_string()
    } else {
        dns_for(&s.default_route)
    };
    // Every tunnel the app can test, with the DNS of a route on it; Tailscale even without an exit route (its nodes).
    let mut probe_tags: IndexMap<String, String> = IndexMap::new();
    for r in &active {
        probe_tags.entry(tag(&r.id)).or_insert_with(|| dns_for(&r.id));
    }
    if ts {
        probe_tags.entry(TS_TAG.into()).or_insert_with(|| default_dns.clone());
    }
    // Apps with their own route, grouped. Direct only appears here under lockdown (otherwise left out by the system).
    let mut per_app: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (pkg, route) in &s.apps {
        per_app
            .entry(if through.contains(pkg) { FILTERED.into() } else { route.clone() })
            .or_default()
            .push(pkg.clone());
    }
    per_app.retain(|id, _| {
        *id != s.default_route
            && match id.as_str() {
                DIRECT => i.lockdown,
                FILTERED => true,
                _ => s.active_routes().iter().any(|r| r.id == *id),
            }
    });
    per_app.values_mut().for_each(|p| p.sort());
    // Destination rules that beat any app rule. Repeated after every resolve, because fake-IP connections only get a
    // real address there.
    let mut network = vec![];
    if let Some(cidrs) = home_wg.map(home_cidrs).filter(|c| !c.is_empty()) {
        network.push(json!({"ip_cidr": cidrs, "outbound": "home-wg"}));
    }
    if home_ts {
        let cidrs = [vec![TAILNET.to_string()], home_subnets(s)].concat();
        network.push(json!({"ip_cidr": cidrs, "outbound": TS_TAG}));
    }
    if s.prefs.lan {
        network.push(json!({"ip_cidr": LAN, "outbound": "direct"}));
    }
    let fake = fake_ranges();
    let block = &fake[i.fake_block as usize];

    let mut servers =
        vec![json!({"type": "fakeip", "tag": "fake", "inet4_range": block}), json!({"type": "local", "tag": "local"})];
    let mut boots = HashSet::new(); // one lookup server per tunnel: the engine allows one OpenVPN DNS server per endpoint
    for r in active.iter().filter(|r| !ovpn_dns(&r.id)) {
        let (t, own_tag) = (tag(&r.id), format!("dns-r-{}", r.id));
        let own = json!({"type": "udp", "tag": own_tag, "server": dns_server(s, r, i.links.get(&r.id)), "detour": t});
        match &filter {
            Some(f) if filter_routes => {
                // A filter reached by name is looked up first through the same tunnel, with the route's own resolver.
                let boot = format!("boot-{t}");
                if by_name(f) && boots.insert(boot.clone()) {
                    servers.push(if ovpn_boot(&r.id) {
                        json!({"type": "openvpn", "tag": boot, "endpoint": t, "accept_default_resolvers": true, "fallback_server": "9.9.9.9"})
                    } else {
                        let mut o = own;
                        o["tag"] = json!(boot);
                        o
                    });
                }
                servers.push(filter_dns(f, &own_tag, &t, &boot));
            }
            _ => servers.push(own),
        }
    }
    // Direct traffic the filter applies to goes to it straight, not through a tunnel.
    if let Some(f) = &filter
        && (direct_filtered || !through.is_empty())
    {
        servers.push(filter_dns(f, "dns-filter", "direct", "local"));
    }
    for t in active.iter().filter(|r| ovpn_dns(&r.id)).map(|r| tag(&r.id)).collect::<IndexSet<_>>() {
        // A server that pushes no DNS at all is answered by Quad9 through the same tunnel (an engine patch).
        servers.push(json!({"type": "openvpn", "tag": format!("dns-ovpn-{t}"), "endpoint": t, "accept_default_resolvers": true, "fallback_server": "9.9.9.9"}));
    }
    if home_ts {
        servers.push(
            json!({"type": "tailscale", "tag": "dns-tailnet", "endpoint": TS_TAG, "accept_default_resolvers": false}),
        );
    }

    let mut dns_rules = vec![];
    if home_ts && !ts_domains.is_empty() {
        dns_rules.push(json!({"domain_suffix": ts_domains, "server": "dns-tailnet"}));
    }
    if s.prefs.lan {
        dns_rules.push(json!({"domain_suffix": ["local", "lan", "home.arpa", "fritz.box"], "server": "local"}));
    }
    dns_rules.push(json!({"query_type": ["A", "AAAA"], "server": "fake", "rewrite_ttl": 1}));
    // Other query types (HTTPS, SVCB, TXT…) go to the asking app's own exit, never the ISP.
    for (id, pkgs) in &per_app {
        dns_rules.push(if i.blocked.contains(id) {
            json!({"package_name": pkgs, "action": "reject"})
        } else {
            json!({"package_name": pkgs, "server": dns_for(id)})
        });
    }
    // A blocked default never falls back to another resolver: the computer's network would see the names.
    if default_blocked {
        dns_rules.push(json!({"action": "reject"}));
    }

    let mut tun = json!({
        "type": "tun", "tag": "tun", "address": ["172.19.0.1/30"], "mtu": 9000, "auto_route": true, "strict_route": true,
        // gVisor: on Android 17 the kernel TCP path of "mixed" never answered (Direct and Shadowsocks timed out on the
        // emulator; cf. sing-tun#98). WireGuard, OpenVPN and Tailscale forward their flows past the stack either way, at
        // the same speed.
        "stack": "gvisor",
        // Forwarded flows and UDP are forgotten after udp_timeout idle (5 min by default), which silently kills idle
        // long-lived connections like push (heartbeats run up to ~28 min apart).
        "udp_timeout": "30m",
    });
    // Under lockdown the system drops anything that bypasses the TUN, so LAN goes through `direct` instead.
    if s.prefs.lan && !i.lockdown {
        // LAN never enters the tunnel: the system sends it straight to the network. Home subnets reached through a
        // tunnel stay routed, because the more specific route wins.
        let home =
            [if home_ts { home_subnets(s) } else { vec![] }, home_wg.map(home_cidrs).unwrap_or_default()].concat();
        let routed = [vec!["0.0.0.0/0".to_string()], home.clone()].concat();
        tun["route_address"] = json!(routed);
        // Exclusions apply after inclusions, so an exclusion equal to a home prefix would win.
        tun["route_exclude_address"] = json!(LAN.iter().filter(|l| !home.iter().any(|h| h == *l)).collect::<Vec<_>>());
    }
    let mut excluded: Vec<&str> =
        if i.lockdown { vec![] } else { direct.iter().filter(|k| !through.contains(*k)).map(|k| k.as_str()).collect() };
    excluded.push(&i.self_package);
    tun["exclude_package"] = json!(excluded);
    let mut inbounds = vec![tun];
    // No tunnel to test, no inbound: the engine would run a proxy with an empty user list unauthenticated.
    if let Some((port, password)) = &i.probe
        && !probe_tags.is_empty()
    {
        let users: Vec<Value> = probe_tags.keys().map(|t| json!({"username": t, "password": password})).collect();
        inbounds
            .push(json!({"type": "mixed", "tag": PROBE, "listen": "127.0.0.1", "listen_port": port, "users": users}));
    }

    let owners: Vec<&Route> =
        active.iter().copied().filter(|r| shared.get(&r.id) == Some(&format!("r-{}", r.id))).collect();
    let mut endpoints = vec![];
    for r in &owners {
        let t = tag(&r.id);
        match &i.links[r.id.as_str()] {
            Link::Wg { peer, .. } => endpoints.push(wg(&t, peer, &r.name())?),
            Link::Ovpn { profile, .. } => {
                let e = manual::ovpn_endpoint(&t, profile)?;
                // Keeps the pushed DNS if any route on this tunnel uses it, not only the route that owns it.
                let pushed = active.iter().any(|a| tag(&a.id) == t && (ovpn_dns(&a.id) || ovpn_boot(&a.id)));
                endpoints.push(Value::Object(if pushed { open_vpn(e) } else { e }));
            }
            Link::Ss { .. } | Link::Ts { .. } => {}
        }
    }
    if let Some(w) = home_wg {
        endpoints.push(wg("home-wg", &WgPeer { mtu: w.mtu.min(MTU_MIN), ..w.clone() }, "the home network")?);
    }
    if ts {
        let mut e = Map::new();
        e.insert("type".into(), json!("tailscale"));
        e.insert("tag".into(), json!(TS_TAG));
        e.insert("state_directory".into(), json!(i.ts_dir));
        e.insert("hostname".into(), json!("unbraid"));
        e.insert("accept_routes".into(), json!(true));
        if let Some(k) = &s.home.ts_auth_key {
            e.insert("auth_key".into(), json!(k));
        }
        if let Some(u) = &s.home.ts_control_url {
            // Over plain HTTP a network attacker could hand Tailscale a fake control-server key.
            require!(u.starts_with("https://"), "Headscale needs an https:// address. Change it in Settings.");
            e.insert("control_url".into(), json!(u));
        }
        if let Some(x) = s.ts_exit() {
            e.insert("exit_node".into(), json!(x));
            e.insert("exit_node_allow_lan_access".into(), json!(s.prefs.lan));
        }
        endpoints.push(Value::Object(e));
    }

    let mut outbounds = vec![json!({"type": "direct", "tag": "direct"})];
    for r in &owners {
        if let Some(Link::Ss { profile, .. }) = i.links.get(&r.id) {
            outbounds.push(Value::Object(manual::ss_outbound(&tag(&r.id), profile)));
        }
    }

    let mut rules = vec![];
    // The tunnels carry the computer's own connections and their replies, never new ones a server or peer opens: those
    // would reach the computer, its network and the home network through another route.
    let mut tunnels: Vec<String> = owners
        .iter()
        .filter(|r| matches!(i.links.get(&r.id), Some(Link::Wg { .. } | Link::Ovpn { .. })))
        .map(|r| tag(&r.id))
        .collect();
    tunnels.extend(home_wg.map(|_| "home-wg".to_string()));
    tunnels.extend(ts.then(|| TS_TAG.to_string()));
    if !tunnels.is_empty() {
        rules.push(json!({"inbound": tunnels, "action": "reject"}));
    }
    rules.push(json!({"inbound": ["tun"], "protocol": "dns", "action": "hijack-dns"}));
    // UDP only: the engine never completes a hijacked TCP connection, and apps test "am I online?" by opening TCP to
    // 8.8.8.8:53. That TCP goes out through the app's own exit like any other connection.
    rules.push(json!({"inbound": ["tun"], "port": 53, "network": "udp", "action": "hijack-dns"}));
    // Fake IPs an app kept from the previous domain table name nothing now: refused at once, so the app looks the name
    // up again instead of waiting on a dead address.
    rules.push(json!({"ip_cidr": fake.iter().filter(|r| *r != block).collect::<Vec<_>>(), "action": "reject", "no_drop": true}));
    // The app's own tests: each proxy user goes out through its exit only, names resolved there too.
    if i.probe.is_some() {
        for (t, dns) in &probe_tags {
            rules.push(json!({"inbound": PROBE, "auth_user": [t], "action": "resolve", "server": dns}));
            rules.push(json!({"inbound": PROBE, "auth_user": [t], "outbound": t}));
        }
    }
    rules.extend(network.iter().cloned());
    // While Tailscale waits for a sign-in, its login pages skip the tailnet for apps on a Tailscale exit: the exit node
    // can't carry them before the sign-in. Other apps keep their own exits, and once signed in these sites follow the
    // exit too (the engine's own control traffic never needs the rule).
    let mut ts_login: Vec<(&str, Value)> = vec![];
    if ts && i.ts_login_pending {
        if s.ts_exit().is_some() && official_ts(&s.home) {
            ts_login.push(("domain_suffix", json!(["tailscale.com", "tailscale.io"])));
        }
        if let Some(u) = &s.home.ts_control_url {
            let host = uri_host(u)
                .map_err(|_| Error::Invalid("Headscale needs an https:// address. Change it in Settings.".into()))?;
            // An address only when it truly is one (no lookup): "1hs.example.com" is a name.
            ts_login.extend(host.and_then(|h| {
                match h.strip_prefix('[') {
                    _ if ipv4(h).is_some() => Some(("ip_cidr", json!([format!("{h}/32")]))),
                    Some(v6) => Some(v6.trim_end_matches(']'))
                        .filter(|a| !a.contains('%'))
                        .map(|a| ("ip_cidr", json!([format!("{a}/128")]))), // a zone can't be routed on
                    None => Some(("domain", json!([h]))),
                }
            }));
        }
    }
    let login_rules = |base: Value| {
        ts_login.iter().map(move |(k, v)| {
            let mut o = base.clone();
            o[*k] = v.clone();
            o
        })
    };
    for (id, p) in &per_app {
        if i.blocked.contains(id) {
            rules.push(json!({"package_name": p, "action": "reject", "no_drop": true}));
            continue;
        }
        // Before its exit's DNS, which an exit node not yet signed in can't answer; Direct resolves locally.
        if on_ts(id) {
            rules.extend(login_rules(json!({"package_name": p, "outbound": "direct"})));
        }
        rules.push(json!({"package_name": p, "action": "resolve", "server": dns_for(id)}));
        rules.extend(network.iter().cloned());
        rules.push(json!({"package_name": p, "outbound": tag(id)}));
    }
    // Everything left follows the default: refused while it has no tunnel, after the LAN and home rules above.
    if default_blocked {
        rules.push(json!({"action": "reject", "no_drop": true}));
    } else {
        if on_ts(&s.default_route) {
            rules.extend(login_rules(json!({"outbound": "direct"})));
        }
        rules.push(json!({"action": "resolve", "server": default_dns}));
        rules.extend(network.iter().cloned());
        // Ping has no owner the engine can look up, so it never matches an app's rule and lands here: with Direct as the
        // default, an app kept on a VPN could ping out from the computer's own address. Refused, after the LAN and home
        // rules (names resolved), so pinging the router or a home box still works.
        if s.default_route == DIRECT && per_app.keys().any(|k| k != DIRECT) {
            rules.push(json!({"network": "icmp", "action": "reject"}));
        }
    }

    let config = json!({
        "log": {"level": "warn", "timestamp": false},
        "dns": {
            "servers": servers,
            "rules": dns_rules,
            "final": default_dns,
            "strategy": "ipv4_only",
            // A slow or re-handshaking exit must not hold every app's new connections: answer from the cache (stale if
            // need be) and refresh in the background, and give up on a lookup sooner than the 10 s default.
            "optimistic": {"enabled": true, "timeout": "1h"}, // stale at most an hour, not the 3-day default
            "timeout": "5s",
            "cache_capacity": 4096,
        },
        "inbounds": inbounds,
        "endpoints": endpoints,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": if active.is_empty() || default_blocked { "direct".to_string() } else { tag(&s.default_route) }, // blocked: never reached
            "auto_detect_interface": true,
            "default_domain_resolver": "local",
        },
        "experimental": {"cache_file": {"enabled": true, "path": i.cache_file, "store_fakeip": true}},
    });
    Ok(config.to_string())
}

/// `cidr` with its host bits cleared ("192.168.1.0/16" → "192.168.0.0/16"), as the system reads it; none if not IPv4.
pub fn canonical(cidr: &str) -> Option<String> {
    let (a, len) = ipv4(cidr)?;
    let v = if len == 0 { 0 } else { a & ((0xFFFF_FFFFu64 << (32 - len)) & 0xFFFF_FFFF) };
    Some(format!("{}.{}.{}.{}/{len}", v >> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255))
}

/// Home subnets behind Tailscale, private only, as the system will route them.
fn home_subnets(s: &Setup) -> Vec<String> {
    s.home
        .subnets
        .iter()
        .filter_map(|c| canonical(c))
        .filter(|c| is_private(c))
        .collect::<IndexSet<_>>()
        .into_iter()
        .collect()
}

/// True when the whole of `cidr` lies inside a private IPv4 range.
pub fn is_private(cidr: &str) -> bool {
    let Some((a, l)) = ipv4(cidr) else { return false };
    PRIVATE.iter().any(|r| {
        let (b, m) = ipv4(r).unwrap();
        l >= m && (a ^ b) >> (32 - m) == 0
    })
}

/// Networks to send through the home tunnel: its private AllowedIPs; else the interface's own subnet.
pub fn home_cidrs(p: &WgPeer) -> Vec<String> {
    let private = |l: &[String]| -> Vec<String> {
        l.iter().filter_map(|c| canonical(c)).filter(|c| is_private(c)).collect::<IndexSet<_>>().into_iter().collect()
    };
    let allowed = private(&p.allowed_ips);
    if allowed.is_empty() { private(&p.address) } else { allowed }
}

/// A DNS server in the engine for filter `d`: over HTTPS or TLS by its address and TLS name, or plain; `boot` looks up a name.
fn filter_dns(d: &Dns, tag: &str, detour: &str, boot: &str) -> Value {
    let kind = if d.path.is_some() {
        "https"
    } else if d.tls.is_some() {
        "tls"
    } else {
        "udp"
    };
    let mut o = json!({"type": kind, "tag": tag, "server": d.ip, "server_port": d.port});
    if let Some(p) = &d.path {
        o["path"] = json!(p);
    }
    if d.path.is_some() || d.tls.is_some() {
        o["tls"] = json!({"enabled": true});
        if let Some(n) = &d.tls {
            o["tls"]["server_name"] = json!(n);
        }
    }
    if by_name(d) {
        o["domain_resolver"] = json!(boot);
    }
    if detour != "direct" {
        o["detour"] = json!(detour);
    }
    o
}

/// Resolver inside a route's tunnel: the provider's blocking resolver if on, else the tunnel's own, else Nord's, else Quad9.
fn dns_server(s: &Setup, r: &Route, link: Option<&Link>) -> String {
    let provider = (!r.imported()).then_some(&r.loc.provider);
    provider
        .filter(|_| s.protects(r))
        .and_then(|p| crate::providers::get(p)?.blocking_dns(&|k: &str| s.opt(p, k)))
        .or_else(|| match link {
            Some(Link::Wg { peer, .. }) => peer.dns.first().cloned(),
            _ => None,
        })
        .unwrap_or_else(|| (if provider.is_some_and(|p| p == "nord") { NORD_DNS } else { "9.9.9.9" }).into())
}

/// The engine's error for a bad key quotes it, so every key is checked here and never named.
fn wg(tag: &str, p: &WgPeer, name: &str) -> Result<Value> {
    require!(
        valid_wg_key(&p.private_key)
            && valid_wg_key(&p.public_key)
            && p.preshared_key.as_deref().is_none_or(valid_wg_key),
        "Invalid WireGuard key for {name}"
    );
    let (host, port) = p.endpoint.rsplit_once(':').unwrap_or((p.endpoint.as_str(), p.endpoint.as_str()));
    let host = host.strip_prefix('[').unwrap_or(host);
    let mut peer = json!({
        "address": host.strip_suffix(']').unwrap_or(host),
        "port": port.parse::<i32>().unwrap_or(51820),
        "public_key": p.public_key,
        "allowed_ips": ["0.0.0.0/0"],
        // Keeps the path's NAT open when idle; 25 s is WireGuard's own advice. An imported config's value wins.
        "persistent_keepalive_interval": keepalive(p),
    });
    if let Some(k) = &p.preshared_key {
        peer["pre_shared_key"] = json!(k);
    }
    // 1280 fits every path (cellular, 464XLAT); 1420 makes 1480-byte packets that stall big uploads there.
    // [`crate::link_picker::ported`] sets it: a provider page's MTU, imports at most 1280.
    Ok(
        json!({"type": "wireguard", "tag": tag, "mtu": p.mtu.min(MTU_MAX), "address": p.address, "private_key": p.private_key, "peers": [peer]}),
    )
}

/// The OpenVPN endpoint is built with `route_no_pull`, which also drops the pushed DNS. Here the server's routes stay
/// ignored (the engine's own rules steer traffic) but its DNS is kept, for the `openvpn` DNS server.
fn open_vpn(mut e: Map<String, Value>) -> Map<String, Value> {
    e.remove("route_no_pull");
    // First match wins: the app's ignores go first, so a profile's own accept filter can't let pushed routes through.
    let mut filters: Vec<Value> = OPENVPN_ROUTING.iter().map(|t| json!({"action": "ignore", "text": t})).collect();
    if let Some(Value::Array(own)) = e.get("pull_filters") {
        filters.extend(own.iter().cloned());
    }
    e.insert("pull_filters".into(), Value::Array(filters));
    e
}

/// A MagicDNS suffix as Tailscale reports it ("tail1234.ts.net." or a Headscale base domain), or none if unusable.
pub fn ts_suffix(raw: Option<&str>) -> Option<String> {
    let t = raw?.trim().to_lowercase();
    let t = t.trim_matches('.');
    ((1..=253).contains(&t.chars().count()) && DOMAIN.is_match(t) && t != "ts.net").then(|| t.to_string())
}

/// Tailscale's own control server (none set, or one on tailscale.com) rather than a Headscale.
pub fn official_ts(h: &Home) -> bool {
    let Some(u) = &h.ts_control_url else { return true };
    uri_host(u)
        .ok()
        .flatten()
        .map(str::to_lowercase)
        .is_some_and(|h| h == "tailscale.com" || h.ends_with(".tailscale.com"))
}

/// The suffix the tailnet's DNS may answer for every app: a tailnet's own under ts.net on Tailscale's server; on Headscale
/// (which can name any domain, even a whole top-level one) only the one the user allowed.
pub fn trusted_suffix(raw: Option<&str>, h: &Home) -> Option<String> {
    ts_suffix(raw)
        .filter(|t| if official_ts(h) { t.ends_with(".ts.net") } else { Some(t) == h.ts_suffix_allowed.as_ref() })
}

/// The host in `url` as java.net.URI reads it, which the earlier app went by: an error for a text it refuses, none for an
/// authority that isn't a server's name or address. A literal IPv6 address keeps its brackets.
fn uri_host(url: &str) -> std::result::Result<Option<&str>, ()> {
    let refused = |c: char| c.is_whitespace() || c.is_control() || "\"<>\\^`{|}".contains(c);
    if url.chars().any(refused)
        || url.split('%').skip(1).any(|e| !e.get(..2).is_some_and(|h| h.chars().all(|c| c.is_ascii_hexdigit())))
    {
        return Err(());
    }
    let Some((scheme, rest)) = url.split_once("://").filter(|(s, _)| !s.contains(['/', '?', '#'])) else {
        return Ok(None);
    };
    if !SCHEME.is_match(scheme) {
        return Err(());
    }
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    if tail[..tail.find(['?', '#']).unwrap_or(tail.len())].contains(['[', ']']) {
        return Err(());
    }
    let host_port = authority.split_once('@').map_or(authority, |(_, h)| h);
    let port_ok = |p: &str| p.is_empty() || (p.chars().all(|c| c.is_ascii_digit()) && p.parse::<i32>().is_ok());
    if let Some(v6) = host_port.strip_prefix('[') {
        let Some((addr, after)) = v6.split_once(']') else { return Err(()) };
        let (ip, zone) = addr.split_once('%').unwrap_or((addr, ""));
        let valid = ip.contains(':')
            && ip.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            && !addr.ends_with('%');
        if !valid
            || !zone.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
            || !(after.is_empty() || after.strip_prefix(':').is_some_and(port_ok))
        {
            return Err(());
        }
        return Ok(Some(&host_port[..addr.len() + 2]));
    }
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
    let address = host.split('.').count() == 4
        && host.split('.').all(|o| {
            !o.is_empty() && o.chars().all(|c| c.is_ascii_digit()) && o.parse::<u32>().is_ok_and(|n| n <= 255)
        });
    let labels: Vec<&str> = host.strip_suffix('.').unwrap_or(host).split('.').collect();
    let label = |l: &&str| {
        !l.is_empty()
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let name = labels.iter().all(label)
        && (labels.len() == 1 || labels.last().is_some_and(|l| l.starts_with(|c: char| c.is_ascii_alphabetic())));
    Ok(((address || name) && port_ok(port)).then_some(host))
}

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Tunnel tag → the DNS server its probe user resolves with, read back from a compiled `config`; none if it can't be read.
pub fn probe_dns(config: &str) -> Option<IndexMap<String, String>> {
    let c: Value = serde_json::from_str(config).ok()?;
    c["route"]["rules"]
        .as_array()?
        .iter()
        .filter(|r| r["inbound"] == PROBE && r["action"] == "resolve")
        .map(|r| Some((r["auth_user"][0].as_str()?.to_string(), r["server"].as_str()?.to_string())))
        .collect()
}

/// Same key = same physical exit with the same credentials, whichever route asked for it.
pub(crate) fn link_key(l: &Link) -> String {
    match l {
        // Everything the engine's WireGuard device is built from, whichever provider or import it came through.
        Link::Wg { peer, .. } => wg_key(peer),
        // Same remotes but another protocol, CA or login is another tunnel: compare the whole profile.
        Link::Ovpn { profile: p, .. } => {
            ["ovpn".into(), sha(&p.config), p.username.clone(), sha(&p.password)].join("|")
        }
        // The plugin and its options (TLS, certificate, host) are part of the tunnel too.
        Link::Ss { profile: p, .. } => [
            "ss".into(),
            p.server.clone(),
            p.port.to_string(),
            p.method.clone(),
            sha(&p.password),
            p.plugin.clone().unwrap_or_default(),
            sha(p.plugin_opts.as_deref().unwrap_or("")),
        ]
        .join("|"),
        Link::Ts { .. } => "ts".into(),
    }
}

fn wg_identity(p: &WgPeer) -> String {
    [p.endpoint.to_lowercase(), p.public_key.clone(), sha(&p.private_key)].join("|")
}

// Address order too: the engine sends from the last IPv4 address.
fn wg_key(p: &WgPeer) -> String {
    [
        "wg".into(),
        wg_identity(p),
        sha(p.preshared_key.as_deref().unwrap_or("")),
        p.address.join(","),
        p.mtu.min(MTU_MIN).to_string(),
        keepalive(p).to_string(),
    ]
    .join("|")
}

fn keepalive(p: &WgPeer) -> i32 {
    p.keepalive.unwrap_or(25)
}

/// Routes whose WireGuard identity (client key on one server) is already taken, with other settings, by an earlier
/// route or the home tunnel: one identity can be one tunnel only, two would knock each other off.
pub fn clashes(s: &Setup, links: &IndexMap<String, Link>) -> IndexSet<String> {
    let mut seen: IndexMap<String, String> = s.home.wg.iter().map(|w| (wg_identity(w), "home".to_string())).collect();
    let mut out = IndexSet::new();
    for r in s.active_routes().into_iter().filter(|r| r.ts_exit.is_none()) {
        let Some(Link::Wg { peer, .. }) = links.get(&r.id) else { continue };
        let first = seen.entry(wg_identity(peer)).or_insert_with(|| wg_key(peer)).clone();
        if first == "home" || first != wg_key(peer) {
            out.insert(r.id.clone());
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manual::parse_ovpn;
    use crate::model::{Filter, Location, OWN, OvpnProfile, Prefs, Server, SsProfile, VERSION, own_dns, stable_id};
    use crate::providers::PROTECT;
    use crate::providers::nord;
    use crate::providers::nord_api::parse_servers;
    use crate::wg_conf;

    pub(crate) const KEY: &str = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMTI=";
    pub(crate) const PUB: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";
    const FRITZ: &str = "
[Interface]
PrivateKey = aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMTI=
Address = 192.168.178.201/24, fd00::201/64
DNS = 192.168.178.1, fd00::1, fritz.box

[Peer]
PublicKey = 5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=
PresharedKey = 5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=
AllowedIPs = 192.168.178.0/24, 0.0.0.0/0, ::/0
Endpoint = abc.myfritz.net:51820
PersistentKeepalive = 25
";

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/compiler/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Keeps a compiled config, named by its content, for the engine's check (tests/engine_check.rs).
    pub(crate) fn keep(dir: &str, config: &str) {
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("{}.json", &sha(config)[..16])), config).unwrap();
    }

    /// A NordVPN server whose address follows its name's hash (Java's String.hashCode; the names here are lower case).
    pub(crate) fn sv(n: &str) -> Server {
        let h = stable_id(n);
        Server {
            name: format!("{n} #1"),
            host: format!("{n}.nordvpn.com"),
            ip: format!("10.9.{}.{}", h & 0xff, h >> 8 & 0xff),
            public_key: PUB.into(),
            load: 10,
            ..Server::default()
        }
    }

    pub(crate) fn wg_link(server: Server, peer: WgPeer) -> Link {
        Link::Wg { server, peer, ports: vec![], entries: vec![] }
    }

    pub(crate) fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    pub(crate) fn pairs(v: &[(&str, &str)]) -> IndexMap<String, String> {
        v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect()
    }

    pub(crate) fn opts(provider: &str, key: &str, value: &str) -> IndexMap<String, IndexMap<String, String>> {
        IndexMap::from([(provider.to_string(), pairs(&[(key, value)]))])
    }

    fn route(id: &str, loc: Location, hue: i32) -> Route {
        Route { hue, ..Route::new(id, loc) }
    }

    fn ts_route(id: &str, exit: &str, hue: i32) -> Route {
        Route { ts_exit: Some(exit.into()), hue, ..Route::new(id, Location::default()) }
    }

    fn nl() -> Route {
        Route::new("nl", Location::country("nord", 153, "NL", "Netherlands"))
    }

    /// Example setup: NL default, US for A, IT for B, X+Y direct, home over Tailscale.
    fn example() -> Setup {
        Setup {
            routes: vec![
                nl(),
                route("us", Location::country("nord", 228, "US", "United States"), 1),
                route("it", Location::country("nord", 106, "IT", "Italy"), 2),
            ],
            default_route: "nl".into(),
            apps: pairs(&[("com.a", "us"), ("com.b", "it"), ("com.x", DIRECT), ("com.y", DIRECT)]),
            home: Home { tailscale: true, subnets: strs(&["192.168.178.0/24"]), ..Home::default() },
            ..Setup::default()
        }
    }

    /// The example with `extra` routes and apps.
    fn plus(s: Setup, extra: Vec<Route>, apps: &[(&str, &str)]) -> Setup {
        let mut out = Setup { routes: [s.routes.clone(), extra].concat(), ..s };
        out.apps.extend(pairs(apps));
        out
    }

    fn with_route(s: &Setup, id: &str, f: impl Fn(Route) -> Route) -> Setup {
        Setup {
            routes: s.routes.iter().map(|r| if r.id == id { f(r.clone()) } else { r.clone() }).collect(),
            ..s.clone()
        }
    }

    fn links(s: &Setup) -> IndexMap<String, Link> {
        s.active_routes()
            .iter()
            .map(|r| {
                let l = match (&r.wg, &r.ts_exit) {
                    (Some(w), _) => wg_link(sv(&r.id), w.clone()),
                    (None, Some(_)) => Link::Ts { server: sv(&r.id) },
                    _ => wg_link(sv(&r.id), nord::peer(&sv(&r.id), KEY)),
                };
                (r.id.clone(), l)
            })
            .collect()
    }

    fn input(s: &Setup) -> Input {
        Input::new(s.clone(), links(s), "app.unbraid", false, "/tmp/ts", "/tmp/cache.db")
    }

    /// Compiles `i` and keeps the config for the engine's check.
    pub(crate) fn raw(i: &Input) -> String {
        let out = compile(i).unwrap();
        keep("compiled", &out);
        out
    }

    fn json(i: &Input) -> Value {
        serde_json::from_str(&raw(i)).unwrap()
    }

    fn compiled(s: &Setup) -> Value {
        json(&input(s))
    }

    /// `s` compiled with `ids` blocked: no tunnel for them.
    fn with_blocked(s: &Setup, lockdown: bool, ids: &[&str]) -> Value {
        let blocked: IndexSet<String> = ids.iter().map(|i| i.to_string()).collect();
        let mut l = links(s);
        l.retain(|k, _| !blocked.contains(k));
        json(&Input { links: l, lockdown, blocked, ..input(s) })
    }

    fn rules(c: &Value) -> &Vec<Value> {
        c["route"]["rules"].as_array().unwrap()
    }
    fn dns_rules(c: &Value) -> &Vec<Value> {
        c["dns"]["rules"].as_array().unwrap()
    }
    fn servers(c: &Value) -> &Vec<Value> {
        c["dns"]["servers"].as_array().unwrap()
    }
    fn dns_server<'a>(c: &'a Value, tag: &str) -> &'a Value {
        servers(c).iter().find(|s| s["tag"] == tag).unwrap()
    }
    fn endpoint_tags(c: &Value) -> Vec<String> {
        strings(&Value::Array(c["endpoints"].as_array().unwrap().iter().map(|e| e["tag"].clone()).collect()))
    }
    fn excluded(c: &Value) -> Value {
        c["inbounds"][0]["exclude_package"].clone()
    }
    pub(crate) fn strings(v: &Value) -> Vec<String> {
        v.as_array().map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect()).unwrap_or_default()
    }
    pub(crate) fn has(v: &Value, s: &str) -> bool {
        v.as_array().is_some_and(|a| a.contains(&json!(s)))
    }
    /// The one item that matches `f`.
    fn single(items: &[Value], f: impl Fn(&Value) -> bool) -> &Value {
        let m: Vec<&Value> = items.iter().filter(|v| f(v)).collect();
        assert_eq!(1, m.len(), "{m:?}");
        m[0]
    }

    /// Each new domain table hands out fake IPs from its block of the pool and refuses the others, before any exit is chosen.
    #[test]
    fn a_fake_ip_from_another_block_is_refused() {
        let ranges = fake_ranges();
        for h in 0..8 {
            let c = json(&Input { fake_block: h, ..input(&example()) });
            let own = &ranges[h as usize];
            assert_eq!(*own, single(servers(&c), |s| s["tag"] == "fake")["inet4_range"]);
            let rules = rules(&c);
            let others: Vec<&String> = ranges.iter().filter(|r| *r != own).collect();
            let refuse = rules.iter().position(|r| r["ip_cidr"] == json!(others)).unwrap();
            assert_eq!("reject", rules[refuse]["action"]);
            assert_eq!(true, rules[refuse]["no_drop"]); // refused every time, never silently dropped
            assert!(
                rules[..refuse]
                    .iter()
                    .all(|r| r["action"] == "hijack-dns" || r.get("inbound").is_some() && r["action"] == "reject")
            );
        }
    }

    /// New tables walk through all eight blocks; a reload keeps its block; older versions' halves start in the other half.
    #[test]
    fn fake_blocks_rotate_and_migrate() {
        assert_eq!(vec![1, 2, 3, 4, 5, 6, 7, 0], (0..8).map(|b| next_block(b, false)).collect::<Vec<_>>());
        assert_eq!(5, next_block(5, true));
        // Half 0 was 198.18.0.0/16 (blocks 0 to 3), half 1 was 198.19.0.0/16 (blocks 4 to 7).
        assert_eq!(4, next_block(block_after_half(Some(0)), false));
        assert_eq!(0, next_block(block_after_half(Some(1)), false));
        assert_eq!(4, next_block(block_after_half(None), false));
    }

    /// Eight equal blocks that tile 198.18.0.0/15 exactly.
    #[test]
    fn fake_blocks_tile_the_benchmark_range() {
        let starts: Vec<u64> = fake_ranges()
            .iter()
            .map(|r| {
                assert!(r.ends_with("/18"));
                r.trim_end_matches("/18").split('.').fold(0, |a, o| a << 8 | o.parse::<u64>().unwrap())
            })
            .collect();
        let base = (198 << 24) | (18 << 16);
        assert_eq!((0..8).map(|i| base + i * 16384).collect::<Vec<u64>>(), starts);
    }

    /// Health checks look their STUN servers up through each tunnel's own DNS server, read back from the config.
    #[test]
    fn each_tunnels_dns_server_is_known() {
        let raw = raw(&Input { probe: Some((40000, "pw".into())), ..input(&example()) });
        let dns = probe_dns(&raw).unwrap();
        for t in ["r-nl", "r-us", "r-it"] {
            assert_eq!(Some(&format!("dns-r-{}", &t[2..])), dns.get(t), "{t}");
        }
        let c: Value = serde_json::from_str(&raw).unwrap();
        for (t, d) in dns.iter().filter(|(t, _)| t.starts_with("r-")) {
            assert_eq!(t.as_str(), single(servers(&c), |s| s["tag"] == d.as_str())["detour"], "{t}");
        }
    }

    /// A new probe pair always changes the config (so every engine start gets one), the same pair never.
    #[test]
    fn the_probe_pair_is_part_of_the_config() {
        let with =
            |p: Option<(u16, &str)>| raw(&Input { probe: p.map(|(n, w)| (n, w.to_string())), ..input(&example()) });
        let a = with(Some((41001, "pw-one")));
        assert_eq!(a, with(Some((41001, "pw-one"))));
        assert_ne!(a, with(Some((41001, "pw-two"))));
        assert_ne!(a, with(Some((41002, "pw-one"))));
        let c: Value = serde_json::from_str(&a).unwrap();
        let probe = single(c["inbounds"].as_array().unwrap(), |i| i["tag"] == PROBE);
        assert_eq!("127.0.0.1", probe["listen"]);
        assert!(probe["users"].as_array().unwrap().iter().all(|u| u["password"] == "pw-one"));
        let none: Value = serde_json::from_str(&with(None)).unwrap();
        assert!(none["inbounds"].as_array().unwrap().iter().all(|i| i["tag"] != PROBE));
    }

    #[test]
    fn example_routes_each_app_to_its_exit() {
        let c = compiled(&example());
        assert_eq!(strs(&["r-nl", "r-us", "r-it", "home-ts"]), endpoint_tags(&c));
        assert_eq!("r-nl", c["route"]["final"]);
        let routed: IndexMap<String, Value> = rules(&c)
            .iter()
            .filter(|r| r.get("outbound").is_some() && r.get("package_name").is_some())
            .map(|r| (r["outbound"].as_str().unwrap().to_string(), r["package_name"].clone()))
            .collect();
        assert_eq!(
            IndexMap::from([("r-it".to_string(), json!(["com.b"])), ("r-us".to_string(), json!(["com.a"]))]),
            routed
        );
        assert_eq!(json!(["com.x", "com.y", "app.unbraid"]), excluded(&c));
    }

    #[test]
    fn home_beats_lan_and_app_rules() {
        let c = compiled(&example());
        let rules = rules(&c);
        let home = rules.iter().position(|r| r["outbound"] == "home-ts").unwrap();
        let lan = rules.iter().position(|r| r["outbound"] == "direct" && r.get("ip_cidr").is_some()).unwrap();
        let app = rules.iter().position(|r| r.get("package_name").is_some()).unwrap();
        assert!(home < lan && lan < app);
        assert!(has(&rules[home]["ip_cidr"], "192.168.178.0/24"));
    }

    /// unbraid's filter: over HTTPS by address and TLS name, through each route's tunnel; Direct scopes go straight to it.
    #[test]
    fn filter_scopes() {
        let quad9 = Filter { id: Some("quad9".into()), ..Filter::default() };
        let with = |f: Filter| Setup { prefs: Prefs { filter: f, ..Prefs::default() }, ..example() };
        // Chosen but on nothing: everything as before.
        let none = compiled(&with(quad9.clone()));
        assert_eq!("udp", dns_server(&none, "dns-r-nl")["type"]);
        assert!(servers(&none).iter().all(|s| s["tag"] != "dns-filter"));
        assert_eq!(json!(["com.x", "com.y", "app.unbraid"]), excluded(&none));
        // VPN routes: each route's resolver is the filter, through its own tunnel, by address with its TLS name.
        let routes = compiled(&with(Filter { routes: true, ..quad9.clone() }));
        let us = dns_server(&routes, "dns-r-us");
        assert_eq!("https", us["type"]);
        assert_eq!("9.9.9.9", us["server"]);
        assert_eq!("r-us", us["detour"]);
        assert_eq!("/dns-query", us["path"]);
        assert_eq!("dns.quad9.net", us["tls"]["server_name"]);
        assert!(us.get("domain_resolver").is_none());
        // Apps set to Direct pass through unbraid, out directly, their lookups to the filter (one app kept outside).
        for lockdown in [false, true] {
            let s = with(Filter {
                direct_apps: true,
                apps: IndexMap::from([("com.y".to_string(), false)]),
                ..quad9.clone()
            });
            let c = json(&Input { lockdown, ..input(&s) });
            let ctx = format!("lockdown={lockdown}");
            assert_eq!(
                if lockdown { json!(["app.unbraid"]) } else { json!(["com.y", "app.unbraid"]) },
                excluded(&c),
                "{ctx}"
            );
            assert!(dns_server(&c, "dns-filter").get("detour").is_none(), "{ctx}");
            let dns_rule = dns_rules(&c).iter().find(|r| r["package_name"] == json!(["com.x"])).unwrap();
            assert_eq!("dns-filter", dns_rule["server"], "{ctx}");
            let out = rules(&c)
                .iter()
                .find(|r| r.get("outbound").is_some() && r["package_name"] == json!(["com.x"]))
                .unwrap();
            assert_eq!("direct", out["outbound"], "{ctx}");
            // Kept outside: only under lockdown does it pass through, with the computer's DNS.
            assert_eq!(
                lockdown,
                rules(&c).iter().any(|r| r["package_name"] == json!(["com.y"]) && r["server"] == "local"),
                "{ctx}"
            );
        }
        // Direct default: apps following it ask the filter, straight out.
        let d = Setup {
            default_route: DIRECT.into(),
            apps: pairs(&[("com.a", "us")]),
            prefs: Prefs { filter: Filter { direct: true, ..quad9.clone() }, ..Prefs::default() },
            ..example()
        };
        assert_eq!("dns-filter", compiled(&d)["dns"]["final"]);
        assert_eq!(
            "local",
            compiled(&Setup { prefs: Prefs { filter: quad9, ..Prefs::default() }, ..d })["dns"]["final"]
        );
        // NextDNS needs a profile; an own server by name is looked up first, through the same tunnel.
        assert_eq!(None, Filter { id: Some("nextdns".into()), ..Filter::default() }.server());
        assert_eq!(
            Some("/abc123".to_string()),
            Filter { id: Some("nextdns".into()), value: "abc123".into(), ..Filter::default() }
                .server()
                .and_then(|d| d.path)
        );
        let own = compiled(&with(Filter {
            id: Some(OWN.into()),
            value: "tls://dns.example.org".into(),
            routes: true,
            ..Filter::default()
        }));
        assert_eq!("tls", dns_server(&own, "dns-r-nl")["type"]);
        assert_eq!("boot-r-nl", dns_server(&own, "dns-r-nl")["domain_resolver"]);
        let boots = servers(&own).iter().filter(|s| s["tag"].as_str().unwrap().starts_with("boot-")).count();
        assert_eq!(
            boots,
            servers(&own).iter().filter_map(|s| s["domain_resolver"].as_str()).collect::<HashSet<_>>().len()
        );
        assert_eq!(853, dns_server(&own, "dns-r-nl")["server_port"]);
        assert_eq!(NORD_TP, dns_server(&own, "boot-r-nl")["server"]);
        assert_eq!("r-nl", dns_server(&own, "boot-r-nl")["detour"]);
        for bad in [
            "http://x.org",
            "https://x.org:99999/q",
            "tls://x.org/path",
            "dns.example.org",
            "1.2.3",
            "https://a b",
            "https://x.org/q%",
            "https://x.org/q%GG",
        ] {
            assert_eq!(None, own_dns(bad), "{bad}");
        }
        assert_eq!(Some("/a%2Fb".to_string()), own_dns("https://x.org/a%2Fb").and_then(|d| d.path));
        // An older custom DNS server becomes this filter on VPN routes, the same resolver as before.
        assert_eq!(
            Filter { id: Some(OWN.into()), value: "1.1.1.1".into(), routes: true, ..Filter::default() },
            Setup { prefs: Prefs { custom_dns: strs(&["1.1.1.1"]), ..Prefs::default() }, ..example() }
                .migrated()
                .prefs
                .filter
        );
    }

    #[test]
    fn lockdown_routes_direct_apps_instead_of_excluding() {
        let c = json(&Input { lockdown: true, ..input(&example()) });
        assert_eq!(json!(["app.unbraid"]), excluded(&c));
        assert!(rules(&c).iter().any(|r| r["outbound"] == "direct" && r.get("package_name").is_some()));
    }

    /// Home subnets are used as the system reads them (host bits cleared), so the LAN exclusion never cancels one; bad ones go.
    #[test]
    fn home_subnets_are_canonical() {
        assert_eq!(Some("192.168.0.0/16".to_string()), canonical("192.168.1.0/16"));
        assert_eq!(Some("10.0.0.0/8".to_string()), canonical("10.42.1.9/8"));
        assert_eq!(Some("10.1.2.3/32".to_string()), canonical("10.1.2.3"));
        for bad in ["10.0.0.1/33", "1.2.3", "1.2.3.4.5", "256.1.1.1/8", "a.b.c.d", "10.0.0.0/8/8", " ", "１.2.3.4"] {
            assert_eq!(None, canonical(bad), "{bad}");
        }
        let s = Setup {
            home: Home {
                tailscale: true,
                subnets: strs(&["192.168.1.0/16", "192.168.0.0/16", "10.0.0.1/33", "8.8.8.0/24"]),
                ..Home::default()
            },
            ..example()
        };
        let c = compiled(&s);
        let tun = &c["inbounds"][0];
        assert_eq!(json!(["0.0.0.0/0", "192.168.0.0/16"]), tun["route_address"]);
        assert!(!has(&tun["route_exclude_address"], "192.168.0.0/16"));
        assert_eq!(
            json!(["100.64.0.0/10", "192.168.0.0/16"]),
            rules(&c).iter().find(|r| r["outbound"] == "home-ts").unwrap()["ip_cidr"]
        );
        // A home WireGuard tunnel's ranges too, and its interface's own subnet when it lists no private ranges.
        let fritz = wg_conf::parse(FRITZ, "Home").unwrap();
        let wg = compiled(&Setup {
            home: Home {
                wg: Some(WgPeer { allowed_ips: strs(&["192.168.1.0/16", "10.0.0.1/33"]), ..fritz.clone() }),
                ..Home::default()
            },
            ..example()
        });
        assert_eq!(
            json!(["192.168.0.0/16"]),
            rules(&wg).iter().find(|r| r["outbound"] == "home-wg").unwrap()["ip_cidr"]
        );
        let wg_tun = &wg["inbounds"][0];
        assert!(has(&wg_tun["route_address"], "192.168.0.0/16"));
        assert!(!has(&wg_tun["route_exclude_address"], "192.168.0.0/16"));
        assert_eq!(
            strs(&["10.7.0.0/24"]),
            home_cidrs(&WgPeer {
                allowed_ips: strs(&["0.0.0.0/0"]),
                address: strs(&["10.7.0.5/24", "bad", "1.2.3.4/33"]),
                ..fritz.clone()
            })
        );
        assert_eq!(
            strs(&["192.168.1.0/24"]),
            home_cidrs(&WgPeer { allowed_ips: strs(&["010.0.0.0/8", "192.168.1.9/24"]), ..fritz })
        );
    }

    /// A Headscale host is an address only when it truly is one: a name that starts with a digit stays a name.
    #[test]
    fn control_host_address_or_name() {
        let login = |url: &str| -> Value {
            let s = plus(
                Setup { home: Home { ts_control_url: Some(url.into()), ..Home::default() }, ..example() },
                vec![ts_route("ts", "100.101.102.103", 4)],
                &[("com.n", "ts")],
            );
            let c = json(&Input { ts_login_pending: true, ..input(&s) });
            rules(&c)
                .iter()
                .find(|r| {
                    r["package_name"] == json!(["com.n"])
                        && r["outbound"] == "direct"
                        && (r.get("domain").is_some() || r.get("ip_cidr").is_some())
                })
                .unwrap()
                .clone()
        };
        assert_eq!(json!(["1hs.example.com"]), login("https://1hs.example.com")["domain"]);
        assert_eq!(json!(["10.1.2.3/32"]), login("https://10.1.2.3:8443")["ip_cidr"]);
        assert_eq!(json!(["010.1.2.3"]), login("https://010.1.2.3")["domain"]);
        assert_eq!(json!(["fd7a:115c::1/128"]), login("https://[fd7a:115c::1]")["ip_cidr"]);
    }

    /// Connections a VPN server or tailnet peer opens are refused first; only the computer's apps get DNS answered.
    #[test]
    fn tunnels_never_open_connections_into_the_phone() {
        let home =
            Setup { home: Home { wg: Some(wg_conf::parse(FRITZ, "Home").unwrap()), ..example().home }, ..example() };
        let c = compiled(&home);
        let first = &rules(&c)[0];
        assert_eq!("reject", first["action"]);
        assert_eq!(
            endpoint_tags(&c).into_iter().collect::<HashSet<_>>(),
            strings(&first["inbound"]).into_iter().collect::<HashSet<_>>()
        );
        assert_eq!(
            HashSet::from(["inbound", "action"]),
            first.as_object().unwrap().keys().map(String::as_str).collect::<HashSet<_>>()
        ); // every protocol, TCP and UDP alike
        let hijacks: Vec<&Value> = rules(&c).iter().filter(|r| r["action"] == "hijack-dns").collect();
        assert_eq!(2, hijacks.len());
        hijacks.iter().for_each(|r| assert_eq!(json!(["tun"]), r["inbound"]));
        let empty = Setup { routes: vec![], default_route: DIRECT.into(), ..Setup::default() };
        assert!(
            rules(&json(&Input { links: IndexMap::new(), ..input(&empty) }))
                .iter()
                .all(|r| !(r["action"] == "reject" && r.get("inbound").is_some()))
        );
        // WireGuard, two OpenVPN routes sharing one endpoint and Shadowsocks, with the probe: every endpoint once, no outbound or probe.
        let ss = SsProfile {
            name: "s".into(),
            server: "h.example".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "pw".into(),
            plugin: None,
            plugin_opts: None,
        };
        let mixed = plus(
            example(),
            vec![
                ovpn_route("o1", "u"),
                ovpn_route("o2", "u"),
                Route { ss: Some(ss.clone()), ..Route::new("s", Location::default()) },
            ],
            &[("com.o1", "o1"), ("com.o2", "o2"), ("com.s", "s")],
        );
        let mut l = links(&mixed);
        for id in ["o1", "o2"] {
            l.insert(
                id.into(),
                Link::Ovpn { server: sv(id), profile: mixed.route(Some(id)).unwrap().ovpn.clone().unwrap() },
            );
        }
        l.insert("s".into(), Link::Ss { server: sv("s"), profile: ss });
        let c = json(&Input { links: l, probe: Some((40000, "pw".into())), ..input(&mixed) });
        let refused = strings(&rules(&c)[0]["inbound"]);
        assert_eq!(endpoint_tags(&c), refused);
        assert_eq!(strs(&["r-nl", "r-us", "r-it", "r-o1", "home-ts"]), refused);
    }

    /// A route without a tunnel refuses its apps' connections and lookups; the other routes keep running.
    #[test]
    fn a_blocked_route_refuses_its_apps_only() {
        for lockdown in [false, true] {
            let c = with_blocked(&example(), lockdown, &["us"]);
            assert_eq!(strs(&["r-nl", "r-it", "home-ts"]), endpoint_tags(&c));
            assert!(!c.to_string().contains("r-us"));
            assert_eq!("reject", single(rules(&c), |r| r["package_name"] == json!(["com.a"]))["action"]);
            assert_eq!("reject", single(dns_rules(&c), |r| r["package_name"] == json!(["com.a"]))["action"]);
            assert!(rules(&c).iter().any(|r| r["outbound"] == "r-it"));
            assert_eq!("r-nl", c["route"]["final"]);
        }
    }

    /// A blocked default refuses everything not sent elsewhere, after the home and LAN rules, and never resolves it locally.
    #[test]
    fn a_blocked_default_refuses_the_rest() {
        for lockdown in [false, true] {
            let c = with_blocked(&example(), lockdown, &["nl"]);
            let rules = rules(&c);
            assert_eq!(&json!({"action": "reject", "no_drop": true}), rules.last().unwrap());
            assert!(rules.iter().position(|r| r["outbound"] == "home-ts").is_none_or(|i| i < rules.len() - 1));
            assert!(rules.iter().any(|r| r["outbound"] == "r-us") && rules.iter().any(|r| r["outbound"] == "r-it"));
            assert_eq!(lockdown, rules.iter().any(|r| r["outbound"] == "direct" && r.get("package_name").is_some()));
            assert_eq!("reject", dns_rules(&c).last().unwrap()["action"]);
            assert!(!c.to_string().contains("r-nl"));
            assert_eq!("direct", c["route"]["final"]);
        }
    }

    #[test]
    fn unused_routes_do_not_connect() {
        let c = compiled(&Setup { apps: pairs(&[("com.a", "us")]), ..example() });
        assert_eq!(strs(&["r-nl", "r-us", "home-ts"]), endpoint_tags(&c));
    }

    #[test]
    fn direct_default_tunnels_only_assigned_apps() {
        let c = compiled(&Setup { default_route: DIRECT.into(), home: Home::default(), ..example() });
        assert_eq!("direct", c["route"]["final"]);
        assert_eq!(strs(&["r-us", "r-it"]), endpoint_tags(&c));
    }

    #[test]
    fn nothing_active_is_all_direct() {
        let s = Setup { routes: vec![], default_route: DIRECT.into(), ..Setup::default() };
        assert!(json(&Input { links: IndexMap::new(), ..input(&s) })["endpoints"].as_array().unwrap().is_empty());
    }

    #[test]
    fn threat_protection_and_custom_dns() {
        let dns_of = |s: &Setup| dns_server(&compiled(s), "dns-r-nl")["server"].as_str().unwrap().to_string();
        assert_eq!(NORD_TP, dns_of(&example()));
        assert_eq!(NORD_DNS, dns_of(&Setup { opts: opts("nord", PROTECT, "off"), ..example() }));
        // A save from before the move keeps the user's choice, now on NordVPN's page.
        let old = Setup { prefs: Prefs { threat_protection: false, ..Prefs::default() }, ..example() }.migrated();
        assert_eq!(Some("off".to_string()), old.opt("nord", PROTECT));
        assert_eq!(NORD_DNS, dns_of(&old));
        assert_eq!(old, old.migrated());
        // A NordVPN route that kept another provider's blocking flag follows the NordVPN page, as it did; new setups aren't migrated.
        let kept = with_route(
            &Setup { prefs: Prefs { threat_protection: false, ..Prefs::default() }, ..example() },
            "nl",
            |r| Route { filter: Some(true), ..r },
        )
        .migrated();
        assert_eq!(NORD_DNS, dns_of(&kept));
        let fresh = with_route(&Setup { version: VERSION, ..example() }, "nl", |r| Route { filter: Some(false), ..r });
        assert_eq!(fresh, fresh.migrated());
        // One route can turn it off for itself.
        assert_eq!(NORD_DNS, dns_of(&with_route(&example(), "nl", |r| Route { filter: Some(false), ..r })));
        assert_eq!(
            "9.9.9.9",
            dns_of(
                &Setup { prefs: Prefs { custom_dns: strs(&["9.9.9.9"]), ..Prefs::default() }, ..example() }.migrated()
            )
        );
    }

    #[test]
    fn lan_bypasses_the_tunnel_but_home_subnets_stay_routed() {
        let c = compiled(&example());
        let tun = &c["inbounds"][0];
        assert!(has(&tun["route_exclude_address"], "192.168.0.0/16"));
        assert!(has(&tun["route_address"], "192.168.178.0/24"));
        assert!(
            compiled(&Setup { prefs: Prefs { lan: false, ..Prefs::default() }, ..example() })["inbounds"][0]
                .get("route_exclude_address")
                .is_none()
        );
    }

    #[test]
    fn lockdown_keeps_lan_inside_the_tunnel() {
        assert!(
            json(&Input { lockdown: true, ..input(&example()) })["inbounds"][0].get("route_exclude_address").is_none()
        );
    }

    /// With a Tailscale exit carrying traffic, its login must not ride that exit; otherwise those sites follow each app.
    #[test]
    fn tailscale_login_goes_direct_only_with_an_exit_node() {
        let login_rule = |r: &Value| r.get("domain_suffix").is_some_and(|d| d.to_string().contains("tailscale.com"));
        let direct = |s: &Setup, login: bool| {
            rules(&json(&Input { ts_login_pending: login, ..input(s) })).iter().find(|r| login_rule(r)).cloned()
        };
        assert_eq!(None, direct(&example(), true));
        let with_exit = plus(example(), vec![ts_route("ts", "100.101.102.103", 4)], &[("com.n", "ts")]);
        // Only while a sign-in waits: once signed in, tailscale.com follows the app's exit like any site.
        assert_eq!(None, direct(&with_exit, false));
        // A Headscale tailnet signs in on its own server: Tailscale's sites never skip the exit.
        assert_eq!(
            None,
            direct(
                &Setup {
                    home: Home { ts_control_url: Some("https://hs.example.org".into()), ..with_exit.home.clone() },
                    ..with_exit.clone()
                },
                true
            )
        );
        let d = direct(&with_exit, true).unwrap();
        assert_eq!("direct", d["outbound"]);
        // Only for the apps on that exit: a browser on another VPN keeps its own exit for tailscale.com.
        assert_eq!(r#"["com.n"]"#, d["package_name"].to_string());
        let c = json(&Input { ts_login_pending: true, ..input(&with_exit) });
        let rs = rules(&c);
        assert_eq!(1, rs.iter().filter(|r| login_rule(r)).count());
        // Ahead of that app's resolve through the exit, which can't answer before the exit node is signed in.
        assert!(
            rs.iter().position(|r| *r == d).unwrap()
                < rs.iter().position(|r| r["package_name"] == json!(["com.n"]) && r["action"] == "resolve").unwrap()
        );
    }

    /// Ping has no owner to route by: with Direct as the default it would leave a VPN app from the computer's address.
    #[test]
    fn ping_is_refused_when_it_would_bypass_an_apps_vpn() {
        let icmp = |s: &Setup| -> Vec<Value> {
            rules(&compiled(s)).iter().filter(|r| r["network"] == "icmp").cloned().collect()
        };
        assert!(icmp(&example()).is_empty());
        let direct_default = Setup { default_route: DIRECT.into(), ..example() };
        assert_eq!("reject", single(&icmp(&direct_default), |_| true)["action"]);
        // LAN and home rules come first, so pinging the router or a home box still works.
        let c = compiled(&direct_default);
        let rs = rules(&c);
        assert!(
            rs.iter().position(|r| r["network"] == "icmp").unwrap()
                > rs.iter().position(|r| r.get("ip_cidr").is_some()).unwrap()
        );
        assert!(icmp(&Setup { apps: pairs(&[("com.x", DIRECT)]), ..direct_default }).is_empty());
    }

    /// Over plain HTTP the Headscale key exchange could be faked, so such a control URL is refused, not used.
    #[test]
    fn headscale_needs_https() {
        let with = |url: &str| Setup {
            home: Home { tailscale: true, ts_control_url: Some(url.into()), ..example().home },
            ..example()
        };
        assert!(compiled(&with("https://hs.example.com")).to_string().contains("https://hs.example.com"));
        assert!(matches!(compile(&input(&with("http://hs.example.com"))), Err(Error::Invalid(_))));
    }

    /// Apps test "online?" with a TCP connect to 8.8.8.8:53; a hijacked TCP flow never completes, so only UDP is hijacked.
    #[test]
    fn only_udp_dns_is_hijacked_so_tcp_port_53_connects() {
        let c = compiled(&example());
        let by_port: Vec<&Value> = rules(&c).iter().filter(|r| r["port"] == 53).collect();
        assert_eq!(1, by_port.len());
        assert_eq!("udp", by_port[0]["network"]);
        assert_eq!("hijack-dns", by_port[0]["action"]);
    }

    /// A route asking for its provider's blocking resolver uses it; a custom DNS still wins.
    #[test]
    fn provider_blocking_dns_per_route() {
        let dns = |s: &Setup, id: &str| {
            dns_server(&compiled(s), &format!("dns-r-{id}"))["server"].as_str().unwrap().to_string()
        };
        let ex = example();
        let r = ex.routes.iter().find(|r| r.id != ex.default_route).unwrap().id.clone();
        // Each provider's blocking resolver while on for the route or its provider page; a custom DNS server replaces it (the choice is kept for later).
        for (provider, blocking) in [("mullvad", "100.64.0.7"), ("pia", "10.0.0.244"), ("ivpn", "10.0.254.2")] {
            let moved =
                with_route(&ex, &r, |x| Route { loc: Location { provider: provider.into(), ..x.loc.clone() }, ..x });
            let on = with_route(&moved, &r, |x| Route { filter: Some(true), ..x });
            assert_eq!(blocking, dns(&on, &r), "{provider}");
            assert_eq!(
                blocking,
                dns(&Setup { opts: opts(provider, PROTECT, "on"), ..moved.clone() }, &r),
                "{provider}"
            );
            assert_ne!(blocking, dns(&moved, &r), "{provider}");
            let own = Filter { id: Some(OWN.into()), value: "1.1.1.1".into(), routes: true, ..Filter::default() };
            assert_eq!(
                "1.1.1.1",
                dns(&Setup { prefs: Prefs { filter: own, ..on.prefs.clone() }, ..on.clone() }, &r),
                "{provider}"
            );
            assert_eq!(Some(true), on.route(Some(&r)).unwrap().filter, "{provider}");
        }
    }

    #[test]
    fn lan_off_removes_direct_lan_rule() {
        assert!(
            !rules(&compiled(&Setup { prefs: Prefs { lan: false, ..Prefs::default() }, ..example() }))
                .iter()
                .any(|r| r["outbound"] == "direct" && r.get("ip_cidr").is_some())
        );
    }

    #[test]
    fn custom_wire_guard_route() {
        let peer = wg_conf::parse(FRITZ, "Home box").unwrap();
        let s = plus(
            example(),
            vec![Route { wg: Some(peer), hue: 3, ..Route::new("w1", Location::default()) }],
            &[("com.c", "w1")],
        );
        let c = compiled(&s);
        let ep = c["endpoints"].as_array().unwrap().iter().find(|e| e["tag"] == "r-w1").unwrap();
        assert_eq!("abc.myfritz.net", ep["peers"][0]["address"]);
        assert_eq!(51820, ep["peers"][0]["port"]);
    }

    #[test]
    fn tailscale_exit_route_rides_the_tailscale_endpoint() {
        let s = plus(Setup { home: Home::default(), ..example() }, vec![ts_route("ts", "nas", 4)], &[("com.n", "ts")]);
        let c = compiled(&s);
        assert_eq!("nas", single(c["endpoints"].as_array().unwrap(), |e| e["type"] == "tailscale")["exit_node"]);
        assert!(rules(&c).iter().any(|r| r["outbound"] == "home-ts" && has(&r["package_name"], "com.n")));
        assert!(!endpoint_tags(&c).contains(&"r-ts".to_string()));
    }

    /// Keeping an exit alive must not grant every app the separately controlled home access.
    #[test]
    fn tailnet_access_toggle_is_independent_of_an_active_exit() {
        let subnets = strs(&["192.168.0.0/16", "10.42.0.0/16"]);
        for home_access in [false, true] {
            for default in [DIRECT, "nl", "ts"] {
                for lan in [false, true] {
                    for lockdown in [false, true] {
                        let base = Setup {
                            home: Home { tailscale: home_access, subnets: subnets.clone(), ..Home::default() },
                            default_route: default.into(),
                            prefs: Prefs { lan, ..example().prefs },
                            ..example()
                        };
                        let s = plus(base, vec![ts_route("ts", "100.101.102.103", 4)], &[("com.n", "ts")]);
                        let c = json(&Input { lockdown, ts_suffix: Some("tail1234.ts.net".into()), ..input(&s) });
                        let ctx = format!("home={home_access} default={default} lan={lan} lockdown={lockdown}");
                        let home_rules: Vec<&Value> = rules(&c)
                            .iter()
                            .filter(|r| r["outbound"] == "home-ts" && r.get("ip_cidr").is_some())
                            .collect();
                        assert_eq!(home_access, !home_rules.is_empty(), "{ctx}");
                        let all = [strs(&["100.64.0.0/10"]), subnets.clone()].concat();
                        home_rules.iter().for_each(|r| assert_eq!(json!(all), r["ip_cidr"], "{ctx}"));
                        let tailnet_dns: Vec<&Value> =
                            dns_rules(&c).iter().filter(|r| r["server"] == "dns-tailnet").collect();
                        assert_eq!(home_access, !tailnet_dns.is_empty(), "{ctx}");
                        if home_access {
                            assert_eq!(
                                json!(["ts.net", "tail1234.ts.net"]),
                                single(&tailnet_dns.into_iter().cloned().collect::<Vec<_>>(), |_| true)["domain_suffix"]
                            );
                        }
                        assert_eq!(home_access, servers(&c).iter().any(|s| s["tag"] == "dns-tailnet"), "{ctx}");
                        let tun = &c["inbounds"][0];
                        if lan && !lockdown {
                            let routed =
                                [strs(&["0.0.0.0/0"]), if home_access { subnets.clone() } else { vec![] }].concat();
                            assert_eq!(json!(routed), tun["route_address"], "{ctx}");
                            assert_eq!(!home_access, has(&tun["route_exclude_address"], "192.168.0.0/16"), "{ctx}");
                        }
                        assert_eq!(
                            "100.101.102.103",
                            single(c["endpoints"].as_array().unwrap(), |e| e["type"] == "tailscale")["exit_node"],
                            "{ctx}"
                        );
                        assert_eq!("home-ts", dns_server(&c, "dns-r-ts")["detour"], "{ctx}");
                        let want = match default {
                            DIRECT => "direct",
                            "ts" => "home-ts",
                            _ => "r-nl",
                        };
                        assert_eq!(want, c["route"]["final"], "{ctx}");
                        if default != "ts" {
                            assert!(
                                rules(&c)
                                    .iter()
                                    .any(|r| r["outbound"] == "home-ts" && has(&r["package_name"], "com.n")),
                                "{ctx}"
                            );
                        }
                        assert!(
                            rules(&c).iter().any(|r| r["outbound"] == "r-us" && has(&r["package_name"], "com.a")),
                            "{ctx}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn disabling_tailnet_access_preserves_the_separate_home_wire_guard_tunnel() {
        let base = Setup {
            home: Home {
                subnets: strs(&["10.42.0.0/16"]),
                wg: Some(wg_conf::parse(FRITZ, "Home").unwrap()),
                ..Home::default()
            },
            ..example()
        };
        let c = compiled(&plus(base, vec![ts_route("ts", "100.101.102.103", 4)], &[("com.n", "ts")]));
        assert!(rules(&c).iter().any(|r| r["outbound"] == "home-wg" && has(&r["ip_cidr"], "192.168.178.0/24")));
        assert_eq!(json!(["0.0.0.0/0", "192.168.178.0/24"]), c["inbounds"][0]["route_address"]);
    }

    #[test]
    fn nord_open_vpn_keeps_nord_dns_while_other_open_vpn_uses_pushed_dns() {
        let p = parse_ovpn(&fixture("nord-double.udp.ovpn"), "dv", "u", "p").unwrap();
        let japan = Location {
            provider: "expressvpn".into(),
            country_code: Some("JP".into()),
            country: Some("Japan".into()),
            ..Location::default()
        };
        let s = Setup {
            home: Home::default(),
            routes: vec![nl(), Route::new("ex", japan)],
            apps: pairs(&[("com.e", "ex")]),
            ..example()
        };
        let l = IndexMap::from([
            ("nl".to_string(), Link::Ovpn { server: sv("nl"), profile: p.clone() }),
            (
                "ex".to_string(),
                Link::Ovpn { server: sv("exx"), profile: OvpnProfile { username: "other".into(), ..p } },
            ),
        ]);
        let c = json(&Input { links: l, ..input(&s) });
        assert_eq!("udp", dns_server(&c, "dns-r-nl")["type"]);
        assert_eq!("openvpn", dns_server(&c, "dns-ovpn-r-ex")["type"]);
    }

    /// A NordVPN OpenVPN route (Nord's DNS) and an import of the same profile share a tunnel, in either order.
    #[test]
    fn nord_and_import_sharing_one_open_vpn_tunnel_keep_pushed_dns() {
        let p = parse_ovpn(&fixture("nord-double.udp.ovpn"), "dv", "u", "p").unwrap();
        let imp = Route { ovpn: Some(p.clone()), hue: 1, ..Route::new("im", Location::default()) };
        for order in [vec![nl(), imp.clone()], vec![imp.clone(), nl()]] {
            for custom in [None, Some("1.1.1.1")] {
                let filter = custom.map_or_else(Filter::default, |c| Filter {
                    id: Some(OWN.into()),
                    value: c.into(),
                    routes: true,
                    ..Filter::default()
                });
                let s = Setup {
                    default_route: order[0].id.clone(),
                    apps: pairs(&[("com.x", &order[1].id)]),
                    prefs: Prefs { filter, ..Prefs::default() },
                    routes: order.clone(),
                    ..Setup::default()
                };
                let l = IndexMap::from([
                    ("nl".to_string(), Link::Ovpn { server: sv("nl"), profile: p.clone() }),
                    ("im".to_string(), Link::Ovpn { server: sv("im"), profile: p.clone() }),
                ]);
                let c = json(&Input { links: l, probe: Some((40000, "pw".into())), ..input(&s) });
                let ctx = format!("order={:?} custom={custom:?}", order.iter().map(|r| &r.id).collect::<Vec<_>>());
                let ep = single(c["endpoints"].as_array().unwrap(), |_| true);
                let ovpn: Vec<&Value> = servers(&c).iter().filter(|s| s["type"] == "openvpn").collect();
                if custom.is_none() {
                    // The import uses the pushed DNS: one server for the tunnel, which keeps it whichever route owns the tunnel.
                    assert_eq!(vec![&ep["tag"]], ovpn.iter().map(|s| &s["endpoint"]).collect::<Vec<_>>(), "{ctx}");
                    assert!(ep.get("route_no_pull").is_none(), "{ctx}");
                } else {
                    assert!(ovpn.is_empty(), "{ctx}");
                    assert_eq!(true, ep["route_no_pull"], "{ctx}");
                }
                // Nord's route keeps Nord's resolver through the tunnel either way.
                assert_eq!(
                    if custom.is_none() { NORD_TP } else { "1.1.1.1" },
                    dns_server(&c, "dns-r-nl")["server"],
                    "{ctx}"
                );
                let tags: HashSet<&str> = servers(&c).iter().map(|s| s["tag"].as_str().unwrap()).collect();
                assert!(
                    dns_rules(&c)
                        .iter()
                        .chain(rules(&c))
                        .filter_map(|r| r["server"].as_str())
                        .all(|u| tags.contains(u)),
                    "{ctx}"
                );
            }
        }
    }

    #[test]
    fn home_tunnel_never_catches_all() {
        let full = wg_conf::parse(&FRITZ.replace("192.168.178.0/24, ", ""), "Home").unwrap(); // AllowedIPs = 0.0.0.0/0 only
        assert_eq!(strs(&["192.168.178.0/24"]), home_cidrs(&full));
        let c = compiled(&Setup { home: Home { wg: Some(full), ..Home::default() }, ..example() });
        for r in rules(&c).iter().filter(|r| r["outbound"] == "home-wg") {
            assert!(!strings(&r["ip_cidr"]).iter().any(|x| x.ends_with("/0")));
        }
    }

    #[test]
    fn home_tunnel_ignores_public_ranges() {
        let evil = wg_conf::parse(
            &FRITZ.replace("192.168.178.0/24, 0.0.0.0/0, ::/0", "0.0.0.0/1, 128.0.0.0/1, 10.9.0.0/16"),
            "Home",
        )
        .unwrap();
        assert_eq!(strs(&["10.9.0.0/16"]), home_cidrs(&evil));
        assert!(is_private("192.168.178.0/24") && is_private("100.100.1.0/24"));
        assert!(!(is_private("0.0.0.0/1") || is_private("8.8.8.0/24") || is_private("10.0.0.0/7")));
    }

    #[test]
    fn public_box_tld_is_not_local() {
        assert!(!dns_rules(&compiled(&example())).iter().any(|r| has(&r["domain_suffix"], "box")));
    }

    #[test]
    fn wg_conf_with_two_peers_is_rejected() {
        let two = format!("{FRITZ}\n[Peer]\nPublicKey = {PUB}\nEndpoint = x:1\nAllowedIPs = 10.0.0.0/8\n");
        assert!(matches!(wg_conf::parse(&two, "x"), Err(Error::Invalid(_))));
    }

    #[test]
    fn wg_conf_with_bad_key_is_rejected() {
        assert!(matches!(
            wg_conf::parse(&FRITZ.replace(&format!("PrivateKey = {KEY}"), "PrivateKey = nope"), "x"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn wg_conf_without_ipv4_allowed_ips_is_rejected() {
        assert!(matches!(
            wg_conf::parse(&FRITZ.replace("AllowedIPs = 192.168.178.0/24, 0.0.0.0/0, ::/0", "AllowedIPs = ::/0"), "x"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn non_address_dns_follows_the_apps_exit() {
        let c = compiled(&Setup { default_route: DIRECT.into(), ..example() });
        assert_eq!("dns-r-us", dns_rules(&c).iter().find(|r| r["package_name"] == json!(["com.a"])).unwrap()["server"]);
    }

    #[test]
    fn home_and_lan_rules_follow_every_resolve() {
        let c = compiled(&example());
        let rs = rules(&c);
        for (i, _) in rs.iter().enumerate().filter(|(_, r)| r["action"] == "resolve") {
            assert_eq!("home-ts", rs[i + 1]["outbound"]);
        }
    }

    #[test]
    fn wg_conf_parses_fritz_export() {
        let p = wg_conf::parse(FRITZ, "Home").unwrap();
        assert_eq!(strs(&["192.168.178.201/24"]), p.address);
        assert_eq!(strs(&["192.168.178.0/24", "0.0.0.0/0"]), p.allowed_ips);
        assert_eq!(strs(&["192.168.178.1"]), p.dns);
        assert_eq!("abc.myfritz.net:51820", p.endpoint);
    }

    #[test]
    fn parses_nord_recommendations() {
        let s = parse_servers(&fixture("recommendations.json"), true).unwrap();
        assert_eq!(1, s.len());
        assert!(Regex::new(r"^nl\d+\.nordvpn\.com$").unwrap().is_match(&s[0].host), "{}", s[0].host);
        assert_eq!("Amsterdam", s[0].city);
        assert_eq!(44, s[0].public_key.len());
    }

    // ---- shared tunnels ----

    fn nl1() -> Location {
        Location::country("nord", 1, "NL", "Netherlands")
    }

    /// Two NordVPN routes, the second for com.b, on the given tunnels.
    fn two(second: Link) -> Value {
        let s = Setup {
            routes: vec![route("a", nl1(), 0), route("b", Location::country("nord", 2, "DE", "Germany"), 1)],
            default_route: "a".into(),
            apps: pairs(&[("com.b", "b")]),
            ..Setup::default()
        };
        json(&Input {
            links: IndexMap::from([
                ("a".to_string(), wg_link(sv("a"), nord::peer(&sv("a"), KEY))),
                ("b".to_string(), second),
            ]),
            ..input(&s)
        })
    }

    #[test]
    fn same_server_and_key_share_one_endpoint() {
        let c = two(wg_link(sv("a"), nord::peer(&sv("a"), KEY)));
        assert_eq!(strs(&["r-a"]), endpoint_tags(&c));
        assert!(rules(&c).iter().any(|r| r["outbound"] == "r-a" && has(&r["package_name"], "com.b")));
        assert!(!c.to_string().contains("\"r-b\""));
        assert_eq!("r-a", dns_server(&c, "dns-r-b")["detour"]);
    }

    #[test]
    fn different_key_or_server_is_not_shared() {
        assert_eq!(strs(&["r-a", "r-b"]), endpoint_tags(&two(wg_link(sv("a"), nord::peer(&sv("a"), PUB)))));
        assert_eq!(strs(&["r-a", "r-b"]), endpoint_tags(&two(wg_link(sv("b"), nord::peer(&sv("b"), KEY)))));
    }

    /// Sharing follows what the engine's WireGuard device is built from, never the provider label.
    #[test]
    fn wire_guard_sharing_follows_the_real_settings() {
        let peer = nord::peer(&sv("a"), KEY);
        let imported =
            Route { wg: Some(WgPeer { name: "mine".into(), ..peer.clone() }), ..Route::new("b", Location::default()) };
        let tags = |second: &WgPeer| -> Result<Vec<String>> {
            let s = Setup {
                routes: vec![route("a", nl1(), 0), imported.clone()],
                default_route: "a".into(),
                apps: pairs(&[("com.b", "b")]),
                ..Setup::default()
            };
            let i = Input {
                links: IndexMap::from([
                    ("a".to_string(), wg_link(sv("a"), peer.clone())),
                    ("b".to_string(), wg_link(sv("a"), second.clone())),
                ]),
                ..input(&s)
            };
            compile(&i).map(|out| {
                keep("compiled", &out);
                endpoint_tags(&serde_json::from_str(&out).unwrap())
            })
        };
        // A provider route and an import of the same config share one tunnel.
        assert_eq!(strs(&["r-a"]), tags(&peer).unwrap());
        // Another server or another client key is another tunnel.
        assert_eq!(strs(&["r-a", "r-b"]), tags(&WgPeer { endpoint: "10.9.9.9:51820".into(), ..peer.clone() }).unwrap());
        assert_eq!(strs(&["r-a", "r-b"]), tags(&WgPeer { private_key: PUB.into(), ..peer.clone() }).unwrap());
        // The same key on the same server with another preshared key, addresses (also their order) or MTU clashes;
        // the compiler refuses it outright, and the link picker blocks such a route before it gets there.
        let two = WgPeer { address: strs(&["10.5.0.2/32", "10.6.0.2/32"]), ..peer.clone() };
        for other in [
            WgPeer { preshared_key: Some(KEY.into()), ..peer.clone() },
            WgPeer { address: strs(&["10.5.0.9/32"]), ..peer.clone() },
            WgPeer { mtu: 1200, ..peer.clone() },
        ] {
            match tags(&other) {
                Err(Error::Invalid(m)) => assert!(!m.contains(KEY)),
                r => panic!("ran two tunnels for one identity: {other:?} gave {r:?}"),
            }
        }
        let reversed = WgPeer { address: two.address.iter().rev().cloned().collect(), ..two.clone() };
        let s2 = Setup {
            routes: vec![
                Route { wg: Some(two.clone()), ..Route::new("a", Location::default()) },
                Route { wg: Some(reversed.clone()), hue: 1, ..Route::new("b", Location::default()) },
            ],
            default_route: "a".into(),
            apps: pairs(&[("com.b", "b")]),
            ..Setup::default()
        };
        assert_eq!(
            IndexSet::from(["b".to_string()]),
            clashes(
                &s2,
                &IndexMap::from([
                    ("a".to_string(), wg_link(sv("a"), two)),
                    ("b".to_string(), wg_link(sv("a"), reversed))
                ])
            )
        );
        // Nor as both a route and the home tunnel.
        let s = Setup {
            routes: vec![route("a", nl1(), 0)],
            default_route: "a".into(),
            home: Home { wg: Some(peer.clone()), ..Home::default() },
            ..Setup::default()
        };
        assert_eq!(
            IndexSet::from(["a".to_string()]),
            clashes(&s, &IndexMap::from([("a".to_string(), wg_link(sv("a"), peer))]))
        );
    }

    #[test]
    fn tunnel_mtu_comes_from_the_ported_peer_at_most_1420() {
        let peer = nord::peer(&sv("a"), KEY);
        let one = Setup { routes: vec![route("a", nl1(), 0)], default_route: "a".into(), ..Setup::default() };
        let mtu = |m: i32| {
            json(&Input {
                links: IndexMap::from([("a".to_string(), wg_link(sv("a"), WgPeer { mtu: m, ..peer.clone() }))]),
                ..input(&one)
            })["endpoints"][0]["mtu"]
                .clone()
        };
        assert_eq!(1400, mtu(1400));
        assert_eq!(1420, mtu(1500));
        let home = Setup {
            home: Home {
                wg: Some(WgPeer { endpoint: "10.1.1.1:51820".into(), mtu: 1420, ..peer.clone() }),
                ..Home::default()
            },
            ..one.clone()
        };
        let c = json(&Input { links: IndexMap::from([("a".to_string(), wg_link(sv("a"), peer))]), ..input(&home) });
        assert_eq!(1280, c["endpoints"].as_array().unwrap().iter().find(|e| e["tag"] == "home-wg").unwrap()["mtu"]);
    }

    fn ovpn_route(id: &str, user: &str) -> Route {
        Route {
            ovpn: Some(parse_ovpn(&fixture("expressvpn.ovpn"), id, user, "pw").unwrap()),
            ..Route::new(id, Location::default())
        }
    }

    #[test]
    fn same_open_vpn_remote_and_user_share_one_endpoint() {
        let s = Setup {
            routes: vec![ovpn_route("a", "u"), ovpn_route("b", "u"), ovpn_route("c", "other")],
            default_route: "a".into(),
            apps: pairs(&[("com.b", "b"), ("com.c", "c")]),
            ..Setup::default()
        };
        let l = s
            .routes
            .iter()
            .map(|r| (r.id.clone(), Link::Ovpn { server: sv(&r.id), profile: r.ovpn.clone().unwrap() }))
            .collect();
        let out = json(&Input { links: l, ..input(&s) });
        assert_eq!(strs(&["r-a", "r-c"]), endpoint_tags(&out));
        // One DNS server per tunnel, which the engine requires; every reference names one that exists.
        assert_eq!(
            vec![&json!("r-a"), &json!("r-c")],
            servers(&out).iter().filter(|x| x["type"] == "openvpn").map(|x| &x["endpoint"]).collect::<Vec<_>>()
        );
        let tags: HashSet<&str> = servers(&out).iter().map(|s| s["tag"].as_str().unwrap()).collect();
        let mut used: Vec<&str> =
            dns_rules(&out).iter().chain(rules(&out)).filter_map(|r| r["server"].as_str()).collect();
        used.push(out["dns"]["final"].as_str().unwrap());
        assert!(used.iter().all(|u| tags.contains(u)), "{used:?}");
        assert!(used.contains(&"dns-ovpn-r-a"));
    }

    #[test]
    fn shadowsocks_routes_with_other_plugin_options_are_not_shared() {
        let p = SsProfile {
            name: "a".into(),
            server: "h.example".into(),
            port: 8388,
            method: "aes-256-gcm".into(),
            password: "pw".into(),
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some("tls;host=a.example".into()),
        };
        let key = |q: &SsProfile| link_key(&Link::Ss { server: sv("a"), profile: q.clone() });
        assert_eq!(key(&p), key(&SsProfile { name: "b".into(), ..p.clone() }));
        assert_ne!(key(&p), key(&SsProfile { plugin_opts: Some("host=a.example".into()), ..p.clone() }));
        assert_ne!(key(&p), key(&SsProfile { plugin: None, plugin_opts: None, ..p.clone() }));
    }

    // ---- WireGuard keys ----

    #[test]
    fn malformed_wire_guard_keys_are_rejected_without_quoting_them() {
        let key_error = |f: &dyn Fn(WgPeer) -> WgPeer| -> String {
            let s = Setup { routes: vec![route("a", nl1(), 0)], default_route: "a".into(), ..Setup::default() };
            match compile(&Input {
                links: IndexMap::from([("a".to_string(), wg_link(sv("a"), f(nord::peer(&sv("a"), KEY))))]),
                ..input(&s)
            }) {
                Err(Error::Invalid(m)) => m,
                r => panic!("expected a rejection, got {r:?}"),
            }
        };
        let secret = "this-is-not-a-key-but-looks-like-one-0123456789";
        let msg = key_error(&|p| WgPeer { private_key: secret.into(), ..p });
        assert_eq!("Invalid WireGuard key for Netherlands", msg);
        assert!(!msg.contains(secret));
        key_error(&|p| WgPeer { public_key: "AAAA".into(), ..p });
        key_error(&|p| WgPeer { preshared_key: Some("c2hvcnQ=".into()), ..p });
        key_error(&|p| WgPeer { private_key: String::new(), ..p });
    }

    // ---- OpenVPN DNS ----

    fn ovpn_setup(prefs: Prefs) -> Setup {
        Setup { routes: vec![ovpn_route("x", "u")], default_route: "x".into(), prefs, ..Setup::default() }
    }

    fn ovpn_links(s: &Setup, ids: &[&str]) -> IndexMap<String, Link> {
        ids.iter()
            .map(|id| (id.to_string(), Link::Ovpn { server: sv("x"), profile: s.routes[0].ovpn.clone().unwrap() }))
            .collect()
    }

    #[test]
    fn open_vpn_routes_use_the_pushed_dns_but_ignore_pushed_routes() {
        let s = ovpn_setup(Prefs::default());
        let c = json(&Input { links: ovpn_links(&s, &["x"]), ..input(&s) });
        let dns = dns_server(&c, "dns-ovpn-r-x");
        assert_eq!("openvpn", dns["type"]);
        // A server that pushes no DNS is answered through the same tunnel, never not at all.
        assert_eq!("9.9.9.9", dns["fallback_server"]);
        assert_eq!("r-x", dns["endpoint"]);
        let ep = &c["endpoints"][0];
        assert!(ep.get("route_no_pull").is_none());
        let filters = ep["pull_filters"].as_array().unwrap();
        let ignored: Vec<&str> =
            filters.iter().filter(|f| f["action"] == "ignore").map(|f| f["text"].as_str().unwrap()).collect();
        assert!(["route ", "route-ipv6 ", "redirect-gateway"].iter().all(|t| ignored.contains(t)));
        // First match wins in the engine, so the app's ignores must come before any filter from the profile.
        assert_eq!(
            ("ignore", "route "),
            (filters[0]["action"].as_str().unwrap(), filters[0]["text"].as_str().unwrap())
        );
        assert!(!ignored.iter().any(|t| t.starts_with("dhcp-option") || t.starts_with("dns")));
    }

    /// An own filter server by name, on an imported OpenVPN route, is looked up with the DNS that tunnel pushes.
    #[test]
    fn own_filter_by_name_on_open_vpn_uses_pushed_dns() {
        let s = ovpn_setup(Prefs {
            filter: Filter {
                id: Some(OWN.into()),
                value: "tls://dns.internal.example".into(),
                routes: true,
                ..Filter::default()
            },
            ..Prefs::default()
        });
        let c = json(&Input { links: ovpn_links(&s, &["x"]), ..input(&s) });
        assert_eq!("openvpn", dns_server(&c, "boot-r-x")["type"]);
        // Two routes on that one tunnel share one lookup server: the engine allows one OpenVPN DNS server per endpoint.
        let two = Setup {
            routes: vec![s.routes[0].clone(), Route { id: "y".into(), ..s.routes[0].clone() }],
            apps: pairs(&[("com.y", "y")]),
            ..s.clone()
        };
        let c2 = json(&Input { links: ovpn_links(&s, &["x", "y"]), ..input(&two) });
        assert_eq!(1, servers(&c2).iter().filter(|x| x["type"] == "openvpn").count());
        assert_eq!("tls", dns_server(&c, "dns-r-x")["type"]);
        assert!(c["endpoints"][0].get("route_no_pull").is_none());
    }

    #[test]
    fn custom_dns_keeps_open_vpn_on_its_own_resolver_and_no_pull() {
        let s = ovpn_setup(Prefs {
            filter: Filter { id: Some(OWN.into()), value: "1.1.1.1".into(), routes: true, ..Filter::default() },
            ..Prefs::default()
        });
        let c = json(&Input { links: ovpn_links(&s, &["x"]), ..input(&s) });
        assert_eq!("udp", dns_server(&c, "dns-r-x")["type"]);
        assert_eq!(true, c["endpoints"][0]["route_no_pull"]);
    }

    // ---- tailnet DNS ----

    #[test]
    fn tailnet_suffix_is_routed_to_tailscale_dns() {
        let suffixes = |suffix: Option<&str>, home: &Home| -> Vec<String> {
            let c = json(&Input {
                ts_suffix: suffix.map(String::from),
                ..input(&Setup { home: home.clone(), ..example() })
            });
            dns_rules(&c)
                .iter()
                .find(|r| r["server"] == "dns-tailnet")
                .map(|r| strings(&r["domain_suffix"]))
                .unwrap_or_default()
        };
        let h = example().home;
        // Tailscale's own server: its ts.net names, never another domain it reports.
        assert_eq!(strs(&["ts.net"]), suffixes(None, &h));
        assert_eq!(strs(&["ts.net", "tail1234.ts.net"]), suffixes(Some("Tail1234.ts.net."), &h));
        let long = format!("{}.ts.net", "x".repeat(64));
        for bad in ["corp.example", "com", "co.uk", "ts.net", "bad\" domain", "-x.ts.net", "a..ts.net", &long] {
            assert_eq!(strs(&["ts.net"]), suffixes(Some(bad), &h), "{bad}");
        }
        // Headscale: no ts.net, and its suffix only once allowed (a switch in Settings), exactly that one.
        let hs = Home { ts_control_url: Some("https://hs.example.org".into()), ..h.clone() };
        let allowed = Home { ts_suffix_allowed: Some("corp.example".into()), ..hs.clone() };
        assert_eq!(Vec::<String>::new(), suffixes(Some("corp.example"), &hs));
        assert_eq!(strs(&["corp.example"]), suffixes(Some("corp.example"), &allowed));
        assert_eq!(Vec::<String>::new(), suffixes(Some("com"), &allowed));
        assert_eq!(
            strs(&["ts.net", "tail9.ts.net"]),
            suffixes(
                Some("tail9.ts.net"),
                &Home { ts_control_url: Some("https://controlplane.tailscale.com".into()), ..h }
            )
        );
    }

    #[test]
    fn tailscale_exit_node_takes_an_ip_and_keeps_its_name() {
        let nas = Route { ts_name: Some("nas".into()), ..ts_route("ts", "100.101.102.103", 4) };
        let s = plus(Setup { home: Home::default(), ..example() }, vec![nas], &[("com.n", "ts")]);
        let c = compiled(&s);
        assert_eq!(
            "100.101.102.103",
            single(c["endpoints"].as_array().unwrap(), |e| e["type"] == "tailscale")["exit_node"]
        );
        assert_eq!("nas", s.route(Some("ts")).unwrap().name());
    }

    /// A config's own PersistentKeepalive is kept (0 = none); without one, and for provider servers, 25 s.
    #[test]
    fn keepalive_follows_the_config() {
        let keepalive = |text: &str| {
            let c = compiled(&Setup {
                home: Home { wg: Some(wg_conf::parse(text, "Home").unwrap()), ..Home::default() },
                ..example()
            });
            c["endpoints"].as_array().unwrap().iter().find(|e| e["tag"] == "home-wg").unwrap()["peers"][0]["persistent_keepalive_interval"].clone()
        };
        assert_eq!(25, keepalive(FRITZ));
        assert_eq!(15, keepalive(&FRITZ.replace("PersistentKeepalive = 25", "PersistentKeepalive = 15")));
        assert_eq!(0, keepalive(&FRITZ.replace("PersistentKeepalive = 25", "PersistentKeepalive = off")));
        assert_eq!(25, keepalive(&FRITZ.replace("PersistentKeepalive = 25", "")));
        assert_eq!(None, wg_conf::parse(&FRITZ.replace("PersistentKeepalive = 25", ""), "x").unwrap().keepalive);
        assert!(matches!(
            wg_conf::parse(&FRITZ.replace("PersistentKeepalive = 25", "PersistentKeepalive = soon"), "x"),
            Err(Error::Invalid(_))
        ));
        let c = compiled(&example());
        let provider = c["endpoints"].as_array().unwrap().iter().find(|e| e["type"] == "wireguard").unwrap();
        assert_eq!(25, provider["peers"][0]["persistent_keepalive_interval"]);
    }

    // ---- golden files: the earlier app's output for the same setups (tests/fixtures/compiler/golden-*.json) ----

    fn g_server(name: &str, ip: &str) -> Server {
        Server {
            name: name.into(),
            host: format!("{}.example.net", name.to_lowercase()),
            ip: ip.into(),
            public_key: PUB.into(),
            load: 10,
            ..Server::default()
        }
    }

    fn g_wg(name: &str, ip: &str, ports: Vec<i32>, entries: &[&str], dns: &[&str]) -> Link {
        let peer = WgPeer {
            dns: strs(dns),
            ..WgPeer::new(name, KEY, strs(&["10.5.0.2/32"]), PUB, &format!("{ip}:51820"), strs(&["0.0.0.0/0"]))
        };
        Link::Wg { server: g_server(name, ip), peer, ports, entries: strs(entries) }
    }

    fn g_loc(provider: &str, code: &str, country: &str) -> Location {
        Location {
            provider: provider.into(),
            country_code: Some(code.into()),
            country: Some(country.into()),
            ..Location::default()
        }
    }

    fn g_nl() -> Route {
        nl()
    }
    fn g_se() -> Route {
        route("se", Location { region: Some("se-got".into()), ..g_loc("mullvad", "SE", "Sweden") }, 1)
    }
    fn g_ch() -> Route {
        route("ch", g_loc("airvpn", "CH", "Switzerland"), 2)
    }
    fn g_nlo() -> Route {
        route(
            "nlo",
            Location { protocol: Some("openvpn_udp".into()), ..Location::country("nord", 153, "NL", "Netherlands") },
            3,
        )
    }
    fn g_im() -> Route {
        Route {
            ovpn: Some(parse_ovpn(&fixture("expressvpn.ovpn"), "Express", "user", "pass").unwrap()),
            hue: 5,
            ..Route::new("im", Location::default())
        }
    }
    fn g_ts() -> Route {
        Route { ts_name: Some("nas".into()), ..ts_route("ts", "100.101.102.103", 4) }
    }
    fn g_off() -> IndexMap<String, IndexMap<String, String>> {
        use crate::providers::{AUTO, ENTRY_OPT, MTU_OPT, PORT_OPT};
        IndexMap::from([
            ("nord".to_string(), pairs(&[(PROTECT, "off")])),
            ("mullvad".to_string(), pairs(&[(PROTECT, "off"), (PORT_OPT, AUTO), (MTU_OPT, "1400")])),
            ("airvpn".to_string(), pairs(&[(PORT_OPT, AUTO), (ENTRY_OPT, "2")])),
        ])
    }
    fn g_setup(routes: Vec<Route>, default_route: &str, apps: &[(&str, &str)]) -> Setup {
        Setup { routes, default_route: default_route.into(), apps: pairs(apps), opts: g_off(), ..Setup::default() }
    }

    fn g_apps(k: &str) -> crate::apps::Matchers {
        if k.starts_with('/') {
            crate::apps::Matchers { paths: strs(&[k]), ..Default::default() }
        } else {
            crate::apps::Matchers {
                dirs: vec![format!("/opt/{k}/")],
                names: strs(&[k.rsplit('.').next().unwrap()]),
                ..Default::default()
            }
        }
    }

    struct Golden {
        setup: Setup,
        step: &'static [(&'static str, usize)],
        ts_suffix: Option<&'static str>,
        fake_block: i32,
        login: bool,
        refused: &'static [(&'static str, &'static str)],
        linux: bool,
    }

    fn g(setup: Setup) -> Golden {
        Golden { setup, step: &[], ts_suffix: None, fake_block: 0, login: false, refused: &[], linux: true }
    }

    /// As the app runs it: picked (kept tunnels, imports built), ported, compiled under lockdown, then made a Linux
    /// config; equal to the earlier app's output for the same setup. The probe pair is fixed on both sides.
    fn golden(name: &str, g: Golden) {
        let mut kept = IndexMap::from([
            ("nl".to_string(), g_wg("NL #1", "185.1.1.1", vec![], &[], &[])),
            ("se".to_string(), g_wg("SE-GOT-1", "185.2.2.2", vec![51820, 53, 443], &[], &["10.64.0.1"])),
            ("ch".to_string(), g_wg("Alchiba", "185.3.3.3", vec![1637, 47107], &["185.3.3.3", "185.3.3.4"], &[])),
        ]);
        kept.insert(
            "nlo".into(),
            Link::Ovpn {
                server: g_server("NL-OVPN", "185.4.4.4"),
                profile: parse_ovpn(&fixture("nord-double.udp.ovpn"), "NL-OVPN", "svc", "svcpw").unwrap(),
            },
        );
        let accounts = pairs(&[("nord", "acc"), ("mullvad", "acc"), ("airvpn", "acc")]);
        let refused = g
            .refused
            .iter()
            .map(|(id, m)| (id.to_string(), Error::Auth { message: m.to_string(), url: None }))
            .collect();
        let picked = crate::link_picker::pick(
            &g.setup,
            &kept,
            Some(&g.setup),
            &accounts,
            &accounts,
            &IndexMap::new(),
            &IndexSet::new(),
            &refused,
            false,
            &|_| None,
        );
        let step = g.step.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let links = crate::link_picker::ported(&g.setup, &picked.links, &step);
        let i = Input {
            ts_suffix: g.ts_suffix.map(String::from),
            probe: Some((40000, "golden-pw".into())),
            fake_block: g.fake_block,
            blocked: picked.blocked.keys().cloned().collect(),
            ts_login_pending: g.login,
            ..Input::new(g.setup.clone(), links, "app.unbraid", g.linux, "tailscale", "cache.db")
        };
        let mut config = raw(&i);
        if g.linux {
            config = crate::linux_pass::config(&config, g_apps, Some("/usr/lib/unbraid/bin/unbraid"));
            keep("compiled-linux", &config);
        }
        let want: Value = serde_json::from_str(&fixture(&format!("golden-{name}.json"))).unwrap();
        if want != serde_json::from_str::<Value>(&config).unwrap() {
            let mine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("target/golden-{name}.json"));
            std::fs::write(
                &mine,
                serde_json::to_string_pretty(&serde_json::from_str::<Value>(&config).unwrap()).unwrap(),
            )
            .unwrap();
            panic!("golden-{name}.json differs; this compiler's output is in {}", mine.display());
        }
    }

    #[test]
    fn golden_wireguard_providers() {
        let s = g_setup(
            vec![g_nl(), g_se(), g_ch()],
            "nl",
            &[("firefox", "se"), ("org.mozilla.Thunderbird", "ch"), ("/usr/bin/curl", "se")],
        );
        golden("wireguard-providers", Golden { step: &[("mullvad", 1)], fake_block: 2, ..g(s) });
    }

    #[test]
    fn golden_openvpn() {
        golden("openvpn", g(g_setup(vec![g_im(), g_nlo()], "im", &[("firefox", "nlo")])));
    }

    #[test]
    fn golden_shadowsocks() {
        let ss = SsProfile {
            name: "Outline".into(),
            server: "203.0.113.5".into(),
            port: 8388,
            method: "chacha20-ietf-poly1305".into(),
            password: "sspw".into(),
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some("tls;host=cdn.example.com".into()),
        };
        let routes = vec![Route { ss: Some(ss), ..Route::new("ss", Location::default()) }, g_nl()];
        golden("shadowsocks", g(g_setup(routes, "ss", &[("firefox", "nl"), ("spotify", DIRECT), ("steam", DIRECT)])));
    }

    #[test]
    fn golden_tailscale_exit() {
        golden(
            "tailscale-exit",
            Golden { login: true, ..g(g_setup(vec![g_nl(), g_ts()], "nl", &[("firefox", "ts")])) },
        );
    }

    #[test]
    fn golden_home_tailnet() {
        let home = Home {
            tailscale: true,
            subnets: strs(&["192.168.178.0/24", "10.42.0.0/16", "8.8.8.0/24"]),
            ..Home::default()
        };
        let s = Setup { home, ..g_setup(vec![g_nl()], "nl", &[("firefox", DIRECT)]) };
        golden("home-tailnet", Golden { ts_suffix: Some("tail1234.ts.net"), fake_block: 5, ..g(s) });
    }

    #[test]
    fn golden_headscale() {
        let home = Home {
            tailscale: true,
            ts_auth_key: Some("tskey-auth-golden".into()),
            ts_control_url: Some("https://hs.example.org".into()),
            subnets: strs(&["192.168.1.0/24"]),
            ts_suffix_allowed: Some("corp.example".into()),
            ..Home::default()
        };
        let s = Setup { home, ..g_setup(vec![g_nl(), g_ts()], "nl", &[("firefox", "ts")]) };
        golden("headscale", Golden { ts_suffix: Some("corp.example"), login: true, ..g(s) });
    }

    #[test]
    fn golden_home_wireguard() {
        let wg = WgPeer {
            preshared_key: Some(PUB.into()),
            dns: strs(&["192.168.178.1"]),
            keepalive: Some(15),
            ..WgPeer::new(
                "Home",
                KEY,
                strs(&["192.168.178.201/24"]),
                PUB,
                "abc.myfritz.net:51820",
                strs(&["192.168.178.0/24", "0.0.0.0/0"]),
            )
        };
        golden(
            "home-wireguard",
            g(Setup { home: Home { wg: Some(wg), ..Home::default() }, ..g_setup(vec![g_nl()], "nl", &[]) }),
        );
    }

    #[test]
    fn golden_direct_default() {
        golden(
            "direct-default",
            g(g_setup(
                vec![g_nl(), g_se()],
                DIRECT,
                &[("firefox", "nl"), ("/usr/bin/curl", "se"), ("spotify", DIRECT)],
            )),
        );
    }

    #[test]
    fn golden_blocking_dns() {
        use crate::providers::{AUTO, MTU_OPT, PORT_OPT};
        let s = Setup {
            opts: IndexMap::from([(
                "mullvad".to_string(),
                pairs(&[(PORT_OPT, AUTO), (MTU_OPT, AUTO), ("adult", "on")]),
            )]),
            ..g_setup(vec![g_nl(), Route { filter: Some(true), ..g_se() }], "nl", &[("firefox", "se")])
        };
        golden("blocking-dns", g(s));
    }

    #[test]
    fn golden_custom_dns() {
        let filter = Filter {
            id: Some(OWN.into()),
            value: "tls://dns.example.org".into(),
            routes: true,
            direct: true,
            direct_apps: true,
            apps: IndexMap::from([("steam".to_string(), false)]),
        };
        let s = Setup {
            prefs: Prefs { filter, ..Prefs::default() },
            ..g_setup(
                vec![g_nl(), g_im()],
                DIRECT,
                &[("firefox", "nl"), ("thunderbird", "im"), ("spotify", DIRECT), ("steam", DIRECT)],
            )
        };
        golden("custom-dns", g(s));
    }

    #[test]
    fn golden_lan_off_quad9() {
        let prefs = Prefs {
            lan: false,
            filter: Filter { id: Some("quad9".into()), routes: true, ..Filter::default() },
            ..Prefs::default()
        };
        golden("lan-off-quad9", g(Setup { prefs, ..g_setup(vec![g_nl(), g_se()], "nl", &[("firefox", "se")]) }));
    }

    #[test]
    fn golden_testing_route() {
        let s =
            Setup { testing: IndexSet::from(["ch".to_string()]), ..g_setup(vec![g_nl(), g_se(), g_ch()], "nl", &[]) };
        golden("testing-route", Golden { step: &[("airvpn", 1)], ..g(s) });
    }

    #[test]
    fn golden_blocked() {
        let s = g_setup(vec![g_nl(), g_se(), g_ch()], "nl", &[("firefox", "ch"), ("steam", "se")]);
        golden("blocked", Golden { refused: &[("nl", "Sign in to NordVPN"), ("se", "Sign in to Mullvad")], ..g(s) });
    }

    #[test]
    fn golden_raw_lan() {
        let home = Home { tailscale: true, subnets: strs(&["192.168.178.0/24"]), ..Home::default() };
        let s = Setup { home, ..g_setup(vec![g_nl(), g_se()], "nl", &[("firefox", "se"), ("spotify", DIRECT)]) };
        golden("raw-lan", Golden { linux: false, ..g(s) });
    }

    /// The fallback cache's keys are the earlier app's, so the tunnels it saved are found again.
    #[test]
    fn golden_cache_keys() {
        let want: IndexMap<String, String> = serde_json::from_str(&fixture("golden-cache-keys.json")).unwrap();
        let pin = Route::new(
            "pin",
            Location {
                provider: "mullvad".into(),
                country_code: Some("SE".into()),
                pinned: Some(g_server("SE-GOT-1", "185.2.2.2")),
                ..Location::default()
            },
        );
        for r in [g_nl(), g_se(), g_ch(), g_nlo(), pin] {
            assert_eq!(want[&r.id], crate::link_picker::cache_key(&r), "{}", r.id);
        }
    }
}
