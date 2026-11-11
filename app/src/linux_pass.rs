//! Turns what [`crate::compiler`] writes into the config the Linux engine runs. Compiled with `lockdown`, the path where
//! the system leaves no app out of the VPN, as Linux can't: Direct apps and the LAN pass through the engine and leave
//! directly, so no lookup (not even one sent to the router) gets past it.
//!
//! - `package_name` becomes the process the app runs as ([`Matchers`]); an app no process is known for matches nothing.
//! - The TUN loses the package lists; the app's own process (`own`) goes out directly, as if left out of the VPN.
//! - The engine's cache file goes: it would keep every name looked up on disk, where only root could delete it. Each
//!   engine start is a new domain table ([`crate::compiler::next_block`]).
//! - Every connection is matched to its process, so statistics can name the app.

use crate::apps::Matchers;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

/// Keys that say what a rule does rather than what it matches.
const ACTION: [&str; 5] = ["action", "outbound", "server", "no_drop", "rewrite_ttl"];

pub fn config(json: &str, apps: impl Fn(&str) -> Matchers, own: Option<&str>) -> String {
    let mut c: Map<String, Value> = serde_json::from_str(json).expect("the compiler's own config");
    let dns_rules = rules(&c["dns"]["rules"], &apps);
    c["dns"]["rules"] = Value::Array(dns_rules);
    for i in c["inbounds"].as_array_mut().into_iter().flatten() {
        if let Some(i) = i.as_object_mut() {
            i.remove("exclude_package");
            i.remove("include_package");
        }
    }
    let mut route_rules = rules(&c["route"]["rules"], &apps);
    if let Some(own) = own {
        // After the DNS hijacks and the refusal of stale fake IPs, before any exit: as early as a left-out app.
        // Only from the TUN: the app's own tests come in on the probe inbound and must leave through the exit they test.
        let at = route_rules
            .iter()
            .position(|r| r["action"] == "reject" && r.get("ip_cidr").is_some() && r.get("inbound").is_none())
            .or_else(|| route_rules.iter().rposition(|r| r["action"] == "hijack-dns"))
            .map_or(0, |i| i + 1);
        route_rules
            .insert(at, json!({"inbound": ["tun"], "process_path": [own], "action": "resolve", "server": "local"}));
        route_rules.insert(at + 1, json!({"inbound": ["tun"], "process_path": [own], "outbound": "direct"}));
    }
    c["route"]["rules"] = Value::Array(route_rules);
    c["route"]["find_process"] = json!(true);
    if let Some(Value::Object(e)) = c.get_mut("experimental") {
        e.remove("cache_file");
        if e.is_empty() {
            c.remove("experimental");
        }
    }
    Value::Object(c).to_string()
}

fn rules(list: &Value, apps: &impl Fn(&str) -> Matchers) -> Vec<Value> {
    list.as_array().into_iter().flatten().filter_map(|r| rule(r.as_object().expect("a rule"), apps)).collect()
}

/// `r` matching processes instead of packages; none when none of its apps has a known process.
fn rule(r: &Map<String, Value>, apps: &impl Fn(&str) -> Matchers) -> Option<Value> {
    let Some(pkgs) = r.get("package_name") else { return Some(Value::Object(r.clone())) };
    let all: Vec<Matchers> =
        pkgs.as_array().expect("a package list").iter().map(|p| apps(p.as_str().expect("a package"))).collect();
    let distinct = |f: fn(&Matchers) -> &Vec<String>| {
        all.iter().flat_map(f).cloned().collect::<IndexSet<_>>().into_iter().collect::<Vec<_>>()
    };
    let m = Matchers { paths: distinct(|m| &m.paths), dirs: distinct(|m| &m.dirs), names: distinct(|m| &m.names) };
    if m.is_empty() {
        return None;
    }
    let kinds: Vec<(&str, Value)> = [
        ("process_path", json!(m.paths)),
        ("process_path_regex", json!(m.dirs.iter().map(|d| format!("^{}", quote(d))).collect::<Vec<_>>())),
        ("process_name", json!(m.names)),
    ]
    .into_iter()
    .filter(|(_, v)| v.as_array().is_some_and(|a| !a.is_empty()))
    .collect();
    let matching: Map<String, Value> = r
        .iter()
        .filter(|(k, _)| *k != "package_name" && !ACTION.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut out: Map<String, Value> =
        r.iter().filter(|(k, _)| ACTION.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    let with = |(k, v): &(&str, Value)| {
        let mut o = matching.clone();
        o.insert(k.to_string(), v.clone());
        Value::Object(o)
    };
    if let [kind] = kinds.as_slice() {
        out.extend(with(kind).as_object().cloned().unwrap_or_default());
        return Some(Value::Object(out));
    }
    // The engine ANDs different fields of one rule: either process kind matches, each with the rule's other conditions.
    out.insert("type".into(), json!("logical"));
    out.insert("mode".into(), json!("or"));
    out.insert("rules".into(), Value::Array(kinds.iter().map(with).collect()));
    Some(Value::Object(out))
}

/// `s` as a literal in the engine's (RE2) regular expressions.
pub fn quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            q.push('\\');
        }
        q.push(c);
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::tests::{KEY, PUB, has, keep, pairs, wg_link};
    use crate::compiler::{Input, compile};
    use crate::model::{DIRECT, Link, Location, Route, Server, Setup};
    use crate::providers::nord;
    use indexmap::IndexMap;

    const OWN: &str = "/usr/lib/unbraid/bin/unbraid";

    // Each route its own server: routes on one server with one key share a tunnel.
    fn sv(n: &str) -> Server {
        let c: Vec<u32> = n.chars().map(u32::from).collect();
        Server {
            name: format!("{n} #1"),
            host: format!("{n}.nordvpn.com"),
            ip: format!("10.9.{}.{}", c[0], c[1]),
            public_key: PUB.into(),
            load: 10,
            ..Server::default()
        }
    }

    fn setup() -> Setup {
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
            ],
            default_route: "nl".into(),
            apps: pairs(&[("firefox", "us"), ("/usr/bin/curl", "us"), ("spotify", DIRECT), ("gone", "us")]),
            ..Setup::default()
        }
    }

    fn apps(k: &str) -> Matchers {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
        match k {
            _ if k.starts_with('/') => Matchers { paths: vec![k.into()], ..Matchers::default() },
            "firefox" => Matchers {
                paths: s(&["/usr/lib/firefox/firefox"]),
                dirs: s(&["/usr/lib/firefox/"]),
                names: s(&["firefox"]),
            },
            "spotify" => Matchers { paths: s(&["/opt/spotify/spotify"]), ..Matchers::default() },
            _ => Matchers::default(),
        }
    }

    fn links(s: &Setup) -> IndexMap<String, Link> {
        s.active_routes().iter().map(|r| (r.id.clone(), wg_link(sv(&r.id), nord::peer(&sv(&r.id), KEY)))).collect()
    }

    fn linux(s: &Setup, own: Option<&str>) -> Value {
        let i = Input {
            probe: Some((40000, "pw".into())),
            ..Input::new(s.clone(), links(s), "app.unbraid", true, "tailscale", "cache.db")
        };
        let out = config(&compile(&i).unwrap(), apps, own);
        keep("compiled-linux", &out);
        serde_json::from_str(&out).unwrap()
    }

    fn rules(c: &Value) -> &Vec<Value> {
        c["route"]["rules"].as_array().unwrap()
    }

    /// No package rule is left; each app is known by its processes, all of its kinds in one OR rule.
    #[test]
    fn apps_are_matched_by_process() {
        let c = linux(&setup(), Some(OWN));
        assert!(!c.to_string().contains("package_name"));
        let us: Vec<&Value> =
            rules(&c).iter().filter(|r| r["outbound"] == "r-us" && r.get("inbound").is_none()).collect(); // the app's own probe has a rule of its own
        // firefox and curl share the route: one rule, with the paths of both, firefox's folder and its name.
        assert_eq!(1, us.len());
        let rule = us[0];
        assert_eq!("logical", rule["type"]);
        assert_eq!("or", rule["mode"]);
        let branch =
            |k: &str| rule["rules"].as_array().unwrap().iter().find(|b| b.get(k).is_some()).unwrap()[k].clone();
        assert_eq!(json!(["/usr/bin/curl", "/usr/lib/firefox/firefox"]), branch("process_path"));
        assert_eq!(json!(["^/usr/lib/firefox/"]), branch("process_path_regex"));
        assert_eq!(json!(["firefox"]), branch("process_name"));
        // The lookup at the app's exit comes first, for the same processes.
        let resolve = rules(&c)
            .iter()
            .find(|r| r["action"] == "resolve" && r["server"] == "dns-r-us" && r.get("inbound").is_none())
            .unwrap();
        assert_eq!("logical", resolve["type"]);
    }

    /// An app no process is known for (uninstalled) matches nothing: its traffic can't be told apart, so it follows the default.
    #[test]
    fn app_without_process_matches_nothing() {
        let c = linux(&Setup { apps: pairs(&[("gone", "us")]), ..setup() }, Some(OWN));
        assert!(rules(&c).iter().all(|r| !(r["outbound"] == "r-us" && r.get("inbound").is_none())));
        assert_eq!("r-nl", c["route"]["final"]);
    }

    /// Linux can't leave an app out of the VPN: Direct apps pass through the engine and go out directly, like the LAN.
    #[test]
    fn direct_apps_leave_through_the_engine() {
        let c = linux(&setup(), Some(OWN));
        let tun = &c["inbounds"][0];
        assert!(
            tun.get("exclude_package").is_none()
                && tun.get("route_exclude_address").is_none()
                && tun.get("route_address").is_none()
        );
        let direct: Vec<&Value> =
            rules(&c).iter().filter(|r| r["process_path"] == json!(["/opt/spotify/spotify"])).collect();
        assert_eq!(vec![Some("local"), None], direct.iter().map(|r| r["server"].as_str()).collect::<Vec<_>>());
        assert_eq!("direct", direct.last().unwrap()["outbound"]);
        assert!(rules(&c).iter().any(|r| has(&r["ip_cidr"], "192.168.0.0/16") && r["outbound"] == "direct"));
    }

    /// The app itself goes out directly, as if left out of the VPN, but only from the TUN: its tests must use the exit they test.
    #[test]
    fn own_traffic_goes_direct_only_from_the_tun() {
        let c = linux(&setup(), Some(OWN));
        let rs = rules(&c);
        let own: Vec<(usize, &Value)> =
            rs.iter().enumerate().filter(|(_, r)| r["process_path"] == json!([OWN])).collect();
        assert_eq!(2, own.len());
        own.iter().for_each(|(_, r)| assert_eq!(json!(["tun"]), r["inbound"]));
        assert_eq!("direct", own[1].1["outbound"]);
        // After stale fake IPs are refused, before any exit.
        let stale = rs.iter().position(|r| r["action"] == "reject" && r.get("ip_cidr").is_some()).unwrap();
        assert_eq!(stale + 1, own[0].0);
        assert!(
            rs.iter().position(|r| r["outbound"].as_str().is_some_and(|o| o.starts_with("r-"))).unwrap() > own[1].0
        );
        assert!(
            rules(&linux(&setup(), None))
                .iter()
                .all(|r| !(r.get("process_path").is_some() && r.get("inbound").is_some()))
        );
    }

    /// Nothing about lookups is kept on disk, and every connection is matched to its process (for statistics).
    #[test]
    fn no_cache_file_and_every_process_found() {
        let c = linux(&setup(), Some(OWN));
        assert!(c.get("experimental").is_none());
        assert_eq!(true, c["route"]["find_process"]);
    }

    #[test]
    fn folders_are_quoted_for_the_engine() {
        assert_eq!(r"/opt/My App \(2\)/v1\.0\+x/", quote("/opt/My App (2)/v1.0+x/"));
        assert_eq!(r"/a\[b\]\{c\}\^\$\|\*\?\\/", quote(r"/a[b]{c}^$|*?\/"));
    }
}
