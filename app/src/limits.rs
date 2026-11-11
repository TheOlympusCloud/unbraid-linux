//! Provider connection limits: what an account allows and what unbraid uses of it. The texts are the same for every
//! provider: only the name, numbers and unit change.

use crate::APP;
use crate::model::Setup;
use crate::providers::Limit;
use indexmap::IndexSet;

/// Page setting with the user's own limit for a provider, a whole number; unset = the provider's.
pub const LIMIT_OPT: &str = "limit";

pub fn units(n: i32, unit: &str) -> String {
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// The account's line on a provider page: `n` is what unbraid uses now, `limit` none when unknown, `all` what the
/// provider counts in use.
pub fn line(name: &str, limit: Option<i32>, unit: &str, n: i32, all: Option<i32>) -> String {
    match (limit, all) {
        (Some(limit), Some(all)) => format!(
            "{name} allows {}. {} in use, {}by {APP}.",
            units(limit, unit),
            if all == 1 { "1 is".to_string() } else { format!("{all} are") },
            if all == n { String::new() } else { format!("{n} of them ") }
        ),
        (Some(limit), None) => {
            format!("{name} allows {}. {APP} is using {n}. Your other devices aren't counted.", units(limit, unit))
        }
        (None, _) => format!(
            "{APP} is using {}. Check how many your plan allows: over the limit, routes can stop working without an error.",
            units(n, unit).replacen(' ', &format!(" {name} "), 1)
        ),
    }
}

/// Before a change that would take `n` over `limit`.
pub fn warning(name: &str, limit: i32, unit: &str, n: i32) -> String {
    format!(
        "{name} allows {}. This would make it {n}. Over the limit, routes can stop working without an error.",
        units(limit, unit)
    )
}

/// A sign-in the provider refused because every slot is taken.
pub fn full(name: &str, limit: Option<i32>, unit: &str) -> String {
    format!(
        "All {}{name} {unit}s are in use. Sign out another device, then try again.",
        limit.map(|l| format!("{l} ")).unwrap_or_default()
    )
}

/// A route that fails on and off.
pub fn dropping(route: &str, name: &str, unit: &str) -> String {
    format!("{route} keeps dropping. {name} may be over its {unit} limit.")
}

/// The limit that applies: the user's own ([`LIMIT_OPT`]) before the provider's.
pub fn effective(p: &Limit, own: Option<&str>) -> Option<i32> {
    own.and_then(|o| o.parse::<i32>().ok()).filter(|n| (1..=999).contains(n)).or(p.value)
}

/// A change that would give `provider` `n` separate tunnels, over its `limit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Over {
    pub provider: String,
    pub limit: i32,
    pub n: usize,
    pub unit: String,
}

/// Separate tunnels `s` opens to `provider`: one per active route, since unpinned routes are spread over different
/// servers ([`crate::link_picker`]); routes pinned to one server over the same protocol share its tunnel.
pub fn tunnels(s: &Setup, provider: &str) -> usize {
    s.active_routes()
        .into_iter()
        .filter(|r| !r.imported() && r.loc.provider == provider)
        .map(|r| match &r.loc.pinned {
            Some(p) => format!("{}|{}", p.host, r.loc.protocol.as_deref().unwrap_or("null")),
            None => r.id.clone(),
        })
        .collect::<IndexSet<_>>()
        .len()
}

/// The first provider counted per tunnel that `new` takes over its known limit with more tunnels than `old` had.
pub fn over(old: &Setup, new: &Setup, limit: impl Fn(&str) -> Option<Limit>) -> Option<Over> {
    let providers: IndexSet<String> =
        new.active_routes().into_iter().filter(|r| !r.imported()).map(|r| r.loc.provider.clone()).collect();
    providers.into_iter().find_map(|p| {
        let l = limit(&p).filter(|l| l.per_tunnel)?;
        let max = effective(&l, new.opt(&p, LIMIT_OPT).as_deref())?;
        let n = tunnels(new, &p);
        (n as i64 > max as i64 && n > tunnels(old, &p)).then(|| Over {
            provider: p,
            limit: max,
            n,
            unit: l.unit.clone(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, Route, Server};
    use indexmap::IndexMap;

    fn limit(unit: &str, per_tunnel: bool, value: Option<i32>) -> Limit {
        Limit { unit: unit.into(), per_tunnel, value }
    }

    /// One wording for every provider: only the name, the numbers and the unit change.
    #[test]
    fn fixed_wording() {
        assert_eq!(
            "Proton VPN Free allows 1 connection. unbraid is using 2. Your other devices aren't counted.",
            line("Proton VPN Free", Some(1), "connection", 2, None)
        );
        assert_eq!(
            "IVPN allows 5 devices. unbraid is using 1. Your other devices aren't counted.",
            line("IVPN", Some(5), "device", 1, None)
        );
        assert_eq!(
            "Mullvad allows 5 devices. 1 is in use, by unbraid.",
            line("Mullvad", Some(5), "device", 1, Some(1))
        );
        assert_eq!(
            "Mullvad allows 5 devices. 3 are in use, 1 of them by unbraid.",
            line("Mullvad", Some(5), "device", 1, Some(3))
        );
        assert_eq!(
            "unbraid is using 2 PIA connections. Check how many your plan allows: over the limit, routes can stop working without an error.",
            line("PIA", None, "connection", 2, None)
        );
        assert_eq!(
            "unbraid is using 1 Proton VPN connection. Check how many your plan allows: over the limit, routes can stop working without an error.",
            line("Proton VPN", None, "connection", 1, None)
        );
        assert_eq!(
            "NordVPN allows 10 connections. This would make it 11. Over the limit, routes can stop working without an error.",
            warning("NordVPN", 10, "connection", 11)
        );
        assert_eq!(
            "All 5 IVPN devices are in use. Sign out another device, then try again.",
            full("IVPN", Some(5), "device")
        );
        assert_eq!(
            "All IVPN devices are in use. Sign out another device, then try again.",
            full("IVPN", None, "device")
        );
        assert_eq!(
            "Netherlands keeps dropping. Proton VPN Free may be over its connection limit.",
            dropping("Netherlands", "Proton VPN Free", "connection")
        );
    }

    /// The user's own figure wins; empty or nonsense falls back to the provider's, which may be unknown.
    #[test]
    fn own_limit_first() {
        let p = limit("connection", true, Some(10));
        assert_eq!(Some(3), effective(&p, Some("3")));
        assert_eq!(Some(10), effective(&p, Some("")));
        assert_eq!(Some(10), effective(&p, None));
        assert_eq!(Some(10), effective(&p, Some("0")));
        assert_eq!(Some(10), effective(&p, Some("abc")));
        assert_eq!(None, effective(&limit("connection", true, None), Some("")));
        assert_eq!(Some(7), effective(&limit("connection", true, None), Some("7")));
    }

    /// What each provider declares: known figures only where documented or reported, how unbraid counts its own use.
    #[test]
    fn providers() {
        use crate::providers::Provider;
        use crate::providers::{
            ivpn::Ivpn, mullvad::Mullvad, nord::Nord, pia::Pia, proton::PROTON, proton::PROTON_FREE,
        };
        assert_eq!(limit("connection", true, Some(10)), Nord.limit(""));
        assert_eq!(limit("connection", true, Some(1)), PROTON_FREE.limit(""));
        assert_eq!(limit("connection", true, Some(10)), PROTON.limit(""));
        assert_eq!(limit("device", false, Some(5)), Mullvad.limit(""));
        assert_eq!(limit("connection", true, None), Pia.limit(""));
        let ivpn = r#"{"accountId":"i-AAAA-BBBB-CCCC","sessionToken":"t","privateKey":"k","ipAddress":"10.0.0.2","device":"Tidy Falcon","limit":5}"#;
        assert_eq!(limit("device", false, Some(5)), Ivpn.limit(ivpn));
        assert_eq!(
            limit("device", false, None),
            Ivpn.limit(r#"{"accountId":"a","sessionToken":"t","privateKey":"k","ipAddress":"10.0.0.2"}"#)
        );
        assert_eq!(limit("device", false, None), Ivpn.limit("not json"));
    }

    fn no() -> Server {
        Server {
            name: "NO-FREE#6".into(),
            host: "node-no-12.protonvpn.net".into(),
            ip: "1.2.3.4".into(),
            public_key: "k".into(),
            load: -1,
            ..Default::default()
        }
    }
    fn pf(id: &str, country: &str, pin: Option<Server>) -> Route {
        Route::new(
            id,
            Location {
                provider: "proton-free".into(),
                country_code: Some(country.into()),
                country: Some(country.into()),
                pinned: pin,
                ..Default::default()
            },
        )
    }
    fn nord() -> Route {
        Route::new("nl", Location::country("nord", 153, "NL", "Netherlands"))
    }
    fn limits(p: &str) -> Option<Limit> {
        match p {
            "proton-free" => Some(limit("connection", true, Some(1))),
            "nord" => Some(limit("connection", true, Some(10))),
            _ => None,
        }
    }
    fn apps(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// One tunnel per active route; routes pinned to one server share it; routes without apps open none.
    #[test]
    fn counts_tunnels() {
        let s = Setup {
            routes: vec![nord(), pf("a", "NO", None), pf("b", "NL", None), pf("c", "JP", None)],
            default_route: "nl".into(),
            apps: apps(&[("x", "a"), ("y", "b")]),
            ..Setup::default()
        };
        assert_eq!(2, tunnels(&s, "proton-free"));
        assert_eq!(1, tunnels(&s, "nord"));
        let pinned = Setup { routes: vec![nord(), pf("a", "NO", Some(no())), pf("b", "NO", Some(no()))], ..s.clone() };
        assert_eq!(1, tunnels(&pinned, "proton-free"));
        let nord_pin = Server {
            name: "nl1302".into(),
            host: "nl1302.nordvpn.com".into(),
            ip: "1.1.1.1".into(),
            public_key: "k".into(),
            load: 4,
            ..Default::default()
        };
        let protocols = Setup {
            routes: vec![
                Route::new("x", Location { pinned: Some(nord_pin.clone()), ..Location::of("nord") }),
                Route::new(
                    "y",
                    Location { pinned: Some(nord_pin), protocol: Some("openvpn_udp".into()), ..Location::of("nord") },
                ),
            ],
            default_route: "x".into(),
            apps: apps(&[("a", "y")]),
            ..Setup::default()
        };
        assert_eq!(2, tunnels(&protocols, "nord")); // one server, two protocols: two tunnels
    }

    /// Only a change that adds a tunnel over the limit asks; changes that keep or lower the count, or other providers, don't.
    #[test]
    fn asks_only_when_going_over() {
        let one = Setup {
            routes: vec![nord(), pf("a", "NO", None), pf("b", "NL", None)],
            default_route: "nl".into(),
            apps: apps(&[("x", "a")]),
            ..Setup::default()
        };
        let with = |s: &Setup, k: &str, v: &str| {
            let mut s = s.clone();
            s.apps.insert(k.into(), v.into());
            s
        };
        let two = with(&one, "y", "b");
        assert_eq!(
            Some(Over { provider: "proton-free".into(), limit: 1, n: 2, unit: "connection".into() }),
            over(&one, &two, limits)
        );
        assert_eq!(None, over(&two, &with(&two, "z", "b"), limits)); // already over: no new tunnel
        assert_eq!(None, over(&two, &one, limits)); // fewer
        assert_eq!(None, over(&one, &with(&one, "z", "a"), limits)); // same route
        let shared =
            Setup { routes: vec![nord(), pf("a", "NO", Some(no())), pf("b", "NO", Some(no()))], ..one.clone() };
        assert_eq!(None, over(&shared, &with(&shared, "y", "b"), limits)); // same server
        assert_eq!(None, over(&one, &two, |_| None)); // not signed in or unknown: never asks
        let mut own = two.clone();
        own.opts.insert("proton-free".into(), [("limit".to_string(), "2".to_string())].into_iter().collect());
        assert_eq!(None, over(&one, &own, limits)); // the user's own limit counts
        assert_eq!(None, over(&one, &two, |_| Some(limit("device", false, Some(1))))); // one session for the account
    }
}
