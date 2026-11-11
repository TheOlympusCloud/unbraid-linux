//! Chooses the tunnel each active route runs. Kept free of the engine and the window so it can be tested.

use crate::compiler::{CLASH, clashes};
use crate::error::{Error, Result};
use crate::model::{DIRECT, Link, Location, Route, Server, Setup, WgPeer};
use crate::providers::{ENTRY_OPT, MTU_MIN, MTU_OPT, PORT_OPT, Provider, mtu};
use indexmap::{IndexMap, IndexSet};

/// What an offline pick's route that needs its provider for a tunnel fails with; see [`waiting`].
pub const WAITING: &str = "waiting for a server";

/// Whether `e` is an offline pick's route that needs its provider for a tunnel.
pub fn waiting(e: &Error) -> bool {
    matches!(e, Error::Fail(m) if m == WAITING)
}

/// `blocked`: routes that got no tunnel, with why; their apps are blocked until one is found
/// ([`crate::compiler::Input::blocked`]).
#[derive(Clone, Debug)]
pub struct Picked {
    pub links: IndexMap<String, Link>,
    pub remember: IndexMap<String, Link>,
    pub blocked: IndexMap<String, Error>,
}

/// Fallback-cache key: a pinned route is its own entry, so it can never inherit another server's tunnel.
pub fn server_key(r: &Route, l: &Link) -> String {
    format!("{}|{}", r.loc.provider, server_id(l.server()))
}

/// The fallback cache's key for `r`: its provider, its place and its pinned server. The place is written as the earlier
/// app wrote it, so the tunnels it saved are found again.
pub fn cache_key(r: &Route) -> String {
    let l = &r.loc;
    let text = |v: &Option<String>| v.clone().unwrap_or_else(|| "null".into());
    let number = |v: Option<i32>| v.map_or_else(|| "null".into(), |n| n.to_string());
    format!(
        "{}|Location(provider={}, countryId={}, countryCode={}, country={}, cityId={}, city={}, region={}, group={}, protocol={}, pinned=null)|{}",
        l.provider,
        l.provider,
        number(l.country_id),
        text(&l.country_code),
        text(&l.country),
        number(l.city_id),
        text(&l.city),
        text(&l.region),
        text(&l.group),
        text(&l.protocol),
        l.pinned.as_ref().map(server_id).unwrap_or_default()
    )
}

fn server_id(s: &Server) -> String {
    if s.ip.is_empty() { s.host.clone() } else { s.ip.clone() }
}

/// The part of `s` before its last `c`, or all of it.
fn before_last(s: &str, c: char) -> &str {
    s.rsplit_once(c).map_or(s, |(b, _)| b)
}

/// Imported configs as they are; provider routes keep the current server if the route's location didn't change, else
/// get their last one while it is still among the best (one-key providers, see `again`), else the best now, falling
/// back to the last good one if the API is down. An unpinned route that lands on a server another route already uses is
/// moved to a different server of its location. A pinned route is never moved: it shares that server's tunnel (see
/// [`crate::compiler`]) or fails. A route that fails (signed out, refused, unreachable) is [`Picked::blocked`]: the
/// others still run.
///
/// `avoid`: servers ("provider|ip") to stay away from, ones that just stopped answering. `refused`: routes whose provider
/// refused the account it still has, blocked as they are and never given a cached tunnel. `offline`: no provider calls;
/// a route without a tunnel it can keep is blocked, for a policy to install before them.
#[allow(clippy::too_many_arguments)]
pub fn pick<'p>(
    setup: &Setup,
    keep: &IndexMap<String, Link>,
    applied: Option<&Setup>,
    applied_accounts: &IndexMap<String, String>,
    accounts: &IndexMap<String, String>,
    last: &IndexMap<String, Link>,
    avoid: &IndexSet<String>,
    refused: &IndexMap<String, Error>,
    offline: bool,
    providers: &dyn Fn(&str) -> Option<&'p dyn Provider>,
) -> Picked {
    let mut used = avoid.clone();
    let mut out: IndexMap<String, Link> = IndexMap::new();
    let mut blocked: IndexMap<String, Error> = IndexMap::new();
    for r in setup.active_routes() {
        if let Some(e) = refused.get(&r.id) {
            blocked.insert(r.id.clone(), e.clone());
            continue;
        }
        let link = if let Some(w) = &r.wg {
            Ok(Link::Wg { server: Server { name: w.name.clone(), host: before_last(&w.endpoint, ':').into(), public_key: w.public_key.clone(), ..Server::default() }, peer: w.clone(), ports: vec![], entries: vec![] })
        } else if let Some(o) = &r.ovpn {
            Ok(Link::Ovpn { server: Server { name: o.name.clone(), host: o.name.clone(), ..Server::default() }, profile: o.clone() })
        } else if let Some(ss) = &r.ss {
            Ok(Link::Ss { server: Server { name: ss.name.clone(), host: ss.server.clone(), ip: ss.server.clone(), ..Server::default() }, profile: ss.clone() })
        } else if let Some(node) = &r.ts_exit {
            Ok(Link::Ts { server: Server { name: r.name(), host: node.clone(), ..Server::default() } })
        } else {
            let unchanged = applied.and_then(|a| a.route(Some(&r.id))).is_some_and(|a| !a.imported() && a.loc == r.loc) && applied_accounts.get(&r.loc.provider) == accounts.get(&r.loc.provider);
            match keep.get(&r.id).filter(|l| unchanged && trusted(l, r, accounts, providers)) {
                Some(l) => Ok(l.clone()),
                None if offline && !accounts.contains_key(&r.loc.provider) => {
                    let name = providers(&r.loc.provider).map_or(r.loc.provider.as_str(), |p| p.name());
                    Err(Error::Auth { message: format!("Sign in to {name} for {}", r.name()), url: None })
                }
                None if offline => Err(Error::Fail(WAITING.into())),
                None => fresh(r, accounts, last, &used, providers),
            }
        };
        match link {
            Ok(l) => {
                if !r.imported() {
                    used.insert(format!("{}|{}", r.loc.provider, server_id(l.server())));
                }
                out.insert(r.id.clone(), l);
            }
            Err(e) => {
                blocked.insert(r.id.clone(), e);
            }
        }
    }
    // A server no longer offered is gone for every route pinned to it, not only the one that asked.
    let gone: IndexMap<String, Error> = blocked
        .iter()
        .filter(|(_, e)| matches!(e, Error::NoLongerOffered(_)))
        .filter_map(|(id, e)| {
            let l = &setup.route(Some(id))?.loc;
            Some((format!("{}|{}", l.provider, l.pinned.as_ref()?.host), e.clone()))
        })
        .collect();
    for r in setup.active_routes().into_iter().filter(|r| !r.imported()) {
        if out.contains_key(&r.id)
            && let Some(e) = r.loc.pinned.as_ref().and_then(|p| gone.get(&format!("{}|{}", r.loc.provider, p.host)))
        {
            blocked.insert(r.id.clone(), e.clone());
            out.shift_remove(&r.id);
        }
    }
    // A provider that refused its account refuses it for every route: none of them keeps a tunnel on it.
    let refused_by: IndexMap<String, Error> = blocked
        .iter()
        .filter(|(_, e)| matches!(e, Error::Auth { .. }))
        .filter_map(|(id, e)| setup.route(Some(id)).filter(|r| !r.imported()).map(|r| (r.loc.provider.clone(), e.clone())))
        .collect();
    for r in setup.active_routes().into_iter().filter(|r| !r.imported()) {
        if out.contains_key(&r.id)
            && let Some(e) = refused_by.get(&r.loc.provider)
        {
            blocked.insert(r.id.clone(), e.clone());
            out.shift_remove(&r.id);
        }
    }
    // A tunnel that would clash with another one's identity is blocked, never started beside it.
    for id in clashes(setup, &out) {
        out.shift_remove(&id);
        blocked.insert(id, Error::Fail(CLASH.into()));
    }
    let remember = setup.active_routes().into_iter().filter(|r| !r.imported()).filter_map(|r| Some((cache_key(r), out.get(&r.id)?.clone()))).collect();
    Picked { links: out, remember, blocked }
}

/// `links` with each provider WireGuard tunnel on the entry address, port and MTU its provider page asks for: a fixed
/// port, or with Automatic the `step`-th of the server's ports (a step per provider moves on when its tunnels stop
/// answering). Imported configs keep their own MTU, at most [`MTU_MIN`].
pub fn ported(setup: &Setup, links: &IndexMap<String, Link>, step: &IndexMap<String, usize>) -> IndexMap<String, Link> {
    let provider = |id: &str| setup.route(Some(id)).filter(|r| !r.imported()).map(|r| r.loc.provider.clone());
    // One list per provider, so a tunnel saved without one (offline) still takes the same port as its provider's others.
    let mut lists: IndexMap<Option<String>, Vec<i32>> = IndexMap::new();
    for (id, l) in links {
        let list = lists.entry(provider(id)).or_default();
        if let Link::Wg { ports, .. } = l
            && list.is_empty()
        {
            list.clone_from(ports);
        }
    }
    links.iter().map(|(id, l)| (id.clone(), ported_one(setup, provider(id).as_deref(), l, &lists, step))).collect()
}

fn ported_one(setup: &Setup, p: Option<&str>, l: &Link, lists: &IndexMap<Option<String>, Vec<i32>>, step: &IndexMap<String, usize>) -> Link {
    let Link::Wg { server, peer, ports, entries } = l else { return l.clone() };
    let Some(p) = p else {
        return Link::Wg { server: server.clone(), peer: WgPeer { mtu: peer.mtu.min(MTU_MIN), ..peer.clone() }, ports: ports.clone(), entries: entries.clone() };
    };
    let (own_host, own_port) = peer.endpoint.rsplit_once(':').unwrap_or((peer.endpoint.as_str(), peer.endpoint.as_str()));
    let entry = setup.opt(p, ENTRY_OPT).and_then(|n| n.parse::<usize>().ok()).and_then(|n| entries.get(n.checked_sub(1)?));
    let port = setup
        .opt(p, PORT_OPT)
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|n| (1..=65535).contains(n))
        .or_else(|| lists.get(&Some(p.to_string())).filter(|l| !l.is_empty()).map(|l| l[step.get(p).copied().unwrap_or(0) % l.len()]))
        .map_or_else(|| own_port.to_string(), |n| n.to_string());
    let endpoint = format!("{}:{port}", entry.map_or(own_host, String::as_str));
    Link::Wg { server: server.clone(), peer: WgPeer { endpoint, mtu: mtu(setup.opt(p, MTU_OPT).as_deref()), ..peer.clone() }, ports: ports.clone(), entries: entries.clone() }
}

/// True if an app that went Direct under `old` goes to one of `routes` under `new` (explicitly or by default).
pub fn leaves_direct(old: Option<&Setup>, new: &Setup, routes: &IndexSet<String>) -> bool {
    let Some(old) = old else { return false };
    routes.iter().any(|id| {
        old.apps.keys().chain(new.apps.keys()).any(|k| new.route_of(k) == *id && old.route_of(k) == DIRECT) || (new.default_route == *id && old.default_route == DIRECT)
    })
}

/// A kept or cached tunnel is reused only if its provider still vouches for its server key ([`Provider::trusts`]).
fn trusted<'p>(l: &Link, r: &Route, accounts: &IndexMap<String, String>, providers: &dyn Fn(&str) -> Option<&'p dyn Provider>) -> bool {
    let Some(p) = providers(&r.loc.provider) else { return true };
    let Some(acc) = accounts.get(p.id()) else { return true };
    p.trusts(l, acc)
}

fn fresh<'p>(r: &Route, accounts: &IndexMap<String, String>, last: &IndexMap<String, Link>, used: &IndexSet<String>, providers: &dyn Fn(&str) -> Option<&'p dyn Provider>) -> Result<Link> {
    let p = providers(&r.loc.provider).ok_or_else(|| Error::State(format!("Unknown provider {}", r.loc.provider)))?;
    let acc = accounts.get(p.id()).ok_or_else(|| Error::Auth { message: format!("Sign in to {} for {}", p.name(), r.name()), url: None })?;
    let pinned = r.loc.pinned.as_ref();
    let cached = last.get(&cache_key(r));
    // A pinned server starts from its last refreshed copy, so going offline never brings back older details.
    let loc = match (pinned, cached.map(Link::server)) {
        (Some(pin), Some(s)) if s.host == pin.host => Location { pinned: Some(s.clone()), ..r.loc.clone() },
        _ => r.loc.clone(),
    };
    let tried = match again(p, r, acc, last, used) {
        Ok(Some(l)) => Ok(l),
        Ok(None) => p.connect(&loc, acc),
        Err(e) => Err(e),
    };
    let l = match tried {
        Ok(l) => l,
        Err(e @ (Error::Auth { .. } | Error::NoLongerOffered(_))) => return Err(e),
        Err(e) => match cached.filter(|c| pinned.is_none_or(|pin| c.server().host == pin.host) && trusted(c, r, accounts, providers)) {
            Some(c) => c.clone(),
            None => return Err(pinned.map_or(e, |pin| Error::Fail(format!("{}: {} is unreachable", r.name(), pin.name)))),
        },
    };
    let taken = |s: &Server| used.contains(&format!("{}|{}", p.id(), server_id(s)));
    if pinned.is_some() || !taken(l.server()) {
        return Ok(l);
    }
    let other = p.servers(&r.loc, acc, 10).and_then(|list| match list.into_iter().find(|s| !taken(s)) {
        Some(s) => p.connect(&Location { pinned: Some(s), ..r.loc.clone() }, acc).map(Some),
        None => Ok(None),
    });
    match other {
        Ok(Some(o)) => Ok(o),
        Err(e @ Error::Auth { .. }) => Err(e),
        _ => Ok(l),
    }
}

/// An unpinned route's last WireGuard server once more, while the provider still lists it among its ten best and it
/// isn't avoided: NordVPN gives an account one key ([`Provider::one_key`]), and moving it can leave the tunnel dead for
/// minutes. None, also when that fails for any reason but the account, picks as usual.
fn again(p: &dyn Provider, r: &Route, acc: &str, last: &IndexMap<String, Link>, used: &IndexSet<String>) -> Result<Option<Link>> {
    if !p.one_key() || r.loc.pinned.is_some() {
        return Ok(None);
    }
    let Some(Link::Wg { server, .. }) = last.get(&cache_key(r)) else { return Ok(None) };
    let id = server_id(server);
    if used.contains(&format!("{}|{id}", p.id())) {
        return Ok(None);
    }
    let found = p.servers(&r.loc, acc, 10).and_then(|list| match list.into_iter().find(|s| server_id(s) == id) {
        Some(s) => p.connect(&Location { pinned: Some(s), ..r.loc.clone() }, acc).map(Some),
        None => Ok(None),
    });
    match found {
        Err(e @ Error::Auth { .. }) => Err(e),
        other => Ok(other.unwrap_or(None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::tests::{opts, pairs, strs};
    use crate::model::Country;
    use crate::providers::{Field, as_listed};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn link(sv: &Server) -> Link {
        let peer = WgPeer::new(&sv.name, "priv", strs(&["10.5.0.2/32"]), &sv.public_key, &format!("{}:51820", sv.ip), strs(&["0.0.0.0/0"]));
        Link::Wg { server: sv.clone(), peer, ports: vec![], entries: vec![] }
    }

    fn server(n: &str, ip: Option<&str>) -> Server {
        Server { name: n.into(), host: "shared.example".into(), ip: ip.map_or_else(|| format!("10.0.0.{}", n.len()), String::from), public_key: "pub".into(), load: 0, ..Server::default() }
    }

    fn a() -> Server {
        server("a", None)
    }

    fn b() -> Server {
        server("bb", Some("10.0.0.9"))
    }

    type Connect = Box<dyn Fn(&Location) -> Result<Link> + Send + Sync>;

    /// `best` is what connect() returns for an unpinned location; a pinned one returns its own server. `connect` replaces
    /// that, for a provider that answers otherwise.
    struct Fake {
        best: Vec<Server>,
        online: bool,
        trusted: bool,
        listed: bool,
        id: &'static str,
        connect: Option<Connect>,
    }

    impl Fake {
        fn new(best: Vec<Server>) -> Fake {
            Fake { best, online: true, trusted: true, listed: true, id: "fake", connect: None }
        }
    }

    impl Provider for Fake {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            "Fake"
        }
        fn fields(&self) -> Vec<Field> {
            vec![]
        }
        fn help(&self) -> String {
            String::new()
        }
        fn sign_in(&self, _: &IndexMap<String, String>) -> Result<String> {
            Ok("acc".into())
        }
        fn countries(&self, _: &str) -> Result<Vec<Country>> {
            Ok(vec![])
        }
        fn connect(&self, loc: &Location, _: &str) -> Result<Link> {
            if let Some(f) = &self.connect {
                return f(loc);
            }
            if !self.online {
                return Err(Error::Io("down".into()));
            }
            Ok(link(loc.pinned.as_ref().unwrap_or(&self.best[0])))
        }
        fn servers(&self, _: &Location, _: &str, limit: usize) -> Result<Vec<Server>> {
            if self.online && self.listed { Ok(self.best.iter().take(limit).cloned().collect()) } else { Err(Error::Io("down".into())) }
        }
        fn one_key(&self) -> bool {
            true
        }
        fn trusts(&self, _: &Link, _: &str) -> bool {
            self.trusted
        }
    }

    fn setup(routes: Vec<Route>) -> Setup {
        Setup { default_route: routes[0].id.clone(), apps: routes[1..].iter().map(|r| (format!("app.{}", r.id), r.id.clone())).collect(), routes, ..Setup::default() }
    }

    fn loc(code: &str) -> Location {
        Location { provider: "fake".into(), country_code: Some(code.into()), ..Location::default() }
    }

    fn pinned(code: &str, s: &Server) -> Location {
        Location { pinned: Some(s.clone()), ..loc(code) }
    }

    fn acc() -> IndexMap<String, String> {
        pairs(&[("fake", "acc")])
    }

    fn none<V>() -> IndexMap<String, V> {
        IndexMap::new()
    }

    fn cached(r: &Route, s: &Server) -> IndexMap<String, Link> {
        IndexMap::from([(cache_key(r), link(s))])
    }

    /// Nothing kept or applied, signed in to the fake provider, avoiding `avoid`.
    fn pick_from(s: &Setup, p: &dyn Provider, last: &IndexMap<String, Link>, avoid: &[String]) -> Picked {
        pick(s, &none(), None, &none(), &acc(), last, &avoid.iter().cloned().collect(), &none(), false, &|id| (id == p.id()).then_some(p))
    }

    fn name(p: &Picked, id: &str) -> String {
        p.links[id].server().name.clone()
    }

    fn endpoint(l: &Link) -> String {
        match l {
            Link::Wg { peer, .. } => peer.endpoint.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn unpinned_collision_moves_to_another_server_by_ip_not_hostname() {
        let p = Fake::new(vec![a(), b()]);
        let r = pick_from(&setup(vec![Route::new("1", loc("NL")), Route::new("2", loc("DE"))]), &p, &none(), &[]);
        assert_eq!("a", name(&r, "1"));
        assert_eq!("bb", name(&r, "2"));
    }

    #[test]
    fn pinned_collision_shares_the_server() {
        let p = Fake::new(vec![a(), b()]);
        let r = pick_from(&setup(vec![Route::new("1", pinned("NL", &a())), Route::new("2", pinned("DE", &a()))]), &p, &none(), &[]);
        assert_eq!(a(), *r.links["1"].server());
        assert_eq!(a(), *r.links["2"].server());
    }

    #[test]
    fn pinned_route_never_falls_back_to_another_server() {
        let p = Fake { online: false, ..Fake::new(vec![a(), b()]) };
        let l = pinned("NL", &a());
        let failed = pick_from(&setup(vec![Route::new("1", l.clone())]), &p, &cached(&Route::new("x", pinned("NL", &b())), &b()), &[]);
        assert!(!failed.links.contains_key("1"));
        assert!(matches!(&failed.blocked["1"], Error::Fail(m) if m == "Fastest: a is unreachable"), "{:?}", failed.blocked["1"]);
        assert_eq!(a(), *pick_from(&setup(vec![Route::new("1", l.clone())]), &p, &cached(&Route::new("1", l), &a()), &[]).links["1"].server());
    }

    #[test]
    fn unpinned_route_may_use_the_last_good_tunnel() {
        let p = Fake { online: false, ..Fake::new(vec![a()]) };
        let r = Route::new("1", loc("NL"));
        assert_eq!(a(), *pick_from(&setup(vec![r.clone()]), &p, &cached(&r, &a()), &[]).links["1"].server());
    }

    #[test]
    fn an_untrusted_cached_tunnel_is_not_reused() {
        let p = Fake { online: false, trusted: false, ..Fake::new(vec![a()]) };
        let r = Route::new("1", loc("NL"));
        let out = pick_from(&setup(vec![r.clone()]), &p, &cached(&r, &a()), &[]);
        assert!(out.links.is_empty(), "an untrusted cached tunnel was reused");
        assert_eq!("down", out.blocked["1"].to_string());
    }

    #[test]
    fn an_untrusted_kept_tunnel_is_replaced() {
        let s = setup(vec![Route::new("1", loc("NL"))]);
        let keep = IndexMap::from([("1".to_string(), link(&b()))]);
        let run = |p: &Fake| pick(&s, &keep, Some(&s), &acc(), &acc(), &none(), &IndexSet::new(), &none(), false, &|_| Some(p as &dyn Provider)).links["1"].server().clone();
        assert_eq!(b(), run(&Fake::new(vec![a()])));
        assert_eq!(a(), run(&Fake { trusted: false, ..Fake::new(vec![a()]) }));
    }

    #[test]
    fn pinned_and_unpinned_have_different_cache_keys() {
        assert_ne!(cache_key(&Route::new("1", loc("NL"))), cache_key(&Route::new("1", pinned("NL", &a()))));
        assert_ne!(cache_key(&Route::new("1", pinned("NL", &a()))), cache_key(&Route::new("1", pinned("NL", &b()))));
    }

    #[test]
    fn dead_server_is_avoided() {
        let p = Fake::new(vec![a(), b()]);
        let r = Route::new("1", loc("NL"));
        let dead = server_key(&r, &link(&a()));
        assert_eq!("bb", name(&pick_from(&setup(vec![r]), &p, &none(), &[dead]), "1"));
    }

    #[test]
    fn a_fresh_connect_keeps_the_last_server_while_it_is_still_offered() {
        let r = Route::new("1", loc("NL"));
        let last = cached(&r, &b());
        assert_eq!("bb", name(&pick_from(&setup(vec![r.clone()]), &Fake::new(vec![a(), b()]), &last, &[]), "1"));
        assert_eq!("a", name(&pick_from(&setup(vec![r]), &Fake::new(vec![a()]), &last, &[]), "1"));
    }

    #[test]
    fn a_failed_retry_of_the_last_server_picks_as_usual() {
        let r = Route::new("1", loc("NL"));
        assert_eq!("a", name(&pick_from(&setup(vec![r.clone()]), &Fake { listed: false, ..Fake::new(vec![a(), b()]) }, &cached(&r, &b()), &[]), "1"));
    }

    #[test]
    fn the_last_server_is_left_when_avoided_or_taken_by_another_route() {
        let r = Route::new("1", loc("NL"));
        let p = Fake::new(vec![a(), b()]);
        let last = cached(&r, &b());
        assert_eq!("a", name(&pick_from(&setup(vec![r.clone()]), &p, &last, &[server_key(&r, &link(&b()))]), "1"));
        let first = Route::new("0", pinned("DE", &b()));
        assert_eq!("a", name(&pick_from(&setup(vec![first, r]), &p, &last, &[]), "1"));
    }

    /// A refusal holds: the route stays blocked, and neither the provider nor its cached tunnel is tried again.
    #[test]
    fn a_refused_route_stays_blocked_without_a_cached_tunnel() {
        let p = Fake { online: false, ..Fake::new(vec![a()]) };
        let r = Route::new("1", loc("NL"));
        let refusal = Error::Auth { message: "Sign-in was refused".into(), url: None };
        let out = pick(&setup(vec![r.clone()]), &none(), None, &none(), &acc(), &cached(&r, &a()), &IndexSet::new(), &IndexMap::from([("1".to_string(), refusal)]), false, &|_| Some(&p as &dyn Provider));
        assert!(out.links.is_empty());
        assert!(matches!(&out.blocked["1"], Error::Auth { message, .. } if message == "Sign-in was refused"));
    }

    /// Offline, only tunnels kept as they are and imports come out; everything needing the provider waits blocked.
    #[test]
    fn offline_picking_never_calls_the_provider() {
        let p = Fake { online: false, ..Fake::new(vec![a()]) };
        let s = setup(vec![Route::new("1", loc("NL")), Route::new("2", loc("DE"))]);
        let out = pick(&s, &IndexMap::from([("1".to_string(), link(&a()))]), Some(&s), &acc(), &acc(), &none(), &IndexSet::new(), &none(), true, &|_| Some(&p as &dyn Provider));
        assert_eq!(a(), *out.links["1"].server());
        assert!(waiting(&out.blocked["2"]));
        // A signed-out provider's route is refused at once, offline too: it never waits for a server.
        let signed_out = pick(&s, &none(), None, &none(), &none(), &none(), &IndexSet::new(), &none(), true, &|_| Some(&p as &dyn Provider));
        assert!(signed_out.blocked.values().all(|e| matches!(e, Error::Auth { .. })));
    }

    /// One refusal blocks every route of that provider, also one that could keep its running tunnel.
    #[test]
    fn a_refusal_blocks_the_providers_other_routes_too() {
        let refusing = Fake { connect: Some(Box::new(|_| Err(Error::Auth { message: "Sign-in was refused".into(), url: None }))), ..Fake::new(vec![a()]) };
        let s = setup(vec![Route::new("1", loc("NL")), Route::new("2", loc("DE"))]);
        let out = pick(&s, &IndexMap::from([("1".to_string(), link(&a()))]), Some(&s), &acc(), &acc(), &none(), &IndexSet::new(), &none(), false, &|_| Some(&refusing as &dyn Provider));
        assert!(out.links.is_empty() && out.remember.is_empty());
        assert_eq!(IndexSet::from(["1", "2"]), out.blocked.keys().map(String::as_str).collect::<IndexSet<_>>());
    }

    #[test]
    fn leaving_direct_is_seen_explicitly_and_by_default() {
        let vpn = Route::new("v", Location::of("fake"));
        let v = IndexSet::from(["v".to_string()]);
        let direct_default = Setup { routes: vec![vpn.clone()], default_route: DIRECT.into(), apps: pairs(&[("a", "v")]), ..Setup::default() };
        // Following a Direct default, now sent to the route.
        assert!(leaves_direct(Some(&direct_default), &Setup { apps: pairs(&[("a", "v"), ("b", "v")]), ..direct_default.clone() }, &v));
        // Explicitly Direct, now following a default that is the route (its entry is gone from apps).
        let vpn_default = Setup { routes: vec![vpn], default_route: "v".into(), apps: pairs(&[("b", DIRECT)]), ..Setup::default() };
        assert!(leaves_direct(Some(&vpn_default), &Setup { apps: IndexMap::new(), ..vpn_default.clone() }, &v));
        // The default itself turns from Direct to the route.
        assert!(leaves_direct(Some(&direct_default), &Setup { default_route: "v".into(), ..direct_default.clone() }, &v));
        // Already on the route, or another route waits: nothing leaves Direct for it.
        assert!(!leaves_direct(Some(&direct_default), &direct_default, &v));
        assert!(!leaves_direct(None, &direct_default, &v));
    }

    /// Two imports of one key on one server with other settings: the second is blocked, the first runs.
    #[test]
    fn a_clashing_wire_guard_route_is_blocked() {
        let Link::Wg { peer, .. } = link(&a()) else { unreachable!() };
        let s = setup(vec![Route { wg: Some(peer.clone()), ..Route::new("1", Location::default()) }, Route { wg: Some(WgPeer { mtu: 1200, ..peer }), ..Route::new("2", Location::default()) }]);
        let out = pick(&s, &none(), None, &none(), &none(), &none(), &IndexSet::new(), &none(), false, &|_| None);
        assert_eq!(vec!["1"], out.links.keys().collect::<Vec<_>>());
        assert!(matches!(out.blocked["2"], Error::Fail(_)));
    }

    /// Offline, a pinned server starts from its last refreshed copy (same host), not the older one saved with the route.
    #[test]
    fn an_offline_pinned_server_uses_its_last_refreshed_copy() {
        let asked: Arc<Mutex<Option<Server>>> = Arc::default();
        let seen = asked.clone();
        let p = Fake {
            connect: Some(Box::new(move |l| {
                *seen.lock().unwrap() = l.pinned.clone();
                Ok(link(l.pinned.as_ref().unwrap()))
            })),
            ..Fake::new(vec![a()])
        };
        let r = Route::new("1", pinned("NL", &a()));
        let newer = Server { ip: "10.0.0.77".into(), public_key: "newer".into(), ..a() };
        pick_from(&setup(vec![r.clone()]), &p, &cached(&r, &newer), &[]);
        assert_eq!(Some(newer), *asked.lock().unwrap());
    }

    /// A server no longer offered blocks every route pinned to it in the same pass, whichever asked first.
    #[test]
    fn a_server_no_longer_offered_blocks_every_route_pinned_to_it() {
        let calls = AtomicUsize::new(0);
        let p = Fake {
            connect: Some(Box::new(move |l| if calls.fetch_add(1, Ordering::SeqCst) == 0 { Ok(link(l.pinned.as_ref().unwrap())) } else { Err(Error::NoLongerOffered(a().name)) })),
            ..Fake::new(vec![a()])
        };
        let s = setup(vec![Route::new("1", pinned("NL", &a())), Route::new("2", pinned("DE", &a()))]);
        assert_eq!(IndexSet::from(["1", "2"]), pick_from(&s, &p, &none(), &[]).blocked.keys().map(String::as_str).collect::<IndexSet<_>>());
        // Another host that once had this address is never taken from the cache for it.
        let r = Route::new("3", pinned("NL", &a()));
        let down = Fake { online: false, ..Fake::new(vec![a()]) };
        assert!(pick_from(&setup(vec![r.clone()]), &down, &cached(&r, &Server { host: "other.example".into(), ..a() }), &[]).links.is_empty());
        // The pin decision: as listed now, as saved without a list, gone when the list lacks it.
        let fresh = Server { ip: "10.0.0.88".into(), ..a() };
        assert_eq!(fresh, as_listed(&a(), Some(vec![fresh.clone()])).unwrap());
        assert_eq!(a(), as_listed(&a(), None).unwrap());
        assert!(matches!(as_listed(&a(), Some(vec![Server { host: "elsewhere.example".into(), ..b() }])), Err(Error::NoLongerOffered(_))));
    }

    /// A pinned server the provider no longer lists is blocked, never brought back from the cache.
    #[test]
    fn a_server_no_longer_offered_is_not_taken_from_the_cache() {
        let gone = Fake { connect: Some(Box::new(|_| Err(Error::NoLongerOffered(a().name)))), ..Fake::new(vec![a()]) };
        let r = Route::new("1", pinned("NL", &a()));
        let out = pick_from(&setup(vec![r.clone()]), &gone, &cached(&r, &a()), &[]);
        assert!(out.links.is_empty());
        assert!(matches!(out.blocked["1"], Error::NoLongerOffered(_)));
    }

    #[test]
    fn a_signed_out_providers_route_is_blocked_and_the_others_still_run() {
        let (fake, other) = (Fake::new(vec![a()]), Fake { id: "other", ..Fake::new(vec![b()]) });
        let s = setup(vec![Route::new("1", loc("NL")), Route::new("2", Location { provider: "other".into(), country_code: Some("DE".into()), ..Location::default() })]);
        let r = pick(&s, &none(), None, &none(), &acc(), &none(), &IndexSet::new(), &none(), false, &|id| Some(if id == "fake" { &fake as &dyn Provider } else { &other }));
        assert_eq!(a(), *r.links["1"].server());
        assert!(matches!(r.blocked["2"], Error::Auth { .. }));
        assert!(!r.links.contains_key("2") && r.remember.values().all(|l| l.server().name != "2"));
    }

    /// The entry address the provider page picks, by number; a tunnel without that many entries keeps its own.
    #[test]
    fn entry_follows_the_provider_page() {
        let peer = WgPeer::new("x", "k", strs(&["10.0.0.2/32"]), "p", "198.51.100.1:1637", strs(&["0.0.0.0/0"]));
        let s = setup(vec![Route::new("1", loc("NL")), Route::new("2", loc("DE"))]);
        let links = IndexMap::from([
            ("1".to_string(), Link::Wg { server: a(), peer: peer.clone(), ports: vec![1637, 47107], entries: strs(&["198.51.100.1", "198.51.100.3"]) }),
            ("2".to_string(), Link::Wg { server: a(), peer, ports: vec![], entries: vec![] }),
        ]);
        let at = |s: &Setup, step: &[(&str, usize)]| -> IndexMap<String, String> {
            let step = step.iter().map(|(k, v)| (k.to_string(), *v)).collect();
            ported(s, &links, &step).iter().map(|(id, l)| (id.clone(), endpoint(l))).collect()
        };
        assert_eq!(pairs(&[("1", "198.51.100.1:1637"), ("2", "198.51.100.1:1637")]), at(&s, &[]));
        let alt = Setup { opts: opts("fake", "entry", "2"), ..s.clone() };
        assert_eq!(pairs(&[("1", "198.51.100.3:1637"), ("2", "198.51.100.1:1637")]), at(&alt, &[]));
        assert_eq!("198.51.100.3:47107", at(&alt, &[("fake", 1)])["1"]);
        assert_eq!("198.51.100.1:1637", at(&Setup { opts: opts("fake", "entry", "9"), ..s }, &[])["1"]);
    }

    /// A fixed port wins; Automatic walks the server's ports one step at a time, per provider; imports keep theirs.
    #[test]
    fn ports_follow_the_provider_page() {
        let peer = WgPeer::new("x", "k", strs(&["10.0.0.2/32"]), "p", "198.51.100.1:2049", strs(&["0.0.0.0/0"]));
        let l = Link::Wg { server: a(), peer: peer.clone(), ports: vec![2049, 443, 53], entries: vec![] };
        let s = setup(vec![Route::new("1", loc("NL")), Route { wg: Some(peer.clone()), ..Route::new("2", Location::default()) }]);
        let links = IndexMap::from([("1".to_string(), l.clone()), ("2".to_string(), Link::Wg { server: a(), peer: peer.clone(), ports: vec![1, 2], entries: vec![] })]);
        let steps = |step: &[(&str, usize)]| step.iter().map(|(k, v)| (k.to_string(), *v)).collect::<IndexMap<_, _>>();
        let port = |s: &Setup, step: &[(&str, usize)], id: &str| endpoint(&ported(s, &links, &steps(step))[id]);
        assert_eq!("198.51.100.1:2049", port(&s, &[], "1"));
        assert_eq!("198.51.100.1:443", port(&s, &[("fake", 1)], "1"));
        assert_eq!("198.51.100.1:2049", port(&s, &[("fake", 3)], "1"));
        assert_eq!("198.51.100.1:53", port(&s, &[("other", 1), ("fake", 2)], "1"));
        assert_eq!("198.51.100.1:2049", port(&s, &[("fake", 1)], "2"));
        assert_eq!("198.51.100.1:80", port(&Setup { opts: opts("fake", "port", "80"), ..s.clone() }, &[("fake", 1)], "1"));
        assert_eq!("198.51.100.1:2049", port(&Setup { opts: opts("fake", "port", "99999"), ..s.clone() }, &[], "1"));
        // A tunnel saved without a list (offline) still takes its provider's step, so two on one server never differ.
        let offline = IndexMap::from([("1".to_string(), l), ("3".to_string(), Link::Wg { server: a(), peer, ports: vec![], entries: vec![] })]);
        let s3 = setup(vec![Route::new("1", loc("NL")), Route::new("3", loc("DE"))]);
        assert_eq!(IndexSet::from(["198.51.100.1:443".to_string()]), ported(&s3, &offline, &steps(&[("fake", 1)])).values().map(endpoint).collect::<IndexSet<_>>());
    }

    /// Provider tunnels take their page's MTU (1280 by default, 1280 to 1420); imports keep theirs, at most 1280.
    #[test]
    fn mtu_follows_the_provider_page() {
        let peer = WgPeer::new("x", "k", strs(&["10.0.0.2/32"]), "p", "198.51.100.1:51820", strs(&["0.0.0.0/0"]));
        let small = WgPeer { mtu: 1200, ..peer.clone() };
        let s = setup(vec![Route::new("1", loc("NL")), Route { wg: Some(peer.clone()), ..Route::new("2", Location::default()) }, Route { wg: Some(small.clone()), ..Route::new("3", Location::default()) }]);
        let wg = |p: &WgPeer| Link::Wg { server: a(), peer: p.clone(), ports: vec![], entries: vec![] };
        let links = IndexMap::from([("1".to_string(), wg(&peer)), ("2".to_string(), wg(&peer)), ("3".to_string(), wg(&small))]);
        let mtu = |s: &Setup| -> IndexMap<String, i32> {
            ported(s, &links, &IndexMap::new())
                .into_iter()
                .map(|(id, l)| match l {
                    Link::Wg { peer, .. } => (id, peer.mtu),
                    _ => (id, 0),
                })
                .collect()
        };
        let want = |v: [i32; 3]| IndexMap::from([("1".to_string(), v[0]), ("2".to_string(), v[1]), ("3".to_string(), v[2])]);
        assert_eq!(want([1280, 1280, 1200]), mtu(&s));
        assert_eq!(want([1400, 1280, 1200]), mtu(&Setup { opts: opts("fake", "mtu", "1400"), ..s.clone() }));
        for bad in ["9000", "1000", "x"] {
            assert_eq!(1280, mtu(&Setup { opts: opts("fake", "mtu", bad), ..s.clone() })["1"]);
        }
        assert_eq!(Some("auto".to_string()), s.opt("anything", "mtu"));
    }
}
