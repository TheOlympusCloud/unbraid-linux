//! Whether a tunnel still carries traffic: a STUN binding round trip (a ~100-byte UDP query) through it to either of
//! two servers, or HTTPS. A WireGuard tunnel whose server stopped answering (a key now used by another device on that
//! server, a server taken down) otherwise stays up but silent, and its apps just time out.

use crate::error::Error;
use crate::probe;
use crate::vpn::live;
use indexmap::IndexSet;
use std::time::Duration;
use tokio::task::JoinSet;

const SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// One check's whole budget; a slower answer counts as none.
pub const BUDGET: i64 = 8_000;
/// A failing tunnel is checked again this soon, twice, before waiting for [`RECOVER`].
pub const QUICK: i64 = 10_000;
/// How long a failing tunnel gets to come back on its own server (WireGuard re-handshakes, OpenVPN restarts).
pub const RECOVER: i64 = 60_000;
/// After a dead tunnel was handled, how long before the same route is handled again.
pub const COOLDOWN: i64 = 120_000;
/// No checks this long after a new network, an engine start or a wake from sleep: tunnels are still settling.
pub const GRACE: i64 = 30_000;
/// The computer's awake time falling this far behind real time means it slept in between.
pub const SLEPT: i64 = 6_000;

/// Some networks and providers block STUN, so HTTPS is tried too, from 3 s on; the first answer wins and stops the
/// others. Never takes much longer than [`BUDGET`].
pub async fn reachable(tag: &str) -> bool {
    let mut checks = JoinSet::new();
    for stun in SERVERS {
        let t = tag.to_string();
        checks.spawn(async move { binding(stun, &t).await });
    }
    let t = tag.to_string();
    checks.spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        https(&t).await
    });
    let first = async {
        while let Some(answered) = checks.join_next().await {
            if answered.unwrap_or(false) {
                return true;
            }
        }
        false
    };
    tokio::time::timeout(Duration::from_millis(BUDGET as u64), first).await.unwrap_or(false)
}

/// A TLS handshake with a well-known site through `tag`, over the app's own way into that exit ([`crate::probe`]).
async fn https(tag: &str) -> bool {
    let t = tag.to_string();
    probe::cancellable(move |raw| probe::open(&t, "www.google.com", 443, 5_000, raw, None).map(|c| c.close()))
        .await
        .is_ok()
}

/// Tunnels a round's failures may be blamed on: none when every checked tunnel failed and so did a plain HTTPS request
/// over the computer's own network (`direct`), since then it is that network that is down, not the servers.
pub async fn blame(
    down: IndexSet<String>,
    checked: &IndexSet<String>,
    direct: impl AsyncFnOnce() -> bool,
) -> Option<IndexSet<String>> {
    if !down.is_empty() && down == *checked && !direct().await { None } else { Some(down) }
}

/// A tunnel's latest checks, oldest first (true = answered), as kept for [`dropping`]: the last six.
pub fn record(history: &[bool], ok: bool) -> Vec<bool> {
    let all = [history, &[ok]].concat();
    all[all.len().saturating_sub(6)..].to_vec()
}

/// A tunnel that keeps dropping: three or more of its last six checks failed and it hasn't answered three in a row
/// since. One that stays down is moved to another server instead; this catches the ones that come and go, like two
/// tunnels taking turns on an account with one connection.
pub fn dropping(history: &[bool]) -> bool {
    history.iter().filter(|ok| !**ok).count() >= 3
        && !(history.len() >= 3 && history[history.len() - 3..].iter().all(|ok| *ok))
}

/// A tunnel's run of failed checks: how many, since when and the latest (elapsed-realtime ms). None = all well.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Streak {
    pub fails: i32,
    pub since: i64,
    pub last: i64,
}

pub fn next(s: &Streak, ok: bool, now: i64) -> Streak {
    if ok {
        Streak::default()
    } else {
        Streak { fails: s.fails + 1, since: if s.fails == 0 { now } else { s.since }, last: now }
    }
}

/// When a failing tunnel is checked again on its own: twice [`QUICK`] apart, then once [`RECOVER`] after its first
/// failure, never before `hold`. None = only with the regular rounds.
pub fn due(s: &Streak, hold: i64) -> Option<i64> {
    if s.fails == 0 {
        None
    } else if s.fails < 3 {
        Some((s.last + QUICK).max(hold))
    } else {
        Some((s.since + RECOVER).max(hold))
    }
}

/// Dead: four failures over at least [`RECOVER`], so it had its chance to come back on the same server.
pub fn dead(s: &Streak, now: i64, hold: i64) -> bool {
    s.fails >= 4 && now - s.since >= RECOVER && now >= hold
}

/// One HTTPS request over `network` itself, past every tunnel: the engine sends the app's own traffic out directly.
pub async fn direct(network: Option<&str>) -> bool {
    if network.is_none() {
        return false;
    }
    tokio::task::spawn_blocking(|| match crate::http::get("https://www.google.com/generate_204", &[], None, None) {
        Ok(_) => true,
        // A redirect off HTTPS isn't followed, but it is an answer.
        Err(Error::Status { code }) => (200..=399).contains(&code),
        Err(_) => false,
    })
    .await
    .unwrap_or(false)
}

async fn binding(stun: &str, tag: &str) -> bool {
    // The STUN server's name is looked up through the tunnel's own DNS server, never the computer's network (an engine
    // patch reads "<dns server>|<host:port>"); a tunnel whose DNS server isn't known relies on HTTPS.
    let Some(dns) = live().tunnel_dns.read().unwrap().get(tag).cloned() else { return false };
    let server = format!("{dns}|{stun}");
    // The first answer with our outside address is enough: the NAT-type phases after it aren't needed.
    let first = async {
        let mut progress = crate::engine::get().stun(&server, tag).await.ok()?;
        while let Some(p) = progress.message().await.ok()? {
            if !p.external_addr.is_empty() || !p.error.is_empty() || p.is_final {
                return Some(p.error.is_empty());
            }
        }
        None
    };
    tokio::time::timeout(Duration::from_millis(BUDGET as u64), first).await.ok().flatten().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(s: &[&str]) -> IndexSet<String> {
        s.iter().map(|t| t.to_string()).collect()
    }

    async fn blamed(down: &[&str], checked: &[&str], direct: bool) -> Option<IndexSet<String>> {
        let (down, checked) = (set(down), set(checked));
        let mut asked = false;
        let r = blame(down.clone(), &checked, async || {
            asked = true;
            direct
        })
        .await;
        // The computer's own network is only checked when every tunnel failed.
        assert_eq!(!down.is_empty() && down == checked, asked);
        r
    }

    #[tokio::test]
    async fn every_tunnel_down_with_the_network_down_blames_no_server() {
        assert_eq!(None, blamed(&["a"], &["a"], false).await);
        assert_eq!(None, blamed(&["a", "b"], &["a", "b"], false).await);
    }

    #[tokio::test]
    async fn every_tunnel_down_while_the_network_works_blames_them() {
        assert_eq!(Some(set(&["a"])), blamed(&["a"], &["a"], true).await);
    }

    #[tokio::test]
    async fn some_partial_or_no_failures_need_no_network_check() {
        assert_eq!(Some(set(&["a"])), blamed(&["a"], &["a", "b"], false).await);
        assert_eq!(Some(set(&[])), blamed(&[], &["a"], false).await);
    }

    /// On and off counts once three of the last six checks failed, and clears after three answers in a row.
    #[test]
    fn keeps_dropping() {
        let h = |ok: &[bool]| ok.iter().fold(vec![], |acc, b| record(&acc, *b));
        assert!(!dropping(&h(&[true, false, true, false, true])));
        assert!(dropping(&h(&[true, false, true, false, true, false])));
        assert!(dropping(&h(&[false, true, false, true, false])));
        assert!(!dropping(&h(&[false, true, false, true, false, true, true, true])));
        assert!(dropping(&h(&[false, false, false]))); // dead too: moved by the other rule, flagged meanwhile
        assert_eq!(6, h(&[true, true, true, true, true, true, true, false]).len());
    }

    /// A failing tunnel: checked again after 10 and 20 s, then a minute after its first failure; dead only then.
    #[test]
    fn a_failing_tunnel_gets_a_minute_on_its_own_server() {
        let mut s = Streak::default();
        assert_eq!(None, due(&s, 0));
        s = next(&s, false, 1_000);
        assert_eq!(Some(11_000), due(&s, 0));
        s = next(&s, false, 11_000);
        assert_eq!(Some(21_000), due(&s, 0));
        s = next(&s, false, 21_000);
        assert_eq!(Some(61_000), due(&s, 0));
        assert!(!dead(&s, 61_000, 0));
        s = next(&s, false, 61_000);
        assert!(dead(&s, 61_000, 0));
        // One answer ends the streak.
        assert_eq!(Streak::default(), next(&s, true, 62_000));
    }

    /// A regular round before the minute is up counts, but doesn't end the minute early.
    #[test]
    fn a_regular_round_doesnt_shorten_the_minute() {
        let mut s = Streak::default();
        for now in [0, 10_000, 20_000, 48_000] {
            s = next(&s, false, now);
        }
        assert!(!dead(&s, 48_000, 0));
        assert_eq!(Some(60_000), due(&s, 0));
        s = next(&s, false, 60_000);
        assert!(dead(&s, 60_000, 0));
        // One just before the minute doesn't push the deadline back.
        let mut late = Streak::default();
        for now in [0, 10_000, 20_000, 58_000] {
            late = next(&late, false, now);
        }
        assert_eq!(Some(60_000), due(&late, 0));
    }

    /// A route handled moments ago waits for its cooldown, and isn't checked on its own before then.
    #[test]
    fn a_held_route_waits_for_its_cooldown() {
        let mut s = Streak::default();
        for now in [0, 10_000, 20_000, 60_000] {
            s = next(&s, false, now);
        }
        let hold = 60_000 + COOLDOWN;
        assert!(!dead(&s, 70_000, hold));
        assert_eq!(Some(hold), due(&s, hold));
        assert!(dead(&next(&s, false, hold), hold, hold));
        assert_eq!(Some(hold), due(&next(&Streak::default(), false, 0), hold)); // quick re-checks wait too
    }
}
