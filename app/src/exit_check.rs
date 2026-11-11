//! Asks Cloudflare's trace page, through each exit (the app's own way in, [`crate::probe`]), which address it sees.
//! While Routes is on screen, after a connect or a server change; one request per tunnel, never for Direct. Only the
//! address is shown: location databases disagree (a provider's virtual locations most of all), so a country would
//! mislead.

use crate::error::Error;
use crate::model::Server;
use crate::probe;
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// What one exit reported when asked: its public address as Cloudflare saw it, or `ip` none when it couldn't be asked.
/// `engine` and `server` are what ran then, so a later restart or server change retires it.
#[derive(Clone, Debug, PartialEq)]
pub struct ExitReport {
    pub ip: Option<String>,
    pub at: i64,
    pub engine: i32,
    pub server: Option<Server>,
}

/// Cloudflare's own sites, tried in turn: a network or a site rule that stops one rarely stops both.
pub const HOSTS: [&str; 2] = ["www.cloudflare.com", "one.one.one.one"];

static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$").unwrap()
});

/// The trace's address (`ip=`), or none without a well-formed one.
pub fn parse(trace: &str) -> Option<String> {
    let ip = trace.split(['\n', '\r']).find(|l| l.starts_with("ip="))?.split_once('=')?.1.trim();
    (IPV4.is_match(ip) || ipv6(ip)).then(|| ip.to_string())
}

/// A numeric IPv6 address: eight groups of up to four hex digits, or fewer around one "::". Never looked up.
pub fn ipv6(a: &str) -> bool {
    if a.len() > 39 || a.matches(':').count() < 2 || a.contains(":::") {
        return false;
    }
    let parts: Vec<&str> = a.split("::").collect();
    if parts.len() > 2 {
        return false;
    }
    let groups: Vec<Vec<&str>> =
        parts.iter().map(|p| if p.is_empty() { vec![] } else { p.split(':').collect() }).collect();
    if groups.iter().flatten().any(|g| !(1..=4).contains(&g.len()) || !g.chars().all(|c| c.is_ascii_hexdigit())) {
        return false;
    }
    let n: usize = groups.iter().map(Vec::len).sum();
    if parts.len() == 2 { n <= 7 } else { n == 8 }
}

/// One trace through `tag` from `host`; none when it fails, logged by kind only (messages can hold addresses).
async fn trace(tag: &str, host: &'static str) -> Option<String> {
    let t = tag.to_string();
    let traced = probe::cancellable(move |raw| probe::get(&t, host, "/cdn-cgi/trace", 4096, "text/plain", raw))
        .await
        .and_then(|body| parse(&body).ok_or_else(|| Error::State("unexpected answer".into())));
    traced.inspect_err(|e| crate::log::w("Unbraid", &format!("exit check {tag} via {host}: {}", probe::kind(e)))).ok()
}

/// Each tunnel's answer by tag, four at a time; none for one that didn't answer within 20 s. Dropping the future stops
/// every check under way.
pub async fn ask(tags: impl IntoIterator<Item = String>) -> IndexMap<String, Option<String>> {
    let gate = Arc::new(Semaphore::new(4));
    let tags: IndexSet<String> = tags.into_iter().collect();
    let mut asking = JoinSet::new();
    for t in tags.iter().cloned() {
        let gate = gate.clone();
        asking.spawn(async move {
            let _turn = gate.acquire().await;
            let first = async {
                for h in HOSTS {
                    if let Some(ip) = trace(&t, h).await {
                        return Some(ip);
                    }
                }
                None
            };
            let ip = tokio::time::timeout(Duration::from_secs(20), first).await.ok().flatten();
            (t, ip)
        });
    }
    let mut seen: IndexMap<String, Option<String>> = asking.join_all().await.into_iter().collect();
    tags.into_iter()
        .map(|t| {
            let ip = seen.shift_remove(&t).flatten();
            (t, ip)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = "fl=123f45\nh=www.cloudflare.com\nip=203.0.113.42\nts=1792875869.1\nvisit_scheme=https\nuag=unbraid\ncolo=AMS\nloc=NL\ntls=TLSv1.3\n";

    #[test]
    fn reads_the_address() {
        assert_eq!(Some("203.0.113.42".to_string()), parse(TRACE));
        assert_eq!(Some("2001:db8::1".to_string()), parse(&TRACE.replace("203.0.113.42", "2001:db8::1")));
    }

    /// Without a well-formed address there is no report.
    #[test]
    fn malformed_traces_are_refused() {
        assert_eq!(None, parse(&TRACE.replace("ip=203.0.113.42", "ip=999.1.1.1")));
        assert_eq!(None, parse(&TRACE.replace("ip=203.0.113.42", "ip=<b>hi</b>")));
        assert_eq!(None, parse("<html>blocked</html>"));
    }

    #[test]
    fn ipv6_addresses() {
        for ok in ["2001:db8::1", "::1", "fe80::", "2001:0db8:0000:0000:0000:ff00:0042:8329"] {
            assert!(ipv6(ok), "{ok}");
        }
        for bad in ["::::", "1:2", "1:2:3:4:5:6:7:8:9", "2001:db8::1::2", "2001:db8:::1", "12345::1", "g::1", "١::1"] {
            assert!(!ipv6(bad), "{bad}");
        }
    }
}
