//! The engine's config for a setup: one tunnel per exit, apps routed by their program, DNS through each exit.

use regex::Regex;
use std::sync::LazyLock;

pub const NORD_DNS: &str = "103.86.96.100";
pub const NORD_TP: &str = "103.86.96.108";
pub const TS_TAG: &str = "home-ts";
/// Inbound tag of the app's own way into a chosen exit, for speed and health tests: a proxy on 127.0.0.1 whose user
/// name is the exit's tunnel tag. The app itself leaves the VPN directly, so this is its only path into a tunnel; the
/// password is random per connection, so no other app on the computer can use it.
pub const PROBE: &str = "probe";
pub const CLASH: &str = "Another of your WireGuard connections uses this key on the same server with other settings. Use one config for both.";

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:/(\d{1,2}))?$").unwrap());

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
