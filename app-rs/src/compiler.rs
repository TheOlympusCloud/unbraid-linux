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
