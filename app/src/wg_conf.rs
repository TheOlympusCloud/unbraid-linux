//! WireGuard configs: reading a .conf into a peer, with the rules an import must meet.

use crate::compiler::ipv4;
use crate::error::Result;
use crate::manual::{invalid, length, lines, require};
use crate::model::WgPeer;
use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

static KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{43}=$").unwrap());
const AMNEZIA: &[&str] =
    &["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"];
// A [Peer] header at the start of a line (after \n, \r or \r\n), letter case aside.
static PEER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?imR)^[[:space:]]*\[peer\]").unwrap());

/// Parses a wg-quick style .conf (one peer). Fails with [`Error::Invalid`] and a readable reason.
pub fn parse(raw: &str, name: &str) -> Result<WgPeer> {
    let text = raw.strip_prefix('\u{FEFF}').unwrap_or(raw); // a byte-order mark some editors write first
    require!(length(text) <= 16_384, "That file is too large for a WireGuard config");
    require!(PEER.find_iter(text).count() == 1, "Config must have exactly one [Peer]");
    let mut kv: IndexMap<String, String> = IndexMap::new();
    let mut section = String::new();
    for l in lines(text) {
        let line = l.split_once('#').map_or(l, |(before, _)| before).trim();
        if line.starts_with('[') {
            section = line.to_lowercase();
            continue;
        }
        let k = line.split_once('=').map_or("", |(k, _)| k).trim().to_lowercase();
        if k.is_empty() {
            continue;
        }
        require!(!AMNEZIA.contains(&k.as_str()), "Obfuscated (AmneziaWG) configs aren't supported");
        let key = format!("{section}.{k}");
        let v = line.split_once('=').map_or(line, |(_, v)| v).trim();
        match kv.get_mut(&key) {
            Some(had) => {
                had.push(',');
                had.push_str(v);
            }
            None => {
                kv.insert(key, v.to_string());
            }
        }
    }
    let need = |k: &str| {
        kv.get(k)
            .cloned()
            .ok_or_else(|| invalid(format!("Missing {} in the config", k.split_once('.').map_or(k, |(_, n)| n))))
    };
    let list = |k: &str| -> Vec<String> {
        kv.get(k)
            .map_or("", String::as_str)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    };
    let key = |k: &str| -> Result<String> {
        let v = need(k)?;
        require!(KEY.is_match(&v), "Invalid key in the config");
        Ok(v)
    };
    let endpoint = need("[peer].endpoint")?;
    require!(
        endpoint.rsplit(':').next().and_then(|p| p.parse::<i32>().ok()).is_some_and(|p| (1..=65535).contains(&p)),
        "Endpoint needs host:port"
    );
    let private_key = key("[interface].privatekey")?;
    // A bare "10.0.0.2" is a host address; the engine needs the prefix.
    let address: Vec<String> = list("[interface].address")
        .into_iter()
        .filter(|a| !a.contains(':'))
        .map(|a| if a.contains('/') { a } else { format!("{a}/32") })
        .collect();
    require!(!address.is_empty(), "Config has no IPv4 address");
    let public_key = key("[peer].publickey")?;
    let preshared_key = kv.get("[peer].presharedkey").cloned();
    if let Some(k) = &preshared_key {
        require!(KEY.is_match(k), "Invalid key in the config");
    }
    let allowed_ips: Vec<String> = list("[peer].allowedips").into_iter().filter(|a| !a.contains(':')).collect();
    require!(!allowed_ips.is_empty(), "Config has no IPv4 AllowedIPs");
    let dns = list("[interface].dns")
        .into_iter()
        .filter(|d| d.starts_with(|c: char| c.is_ascii_digit()) && !d.contains(':'))
        .collect();
    let mtu = kv.get("[interface].mtu").and_then(|m| m.parse::<i32>().ok()).map_or(1420, |m| m.clamp(1280, 1500));
    let keepalive = match kv.get("[peer].persistentkeepalive") {
        None => None,
        Some(v) if v.eq_ignore_ascii_case("off") => Some(0),
        Some(v) => Some(
            v.parse::<i32>()
                .ok()
                .filter(|n| (0..=65535).contains(n))
                .ok_or_else(|| invalid("Invalid PersistentKeepalive in the config"))?,
        ),
    };
    Ok(WgPeer {
        name: name.into(),
        private_key,
        address,
        public_key,
        preshared_key,
        endpoint,
        allowed_ips,
        dns,
        mtu,
        keepalive,
    })
}

/// Fails unless `p` sends all IPv4 traffic through its peer, as a route (an app's exit) must: 0.0.0.0/0, or ranges
/// that together cover every address (0.0.0.0/1 and 128.0.0.0/1). Subnet-only profiles belong under Home.
pub fn require_full_tunnel(p: &WgPeer) -> Result<()> {
    let mut ranges = p
        .allowed_ips
        .iter()
        .map(|it| {
            let (a, len) = ipv4(it).ok_or_else(|| invalid(format!("AllowedIPs has an invalid range: {it}")))?;
            let start = a & ((0xFFFF_FFFFu64 << (32 - len)) & 0xFFFF_FFFF);
            Ok((start, start + (1u64 << (32 - len))))
        })
        .collect::<Result<Vec<_>>>()?;
    ranges.sort_by_key(|(start, _)| *start);
    let mut covered = 0u64; // every address below this is in some range
    for (start, end) in ranges {
        if start <= covered {
            covered = covered.max(end);
        }
    }
    require!(
        covered >= 1 << 32,
        "{}",
        if p.allowed_ips.iter().any(|it| it.starts_with("0.0.0.0/") || it.starts_with("1.0.0.0/")) {
            "This config leaves out some addresses (private ranges, for example). Use a config whose AllowedIPs is 0.0.0.0/0 for an app's exit".to_string()
        } else {
            format!("This config only reaches {}; import it under Settings → Home instead", p.allowed_ips.join(", "))
        }
    );
    Ok(())
}

/// Standard Base64, padded or not; bits left over at the end are ignored.
const B64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// A WireGuard key: 32 bytes in Base64.
pub fn valid_wg_key(k: &str) -> bool {
    B64.decode(k).is_ok_and(|b| b.len() == 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn rejects<T: std::fmt::Debug>(why: &str, r: Result<T>) {
        match r {
            Err(Error::Invalid(m)) => {
                assert!(m.to_lowercase().contains(&why.to_lowercase()), "'{m}' should mention '{why}'")
            }
            other => panic!("expected rejection mentioning '{why}', got {other:?}"),
        }
    }

    #[test]
    fn wire_guard_import_rules_for_routes_and_amnezia() {
        let key = "A".repeat(43) + "=";
        let conf = |allowed: &str, extra: &str| {
            format!(
                "[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\n{extra}\n[Peer]\nPublicKey = {key}\nEndpoint = 203.0.113.1:51820\nAllowedIPs = {allowed}\n"
            )
        };
        let full = parse(&conf("0.0.0.0/0, ::/0", ""), "x").unwrap();
        require_full_tunnel(&full).unwrap();
        assert_eq!(vec!["0.0.0.0/0"], full.allowed_ips);
        let subnet = parse(&conf("10.0.0.0/24, 192.168.1.0/24", ""), "x").unwrap();
        assert_eq!(vec!["10.0.0.0/24", "192.168.1.0/24"], subnet.allowed_ips);
        rejects(
            "only reaches 10.0.0.0/24, 192.168.1.0/24; import it under Settings → Home",
            require_full_tunnel(&subnet),
        );
        // Ranges that together cover every IPv4 address are a full tunnel too, in any order, overlapping or not.
        for all in [
            "0.0.0.0/1, 128.0.0.0/1",
            "128.0.0.0/1, 0.0.0.0/1",
            "0.0.0.0/2, 64.0.0.0/2, 128.0.0.0/2, 192.0.0.0/2",
            "0.0.0.0/1, 0.0.0.0/0",
            "0.0.0.0/1, 64.0.0.0/2, 128.0.0.0/1",
        ] {
            require_full_tunnel(&parse(&conf(all, ""), "x").unwrap()).unwrap();
        }
        // A malformed range is refused, never silently dropped.
        rejects(
            "invalid range: 999.1.1.1/32",
            require_full_tunnel(&parse(&conf("0.0.0.0/1, 128.0.0.0/1, 999.1.1.1/32", ""), "x").unwrap()),
        );
        rejects("invalid range: 0.0.0.0/33", require_full_tunnel(&parse(&conf("0.0.0.0/33", ""), "x").unwrap()));
        // A gap of even one address, or the official app's "exclude private IPs" list, is not.
        rejects("leaves out some addresses", require_full_tunnel(&parse(&conf("0.0.0.0/1, 128.0.0.0/2, 192.0.0.0/3, 224.0.0.0/4, 240.0.0.0/5, 248.0.0.0/6, 252.0.0.0/7, 254.0.0.0/8, 255.0.0.0/9, 255.128.0.0/10, 255.192.0.0/11, 255.224.0.0/12, 255.240.0.0/13, 255.248.0.0/14, 255.252.0.0/15, 255.254.0.0/16, 255.255.0.0/17, 255.255.128.0/18, 255.255.192.0/19, 255.255.224.0/20, 255.255.240.0/21, 255.255.248.0/22, 255.255.252.0/23, 255.255.254.0/24, 255.255.255.0/25, 255.255.255.128/26, 255.255.255.192/27, 255.255.255.224/28, 255.255.255.240/29, 255.255.255.248/30, 255.255.255.252/31, 255.255.255.254/32", ""), "x").unwrap()));
        rejects("leaves out some addresses", require_full_tunnel(&parse(&conf("0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 224.0.0.0/3", ""), "x").unwrap()));
        for k in ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4", "I1", "I5"] {
            rejects(
                "Obfuscated (AmneziaWG) configs aren't supported",
                parse(&conf("0.0.0.0/0", &format!("{k} = 5")), "x"),
            );
        }
        rejects("AmneziaWG", parse(&conf("0.0.0.0/0", "").replace("Endpoint", "jc = 4\nEndpoint"), "x"));
    }
}
