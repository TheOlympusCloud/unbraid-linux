//! Imported servers: WireGuard and OpenVPN files, Shadowsocks links, and the engine's endpoints for them.
//!
//! Manually configured servers: OpenVPN (.ovpn) and Shadowsocks (ss:// links) → sing-box JSON. Input that can't be
//! used fails with [`Error::Invalid`] and a readable reason.

use crate::error::{Error, Result};
use crate::model::{OvpnProfile, SsProfile, eq_ignore_case};
use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::LazyLock;

/// Fails with [`Error::Invalid`] and the formatted reason unless `ok`.
macro_rules! require {
    ($ok:expr, $($why:tt)+) => {
        if !$ok {
            return Err($crate::error::Error::Invalid(format!($($why)+)));
        }
    };
}
pub(crate) use require;

pub(crate) fn invalid(why: impl Into<String>) -> Error {
    Error::Invalid(why.into())
}

/// A text's length as the size limits count it: in UTF-16 units.
pub(crate) fn length(s: &str) -> usize {
    s.encode_utf16().count()
}

static LINE_BREAK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r\n|\n|\r").unwrap());

/// The lines of `s`, broken at "\r\n", "\n" or "\r"; a text that ends with a line break ends with an empty line.
pub(crate) fn lines(s: &str) -> impl Iterator<Item = &str> {
    LINE_BREAK.split(s)
}

const MAX_OVPN: usize = 256 * 1024;
const DEFAULT_CIPHERS: [&str; 3] = ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];
static CIPHERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:AES-(128|192|256)-(CBC|GCM)|CHACHA20-POLY1305|(CAMELLIA|ARIA)-(128|192|256)-CBC)$").unwrap()
});
const DIGESTS: &[&str] = &["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"];
static PEM_BEGIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-----BEGIN ([A-Za-z0-9 ]+)-----").unwrap());
const TLS_VERSIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];
const PROFILES: &[&str] = &["legacy", "preferred", "insecure", "suiteb"];
const MAX_SS_LINK: usize = 8 * 1024;
const MAX_SS_USERINFO: usize = 1024;
const MAX_SS_NAME: usize = 128;
const MAX_HOST: usize = 253;

/// The TLS 1.2 suites sing-openvpn's `tls.cipher` accepts, by OpenSSL and by IANA name.
const TLS_CIPHERS: &str = concat!(
    "RC4-SHA DES-CBC3-SHA AES128-SHA AES256-SHA AES128-SHA256 AES128-GCM-SHA256 AES256-GCM-SHA384 ",
    "ECDHE-ECDSA-AES128-SHA ECDHE-ECDSA-AES256-SHA ECDHE-ECDSA-RC4-SHA ECDHE-RSA-RC4-SHA ECDHE-RSA-DES-CBC3-SHA ",
    "ECDHE-RSA-AES128-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ",
    "ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ",
    "ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ",
    "TLS_RSA_WITH_RC4_128_SHA TLS_RSA_WITH_3DES_EDE_CBC_SHA TLS_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_CBC_SHA ",
    "TLS_RSA_WITH_AES_128_CBC_SHA256 TLS_RSA_WITH_AES_128_GCM_SHA256 TLS_RSA_WITH_AES_256_GCM_SHA384 ",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA ",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
);

#[rustfmt::skip]
const USED: &[&str] = &[
    "client", "tls-client", "pull", "remote", "remote-random", "port", "rport", "proto", "dev", "dev-type", "ca", "cert", "key",
    "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "auth-user-pass", "auth-retry", "cipher", "data-ciphers", "ncp-ciphers",
    "data-ciphers-fallback", "ncp-disable", "auth", "remote-cert-tls", "remote-cert-eku", "remote-cert-ku", "ns-cert-type", "x509-username-field",
    "verify-x509-name", "tls-version-min", "tls-version-max", "tls-cert-profile", "comp-lzo", "compress", "allow-compression",
    "mssfix", "fragment", "tun-mtu", "reneg-sec", "reneg-bytes", "reneg-pkts", "ping", "ping-restart", "keepalive", "tls-timeout",
    "hand-window", "explicit-exit-notify", "replay-window", "peer-fingerprint", "key-method", "tls-cipher", "pull-filter", "compat-mode",
];

/// Directives that only affect the host OS, routing, logging or scripts; sing-box decides routing itself, scripts never run.
#[rustfmt::skip]
const IGNORED: &[&str] = &[
    "nobind", "persist-key", "persist-tun", "persist-local-ip", "persist-remote-ip", "resolv-retry", "verb", "mute", "mute-replay-warnings",
    "connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout", "auth-nocache", "fast-io", "float", "sndbuf", "rcvbuf",
    "socket-flags", "tcp-nodelay", "tcp-queue-limit", "txqueuelen", "user", "group", "daemon", "log", "log-append", "syslog", "status",
    "suppress-timestamps", "script-security", "up", "down", "up-restart", "down-pre", "route-up", "route-pre-down", "ipchange", "setenv",
    "setenv-safe", "route", "route-ipv6", "route-gateway", "route-metric", "route-delay", "route-method", "route-noexec", "route-nopull",
    "redirect-gateway", "redirect-private", "block-outside-dns", "dhcp-option", "dhcp-renew", "dhcp-release", "register-dns",
    "ifconfig-noexec", "ifconfig-nowarn", "push-peer-info", "disable-occ", "ignore-unknown-option", "remote-random-hostname",
    "tls-exit", "ping-exit", "ping-timer-rem", "inactive", "lport", "local", "bind", "topology",
    "tun-ipv6", "mlock", "mtu-disc", "mtu-test", "link-mtu", "tun-mtu-extra", "dev-node", "ip-win32", "win-sys", "keysize",
    "opt-verify", "dns", "allow-pull-fqdn", "tran-window", "auth-token", "show-ciphers",
];

const REJECTED: &[(&str, &str)] = &[
    ("pkcs12", "PKCS#12 bundles aren't supported; use a .ovpn with inline <ca>, <cert> and <key> blocks"),
    ("secret", "Static-key (secret) profiles aren't supported"),
    ("mode", "Only client profiles are supported"),
    ("tls-server", "Only client profiles are supported"),
    ("server", "Only client profiles are supported"),
    ("http-proxy", "OpenVPN over an HTTP proxy isn't supported"),
    ("socks-proxy", "OpenVPN over a SOCKS proxy isn't supported"),
    ("plugin", "OpenVPN plugins aren't supported"),
    ("crl-verify", "crl-verify isn't supported"),
    ("static-challenge", "Interactive (2FA) logins aren't supported"),
    ("auth-user-pass-verify", "Only client profiles are supported"),
    ("ifconfig", "Static tunnel addresses aren't supported"),
    ("connection", "<connection> blocks aren't supported"),
    ("askpass", "Encrypted private keys aren't supported"),
    ("capath", "capath isn't supported; embed the CA in a <ca> block"),
    ("cryptoapicert", "Windows certificate store isn't supported"),
    ("management", "Management interface isn't supported"),
    (
        "tls-ciphersuites",
        "tls-ciphersuites (a TLS 1.3 cipher restriction) can't be enforced; remove it from the profile",
    ),
];

fn rejected(k: &str) -> Option<&'static str> {
    REJECTED.iter().find(|(name, _)| *name == k).map(|(_, why)| *why)
}

const BLOCKS: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "dh",
    "extra-certs",
    "auth-user-pass",
    "peer-fingerprint",
];

const PULL_ACTIONS: &[&str] = &["accept", "ignore", "reject"];
const SERVER_EKU: &[&str] = &["serverauth", "tls web server authentication", "1.3.6.1.5.5.7.3.1"];
const CLIENT_EKU: &[&str] = &["clientauth", "tls web client authentication", "1.3.6.1.5.5.7.3.2"];

static COMPAT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$").unwrap());
static FINGERPRINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").unwrap());
static KU: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(0x)?[0-9a-fA-F]+$").unwrap());

/// `seq` keeps every directive in file order, for options where a later one overrides an earlier one of another name.
#[derive(Default)]
struct Cfg {
    d: IndexMap<String, Vec<Vec<String>>>,
    blocks: IndexMap<String, String>,
    seq: Vec<(String, Vec<String>)>,
}

impl Cfg {
    fn has(&self, k: &str) -> bool {
        self.d.contains_key(k)
    }
    fn arg(&self, k: &str) -> Option<&str> {
        self.arg_at(k, 0)
    }
    fn arg_at(&self, k: &str, i: usize) -> Option<&str> {
        self.d.get(k)?.last()?.get(i).map(String::as_str)
    }
    /// The last of every `k` directive, all names together.
    fn last(&self, k: &[&str]) -> Option<&(String, Vec<String>)> {
        self.seq.iter().rev().find(|(name, _)| k.contains(&name.as_str()))
    }
    fn all(&self, k: &str) -> impl Iterator<Item = &Vec<String>> {
        self.d.get(k).into_iter().flatten()
    }
}

fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut active = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' {
                cur.push(chars.next().unwrap_or(c));
            } else {
                cur.push(c);
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
            active = true;
        } else if c.is_whitespace() {
            if active {
                out.push(std::mem::take(&mut cur));
                active = false;
            }
        } else if !active && (c == '#' || c == ';') {
            return out;
        } else if c == '\\' {
            cur.push(chars.next().unwrap_or(c));
            active = true;
        } else {
            cur.push(c);
            active = true;
        }
    }
    if active {
        out.push(cur);
    }
    out
}

fn read(text: &str) -> Result<Cfg> {
    let mut c = Cfg::default();
    let mut open: Option<String> = None;
    let mut buf = String::new();
    for raw in lines(text.strip_prefix('\u{FEFF}').unwrap_or(text)) {
        let line = raw.trim();
        if let Some(o) = &open {
            if line == format!("</{o}>") {
                c.blocks.insert(o.clone(), std::mem::take(&mut buf));
                open = None;
            } else {
                buf.push_str(if o == "auth-user-pass" { raw } else { line });
                buf.push('\n');
            }
            continue;
        }
        let t = tokens(line);
        if t.is_empty() {
            continue;
        }
        if t.len() == 1 && t[0].starts_with('<') && t[0].ends_with('>') && !t[0].starts_with("</") {
            open = Some(t[0][1..t[0].len() - 1].to_string());
            continue;
        }
        let name = t[0].strip_prefix("--").unwrap_or(&t[0]).to_string();
        let args = t[1..].to_vec();
        c.d.entry(name.clone()).or_default().push(args.clone());
        c.seq.push((name, args));
    }
    if let Some(o) = open {
        return Err(invalid(format!("Unterminated <{o}> block")));
    }
    Ok(c)
}

/// The PEM sections of `block`, each from its BEGIN line to the first END line of the same label.
fn pem_sections(block: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(m) = PEM_BEGIN.captures_at(block, at) {
        let begin = m.get(0).unwrap();
        let end = format!("-----END {}-----", &m[1]);
        match block[begin.end()..].find(&end) {
            Some(i) => {
                at = begin.end() + i + end.len();
                found.push(&block[begin.start()..at]);
            }
            None => at = begin.start() + 1,
        }
    }
    found
}

fn pems(name: &str, block: &str) -> Result<String> {
    require!(!block.contains("ENCRYPTED") && !block.contains("Proc-Type"), "Encrypted private keys aren't supported");
    let found: Vec<String> =
        pem_sections(block).into_iter().map(|p| lines(p).map(str::trim).collect::<Vec<_>>().join("\n")).collect();
    require!(!found.is_empty(), "The <{name}> block is empty or malformed");
    Ok(found.join("\n"))
}

fn network(s: &str) -> Result<String> {
    let n = s.to_lowercase();
    let n = n.strip_suffix("-client").unwrap_or(&n);
    require!(["udp", "udp4", "udp6", "tcp", "tcp4", "tcp6"].contains(&n), "Unsupported protocol: {s}");
    Ok(n.to_string())
}

fn seconds(k: &str, v: &str) -> Result<String> {
    match v.parse::<i32>() {
        Ok(n) if n >= 0 => Ok(format!("{n}s")),
        _ => Err(invalid(format!("Invalid {k} value"))),
    }
}

fn ciphers(k: &str, v: &str) -> Result<Vec<String>> {
    v.to_uppercase()
        .split(':')
        .filter(|c| !c.is_empty())
        .map(|c| {
            require!(
                CIPHERS.is_match(c),
                "Unsupported cipher in {k}: {c} (use AES-GCM, ChaCha20 or an AES/Camellia/ARIA CBC cipher)"
            );
            Ok(c.to_string())
        })
        .collect()
}

fn put(o: &mut Map<String, Value>, k: &str, v: impl Into<Value>) {
    o.insert(k.to_string(), v.into());
}

/// Validates a .ovpn and keeps it with its login.
pub fn parse_ovpn(text: &str, name: &str, username: &str, password: &str) -> Result<OvpnProfile> {
    let p =
        OvpnProfile { name: name.into(), config: text.into(), username: username.into(), password: password.into() };
    build("check", &p)?;
    Ok(p)
}

const RISK: &str = " Someone between you and this server may be able to read or change your traffic. Import it only if the server can't be updated.";

/// What weakens `p`'s encryption, or none. Old servers can need it, so the user is warned and may import anyway.
pub fn ovpn_weakness(p: &OvpnProfile) -> Result<Option<String>> {
    let c = read(&p.config)?;
    let issues: Vec<&str> = [
        ("allows TLS 1.0 or 1.1", matches!(c.arg("tls-version-min"), Some("1.0" | "1.1"))),
        (
            "allows the broken RC4 or 3DES ciphers",
            c.arg("tls-cipher").unwrap_or("").split(':').any(|s| s.contains("RC4") || s.contains("3DES") || s.contains("DES-CBC3")),
        ),
        ("accepts weak server certificates (tls-cert-profile insecure)", c.arg("tls-cert-profile") == Some("insecure")),
        ("doesn't check that it reaches the right server (no remote-cert-tls server, verify-x509-name or peer-fingerprint)", !checks_server(&c)),
    ]
    .into_iter()
    .filter_map(|(issue, applies)| applies.then_some(issue))
    .collect();
    Ok((!issues.is_empty()).then(|| format!("This config {}.{RISK}", issues.join(", "))))
}

/// Whether the server's certificate must be a server's (by its key usage, the last of remote-cert-tls and
/// remote-cert-eku deciding) or this one by name or fingerprint. The CA alone also signs every customer's certificate.
fn checks_server(c: &Cfg) -> bool {
    let role = c.last(&["remote-cert-eku", "remote-cert-tls"]).is_some_and(|(k, a)| match &a[..] {
        [v] if k == "remote-cert-tls" => v.to_lowercase() == "server",
        [v] => SERVER_EKU.contains(&v.to_lowercase().as_str()),
        _ => false,
    });
    role || c.arg("ns-cert-type") == Some("server")
        || c.arg("verify-x509-name").is_some_and(|v| !v.is_empty())
        || c.all("peer-fingerprint").any(|a| !a.is_empty())
        || c.blocks.get("peer-fingerprint").is_some_and(|b| !b.trim().is_empty())
}

/// Stream ciphers have no integrity check (see [`ovpn_weakness`] for OpenVPN).
pub fn ss_weakness(p: &SsProfile) -> Option<String> {
    if p.method.contains("gcm") || p.method.contains("poly1305") {
        None
    } else {
        Some(format!("{} has no integrity check.{RISK}", p.method))
    }
}

/// A sing-box `openvpn-client` endpoint for `p`.
pub fn ovpn_endpoint(tag: &str, p: &OvpnProfile) -> Result<Map<String, Value>> {
    build(tag, p)
}

/// Where a profile connects: its remotes plus the default port and protocol, as parsed (inline blocks never count).
pub fn ovpn_servers(p: &OvpnProfile) -> Vec<String> {
    let Ok(c) = read(&p.config) else { return vec![] };
    let mut servers: Vec<String> = c.all("remote").map(|a| a.join(" ")).collect();
    servers.extend(c.last(&["port", "rport"]).and_then(|(_, a)| a.first()).cloned());
    servers.extend(c.arg("proto").map(String::from));
    servers
}

/// The login to use: what was typed wins; otherwise the profile's inline `<auth-user-pass>` block (username line, password line).
fn login(p: &OvpnProfile, inline: Option<&str>) -> (String, String) {
    let Some(inline) = inline.filter(|_| p.username.trim().is_empty() && p.password.is_empty()) else {
        return (p.username.clone(), p.password.clone());
    };
    let l: Vec<&str> = lines(inline).filter(|l| !l.trim().is_empty()).collect();
    if l.len() >= 2 { (l[0].trim().to_string(), l[1].to_string()) } else { (String::new(), String::new()) }
}

fn build(tag: &str, p: &OvpnProfile) -> Result<Map<String, Value>> {
    require!(length(&p.config) <= MAX_OVPN, "That file is too large for an OpenVPN config");
    let c = read(&p.config)?;
    for k in c.d.keys() {
        if let Some(why) = rejected(k) {
            return Err(invalid(why));
        }
        require!(USED.contains(&k.as_str()) || IGNORED.contains(&k.as_str()), "Unsupported OpenVPN option: {k}");
    }
    for k in c.blocks.keys() {
        if let Some(why) = rejected(k) {
            return Err(invalid(why));
        }
        require!(BLOCKS.contains(&k.as_str()), "Unsupported OpenVPN block: <{k}>");
    }
    require!(c.has("client") || (c.has("tls-client") && c.has("pull")), "Not a client profile (no 'client' line)");
    let dev = c.arg("dev");
    let dev_type = c.arg("dev-type");
    require!(
        matches!(dev_type, None | Some("tun")) && dev.map_or(dev_type == Some("tun"), |d| d.starts_with("tun")),
        "Only tun (layer 3) profiles are supported"
    );
    require!(matches!(c.arg("key-method"), None | Some("2")), "Unsupported key-method");

    let default_port = match c.last(&["port", "rport"]).and_then(|(_, a)| a.first()) {
        Some(it) => it.parse::<i32>().map_err(|_| invalid(format!("Invalid port: {it}")))?,
        None => 1194,
    };
    let default_net = network(c.arg("proto").unwrap_or("udp"))?;
    let mut remotes = Vec::new();
    for a in c.all("remote") {
        let host = a.first().map_or("", String::as_str);
        require!(!host.trim().is_empty(), "Empty remote host");
        let port = match a.get(1) {
            Some(it) => it.parse::<i32>().map_err(|_| invalid(format!("Invalid remote port: {it}")))?,
            None => default_port,
        };
        require!((1..=65535).contains(&port), "Remote port out of range: {port}");
        let net = match a.get(2) {
            Some(n) => network(n)?,
            None => default_net.clone(),
        };
        remotes.push((host.to_string(), port, net));
    }
    require!(!remotes.is_empty(), "The profile has no 'remote' server");

    require!(!c.has("ca") || c.blocks.contains_key("ca"), "The CA must be inline (<ca> block), not a file path");
    for k in ["cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"] {
        require!(!c.has(k) || c.blocks.contains_key(k), "{k} must be inline (<{k}> block), not a file path");
    }
    let mut fingerprints: Vec<String> = c.all("peer-fingerprint").filter_map(|a| a.first().cloned()).collect();
    fingerprints.extend(
        lines(c.blocks.get("peer-fingerprint").map_or("", String::as_str))
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(String::from),
    );
    require!(c.blocks.contains_key("ca") || !fingerprints.is_empty(), "The profile has no <ca> block");
    require!(
        c.blocks.contains_key("cert") == c.blocks.contains_key("key"),
        "The profile needs both <cert> and <key>, or neither"
    );
    let wraps: Vec<&str> =
        ["tls-auth", "tls-crypt", "tls-crypt-v2"].into_iter().filter(|w| c.blocks.contains_key(*w)).collect();
    require!(wraps.len() <= 1, "Use only one of tls-auth, tls-crypt and tls-crypt-v2");

    require!(
        !c.blocks.contains_key("extra-certs") || c.blocks.contains_key("cert"),
        "<extra-certs> needs a <cert> block"
    );

    let needs_login = c.has("auth-user-pass") || c.blocks.contains_key("auth-user-pass");
    let (user, pass) = login(p, c.blocks.get("auth-user-pass").map(String::as_str));
    require!(
        !needs_login || (!user.trim().is_empty() && !pass.is_empty()),
        "This profile needs a username and password"
    );

    let compat = match c.arg("compat-mode") {
        Some(v) => match COMPAT.captures(v) {
            Some(m) => {
                let n = |i: usize| m[i].parse::<i32>().unwrap_or(0);
                n(1) * 10000 + n(2) * 100 + n(3)
            }
            None => return Err(invalid(format!("Invalid compat-mode: {v}"))),
        },
        None => 0,
    };
    let before24 = (1..20400).contains(&compat);
    let before25 = (1..20500).contains(&compat);
    let single = |k: &str, v: &str| -> Result<String> {
        match &ciphers(k, v)?[..] {
            [one] => Ok(one.clone()),
            _ => Err(invalid(format!("Invalid {k} value"))),
        }
    };
    // OpenVPN stores `cipher` and `data-ciphers-fallback` in one slot, so whichever comes last names the cipher.
    let named = c
        .seq
        .iter()
        .filter(|(k, _)| k == "cipher" || k == "data-ciphers-fallback")
        .map(|(k, a)| single(k, a.first().map_or("", String::as_str)))
        .collect::<Result<Vec<_>>>()?
        .pop();
    let explicit = c.arg("data-ciphers").or(c.arg("ncp-ciphers")).map(|v| ciphers("data-ciphers", v)).transpose()?;
    let pinned = if c.has("ncp-disable") {
        let cipher = c.arg("cipher").map(|v| single("cipher", v)).transpose()?;
        Some(vec![cipher.ok_or_else(|| invalid("ncp-disable needs a cipher line"))?])
    } else {
        None
    };
    require!(
        !before24 || named.is_some(),
        "compat-mode below 2.4.0 needs a cipher line (the old BF-CBC default isn't supported)"
    );
    // OpenVPN 2.6 negotiates only from data-ciphers; a lone `cipher` is the fallback only for compat-mode < 2.4.0 or data-ciphers-fallback.
    let fallback = match &pinned {
        Some(p) => Some(p[0].clone()),
        None => named.clone().filter(|_| c.has("data-ciphers-fallback") || before24),
    };
    let base = explicit.clone().unwrap_or_else(|| DEFAULT_CIPHERS.map(String::from).to_vec());
    let data_ciphers = match pinned {
        Some(p) => Some(p),
        None => {
            let list = match &named {
                Some(n) if before25 && !base.contains(n) => [base, vec![n.clone()]].concat(),
                _ => base,
            };
            (explicit.is_some() || list != DEFAULT_CIPHERS).then_some(list)
        }
    };
    let tls_cipher = c.arg("tls-cipher");
    if let Some(bad) = tls_cipher.and_then(|v| v.split(':').find(|s| !TLS_CIPHERS.split(' ').any(|t| t == *s))) {
        return Err(invalid(format!(
            "Unsupported tls-cipher: {bad} (only the TLS 1.2 suites sing-box implements, by OpenSSL or IANA name)"
        )));
    }
    let auth = c.arg("auth").map(str::to_uppercase);
    if let Some(a) = &auth {
        require!(DIGESTS.contains(&a.as_str()), "Unsupported auth digest: {a}");
    }

    let lzo = if c.has("comp-lzo") {
        let v = c.arg("comp-lzo").unwrap_or("adaptive").to_lowercase();
        require!(["yes", "no", "adaptive", "asym"].contains(&v.as_str()), "Unsupported comp-lzo value: {v}");
        Some(v)
    } else {
        None
    };
    let compress = if c.has("compress") {
        let v = c.arg("compress").unwrap_or("stub").to_lowercase();
        require!(["stub", "stub-v2", "lz4", "lz4-v2"].contains(&v.as_str()), "Unsupported compression: compress {v}");
        Some(v)
    } else {
        None
    };
    let compressing =
        lzo.as_deref().is_some_and(|l| l != "no") || compress.as_deref().is_some_and(|v| v.starts_with("lz4"));
    let allow = c.arg("allow-compression");
    if let Some(a) = allow {
        require!(["no", "asym", "yes"].contains(&a), "Invalid allow-compression");
    }
    require!(
        !compressing || allow != Some("no"),
        "allow-compression no conflicts with the compression in this profile"
    );

    let tcp = remotes.iter().any(|(_, _, net)| net.starts_with("tcp"));
    let fragment = c
        .arg("fragment")
        .map(|f| f.parse::<i32>().ok().filter(|n| *n >= 68).ok_or_else(|| invalid("Invalid fragment value")))
        .transpose()?;
    require!(fragment.is_none() || !tcp, "fragment only works over UDP");
    let mtu = c
        .arg("tun-mtu")
        .map(|m| {
            m.parse::<i32>().ok().filter(|n| (576..=9000).contains(n)).ok_or_else(|| invalid("Invalid tun-mtu value"))
        })
        .transpose()?;

    let mut o = Map::new();
    put(&mut o, "type", "openvpn-client");
    put(&mut o, "tag", tag);
    if let [(host, port, net)] = &remotes[..] {
        put(&mut o, "server", host.as_str());
        put(&mut o, "server_port", *port);
        put(&mut o, "network", net.as_str());
    } else {
        put(
            &mut o,
            "servers",
            remotes
                .iter()
                .map(|(host, port, net)| json!({"server": host, "server_port": port, "network": net}))
                .collect::<Vec<_>>(),
        );
        if c.has("remote-random") {
            put(&mut o, "remote_random", true);
        }
    }
    if needs_login {
        put(&mut o, "username", user);
        put(&mut o, "password", pass);
    }
    if let Some(r) = c.arg("auth-retry") {
        require!(["none", "nointeract", "interact"].contains(&r), "Invalid auth-retry");
        put(&mut o, "auth_retry", r);
    }

    let mut t = Map::new();
    if let Some(a) = c.d.get("verify-x509-name").and_then(|v| v.last()) {
        put(&mut t, "server_name", a.first().ok_or_else(|| invalid("Invalid verify-x509-name"))?.as_str());
        let kind = a.get(1).map_or("subject", String::as_str);
        require!(["subject", "name", "name-prefix"].contains(&kind), "Invalid verify-x509-name type: {kind}");
        put(&mut t, "server_name_type", kind);
        // The engine compares a name with the certificate's CN only: a profile asking for another field would
        // pass certificates it means to refuse.
        if let Some(f) = c.d.get("x509-username-field").and_then(|v| v.last()) {
            require!(
                kind == "subject" || matches!(&f[..], [one] if eq_ignore_case(one, "CN")),
                "verify-x509-name with x509-username-field {} isn't supported: only the certificate's CN can be checked",
                f.join(" ")
            );
        }
    }
    if let Some(b) = c.blocks.get("ca") {
        put(&mut t, "certificate", pems("ca", b)?);
    }
    // A client certificate chain is the leaf followed by its intermediates, which is how <extra-certs> is meant.
    if let Some(b) = c.blocks.get("cert") {
        let mut chain = vec![pems("cert", b)?];
        if let Some(x) = c.blocks.get("extra-certs") {
            chain.push(pems("extra-certs", x)?);
        }
        put(&mut t, "client_certificate", chain.join("\n"));
    }
    if let Some(b) = c.blocks.get("key") {
        put(&mut t, "client_key", pems("key", b)?);
    }
    if !fingerprints.is_empty() {
        let fingerprints = fingerprints
            .iter()
            .map(|f| {
                let v = f.replace(':', "").to_lowercase();
                require!(FINGERPRINT.is_match(&v), "Invalid peer-fingerprint");
                Ok(v)
            })
            .collect::<Result<Vec<_>>>()?;
        put(&mut t, "peer_fingerprint", fingerprints);
    }
    let ku = c.d.get("remote-cert-ku").and_then(|v| v.last());
    if let Some(k) = ku.filter(|k| !k.is_empty()) {
        for v in k {
            require!(KU.is_match(v), "Invalid remote-cert-ku value");
        }
        put(&mut t, "remote_certificate_ku", k.clone());
    }
    // The last of remote-cert-tls / remote-cert-eku sets the EKU; remote-cert-tls and a bare remote-cert-ku also require a KU extension.
    let role = c.last(&["remote-cert-eku", "remote-cert-tls"]);
    if let Some((k, a)) = role {
        let [v] = &a[..] else { return Err(invalid(format!("Invalid {k}"))) };
        let needs_ku = ku.is_some_and(|k| k.is_empty()) || c.has("remote-cert-tls");
        let no_ku = ku.is_none_or(|k| k.is_empty());
        let shorthand = if k == "remote-cert-tls" {
            Some(v.clone())
        } else if SERVER_EKU.contains(&v.to_lowercase().as_str()) {
            (needs_ku && no_ku).then(|| "server".to_string())
        } else if CLIENT_EKU.contains(&v.to_lowercase().as_str()) {
            (needs_ku && no_ku).then(|| "client".to_string())
        } else {
            None
        };
        match shorthand {
            Some(s) => {
                require!(s == "server" || s == "client", "Invalid remote-cert-tls");
                put(&mut t, "remote_certificate_tls", s);
            }
            None if needs_ku && no_ku => {
                return Err(invalid(format!(
                    "remote-cert-eku {v} can't be combined with remote-cert-tls or a bare remote-cert-ku (which require a key-usage extension); list the key usages (remote-cert-ku a0 88) or drop one"
                )));
            }
            None => put(&mut t, "remote_certificate_eku", v.as_str()),
        }
    }
    // Alone, a bare remote-cert-ku only demands that a key-usage extension exist: no engine field says that.
    if ku.is_some_and(|k| k.is_empty()) && role.is_none() {
        return Err(invalid(
            "A bare remote-cert-ku isn't supported on its own; list the key usages (remote-cert-ku a0 88) or add remote-cert-tls server",
        ));
    }
    if let Some(v) = c.arg("ns-cert-type") {
        require!(v == "server" || v == "client", "Invalid ns-cert-type");
        put(&mut t, "ns_certificate_type", v);
    }
    if let Some(v) = c.arg("tls-version-min") {
        require!(TLS_VERSIONS.contains(&v), "Invalid tls-version-min");
        put(&mut t, "version_min", v);
    }
    if let Some(v) = c.arg("tls-version-max") {
        require!(TLS_VERSIONS.contains(&v), "Invalid tls-version-max");
        put(&mut t, "version_max", v);
    }
    if let Some(v) = tls_cipher {
        put(&mut t, "cipher", v);
    }
    if let Some(v) = c.arg("tls-cert-profile") {
        require!(PROFILES.contains(&v), "Unsupported tls-cert-profile: {v}");
        put(&mut t, "certificate_profile", v);
    }
    if let [w] = wraps[..] {
        let mut wrap = Map::new();
        put(&mut wrap, "type", w.replace('-', "_"));
        put(&mut wrap, "key", pems(w, &c.blocks[w])?);
        if w == "tls-auth"
            && let Some(d) = c.arg_at("tls-auth", 1).filter(|d| *d != "[inline]").or(c.arg("key-direction"))
        {
            let direction = match d {
                "0" => "server",
                "1" => "client",
                _ => return Err(invalid(format!("Invalid key-direction: {d}"))),
            };
            put(&mut wrap, "direction", direction);
        }
        put(&mut t, "control_wrap", wrap);
    }
    put(&mut o, "tls", t);

    if let Some(d) = data_ciphers {
        put(&mut o, "data_ciphers", d);
    }
    if let Some(f) = fallback {
        put(&mut o, "data_ciphers_fallback", f);
    }
    if let Some(a) = auth {
        put(&mut o, "auth", a);
    }
    if let Some(l) = &lzo {
        put(&mut o, "compression_lzo", l.as_str());
    }
    if let Some(v) = &compress {
        put(&mut o, "compression", v.as_str());
    }
    if compressing || matches!(allow, Some("yes" | "asym")) {
        put(&mut o, "allow_compression", "asym");
    }
    if let Some(a) = c.d.get("mssfix").and_then(|v| v.last()) {
        let n = a
            .first()
            .map(|v| v.parse::<i32>().ok().filter(|n| *n >= 0).ok_or_else(|| invalid("Invalid mssfix value")))
            .transpose()?;
        if n == Some(0) {
            put(&mut o, "mss_fix_disabled", true);
        } else if let Some(n) = n {
            put(&mut o, "mss_fix", n);
            if let Some(m) = a.get(1) {
                require!(m == "mtu" || m == "fixed", "Invalid mssfix mode");
                put(&mut o, "mss_fix_mode", m.as_str());
            }
        }
    }
    if let Some(f) = fragment {
        put(&mut o, "fragment", f);
    }
    if let Some(m) = mtu {
        put(&mut o, "mtu", m);
    }
    if let Some(r) = c.arg("reneg-sec") {
        if r.parse::<i32>() == Ok(0) {
            put(&mut o, "renegotiate_disabled", true);
        } else {
            put(&mut o, "renegotiate_interval", seconds("reneg-sec", r)?);
        }
    }
    if let Some(b) = c.arg("reneg-bytes") {
        put(
            &mut o,
            "renegotiate_bytes",
            b.parse::<i64>().ok().filter(|n| *n >= 0).ok_or_else(|| invalid("Invalid reneg-bytes"))?,
        );
    }
    if let Some(b) = c.arg("reneg-pkts") {
        put(
            &mut o,
            "renegotiate_packets",
            b.parse::<i64>().ok().filter(|n| *n >= 0).ok_or_else(|| invalid("Invalid reneg-pkts"))?,
        );
    }
    let ka = c.d.get("keepalive").and_then(|v| v.last());
    if let Some(v) = c.arg("ping").or(ka.and_then(|k| k.first()).map(String::as_str)).filter(|v| *v != "0") {
        put(&mut o, "ping_interval", seconds("ping", v)?);
    }
    if let Some(v) = c.arg("ping-restart").or(ka.and_then(|k| k.get(1)).map(String::as_str)) {
        if v.parse::<i32>() == Ok(0) {
            put(&mut o, "ping_restart_disabled", true);
        } else {
            put(&mut o, "ping_restart", seconds("ping-restart", v)?);
        }
    }
    if let Some(v) = c.arg("tls-timeout") {
        put(&mut o, "tls_timeout", seconds("tls-timeout", v)?);
    }
    if let Some(v) = c.arg("hand-window") {
        put(&mut o, "handshake_window", seconds("hand-window", v)?);
    }
    if c.has("explicit-exit-notify") {
        let n = c.arg("explicit-exit-notify").unwrap_or("1").parse::<i32>().ok().filter(|n| *n >= 0);
        put(&mut o, "explicit_exit_notify", n.ok_or_else(|| invalid("Invalid explicit-exit-notify"))?);
    }
    if let Some(w) = c.arg("replay-window") {
        put(
            &mut o,
            "replay_window",
            w.parse::<i32>()
                .ok()
                .filter(|n| (1..=65536).contains(n))
                .ok_or_else(|| invalid("Invalid replay-window"))?,
        );
        if let Some(v) = c.arg_at("replay-window", 1) {
            put(&mut o, "replay_window_time", seconds("replay-window", v)?);
        }
    }
    if let Some(filters) = c.d.get("pull-filter").filter(|f| !f.is_empty()) {
        let filters = filters
            .iter()
            .map(|a| {
                require!(
                    a.len() == 2 && PULL_ACTIONS.contains(&a[0].as_str()) && !a[1].is_empty(),
                    "Invalid pull-filter: expected accept, ignore or reject and one text"
                );
                Ok(json!({"action": a[0], "text": a[1]}))
            })
            .collect::<Result<Vec<_>>>()?;
        put(&mut o, "pull_filters", filters);
    }
    put(&mut o, "route_no_pull", true);
    Ok(o)
}

#[rustfmt::skip]
const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
];

fn ss_plugin(name: &str) -> Option<&'static str> {
    match name {
        "obfs-local" | "simple-obfs" => Some("obfs-local"),
        "v2ray-plugin" => Some("v2ray-plugin"),
        _ => None,
    }
}

/// `s` with its %-escapes decoded as UTF-8; a `+` stays a `+`.
fn unpercent(s: &str) -> Result<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] == b'%' {
            let byte = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok());
            out.push(byte.ok_or_else(|| invalid("The link has a malformed %-escape"))?);
            i += 3;
        } else {
            out.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Base64 of either alphabet, padded or not; bits left over at the end are ignored.
const B64: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

fn b64(s: &str) -> Option<String> {
    let bytes = B64.decode(s.replace('+', "-").replace('/', "_").trim_end_matches('=')).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Whether `s` starts with `prefix`, letter case aside.
fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    eq_ignore_case(&s.chars().take(prefix.chars().count()).collect::<String>(), prefix)
}

/// Parses a SIP002 (`ss://base64(method:password)@host:port/?plugin=…#name`, or with plain userinfo) or legacy `ss://base64(method:password@host:port)#name` link.
pub fn parse_ss(link: &str, name: &str) -> Result<SsProfile> {
    require!(length(link) <= MAX_SS_LINK, "That link is too long to be a Shadowsocks key");
    let s = link.trim();
    require!(!starts_with_ignore_case(s, "ssconf://"), "Dynamic ssconf:// keys aren't supported; use the ss:// key");
    require!(starts_with_ignore_case(s, "ss://"), "Not a Shadowsocks link (expected ss://…)");
    let rest = &s[s.char_indices().nth(5).map_or(s.len(), |(i, _)| i)..];
    let tag = unpercent(rest.split_once('#').map_or("", |(_, t)| t))?.trim().to_string();
    let no_frag = rest.split_once('#').map_or(rest, |(r, _)| r);
    let query = no_frag.split_once('?').map_or("", |(_, q)| q);
    let body = no_frag.split_once('?').map_or(no_frag, |(b, _)| b).trim_end_matches('/');

    let (userinfo, host_port) = match body.rsplit_once('@') {
        Some((userinfo, host_port)) => {
            let userinfo = unpercent(userinfo)?;
            let userinfo = if userinfo.contains(':') {
                userinfo
            } else {
                b64(&userinfo).ok_or_else(|| invalid("Can't decode the link's credentials"))?
            };
            (userinfo, host_port.to_string())
        }
        None => {
            let decoded = b64(&unpercent(body)?).ok_or_else(|| invalid("Can't decode the link"))?;
            let Some((userinfo, host_port)) = decoded.rsplit_once('@') else {
                return Err(invalid("The link has no server address"));
            };
            (userinfo.to_string(), host_port.to_string())
        }
    };
    require!(length(&userinfo) <= MAX_SS_USERINFO, "The link's credentials are too long");
    let Some((method, password)) = userinfo.split_once(':') else {
        return Err(invalid("The link has no method or password"));
    };
    let method = method.to_lowercase();
    require!(SS_METHODS.contains(&method.as_str()), "Unsupported Shadowsocks cipher: {method}");
    require!(!password.is_empty(), "The link has an empty password");

    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']').map_or(bracketed, |(h, _)| h),
        None => host_port.rsplit_once(':').map_or(host_port.as_str(), |(h, _)| h),
    };
    let port = host_port.rsplit_once(':').map_or("", |(_, p)| p).parse::<i32>().ok();
    require!(
        !host.trim().is_empty() && !host.chars().any(|c| c.is_whitespace() || c == '/'),
        "The link has no server host"
    );
    require!(length(host) <= MAX_HOST, "The link's server host is too long");
    let Some(port) = port.filter(|p| (1..=65535).contains(p)) else {
        return Err(invalid("The link has an invalid port"));
    };

    let mut params = HashMap::new();
    for p in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = p.split_once('=').unwrap_or((p, ""));
        params.insert(k, unpercent(v)?);
    }
    require!(!params.contains_key("prefix"), "Outline connection prefixes aren't supported");
    let spec = params.get("plugin").filter(|s| !s.trim().is_empty());
    let plugin = match spec {
        Some(s) => {
            let n = s.split_once(';').map_or(s.as_str(), |(n, _)| n);
            Some(ss_plugin(n).ok_or_else(|| {
                invalid(format!("Unsupported Shadowsocks plugin: {n} (only obfs-local and v2ray-plugin)"))
            })?)
        }
        None => None,
    };
    let label = [name, tag.as_str()].into_iter().find(|l| !l.trim().is_empty()).unwrap_or(host);
    require!(
        length(label) <= MAX_SS_NAME || label == host,
        "The server name is too long (at most {MAX_SS_NAME} characters)"
    );
    let opts = spec.and_then(|s| s.split_once(';')).map(|(_, o)| o).filter(|o| !o.is_empty());
    // v2ray-plugin's cert= names a file on this computer, which the engine would read: only an inline certificate is
    // taken. SIP003 escapes with backslashes; they're dropped first so "c\ert=" can't slip past.
    require!(
        opts.is_none_or(|o| !o
            .replace('\\', "")
            .split(';')
            .any(|it| it.split_once('=').map_or(it, |(k, _)| k).trim() == "cert")),
        "The plugin's cert= option reads a file on this computer; paste the certificate as certRaw= instead"
    );
    Ok(SsProfile {
        name: label.into(),
        server: host.into(),
        port,
        method,
        password: password.into(),
        plugin: plugin.map(String::from),
        plugin_opts: opts.map(String::from),
    })
}

/// A sing-box `shadowsocks` outbound for `p`.
pub fn ss_outbound(tag: &str, p: &SsProfile) -> Map<String, Value> {
    let mut o = Map::new();
    put(&mut o, "type", "shadowsocks");
    put(&mut o, "tag", tag);
    put(&mut o, "server", p.server.as_str());
    put(&mut o, "server_port", p.port);
    put(&mut o, "method", p.method.as_str());
    put(&mut o, "password", p.password.as_str());
    if let Some(v) = &p.plugin {
        put(&mut o, "plugin", v.as_str());
    }
    if let Some(v) = &p.plugin_opts {
        put(&mut o, "plugin_opts", v.as_str());
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use std::path::Path;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/manual/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// A value as text: a string as it is, a number or a boolean as JSON writes it.
    fn str(o: &Map<String, Value>, k: &str) -> String {
        match &o[k] {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
    fn obj<'a>(o: &'a Map<String, Value>, k: &str) -> &'a Map<String, Value> {
        o[k].as_object().unwrap()
    }
    fn strings(o: &Map<String, Value>, k: &str) -> Vec<String> {
        o[k].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
    }

    /// The smallest full sing-box config that routes everything through `tag`; checked with `sing-box check` after the run.
    fn write(file: &str, tag: &str, endpoint: Option<&Map<String, Value>>, outbound: Option<&Map<String, Value>>) {
        let mut cfg = Map::new();
        cfg.insert("log".into(), json!({"level": "info"}));
        if let Some(e) = endpoint {
            cfg.insert("endpoints".into(), json!([e]));
        }
        let mut outbounds = vec![json!({"type": "direct", "tag": "direct"})];
        outbounds.extend(outbound.map(|o| Value::Object(o.clone())));
        cfg.insert("outbounds".into(), Value::Array(outbounds));
        cfg.insert("route".into(), json!({"final": tag}));
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/manual");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{file}.json")), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    }

    fn ovpn(file: &str, text: &str) -> Map<String, Value> {
        let p = parse_ovpn(text, file, "u", "p").unwrap();
        assert_eq!(text, p.config);
        let e = ovpn_endpoint(&format!("ovpn-{file}"), &p).unwrap();
        write(file, &format!("ovpn-{file}"), Some(&e), None);
        e
    }

    fn rejects<T: std::fmt::Debug>(why: &str, r: Result<T>) {
        match r {
            Err(Error::Invalid(m)) => {
                assert!(m.to_lowercase().contains(&why.to_lowercase()), "'{m}' should mention '{why}'")
            }
            other => panic!("expected rejection mentioning '{why}', got {other:?}"),
        }
    }

    #[test]
    fn express_vpn() {
        let e = ovpn("expressvpn", &fixture("expressvpn.ovpn"));
        assert_eq!("openvpn-client", str(&e, "type"));
        assert_eq!("usa-new-york-1-ca-version-2.expressnetw.com", str(&e, "server"));
        assert_eq!("1195", str(&e, "server_port"));
        assert_eq!("udp", str(&e, "network"));
        assert_eq!("u", str(&e, "username"));
        assert_eq!("p", str(&e, "password"));
        assert_eq!("SHA512", str(&e, "auth"));
        assert_eq!(None, e.get("data_ciphers"));
        assert_eq!(None, e.get("data_ciphers_fallback"));
        assert_eq!("no", str(&e, "compression_lzo"));
        assert_eq!(None, e.get("allow_compression"));
        assert_eq!("1300", str(&e, "fragment"));
        assert_eq!("1200", str(&e, "mss_fix"));
        assert_eq!("1500", str(&e, "mtu"));
        assert_eq!("true", str(&e, "route_no_pull"));
        let tls = obj(&e, "tls");
        assert_eq!("Server", str(tls, "server_name"));
        assert_eq!("name-prefix", str(tls, "server_name_type"));
        assert_eq!("server", str(tls, "ns_certificate_type"));
        assert!(str(tls, "certificate").starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(None, tls.get("client_certificate"));
        let wrap = obj(tls, "control_wrap");
        assert_eq!("tls_auth", str(wrap, "type"));
        assert_eq!("client", str(wrap, "direction"));
        assert!(str(wrap, "key").starts_with("-----BEGIN OpenVPN Static key V1-----"));
        assert!(!str(wrap, "key").contains('#'));
    }

    #[test]
    fn cyber_ghost() {
        let e = ovpn("cyberghost", &fixture("cyberghost.ovpn"));
        assert_eq!("87-1-nl.cg-dialup.net", str(&e, "server"));
        assert_eq!("443", str(&e, "server_port"));
        assert_eq!(None, e.get("data_ciphers_fallback"));
        assert_eq!(None, e.get("data_ciphers"));
        assert_eq!("SHA256", str(&e, "auth"));
        assert_eq!("5s", str(&e, "ping_interval"));
        assert_eq!("20s", str(&e, "ping_restart"));
        assert_eq!("true", str(&e, "renegotiate_disabled"));
        assert_eq!("2", str(&e, "explicit_exit_notify"));
        assert_eq!("adaptive", str(&e, "compression_lzo"));
        assert_eq!("asym", str(&e, "allow_compression"));
        let tls = obj(&e, "tls");
        assert_eq!("server", str(tls, "remote_certificate_tls"));
        assert!(str(tls, "client_certificate").contains("BEGIN CERTIFICATE"));
        assert!(str(tls, "client_key").contains("BEGIN PRIVATE KEY"));
        let wrap = obj(tls, "control_wrap");
        assert_eq!("tls_crypt", str(wrap, "type"));
        assert_eq!(None, wrap.get("direction"));
    }

    #[test]
    fn self_hosted() {
        let e = ovpn("selfhosted", &fixture("selfhosted.ovpn"));
        assert_eq!(None, e.get("server"));
        let servers: Vec<&Map<String, Value>> =
            e["servers"].as_array().unwrap().iter().map(|s| s.as_object().unwrap()).collect();
        assert_eq!(
            vec!["vpn.example.net", "vpn2.example.net", "203.0.113.10"],
            servers.iter().map(|s| str(s, "server")).collect::<Vec<_>>()
        );
        assert_eq!(vec!["443", "8443", "1194"], servers.iter().map(|s| str(s, "server_port")).collect::<Vec<_>>());
        assert_eq!(vec!["tcp", "tcp", "udp"], servers.iter().map(|s| str(s, "network")).collect::<Vec<_>>());
        assert_eq!("true", str(&e, "remote_random"));
        assert_eq!(vec!["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"], strings(&e, "data_ciphers"));
        assert_eq!("AES-128-CBC", str(&e, "data_ciphers_fallback"));
        assert_eq!("3600s", str(&e, "renegotiate_interval"));
        assert_eq!("10s", str(&e, "ping_interval"));
        assert_eq!("60s", str(&e, "ping_restart"));
        let tls = obj(&e, "tls");
        assert_eq!("vpn.example.net", str(tls, "server_name"));
        assert_eq!("name", str(tls, "server_name_type"));
        assert_eq!("1.2", str(tls, "version_min"));
        assert_eq!("client", str(obj(tls, "control_wrap"), "direction"));
        assert_eq!(None, e.get("redirect_gateway"));
    }

    #[test]
    fn ovpn_rejections() {
        let ex = fixture("expressvpn.ovpn");
        let with = |extra: &str| format!("{ex}\n{extra}");
        let without = |re: &str| Regex::new(re).unwrap().replace_all(&ex, "").into_owned();
        let parse = |text: &str| parse_ovpn(text, "x", "u", "p");
        rejects("username and password", parse_ovpn(&ex, "x", "", ""));
        rejects("username and password", parse_ovpn(&ex, "x", "u", ""));
        rejects("too large", parse(&(ex.clone() + &"#".repeat(300_000))));
        rejects("no 'remote'", parse(&without("remote [^\\n]+\\n")));
        rejects("client profile", parse(&without("tls-client\\n")));
        rejects("<ca>", parse(&without("(?s)<ca>.*?</ca>\\n")));
        rejects("tun", parse(&ex.replace("dev tun", "dev tap")));
        rejects("cipher", parse(&ex.replace("AES-256-CBC", "BF-CBC")));
        rejects("auth digest", parse(&ex.replace("SHA512", "MD5")));
        rejects("PKCS#12", parse(&with("<pkcs12>\nAAAA\n</pkcs12>")));
        rejects("PKCS#12", parse(&with("pkcs12 client.p12")));
        rejects("inline", parse(&(without("(?s)<ca>.*?</ca>\\n") + "\nca ca.crt")));
        rejects("inline", parse(&with("cert client.crt")));
        rejects(
            "both <cert> and <key>",
            parse(&with("<cert>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</cert>")),
        );
        rejects("compress lzo", parse(&with("compress lzo")));
        rejects("proxy", parse(&with("http-proxy 10.0.0.1 8080")));
        rejects("2FA", parse(&with("static-challenge \"Code\" 1")));
        rejects("fragment only works over UDP", parse(&ex.replace("proto udp", "proto tcp")));
        rejects("Unsupported OpenVPN option: frobnicate", parse(&with("frobnicate 1")));
        rejects(
            "Encrypted private key",
            parse(&with(
                "<cert>\n-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAA==\n-----END RSA PRIVATE KEY-----\n</key>",
            )),
        );
        rejects("Unterminated", parse(&with("<ca>\nxx")));
    }

    #[test]
    fn tls_cipher_is_enforced_and_tls13_suites_are_refused() {
        let ex = fixture("expressvpn.ovpn");
        let e = ovpn(
            "tls-cipher",
            &format!("{ex}\ntls-cipher ECDHE-RSA-AES256-GCM-SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
        );
        assert_eq!(
            "ECDHE-RSA-AES256-GCM-SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            str(obj(&e, "tls"), "cipher")
        );
        assert_eq!(None, obj(&ovpn("no-tls-cipher", &ex), "tls").get("cipher"));
        rejects("tls-cipher", parse_ovpn(&format!("{ex}\ntls-cipher DEFAULT"), "x", "u", "p"));
        rejects(
            "tls-cipher",
            parse_ovpn(&format!("{ex}\ntls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"), "x", "u", "p"),
        );
        rejects(
            "tls-ciphersuites",
            parse_ovpn(&format!("{ex}\ntls-ciphersuites TLS_AES_256_GCM_SHA384"), "x", "u", "p"),
        );
    }

    #[test]
    fn ncp_disable_wins_over_an_explicit_cipher_list() {
        let ex = fixture("expressvpn.ovpn");
        let e = ovpn(
            "ncp-disable",
            &format!(
                "{ex}\nncp-disable\ndata-ciphers AES-128-GCM:CHACHA20-POLY1305\ndata-ciphers-fallback AES-128-CBC"
            ),
        );
        assert_eq!(vec!["AES-256-CBC"], strings(&e, "data_ciphers"));
        assert_eq!("AES-256-CBC", str(&e, "data_ciphers_fallback"));
        let gcm =
            ovpn("ncp-disable-gcm", &format!("{}\nncp-disable\nncp-ciphers AES-128-GCM", fixture("cyberghost.ovpn")));
        assert_eq!(vec!["AES-256-GCM"], strings(&gcm, "data_ciphers"));
        assert_eq!("AES-256-GCM", str(&gcm, "data_ciphers_fallback"));
        rejects(
            "ncp-disable needs a cipher",
            parse_ovpn(
                &format!("{}\nncp-disable", Regex::new("cipher AES-256-CBC\\n").unwrap().replace_all(&ex, "")),
                "x",
                "u",
                "p",
            ),
        );
    }

    #[test]
    fn ping_restart_zero_disables_the_restart_timeout() {
        let ex = fixture("expressvpn.ovpn");
        let off = ovpn("ping-restart-0", &format!("{ex}\nping-restart 0"));
        assert_eq!("true", str(&off, "ping_restart_disabled"));
        assert_eq!(None, off.get("ping_restart"));
        let keepalive = ovpn("keepalive-0", &format!("{ex}\nkeepalive 10 0"));
        assert_eq!("true", str(&keepalive, "ping_restart_disabled"));
        assert_eq!("10s", str(&keepalive, "ping_interval"));
        assert_eq!(None, ovpn("ping-restart-default", &ex).get("ping_restart_disabled"));
        assert_eq!(None, ovpn("ping-restart-30", &format!("{ex}\nping-restart 30")).get("ping_restart_disabled"));
    }

    #[test]
    fn ovpn_without_login_needs_none() {
        let text = fixture("cyberghost.ovpn").replace("auth-user-pass\n", "");
        let e = ovpn_endpoint("t", &parse_ovpn(&text, "x", "", "").unwrap()).unwrap();
        assert_eq!(None, e.get("username"));
    }

    #[test]
    fn inline_login_is_used_when_nothing_was_typed() {
        let base = fixture("cyberghost.ovpn");
        let text = base.replace("auth-user-pass\n", "<auth-user-pass>\n  alice \npass word \n</auth-user-pass>\n");
        let e = ovpn_endpoint("t", &parse_ovpn(&text, "x", "", "").unwrap()).unwrap();
        assert_eq!("alice", str(&e, "username"));
        assert_eq!("pass word ", str(&e, "password"));
        write("inline-login", "t", Some(&e), None);
        let typed = ovpn_endpoint("t", &parse_ovpn(&text, "x", "bob", " s p ").unwrap()).unwrap();
        assert_eq!("bob", str(&typed, "username"));
        assert_eq!(" s p ", str(&typed, "password"));
        rejects(
            "username and password",
            parse_ovpn(&base.replace("auth-user-pass\n", "<auth-user-pass>\nalice\n</auth-user-pass>\n"), "x", "", ""),
        );
        rejects("username and password", parse_ovpn(&base, "x", "", ""));
    }

    #[test]
    fn extra_certs_extend_the_client_chain() {
        let base = fixture("cyberghost.ovpn");
        let ca = Regex::new(r"(?s)<ca>\s*(.*?)\s*</ca>").unwrap().captures(&base).unwrap()[1].to_string();
        let e = ovpn("extra-certs", &base.replace("<key>", &format!("<extra-certs>\n{ca}\n</extra-certs>\n<key>")));
        let chain = str(obj(&e, "tls"), "client_certificate");
        assert_eq!(2, chain.matches("BEGIN CERTIFICATE").count());
        assert!(chain.ends_with(lines(&ca).last().unwrap().trim()));
        assert_eq!(
            1,
            str(obj(&ovpn("no-extra-certs", &base), "tls"), "client_certificate").matches("BEGIN CERTIFICATE").count()
        );
        let ex = fixture("expressvpn.ovpn");
        rejects("extra-certs", parse_ovpn(&format!("{ex}\n<extra-certs>\n{ca}\n</extra-certs>"), "x", "u", "p"));
    }

    fn key16() -> String {
        STANDARD.encode((0..16u32).map(|i| (i * 11 + 5) as u8).collect::<Vec<_>>())
    }
    fn key32() -> String {
        STANDARD.encode((0..32u32).map(|i| (i * 13 + 1) as u8).collect::<Vec<_>>())
    }

    fn ss(file: &str, link: &str) -> Map<String, Value> {
        let p = parse_ss(link, "").unwrap();
        let o = ss_outbound(&format!("ss-{file}"), &p);
        write(file, &format!("ss-{file}"), None, Some(&o));
        o
    }

    fn base() -> String {
        fixture("expressvpn.ovpn").replace("ns-cert-type server\n", "")
    }

    fn tls(name: &str, extra: &str) -> Map<String, Value> {
        obj(&ovpn(name, &format!("{}\n{extra}", base())), "tls").clone()
    }

    #[test]
    fn bare_remote_cert_ku_keeps_the_extension_requirement_alongside_eku() {
        let server = tls("ku-eku-server", "remote-cert-ku\nremote-cert-eku \"TLS Web Server Authentication\"");
        assert_eq!("server", str(&server, "remote_certificate_tls"));
        assert_eq!(None, server.get("remote_certificate_eku"));
        let client = tls("ku-eku-client", "remote-cert-eku 1.3.6.1.5.5.7.3.2\nremote-cert-ku");
        assert_eq!("client", str(&client, "remote_certificate_tls"));
        assert_eq!(None, client.get("remote_certificate_eku"));
        let tls_plus_eku = tls("tls-eku", "remote-cert-tls client\nremote-cert-eku clientAuth");
        assert_eq!("client", str(&tls_plus_eku, "remote_certificate_tls"));
        assert_eq!(None, tls_plus_eku.get("remote_certificate_eku"));
        rejects(
            "can't be combined",
            parse_ovpn(&format!("{}\nremote-cert-ku\nremote-cert-eku 1.3.6.1.5.5.7.3.3", base()), "x", "u", "p"),
        );
        // Alone, a bare remote-cert-ku demands a key-usage extension the engine can't express: refused, not dropped.
        rejects("bare remote-cert-ku", parse_ovpn(&format!("{}\nremote-cert-ku", base()), "x", "u", "p"));
        rejects(
            "can't be combined",
            parse_ovpn(
                &format!("{}\nremote-cert-tls server\nremote-cert-eku 1.3.6.1.5.5.7.3.3", base()),
                "x",
                "u",
                "p",
            ),
        );
        let values = tls("ku-values-eku", "remote-cert-ku a0 88\nremote-cert-eku 1.3.6.1.5.5.7.3.3");
        assert_eq!(vec!["a0", "88"], strings(&values, "remote_certificate_ku"));
        assert_eq!("1.3.6.1.5.5.7.3.3", str(&values, "remote_certificate_eku"));
        let eku = tls("eku-only", "remote-cert-eku 1.3.6.1.5.5.7.3.3");
        assert_eq!("1.3.6.1.5.5.7.3.3", str(&eku, "remote_certificate_eku"));
        assert_eq!(None, eku.get("remote_certificate_tls"));
        assert_eq!("server", str(&tls("tls-only", "remote-cert-tls server"), "remote_certificate_tls"));
        assert_eq!(
            "1.3.6.1.5.5.7.3.3",
            str(
                &tls(
                    "eku-after-tls-ku",
                    "remote-cert-tls server\nremote-cert-ku a0\nremote-cert-eku 1.3.6.1.5.5.7.3.3"
                ),
                "remote_certificate_eku"
            )
        );
    }

    #[test]
    fn cipher_alone_never_widens_negotiation() {
        let lone = ovpn("cipher-only", &base());
        assert_eq!(None, lone.get("data_ciphers"));
        assert_eq!(None, lone.get("data_ciphers_fallback"));
        let with_list = ovpn("cipher-list", &format!("{}\ndata-ciphers AES-128-GCM", base()));
        assert_eq!(vec!["AES-128-GCM"], strings(&with_list, "data_ciphers"));
        assert_eq!(None, with_list.get("data_ciphers_fallback"));
        let fb = ovpn("cipher-fallback", &format!("{}\ndata-ciphers-fallback AES-128-CBC", base()));
        assert_eq!(None, fb.get("data_ciphers"));
        assert_eq!("AES-128-CBC", str(&fb, "data_ciphers_fallback"));
        let flipped = ovpn(
            "fallback-then-cipher",
            &format!(
                "{}\ndata-ciphers-fallback AES-128-CBC\ncipher AES-192-CBC",
                base().replace("cipher AES-256-CBC\n", "")
            ),
        );
        assert_eq!("AES-192-CBC", str(&flipped, "data_ciphers_fallback"));
        let only_fallback = ovpn(
            "fallback-only",
            &format!("{}\ndata-ciphers-fallback AES-128-CBC", base().replace("cipher AES-256-CBC\n", "")),
        );
        assert_eq!("AES-128-CBC", str(&only_fallback, "data_ciphers_fallback"));
    }

    #[test]
    fn compat_mode_restores_the_legacy_cipher_only_where_open_vpn_does() {
        let c24 = ovpn("compat-2.4.0", &format!("{}\ncompat-mode 2.4.0", base()));
        assert_eq!(
            vec!["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            strings(&c24, "data_ciphers")
        );
        assert_eq!(None, c24.get("data_ciphers_fallback"));
        let c24_fixed = ovpn("compat-2.4.0-list", &format!("{}\ncompat-mode 2.4.0\ndata-ciphers AES-128-GCM", base()));
        assert_eq!(vec!["AES-128-GCM", "AES-256-CBC"], strings(&c24_fixed, "data_ciphers"));
        let c24_gcm =
            ovpn("compat-2.4.0-gcm", &format!("{}\ncompat-mode 2.4.0", base().replace("AES-256-CBC", "AES-256-GCM")));
        assert_eq!(None, c24_gcm.get("data_ciphers"));
        let c25 = ovpn("compat-2.5.0", &format!("{}\ncompat-mode 2.5.0", base()));
        assert_eq!(None, c25.get("data_ciphers"));
        assert_eq!(None, c25.get("data_ciphers_fallback"));
        let c23 = ovpn("compat-2.3.0", &format!("{}\ncompat-mode 2.3.0", base()));
        assert_eq!("AES-256-CBC", str(&c23, "data_ciphers_fallback"));
        assert_eq!(
            vec!["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            strings(&c23, "data_ciphers")
        );
        rejects("compat-mode", parse_ovpn(&format!("{}\ncompat-mode 2.4", base()), "x", "u", "p"));
        rejects(
            "needs a cipher",
            parse_ovpn(&format!("{}\ncompat-mode 2.3.0", base().replace("cipher AES-256-CBC\n", "")), "x", "u", "p"),
        );
        rejects(
            "Invalid data-ciphers-fallback",
            parse_ovpn(&format!("{}\ndata-ciphers-fallback AES-128-CBC:AES-256-CBC", base()), "x", "u", "p"),
        );
    }

    #[test]
    fn pull_filters_keep_their_order_and_route_no_pull_stays_on() {
        let e = ovpn(
            "pull-filters",
            &format!(
                "{}\npull-filter accept \"dhcp-option DNS 10.\"\npull-filter ignore \"dhcp-option\"\npull-filter reject redirect-gateway",
                base()
            ),
        );
        let f: Vec<(String, String)> = e["pull_filters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_object().unwrap())
            .map(|o| (str(o, "action"), str(o, "text")))
            .collect();
        let expected = [("accept", "dhcp-option DNS 10."), ("ignore", "dhcp-option"), ("reject", "redirect-gateway")];
        assert_eq!(expected.map(|(a, t)| (a.to_string(), t.to_string())).to_vec(), f);
        assert_eq!("true", str(&e, "route_no_pull"));
        assert_eq!(None, ovpn("no-pull-filters", &base()).get("pull_filters"));
        let shipped = ovpn("selfhosted-filters", &fixture("selfhosted.ovpn"));
        let [shipped] = &shipped["pull_filters"].as_array().unwrap()[..] else { panic!("one pull-filter expected") };
        assert_eq!("ignore", str(shipped.as_object().unwrap(), "action"));
        assert_eq!("route-ipv6", str(shipped.as_object().unwrap(), "text"));
        rejects("pull-filter", parse_ovpn(&format!("{}\npull-filter drop foo", base()), "x", "u", "p"));
        rejects("pull-filter", parse_ovpn(&format!("{}\npull-filter ignore", base()), "x", "u", "p"));
        rejects("pull-filter", parse_ovpn(&format!("{}\npull-filter ignore a b", base()), "x", "u", "p"));
    }

    #[test]
    fn port_and_rport_follow_directive_order_for_remotes_without_a_port() {
        let no_port = base().replace(
            "remote usa-new-york-1-ca-version-2.expressnetw.com 1195",
            "remote a.example.net\nremote b.example.net 8443",
        );
        let ports = |extra: &str| -> Vec<String> {
            ovpn("ports", &format!("{no_port}\n{extra}"))["servers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| str(s.as_object().unwrap(), "server_port"))
                .collect()
        };
        assert_eq!(vec!["1194", "8443"], ports(""));
        assert_eq!(vec!["443", "8443"], ports("port 1194\nrport 443"));
        assert_eq!(vec!["1194", "8443"], ports("rport 443\nport 1194"));
        assert_eq!(vec!["443", "8443"], ports("rport 443"));
        assert_eq!(vec!["1195", "8443"], ports("port 1195"));
        assert_eq!(vec!["443", "8443"], ports("port 1194\nremote-random\nrport 443"));
        rejects("Invalid port", parse_ovpn(&format!("{no_port}\nrport x"), "x", "u", "p"));
    }

    #[test]
    fn ss_sip002_base64() {
        let userinfo = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pa:ss/w0rd+1");
        let o = ss("ss-sip002-b64", &format!("ss://{userinfo}@ss.example.net:8388/?outline=1#Outline%20NL"));
        assert_eq!("shadowsocks", str(&o, "type"));
        assert_eq!("ss.example.net", str(&o, "server"));
        assert_eq!("8388", str(&o, "server_port"));
        assert_eq!("chacha20-ietf-poly1305", str(&o, "method"));
        assert_eq!("pa:ss/w0rd+1", str(&o, "password"));
        assert_eq!(None, o.get("plugin"));
        assert_eq!(
            "Outline NL",
            parse_ss(&format!("ss://{userinfo}@ss.example.net:8388#Outline%20NL"), "").unwrap().name
        );
        assert_eq!("Mine", parse_ss(&format!("ss://{userinfo}@ss.example.net:8388#x"), "Mine").unwrap().name);
        assert_eq!("ss.example.net", parse_ss(&format!("ss://{userinfo}@ss.example.net:8388"), "").unwrap().name);
        // v2ray-plugin's cert= would make the engine read a file on this computer.
        rejects(
            "certRaw",
            parse_ss(
                &format!("ss://{userinfo}@ss.example.net:8388/?plugin=v2ray-plugin%3Btls%3Bcert%3D%2Fdev%2Fzero#x"),
                "",
            ),
        );
        rejects(
            "certRaw",
            parse_ss(
                &format!("ss://{userinfo}@ss.example.net:8388/?plugin=v2ray-plugin%3Btls%3Bc%5Cert%3D%2Fdev%2Fzero#x"),
                "",
            ),
        );
        assert_eq!(
            Some("tls;host=a.example".to_string()),
            parse_ss(
                &format!("ss://{userinfo}@ss.example.net:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Da.example#x"),
                ""
            )
            .unwrap()
            .plugin_opts
        );
    }

    #[test]
    fn ss_sip002_plain_with_plugin() {
        let pw = crate::http::enc(&key32());
        let o = ss(
            "ss-sip002-plain",
            &format!(
                "ss://2022-blake3-aes-256-gcm:{pw}@[2001:db8::1]:443/?plugin=v2ray-plugin%3Bhost%3Dcdn.example.net%3Bpath%3D%2Fws#IPv6"
            ),
        );
        assert_eq!("2001:db8::1", str(&o, "server"));
        assert_eq!("443", str(&o, "server_port"));
        assert_eq!("2022-blake3-aes-256-gcm", str(&o, "method"));
        assert_eq!(key32(), str(&o, "password"));
        assert_eq!("v2ray-plugin", str(&o, "plugin"));
        assert_eq!("host=cdn.example.net;path=/ws", str(&o, "plugin_opts"));
    }

    #[test]
    fn ss_legacy() {
        let body = STANDARD.encode("aes-128-gcm:s3cret@legacy.example.net:8443");
        let o = ss("ss-legacy", &format!("ss://{body}#Legacy%20box"));
        assert_eq!("legacy.example.net", str(&o, "server"));
        assert_eq!("8443", str(&o, "server_port"));
        assert_eq!("aes-128-gcm", str(&o, "method"));
        assert_eq!("s3cret", str(&o, "password"));
        assert_eq!("Legacy box", parse_ss(&format!("ss://{body}#Legacy%20box"), "").unwrap().name);
    }

    #[test]
    fn ss_obfs() {
        let userinfo = STANDARD.encode(format!("2022-blake3-aes-128-gcm:{}", key16()));
        let o = ss(
            "ss-obfs",
            &format!("ss://{userinfo}@203.0.113.7:8388/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcdn.example.com"),
        );
        assert_eq!("obfs-local", str(&o, "plugin"));
        assert_eq!("obfs=tls;obfs-host=cdn.example.com", str(&o, "plugin_opts"));
        assert_eq!(
            Some("obfs-local".to_string()),
            parse_ss(&format!("ss://{userinfo}@h.example:1/?plugin=simple-obfs%3Bobfs%3Dhttp"), "").unwrap().plugin
        );
    }

    #[test]
    fn ss_rejections() {
        let ok = STANDARD.encode("aes-256-gcm:pw");
        rejects("ss://", parse_ss("vmess://abc", ""));
        rejects("ssconf", parse_ss("ssconf://example.com/key", ""));
        rejects("cipher", parse_ss(&format!("ss://{}@h.example:1", STANDARD.encode("bf-cfb:pw")), ""));
        rejects("cipher", parse_ss("ss://none:pw@h.example:1", ""));
        rejects("port", parse_ss(&format!("ss://{ok}@h.example:0"), ""));
        rejects("port", parse_ss(&format!("ss://{ok}@h.example:70000"), ""));
        rejects("port", parse_ss(&format!("ss://{ok}@h.example"), ""));
        rejects("host", parse_ss(&format!("ss://{ok}@:8388"), ""));
        rejects("empty password", parse_ss("ss://aes-256-gcm:@h.example:1", ""));
        rejects("plugin", parse_ss(&format!("ss://{ok}@h.example:1/?plugin=kcptun%3Bkey%3Dx"), ""));
        rejects("prefix", parse_ss(&format!("ss://{ok}@h.example:1/?prefix=%16%03%01"), ""));
        rejects("malformed", parse_ss("ss://%%%@h.example:1", ""));
        rejects("decode", parse_ss("ss://!!!notbase64!!!", ""));
    }

    #[test]
    fn ss_size_limits() {
        let ok = STANDARD.encode("aes-256-gcm:pw");
        rejects("too long", parse_ss(&format!("ss://{ok}@h.example:1/?plugin={}", "a".repeat(9000)), ""));
        let long_pw = STANDARD.encode(format!("aes-256-gcm:{}", "p".repeat(2000)));
        rejects("credentials are too long", parse_ss(&format!("ss://{long_pw}@h.example:1"), ""));
        rejects(
            "credentials are too long",
            parse_ss(&format!("ss://aes-256-gcm:{}@h.example:1", "p".repeat(2000)), ""),
        );
        rejects("name is too long", parse_ss(&format!("ss://{ok}@h.example:1#{}", "n".repeat(200)), ""));
        rejects("name is too long", parse_ss(&format!("ss://{ok}@h.example:1"), &"n".repeat(200)));
        rejects("host is too long", parse_ss(&format!("ss://{ok}@{}:1", "h".repeat(300)), ""));
        assert_eq!(128, parse_ss(&format!("ss://{ok}@h.example:1#{}", "n".repeat(128)), "").unwrap().name.len());
    }

    /// A profile that only trusts its CA (which signs every customer's certificate too) gets the warning; a server check clears it.
    #[test]
    fn a_profile_that_never_checks_the_server_is_flagged() {
        let no_check = lines(&base())
            .filter(|l| {
                !(l.starts_with("remote-cert-tls")
                    || l.starts_with("verify-x509-name")
                    || l.starts_with("ns-cert-type"))
            })
            .collect::<Vec<_>>()
            .join("\n");
        let w =
            |extra: &str| ovpn_weakness(&parse_ovpn(&format!("{no_check}\n{extra}"), "x", "u", "p").unwrap()).unwrap();
        assert!(w("").unwrap().contains("right server"));
        assert!(w("peer-fingerprint").unwrap().contains("right server")); // a bare directive checks nothing
        for ok in [
            "remote-cert-tls server",
            "remote-cert-eku \"TLS Web Server Authentication\"",
            "remote-cert-eku serverAuth",
            "ns-cert-type server",
            "verify-x509-name vpn.example name",
        ] {
            assert_eq!(None, w(ok), "{ok}");
        }
        // The client's role, or a later EKU overriding a server check, is no server check.
        assert!(w("remote-cert-tls client").unwrap().contains("right server"));
        assert!(
            w("remote-cert-tls server\nremote-cert-eku clientAuth\nremote-cert-ku a0")
                .unwrap()
                .contains("right server")
        );
        // Weak crypto and no server check are both named.
        assert!(w("tls-version-min 1.0").is_some_and(|m| m.contains("TLS 1.0") && m.contains("right server")));
    }

    /// The engine checks a name against the CN only: a profile asking for another certificate field is refused.
    #[test]
    fn x509_username_field_other_than_cn_is_refused() {
        let unnamed = lines(&base()).filter(|l| !l.starts_with("verify-x509-name")).collect::<Vec<_>>().join("\n");
        let named = format!("{unnamed}\nverify-x509-name gw.example name");
        parse_ovpn(&named, "x", "u", "p").unwrap();
        parse_ovpn(&format!("{named}\nx509-username-field CN"), "x", "u", "p").unwrap();
        for f in ["OU", "emailAddress", "ext:subjectAltName", "CN OU"] {
            rejects(
                "only the certificate's CN",
                parse_ovpn(&format!("{named}\nx509-username-field {f}"), "x", "u", "p"),
            );
        }
        // Without a name check the field changes nothing on the client.
        parse_ovpn(&format!("{unnamed}\nx509-username-field OU"), "x", "u", "p").unwrap();
    }

    #[test]
    fn weak_encryption_is_flagged_but_still_imports() {
        assert_eq!(None, ovpn_weakness(&parse_ovpn(&base(), "x", "u", "p").unwrap()).unwrap());
        for (extra, says) in [
            ("tls-version-min 1.0", "TLS 1.0"),
            ("tls-cipher AES128-SHA:DES-CBC3-SHA", "3DES"),
            ("tls-cert-profile insecure", "certificates"),
        ] {
            assert!(
                ovpn_weakness(&parse_ovpn(&format!("{}\n{extra}", base()), "x", "u", "p").unwrap())
                    .unwrap()
                    .unwrap()
                    .contains(says),
                "{extra}"
            );
        }
        assert_eq!(
            None,
            ovpn_weakness(&parse_ovpn(&format!("{}\ntls-version-min 1.2", base()), "x", "u", "p").unwrap()).unwrap()
        );
        let link =
            |userinfo: &str| parse_ss(&format!("ss://{}@h.example:1", URL_SAFE_NO_PAD.encode(userinfo)), "").unwrap();
        assert_eq!(None, ss_weakness(&link("chacha20-ietf-poly1305:pw")));
        assert_eq!(None, ss_weakness(&link(&format!("2022-blake3-aes-128-gcm:{}", key16()))));
        assert!(ss_weakness(&link("aes-256-cfb:pw")).unwrap().contains("aes-256-cfb"));
    }
}
