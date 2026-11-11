//! Tailscale's sign-in link, checked before it is opened.
//!
//! Tailscale sign-in links come from the control server, so a malicious or compromised one could send any link: one into
//! another app, or a phishing page. Only an HTTPS link to the control server itself (or to Tailscale's own servers when
//! none is set) opens straight away; another web address is shown first; anything else never opens.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Open,
    Ask,
    Refuse,
}

/// `url` is the cleaned link to launch (lowercase scheme, no surrounding space); none when refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub verdict: Verdict,
    pub url: Option<String>,
    pub host: Option<String>,
}

const TAILSCALE_CONTROL: [&str; 2] = ["controlplane.tailscale.com", "login.tailscale.com"];

/// Whether a sign-in waits, from a Tailscale status: yes with a sign-in link, no once signed in (Running), else as
/// `was`. A restarted engine reports no link at first: that alone never ends a sign-in.
pub fn pending(auth_url: &str, backend: Option<&str>, was: bool) -> bool {
    if !auth_url.is_empty() {
        true
    } else if backend == Some("Running") {
        false
    } else {
        was
    }
}

pub fn check(url: &str, control_url: Option<&str>) -> Check {
    let refuse = Check { verdict: Verdict::Refuse, url: None, host: None };
    let t = url.trim();
    let Some(link) = Link::parse(t) else { return refuse };
    let Some(host) = link.host.map(|h| h.to_lowercase().trim_end_matches('.').to_string()) else { return refuse };
    if !link.scheme.eq_ignore_ascii_case("https") || host.is_empty() || link.user_info {
        return refuse;
    }
    if let Some(p) = link.port
        && !(1..=65535).contains(&p)
    {
        return refuse;
    }
    let clean = format!("https{}", &t[link.scheme.len()..]);
    // No control server set, or Tailscale's own: Tailscale's hosts are trusted. A custom server (even one that can't be
    // parsed) trusts only its own host, so a typo never widens trust to Tailscale.
    let control = control_url.map(str::trim).filter(|c| !c.is_empty()).map(|c| {
        Link::parse(c)
            .and_then(|l| l.host)
            .map(|h| h.to_lowercase().trim_end_matches('.').to_string())
            .unwrap_or_default()
    });
    let trusted = match control {
        None => tailscale(&host),
        Some(c) if TAILSCALE_CONTROL.contains(&c.as_str()) => tailscale(&host),
        Some(c) => host == c,
    };
    Check { verdict: if trusted { Verdict::Open } else { Verdict::Ask }, url: Some(clean), host: Some(host) }
}

fn tailscale(host: &str) -> bool {
    host == "tailscale.com" || host.ends_with(".tailscale.com")
}

/// A link read as Java's `java.net.URI` reads one (RFC 2396), so what failed closed there fails closed here: only ASCII
/// characters a URI allows, and a host only when the authority is a plain server (no host for anything else).
struct Link<'a> {
    scheme: &'a str,
    host: Option<&'a str>,
    port: Option<u64>,
    user_info: bool,
}

impl<'a> Link<'a> {
    fn parse(s: &'a str) -> Option<Link<'a>> {
        let allowed =
            |c: char| c.is_ascii_graphic() && !matches!(c, '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}');
        if s.is_empty() || !s.chars().all(allowed) {
            return None;
        }
        // Escapes must be complete.
        let bytes = s.as_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if *b == b'%'
                && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit))
            {
                return None;
            }
        }
        let colon = s.find(':');
        let scheme_end = colon.filter(|&i| {
            i > 0
                && s[..i].starts_with(|c: char| c.is_ascii_alphabetic())
                && s[..i].chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        });
        let Some(i) = scheme_end else {
            // A relative reference: no scheme, no host.
            return Some(Link { scheme: "", host: None, port: None, user_info: false });
        };
        let scheme = &s[..i];
        let rest = &s[i + 1..];
        let Some(hier) = rest.strip_prefix("//") else {
            return Some(Link { scheme, host: None, port: None, user_info: false });
        };
        let end = hier.find(['/', '?', '#']).unwrap_or(hier.len());
        let authority = &hier[..end];
        if authority.is_empty() {
            return Some(Link { scheme, host: None, port: None, user_info: false });
        }
        let (user_info, hostport) = match authority.rfind('@') {
            Some(at) => (true, &authority[at + 1..]),
            None => (false, authority),
        };
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let close = v6.find(']')?;
            let after = &v6[close + 1..];
            let port = match after.strip_prefix(':') {
                Some(p) if !p.is_empty() => Some(p.parse::<u64>().ok()?),
                Some(_) => None,
                None if after.is_empty() => None,
                None => return None,
            };
            (&hostport[..close + 2], port)
        } else {
            match hostport.rfind(':') {
                Some(c) => {
                    let p = &hostport[c + 1..];
                    let port = if p.is_empty() {
                        None
                    } else {
                        Some(p.parse::<u64>().ok().filter(|_| p.chars().all(|c| c.is_ascii_digit()))?)
                    };
                    (&hostport[..c], port)
                }
                None => (hostport, None),
            }
        };
        // A registry-based authority (anything but a server's name or address) has no host in java.net.URI.
        let server = !host.is_empty() && (host.starts_with('[') || hostname(host) || ipv4(host));
        Some(Link {
            scheme,
            host: server.then_some(host),
            port: if server { port } else { None },
            user_info: user_info && server,
        })
    }
}

/// RFC 2396's hostname: dot-separated labels of letters, digits and inner hyphens, the last starting with a letter, an
/// optional final dot.
fn hostname(h: &str) -> bool {
    let h = h.strip_suffix('.').unwrap_or(h);
    let labels: Vec<&str> = h.split('.').collect();
    let label = |l: &str| {
        !l.is_empty()
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.iter().all(|l| label(l)) && labels.last().is_some_and(|l| l.starts_with(|c: char| c.is_ascii_alphabetic()))
}

fn ipv4(h: &str) -> bool {
    let parts: Vec<&str> = h.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Verdict::*;

    fn v(url: &str, control: Option<&str>) -> Verdict {
        check(url, control).verdict
    }

    #[test]
    fn a_sign_in_waits_from_its_link_until_running() {
        assert!(pending("https://login.tailscale.com/a/1", Some("NeedsLogin"), false));
        // A restarted engine: no link yet, not signed in. The sign-in still waits.
        assert!(pending("", Some("NoState"), true));
        assert!(pending("", Some("Starting"), true));
        assert!(!pending("", Some("Running"), true));
        assert!(!pending("", Some("Starting"), false));
    }

    #[test]
    fn tailscale_links_open_with_the_default_server() {
        assert_eq!(Open, v("https://login.tailscale.com/a/1a2b3c", None));
        assert_eq!(Open, v("https://LOGIN.Tailscale.com./a/1a2b3c", None));
        assert_eq!(Open, v("https://login.tailscale.com/a/x", Some("https://controlplane.tailscale.com")));
        assert_eq!(Open, v("https://login.tailscale.com/a/x", Some("  ")));
    }

    #[test]
    fn headscale_links_open_only_on_its_own_host() {
        assert_eq!(Open, v("https://hs.example.net/register/nodekey:abc", Some("https://hs.example.net")));
        assert_eq!(Open, v("https://hs.example.net:8443/oidc/register/x", Some("https://hs.example.net:8443/")));
        assert_eq!(Ask, v("https://login.tailscale.com/a/x", Some("https://hs.example.net")));
        assert_eq!(Ask, v("https://idp.example.org/auth", Some("https://hs.example.net")));
        assert_eq!(Ask, v("https://login.tailscale.com/a/x", Some("https://other.tailscale.com")));
    }

    #[test]
    fn an_unreadable_custom_server_trusts_nothing() {
        assert_eq!(Ask, v("https://login.tailscale.com/a/x", Some("hs example net")));
        assert_eq!(Ask, v("https://login.tailscale.com/a/x", Some("not-a-url")));
    }

    #[test]
    fn lookalike_hosts_ask() {
        assert_eq!(Ask, v("https://login.tailscale.com.evil.example/a/x", None));
        assert_eq!(Ask, v("https://eviltailscale.com/a/x", None));
        assert_eq!(Some("evil.example".to_string()), check("https://evil.example/a", None).host);
    }

    #[test]
    fn the_launched_link_is_the_cleaned_one() {
        let r = check("  HTTPS://login.tailscale.com/a/x?y=1  ", None);
        assert_eq!(Open, r.verdict);
        assert_eq!(Some("https://login.tailscale.com/a/x?y=1".to_string()), r.url);
    }

    #[test]
    fn non_web_or_malformed_links_never_open() {
        for u in [
            "http://login.tailscale.com/a/x",
            "intent://scan/#Intent;scheme=zxing;package=com.example;end",
            "javascript:alert(1)",
            "market://details?id=x",
            "https://user:pw@login.tailscale.com/a/x",
            "https:///a/x",
            "not a url",
            "https://login.tailscale.com:65536/a",
            "https://login.tailscale.com:0/a",
        ] {
            let r = check(u, None);
            assert_eq!(Refuse, r.verdict, "{u}");
            assert_eq!(None, r.url, "{u}");
        }
        assert_eq!(Open, v("https://login.tailscale.com:443/a", None));
        assert_eq!(Open, v("https://login.tailscale.com:1/a", None));
        assert_eq!(Open, v("https://login.tailscale.com:65535/a", None));
        // Internationalised hosts fail closed (java.net.URI gives no host); their punycode form works.
        assert_eq!(Refuse, v("https://bücher.example/auth", Some("https://bücher.example")));
        assert_eq!(Open, v("https://xn--bcher-kva.example/auth", Some("https://xn--bcher-kva.example")));
    }
}
