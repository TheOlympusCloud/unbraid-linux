//! Proton VPN over WireGuard. Sign-in is local: the private key (or the whole .conf) of a config downloaded at
//! account.protonvpn.com → Downloads → WireGuard configuration. gluetun's wiki confirms that one key works on every server.
//! Servers: gluetun's catalogue (Proton's own list needs a login). Port 51820 is gluetun's WireGuard port for Proton;
//! address 10.2.0.2/32 and DNS 10.2.0.1 are the defaults of Proton's generated config (their multi-tunnel guide
//! lists 10.3.0.2 / 10.3.0.1 as the *second* config, https://protonvpn.com/support/wireguard-configurations/).
//! Secure Core (`CH-US#1`) and Tor (`FR#13-TOR`) servers are left out: they need a plan feature and a different route.
//! A Free plan's key works only on Proton's free servers (https://protonvpn.com/free-vpn/server; gluetun marks them
//! `"free": true`), so [`PROTON_FREE`] lists just those while [`PROTON`] lists everything else plus them.
//! The endpoint port follows gluetun.

use super::key_provider::{self, Account, KeyProvider};
use super::{Field, Limit, Provider};
use crate::APP;
use crate::catalog::{self, Entry};
use crate::error::Result;
use crate::model::{Country, Link, Location, Server};
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

static SECURE_CORE: LazyLock<Regex> = LazyLock::new(|| Regex::new("^(CH|IS|SE)-[A-Z]{2}#").unwrap());

pub struct ProtonVpn {
    free: bool,
}

/// Proton VPN with a paid plan: every normal server, free ones included.
pub static PROTON: ProtonVpn = ProtonVpn { free: false };
/// Proton VPN with a Free plan: only the servers that plan can use.
pub static PROTON_FREE: ProtonVpn = ProtonVpn { free: true };

impl ProtonVpn {
    pub(crate) fn filtered(&self, all: Vec<Entry>) -> Vec<Entry> {
        all.into_iter()
            .filter(|e| {
                let n = e.server_name.as_deref().unwrap_or_default();
                (e.free || !self.free) && !SECURE_CORE.is_match(n) && !n.ends_with("-TOR")
            })
            .collect()
    }
}

impl Provider for ProtonVpn {
    fn id(&self) -> &'static str {
        if self.free { "proton-free" } else { "proton" }
    }

    fn name(&self) -> &'static str {
        if self.free { "Proton VPN Free" } else { "Proton VPN" }
    }

    fn fields(&self) -> Vec<Field> {
        vec![Field { hint: "Paste the whole file, or the PrivateKey".into(), file: true, ..Field::new("key", "WireGuard key or .conf") }]
    }

    fn help(&self) -> String {
        let plan = if self.free {
            "A Free plan's key works only on Proton's free servers (see protonvpn.com/free-vpn/server), so this list shows just those; with a paid plan choose Proton VPN."
        } else {
            "The same key works on every Proton server. A Free plan's key works only on Proton's free servers: choose Proton VPN Free for those."
        };
        format!(
            "Sign in at account.protonvpn.com → Downloads → WireGuard configuration. Name the config, pick any platform and server, then Create and Download. Paste the whole .conf (or just the PrivateKey value). {plan}"
        )
    }

    fn blocking_note(&self) -> String {
        if self.free {
            format!("None on the Free plan. Use {APP}'s Protection filter instead")
        } else {
            format!("NetShield is chosen when you make a config at Proton. Or use {APP}'s Protection filter instead")
        }
    }

    /// Proton's plans: Free one connection at a time, Plus and Unlimited ten; a manual key counts per tunnel (tested live).
    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "connection".into(), per_tunnel: true, value: Some(if self.free { 1 } else { 10 }) }
    }

    fn config_help(&self) -> Option<(String, String)> {
        Some(("Proton configs expire. Extend yours at account.protonvpn.com, Downloads".into(), "https://account.protonvpn.com/downloads".into()))
    }

    fn list_source(&self) -> Option<String> {
        Some("protonvpn".into())
    }

    fn facts(&self, account: &str) -> Option<String> {
        key_provider::facts(self, account)
    }

    fn trusts(&self, link: &Link, account: &str) -> bool {
        key_provider::trusts(self, link, account)
    }

    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String> {
        key_provider::sign_in(self, input)
    }

    fn countries(&self, account: &str) -> Result<Vec<Country>> {
        key_provider::countries(self, account)
    }

    fn connect(&self, loc: &Location, account: &str) -> Result<Link> {
        key_provider::connect(self, loc, account)
    }

    fn servers(&self, loc: &Location, account: &str, limit: usize) -> Result<Vec<Server>> {
        key_provider::servers(self, loc, account, limit)
    }
}

impl KeyProvider for ProtonVpn {
    /// The options Proton writes into each config it makes, as comments; changing one takes a new config.
    fn config_facts(&self) -> &'static [&'static str] {
        &["VPN Accelerator", "NetShield", "Moderate NAT", "NAT-PMP (Port Forwarding)"]
    }

    fn fact(&self, key: &str, value: &str) -> String {
        match key {
            "NetShield" => format!(
                "NetShield {}",
                match value {
                    "0" => "off",
                    "1" => "malware",
                    "2" => "malware, ads and trackers",
                    other => other,
                }
            ),
            "NAT-PMP (Port Forwarding)" => format!("Port forwarding {value}"),
            _ => format!("{key} {value}"),
        }
    }

    fn default_address(&self) -> Option<Vec<String>> {
        Some(vec!["10.2.0.2/32".into()])
    }

    fn default_dns(&self) -> Vec<String> {
        vec!["10.2.0.1".into()]
    }

    fn default_port(&self) -> i32 {
        51820
    }

    fn entries(&self, _a: &Account) -> Result<Vec<Entry>> {
        Ok(self.filtered(catalog::fetch("protonvpn", "wireguard")?))
    }
}
