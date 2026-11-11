//! VPN providers unbraid signs in to, and what every provider page shares.

pub mod airvpn;
pub mod expressvpn;
pub mod ivpn;
pub mod key_provider;
pub mod mullvad;
pub mod nord;
pub mod nord_api;
pub mod pia;
pub mod proton;
pub mod surfshark;
pub mod windscribe;

use crate::error::{Error, Result};
use crate::model::{Country, Link, Location, Server};
use indexmap::IndexMap;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock};

/// Key of a provider's own blocking switch on its page ("on"/"off"); a route can override it ([`crate::model::Route::filter`]).
pub const PROTECT: &str = "protect";
/// Key of a WireGuard provider's port setting: [`AUTO`] or a port number.
pub const PORT_OPT: &str = "port";
pub const AUTO: &str = "auto";
/// Key of every WireGuard provider's MTU setting: [`AUTO`] is 1280, as in Mullvad's Android app; else up to 1420.
pub const MTU_OPT: &str = "mtu";
pub const MTU_MIN: i32 = 1280;
pub const MTU_MAX: i32 = 1420;
/// Key of a provider's entry address setting: the number of one of a server's entries, from 1.
pub const ENTRY_OPT: &str = "entry";

/// Settings every provider page has, with their defaults.
pub fn common_default(key: &str) -> Option<String> {
    (key == MTU_OPT).then(|| AUTO.to_string())
}

/// The MTU setting every WireGuard provider's page has.
pub static MTU: LazyLock<Opt> = LazyLock::new(|| Opt {
    choices: std::iter::once((AUTO.to_string(), format!("Default ({MTU_MIN})")))
        .chain([1320, 1360, 1380, 1400, MTU_MAX].map(|m| (m.to_string(), m.to_string())))
        .collect(),
    advanced: true,
    ..Opt::new(
        MTU_OPT,
        "MTU",
        "Default works on every network. Larger can be faster on Wi-Fi but can stall uploads on mobile data",
    )
});

/// The MTU a provider's tunnels use, from its page's [`MTU_OPT`].
pub fn mtu(value: Option<&str>) -> i32 {
    value.and_then(|v| v.parse::<i32>().ok()).filter(|m| (MTU_MIN..=MTU_MAX).contains(m)).unwrap_or(MTU_MIN)
}

/// `server` as `list` (the provider's current one) has it; as saved when there is no list; gone if it lacks it.
pub fn as_listed(server: &Server, list: Option<Vec<Server>>) -> Result<Server> {
    match list {
        None => Ok(server.clone()),
        Some(l) => {
            l.into_iter().find(|s| s.host == server.host).ok_or_else(|| Error::NoLongerOffered(server.name.clone()))
        }
    }
}

/// Whether the earlier app counted `e` as an I/O failure, one a provider may fall back from: every kind but bad input
/// and a bad state.
pub(crate) fn is_io(e: &Error) -> bool {
    !matches!(e, Error::Invalid(_) | Error::State(_))
}

/// `r`'s value, or none after an I/O failure ([`is_io`]); any other failure is passed on.
pub(crate) fn unless_io<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if is_io(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// An account as the blob the store keeps: JSON without defaults or empty values, as the earlier app wrote it.
pub(crate) fn encode(account: &impl Serialize) -> Result<String> {
    serde_json::to_string(account).map_err(|e| Error::State(e.to_string()))
}

/// One sign-in form field. `file` = can hold a whole config file; `qr` = can be filled by scanning a QR code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub label: String,
    pub secret: bool,
    pub hint: String,
    pub file: bool,
    pub qr: bool,
}

impl Field {
    pub fn new(key: &str, label: &str) -> Self {
        Field { key: key.into(), label: label.into(), secret: true, hint: String::new(), file: false, qr: false }
    }
}

/// A setting on a provider's page, saved in the setup's opts. No `choices` = an on/off switch ("on"/"off").
/// `advanced`: one most people never need, listed under the page's Advanced settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub key: String,
    pub label: String,
    pub sub: String,
    pub choices: Vec<(String, String)>,
    pub advanced: bool,
}

impl Opt {
    pub fn new(key: &str, label: &str, sub: &str) -> Self {
        Opt { key: key.into(), label: label.into(), sub: sub.into(), choices: vec![], advanced: false }
    }
}

/// What a provider says about the device slot this computer holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub line: String,
    pub url: Option<String>,
    pub used: Option<i32>,
}

/// How many `unit`s ("connection" or "device") an account may use at once, and how unbraid counts its own: one per
/// separate tunnel (`per_tunnel`), or one for the whole account. `value` none = unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub unit: String,
    pub per_tunnel: bool,
    pub value: Option<i32>,
}

/// A VPN provider unbraid can sign in to. Every call may block on the network and runs off the window's thread.
/// `account` is the opaque, sealed blob [`Provider::sign_in`] returned.
pub trait Provider: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn fields(&self) -> Vec<Field>;
    /// Where the user finds what `fields` ask for.
    fn help(&self) -> String;
    /// Validates credentials (talking to the provider) and returns what `connect` needs later.
    fn sign_in(&self, input: &IndexMap<String, String>) -> Result<String>;
    /// Countries with cities, sorted by name.
    fn countries(&self, account: &str) -> Result<Vec<Country>>;
    /// Picks the best server for `loc` and returns a ready tunnel.
    fn connect(&self, loc: &Location, account: &str) -> Result<Link>;
    /// Up to `limit` servers for a manual pick, best first.
    fn servers(&self, _loc: &Location, _account: &str, _limit: usize) -> Result<Vec<Server>> {
        Ok(vec![])
    }
    fn has_load(&self) -> bool {
        false
    }
    fn one_key(&self) -> bool {
        false
    }
    fn protocol(&self) -> String {
        "WireGuard".into()
    }
    fn sign_out(&self, _account: &str) -> bool {
        true
    }
    fn revoked(&self, _account: &str) -> bool {
        false
    }
    fn trusts(&self, _link: &Link, _account: &str) -> bool {
        true
    }
    fn protection(&self) -> Option<Opt> {
        None
    }
    fn facts(&self, _account: &str) -> Option<String> {
        None
    }
    fn config_help(&self) -> Option<(String, String)> {
        None
    }
    fn list_source(&self) -> Option<String> {
        None
    }
    fn blocking_note(&self) -> String {
        format!("{} can't turn it on or off. Use {}'s Protection filter instead", crate::APP, crate::APP)
    }
    fn blocking_url(&self) -> Option<String> {
        None
    }
    fn options(&self, _account: &str) -> Vec<Opt> {
        vec![]
    }
    fn defaults(&self) -> IndexMap<String, String> {
        IndexMap::new()
    }
    fn blocking_dns(&self, _opts: &dyn Fn(&str) -> Option<String>) -> Option<String> {
        None
    }
    fn device(&self, _account: &str) -> Option<Device> {
        None
    }
    fn plan(&self, _account: &str) -> Option<String> {
        None
    }
    fn limit(&self, _account: &str) -> Limit {
        Limit { unit: "connection".into(), per_tunnel: true, value: None }
    }
    fn key_setup_ms(&self) -> u64 {
        0
    }
}

/// The account's plan, as its provider page shows it.
pub mod plans {
    use chrono::{DateTime, Local};

    /// "Paid until 22 Nov 2026", "Ended on …" once past, or "No active plan" when `paid_until` (epoch seconds) is none.
    pub fn line(paid_until: Option<i64>, now: i64) -> String {
        let Some(t) = paid_until else { return "No active plan".into() };
        let date = DateTime::from_timestamp(t, 0)
            .map(|d| d.with_timezone(&Local).format("%-d %b %Y").to_string())
            .unwrap_or_default();
        if t < now { format!("Ended on {date}") } else { format!("Paid until {date}") }
    }
}

/// Providers that only offer downloadable configs: the user imports one file per location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportGuide {
    pub id: &'static str,
    pub name: &'static str,
    pub open_vpn: bool,
    pub r#where: &'static str,
    pub url: &'static str,
}

pub const IMPORTS: &[ImportGuide] = &[
    ImportGuide {
        id: "purevpn",
        name: "PureVPN",
        open_vpn: false,
        r#where: "Member Area → Manual configuration → WireGuard",
        url: "https://my.purevpn.com/",
    },
    ImportGuide {
        id: "cyberghost",
        name: "CyberGhost",
        open_vpn: true,
        r#where: "My Devices → Configure new device → OpenVPN",
        url: "https://my.cyberghostvpn.com/",
    },
];

/// Provider id → when it was last signed in to (ms), in this process: its new key may still be spreading
/// ([`Provider::key_setup_ms`]).
pub static SIGNED_IN_AT: LazyLock<Mutex<HashMap<String, i64>>> = LazyLock::new(Default::default);

/// Providers whose key is still being set up at `now` (ms).
pub fn setting_up(now: i64) -> HashSet<String> {
    let signed_in = SIGNED_IN_AT.lock().unwrap_or_else(PoisonError::into_inner);
    signed_in
        .iter()
        .filter(|(id, t)| now - **t < get(id).map_or(0, |p| p.key_setup_ms() as i64))
        .map(|(id, _)| id.clone())
        .collect()
}

type Lookup = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;
static OPT: RwLock<Option<Lookup>> = RwLock::new(None);

/// A provider page setting's saved value, for choices made outside [`Provider::connect`]'s arguments: the provider's
/// default until the app points it at the saved settings ([`set_opt`]).
pub fn opt(provider: &str, key: &str) -> Option<String> {
    let lookup = OPT.read().unwrap_or_else(PoisonError::into_inner).clone();
    match lookup {
        Some(f) => f(provider, key),
        None => get(provider).and_then(|p| p.defaults().get(key).cloned()),
    }
}

/// Where [`opt`] reads the saved settings from; set once by the app at start.
pub fn set_opt(f: impl Fn(&str, &str) -> Option<String> + Send + Sync + 'static) {
    *OPT.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(f));
}

/// Every provider, in the order the sign-in list shows them.
pub fn all() -> Vec<&'static dyn Provider> {
    vec![
        &nord::Nord,
        &mullvad::Mullvad,
        &pia::Pia,
        &ivpn::Ivpn,
        &proton::PROTON,
        &proton::PROTON_FREE,
        &surfshark::Surfshark,
        &expressvpn::ExpressVpn,
        &windscribe::Windscribe,
        &airvpn::AirVpn,
    ]
}

pub fn get(id: &str) -> Option<&'static dyn Provider> {
    all().into_iter().find(|p| p.id() == id)
}

/// Name short enough for a route label: "Nord", "PIA", "Proton".
pub fn short(id: &str) -> String {
    match id {
        "nord" => "Nord".into(),
        "pia" => "PIA".into(),
        "proton" => "Proton".into(),
        "proton-free" => "Proton Free".into(),
        _ => get(id).map(|p| p.name().to_string()).unwrap_or_else(|| id.to_string()),
    }
}

/// A provider page setting's default: the provider's own, else every page's.
pub fn default_opt(provider: &str, key: &str) -> Option<String> {
    get(provider).and_then(|p| p.defaults().get(key).cloned()).or_else(|| common_default(key))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::catalog::Entry;
    use crate::model::WgPeer;
    use crate::snapshot::Snapshot;
    use serde_json::{Map, Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::MutexGuard;
    use std::time::{Duration, Instant};

    /// A fixture under tests/fixtures, e.g. "providers/mullvad_relays.json".
    pub(crate) fn fixture(path: &str) -> String {
        std::fs::read_to_string(format!("{}/tests/fixtures/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// A sign-in form's answers.
    pub(crate) fn input(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    pub(crate) fn by_country(provider: &str, country: &str) -> Location {
        Location { country: Some(country.into()), ..Location::of(provider) }
    }

    pub(crate) fn by_code(provider: &str, code: &str) -> Location {
        Location { country_code: Some(code.into()), ..Location::of(provider) }
    }

    pub(crate) fn pinned_to(provider: &str, server: Server) -> Location {
        Location { pinned: Some(server), ..Location::of(provider) }
    }

    /// A WireGuard tunnel's peer.
    pub(crate) fn peer(l: &Link) -> &WgPeer {
        match l {
            Link::Wg { peer, .. } => peer,
            _ => panic!("not a WireGuard tunnel"),
        }
    }

    fn down<T>() -> Result<T> {
        Err(Error::Io("offline".into()))
    }

    /// Held by every test that changes a provider's sources, which start offline: no test reaches the internet.
    pub(crate) fn offline() -> MutexGuard<'static, ()> {
        static SOURCES: Mutex<()> = Mutex::new(());
        let held = SOURCES.lock().unwrap_or_else(PoisonError::into_inner);
        surfshark::set_catalogue(down);
        *surfshark::ADDRESS_BOOK.write().unwrap() = Snapshot::memory(None);
        *surfshark::LIVE.write().unwrap() = Arc::new(down::<String>);
        *surfshark::SNAPSHOT.write().unwrap() = Snapshot::memory(None);
        *airvpn::STATUS.write().unwrap() = Arc::new(down::<String>);
        *airvpn::CATALOGUE.write().unwrap() = Arc::new(down::<Vec<Entry>>);
        *airvpn::API_CALL.write().unwrap() = Arc::new(|_, _, _| down());
        *airvpn::PAUSE.write().unwrap() = Arc::new(|_| panic!("no waiting in tests"));
        *windscribe::NODE_HOSTS.write().unwrap() = Arc::new(|| None);
        held
    }

    /// Surfshark's addresses come from the catalogue: give every one of `entries`' hosts the address `ip`.
    pub(crate) fn surfshark_at(entries: &[Entry], ip: &str) {
        let at: Vec<Entry> = entries
            .iter()
            .map(|e| Entry {
                vpn: "wireguard".into(),
                country: Some(if e.place().is_empty() { "Netherlands".into() } else { e.place().into() }),
                hostname: e.hostname.clone(),
                wgpubkey: Some("unused".into()),
                ips: vec![ip.into()],
                ..Entry::default()
            })
            .collect();
        surfshark::set_catalogue(move || Ok(at.clone()));
    }

    /// A value as text: a string as it is, a number or a boolean as JSON writes it.
    fn text(o: &Map<String, Value>, k: &str) -> String {
        match &o[k] {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }

    /// Same shape as the compiler's WireGuard endpoint.
    pub(crate) fn wg(tag: &str, p: &WgPeer) -> Value {
        let (address, port) = p.endpoint.rsplit_once(':').unwrap();
        let mut peer = json!({"address": address, "port": port.parse::<i32>().unwrap(), "public_key": p.public_key, "allowed_ips": ["0.0.0.0/0"], "persistent_keepalive_interval": 25});
        if let Some(k) = &p.preshared_key {
            peer["pre_shared_key"] = json!(k);
        }
        json!({"type": "wireguard", "tag": tag, "mtu": p.mtu, "address": p.address, "private_key": p.private_key, "peers": [peer]})
    }

    /// The smallest full sing-box config that routes everything through `tag`, for [`sing_box_check`].
    pub(crate) fn sing_box_config(file: &str, tag: &str, endpoint: Value) -> PathBuf {
        let cfg = json!({"log": {"level": "info"}, "endpoints": [endpoint], "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": tag}});
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/providers");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join(format!("{file}.json"));
        std::fs::write(&f, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        f
    }

    /// `sing-box check` on `f`, when a sing-box binary is at hand ($SING_BOX_CLI, else the one engine/build.sh
    /// built, else sing-box-cli in $WORK or ~/.cache/unbraid-libbox); without one the check is skipped.
    pub(crate) fn sing_box_check(f: &Path) {
        let home = std::env::var("HOME").unwrap_or_default();
        let built = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine/out/sing-box-cli");
        let bin = std::env::var_os("SING_BOX_CLI")
            .map(PathBuf::from)
            .or_else(|| built.exists().then_some(built))
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var("WORK").unwrap_or_else(|_| format!("{home}/.cache/unbraid-libbox")))
                    .join("sing-box-cli")
            });
        if !bin.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0) {
            eprintln!("sing-box-cli not found: {} not checked", f.display());
            return;
        }
        let mut child = Command::new(&bin)
            .args(["check", "-c"])
            .arg(f)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                panic!("sing-box check {} timed out", f.display());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "sing-box check {}: {}{}",
            f.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Fixes across providers: load shown only where it is real, pinned servers refreshed, NordVPN's groups, imports refused.
    mod provider_fixes {
        use super::*;
        use crate::catalog::{self, Entry};
        use crate::providers::airvpn::AirVpn;
        use crate::providers::expressvpn::ExpressVpn;
        use crate::providers::ivpn::Ivpn;
        use crate::providers::key_provider;
        use crate::providers::mullvad::{self, Mullvad};
        use crate::providers::nord::Nord;
        use crate::providers::pia::Pia;
        use crate::providers::proton::{PROTON, PROTON_FREE};
        use crate::providers::surfshark::Surfshark;
        use crate::providers::windscribe::Windscribe;
        use chrono::NaiveDate;

        const PRIV: &str = "dW5icmFpZC10ZXN0LXByaXZhdGUta2V5LTAwMDAwMDE=";
        const PSK: &str = "dW5icmFpZC10ZXN0LXByZXNoYXJlZC1rZXktMDAwMDE=";
        const KEY1: &str = "vOgsnvam/Xc6w8zfQeGcynOr8RMxYzpki3b0EaOkEoI=";
        const KEY2: &str = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=";

        fn account() -> key_provider::Account {
            key_provider::Account::new(PRIV, vec!["10.2.0.2/32".into()], vec!["10.2.0.1".into()], 51820, 1420)
        }

        // ---- load is shown only where it is real

        #[test]
        fn only_providers_with_real_load_say_fastest() {
            let loaded: HashSet<&str> = [&Nord as &dyn Provider, &Ivpn, &Surfshark, &AirVpn]
                .into_iter()
                .filter(|p| p.has_load())
                .map(|p| p.id())
                .collect();
            assert_eq!(HashSet::from(["nord", "ivpn", "surfshark", "airvpn"]), loaded);
            assert!(
                [&Mullvad as &dyn Provider, &Pia, &PROTON, &PROTON_FREE, &ExpressVpn, &Windscribe]
                    .into_iter()
                    .all(|p| !p.has_load())
            );
        }

        #[test]
        fn live_load_is_ingested_and_ranks_the_catalogue() {
            let _held = offline();
            let clusters = surfshark::parse(&format!(
                r#"[{{"country":"Netherlands","location":"Amsterdam","connectionName":"nl-ams.prod.surfshark.com","pubKey":"{KEY1}","load":41}},
                {{"country":"Netherlands","location":"Amsterdam","connectionName":"nl-ams2.prod.surfshark.com","pubKey":"{KEY1}","load":6}},
                {{"country":"Netherlands","location":"Amsterdam","connectionName":"nl-ams3.prod.surfshark.com","pubKey":"{KEY1}"}}]"#
            ))
            .unwrap();
            assert_eq!(vec![41, 6, -1], clusters.iter().map(|e| e.load).collect::<Vec<_>>());
            surfshark_at(&clusters, "203.0.113.7");
            let l = key_provider::link(&Surfshark, &by_country("surfshark", "Netherlands"), &account(), || {
                Ok(clusters.clone())
            })
            .unwrap();
            assert_eq!("nl-ams2.prod.surfshark.com", l.server().host);
            assert_eq!(6, l.server().load);

            let air = airvpn::parse(
                r#"{"servers":[{"public_name":"A","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.4","health":"ok","currentload":70},
                {"public_name":"B","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.5","health":"ok","currentload":12}]}"#,
                KEY1,
            )
            .unwrap();
            assert_eq!(vec![70, 12], air.iter().map(|e| e.load).collect::<Vec<_>>());
            let sv = key_provider::link(&AirVpn, &by_country("airvpn", "Austria"), &account(), || Ok(air.clone()))
                .unwrap()
                .server()
                .clone();
            assert_eq!("B", sv.name);
            assert_eq!(12, sv.load);
            let bare = Entry {
                vpn: "wireguard".into(),
                country: Some("Austria".into()),
                ips: vec!["1.2.3.4".into()],
                ..Entry::default()
            };
            assert_eq!(-1, catalog::server(&bare, None).unwrap().load);
        }

        // ---- pinned servers are refreshed

        fn relays() -> String {
            format!(
                r#"{{"locations":{{"se-got":{{"country":"Sweden","city":"Gothenburg"}}}},"wireguard":{{"relays":[
                {{"hostname":"se-got-wg-001","location":"se-got","active":true,"ipv4_addr_in":"10.0.0.9","public_key":"{KEY2}","weight":1}},
                {{"hostname":"se-got-wg-002","location":"se-got","active":false,"ipv4_addr_in":"10.0.0.10","public_key":"{KEY2}","weight":1}}]}}}}"#
            )
        }

        #[test]
        fn mullvad_pinned_server_uses_the_fresh_address_and_key() {
            let a = mullvad::Account {
                account: "1234567890123456".into(),
                private_key: PRIV.into(),
                ipv4_address: "10.66.12.34/32".into(),
                device_id: "dev-1".into(),
                device: String::new(),
            };
            let list = mullvad::parse(&relays()).unwrap();
            let stale = Server {
                name: "se-got-wg-001".into(),
                host: "se-got-wg-001".into(),
                ip: "10.0.0.1".into(),
                public_key: KEY1.into(),
                load: 0,
                city: "Gothenburg".into(),
                country: String::new(),
            };
            let l =
                mullvad::link(Some(&list), &pinned_to("mullvad", stale.clone()), &a, &mut rand::rng(), false).unwrap();
            assert_eq!("10.0.0.9:51820", peer(&l).endpoint);
            assert_eq!(KEY2, peer(&l).public_key);
            assert_eq!(KEY2, l.server().public_key);
            // The list is down: the pinned values stand in.
            assert_eq!(
                "10.0.0.1:51820",
                peer(&mullvad::link(None, &pinned_to("mullvad", stale.clone()), &a, &mut rand::rng(), false).unwrap())
                    .endpoint
            );
            // A relay the list no longer offers is an error, not a stale endpoint.
            let inactive = Server {
                name: "se-got-wg-002".into(),
                host: "se-got-wg-002".into(),
                ip: "10.0.0.10".into(),
                ..stale.clone()
            };
            let unknown = Server { name: "se-got-wg-777".into(), host: "se-got-wg-777".into(), ..stale.clone() };
            for gone in [inactive, unknown] {
                assert!(
                    mullvad::link(Some(&list), &pinned_to("mullvad", gone), &a, &mut rand::rng(), false)
                        .is_err_and(|e| is_io(&e))
                );
            }
        }

        #[test]
        fn key_provider_pinned_server_uses_the_fresh_entry() {
            let old = Entry {
                vpn: "wireguard".into(),
                country: Some("Germany".into()),
                city: Some("Berlin".into()),
                server_name: Some("DE#1".into()),
                hostname: "node-de-01.protonvpn.net".into(),
                wgpubkey: Some(KEY1.into()),
                ips: vec!["1.1.1.1".into()],
                ..Entry::default()
            };
            let fresh = Entry { wgpubkey: Some(KEY2.into()), ips: vec!["2.2.2.2".into()], ..old.clone() };
            let pinned = catalog::server(&old, None).unwrap();
            let l = key_provider::link(&PROTON, &pinned_to("proton", pinned.clone()), &account(), || {
                Ok(vec![fresh.clone()])
            })
            .unwrap();
            assert_eq!("2.2.2.2:51820", peer(&l).endpoint);
            assert_eq!(KEY2, peer(&l).public_key);
            assert_eq!("DE#1", l.server().name);
            // Moved to a new host name but the same IP: still found.
            let renamed = pinned_to("proton", Server { host: "old-name".into(), ..pinned.clone() });
            let same_ip = Entry { ips: vec!["1.1.1.1".into()], ..fresh.clone() };
            assert_eq!(
                KEY2,
                peer(&key_provider::link(&PROTON, &renamed, &account(), || Ok(vec![same_ip.clone()])).unwrap())
                    .public_key
            );
            let offline_list = key_provider::link(&PROTON, &pinned_to("proton", pinned.clone()), &account(), || {
                Err(Error::Io("offline".into()))
            })
            .unwrap();
            assert_eq!("1.1.1.1:51820", peer(&offline_list).endpoint);
            let gone = pinned_to("proton", Server { name: "DE#9".into(), host: "x".into(), ..pinned.clone() });
            assert!(
                key_provider::link(&PROTON, &gone, &account(), || Ok(vec![fresh.clone()])).is_err_and(|e| is_io(&e))
            );
        }

        #[test]
        fn airvpn_pinned_server_is_found_by_name_because_host_names_are_shared() {
            let body = r#"{"servers":[{"public_name":"A","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.4","health":"ok"},
                {"public_name":"B","country_name":"Austria","country_code":"at","location":"Vienna","continent":"Europe","ip_v4_in1":"1.2.3.5","health":"ok"}]}"#;
            let list = airvpn::parse(body, KEY1).unwrap();
            let pinned = Server {
                name: "B".into(),
                host: "at.vpn.airdns.org".into(),
                ip: "9.9.9.9".into(),
                public_key: KEY1.into(),
                load: 0,
                ..Server::default()
            };
            let a = key_provider::Account { port: 1637, ..account() };
            assert_eq!(
                "1.2.3.5:1637",
                peer(&key_provider::link(&AirVpn, &pinned_to("airvpn", pinned), &a, || Ok(list.clone())).unwrap())
                    .endpoint
            );
        }

        // ---- NordVPN

        #[test]
        fn group_countries_are_read_from_the_full_server_list() {
            let body = r#"[{"hostname":"a","locations":[{"country":{"code":"US"}}]},{"hostname":"b","locations":[{"country":{"code":"NL"}}]},{"hostname":"c","locations":[{"country":{"code":"US"}}]}]"#;
            assert_eq!(
                HashSet::from(["US".to_string(), "NL".to_string()]),
                nord_api::country_codes(body).unwrap().into_iter().collect::<HashSet<_>>()
            );
        }

        #[test]
        fn dedicated_servers_come_from_the_accounts_own_service() {
            let services = r#"[{"ID":1,"expires_at":"2099-01-01 00:00:00","service":{"id":1,"name":"VPN"},"details":{}},
                {"ID":2,"expires_at":"2099-01-01 00:00:00","service":{"id":11,"name":"Dedicated IP"},"details":{"servers":[{"id":947235},{"id":947238}]}},
                {"ID":3,"expires_at":"2020-01-01 00:00:00","service":{"id":11,"name":"Dedicated IP"},"details":{"servers":[{"id":111}]}},
                {"ID":4,"expires_at":"2099-01-01 00:00:00","service":{"id":33,"name":"Dedicated server"},"details":{"servers":[{"id":222}]}}]"#;
            let ids = nord_api::dedicated_ids(
                services,
                NaiveDate::from_ymd_opt(2026, 10, 18).unwrap().and_hms_opt(12, 0, 0).unwrap(),
            )
            .unwrap();
            assert_eq!(HashSet::from([947235, 947238]), ids);
            assert!(nord_api::dedicated_ids("[]", chrono::Utc::now().naive_utc()).unwrap().is_empty());

            let sv = |id: i64, host: &str| {
                format!(
                    r#"{{"id":{id},"name":"United States #{id}","hostname":"{host}.nordvpn.com","station":"89.187.175.{id}","load":3,
                    "locations":[{{"country":{{"code":"US","city":{{"name":"Dallas"}}}}}}],
                    "technologies":[{{"identifier":"wireguard_udp","metadata":[{{"name":"public_key","value":"{KEY1}"}}]}}]}}"#
                )
            };
            let all = format!("[{},{},{}]", sv(947235, "us2943"), sv(947238, "us2944"), sv(5, "us1"));
            let mine = nord_api::with_ids(&all, &ids, true).unwrap();
            assert_eq!(
                vec!["us2943.nordvpn.com", "us2944.nordvpn.com"],
                mine.iter().map(|s| s.host.as_str()).collect::<Vec<_>>()
            );
            assert_eq!("Dallas", mine[0].city);
            assert_eq!(KEY1, mine[0].public_key);
        }

        // ---- Windscribe, AirVPN

        fn ws_conf(endpoint: &str) -> String {
            format!(
                "[Interface]\nPrivateKey = {PRIV}\nAddress = 100.96.12.34/32\nDNS = 10.255.255.1\n\n[Peer]\nPublicKey = {KEY1}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}"
            )
        }

        #[test]
        fn windscribe_static_ip_configs_are_refused() {
            let _held = offline();
            *windscribe::NODE_HOSTS.write().unwrap() =
                Arc::new(|| Some(HashSet::from(["us-central-117.whiskergalaxy.com".to_string()])));
            Windscribe.sign_in(&input(&[("config", &ws_conf("us-central-117.whiskergalaxy.com:443"))])).unwrap();
            for endpoint in ["203.0.113.5:443", "static-1.whiskergalaxy.com:443", "unlisted-1.whiskergalaxy.com:443"] {
                match Windscribe.sign_in(&input(&[("config", &ws_conf(endpoint))])) {
                    Err(Error::Invalid(m)) => assert!(m.contains("Your own servers") && !m.contains(PRIV), "{m}"),
                    _ => panic!("not refused: {endpoint}"),
                }
            }
            // The list can't be read: only the endpoint's shape is checked.
            *windscribe::NODE_HOSTS.write().unwrap() = Arc::new(|| None);
            Windscribe.sign_in(&input(&[("config", &ws_conf("unlisted-1.whiskergalaxy.com:443"))])).unwrap();
        }

        /// Generated configs name the location's WireGuard host (wg_endpoint), not a node: those are ordinary configs.
        #[test]
        fn windscribe_accepts_the_locations_wire_guard_host() {
            let _held = offline();
            let hosts =
                windscribe::hosts(&windscribe::parse(&fixture("providers/windscribe_serverlist.json")).unwrap());
            assert!(
                hosts.contains("dfw-86-wg.whiskergalaxy.com") && hosts.contains("us-central-117.whiskergalaxy.com")
            );
            *windscribe::NODE_HOSTS.write().unwrap() = Arc::new(move || Some(hosts.clone()));
            let blob = Windscribe.sign_in(&input(&[("config", &ws_conf("DFW-86-WG.whiskergalaxy.com:443"))])).unwrap();
            assert!(blob.contains(PSK));
            // A byte-order mark in front (some editors write one) changes nothing.
            let marked = format!("\u{FEFF}{}", ws_conf("dfw-86-wg.whiskergalaxy.com:443").replace('\n', "\r\n"));
            assert_eq!(blob, Windscribe.sign_in(&input(&[("config", &marked)])).unwrap());
        }

        #[test]
        fn airvpn_refuses_amnezia_configs() {
            let conf = |extra: &str| {
                format!(
                    "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.164.20.6/32\nDNS = 10.128.0.1\n{extra}\n\n[Peer]\nPublicKey = {KEY1}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0\nEndpoint = at.vpn.airdns.org:1637"
                )
            };
            AirVpn.sign_in(&input(&[("key", &conf(""))])).unwrap();
            for line in [
                "Jc = 4",
                "Jmin = 8",
                "Jmax=80",
                "S1 = 15",
                "S2 = 18",
                "H1 = 123456",
                "H4 = 5",
                "I1 = <b 0x00>",
                "i5 = x",
            ] {
                match AirVpn.sign_in(&input(&[("key", &conf(line))])) {
                    Err(Error::Invalid(m)) => assert!(m.contains("Amnezia") && !m.contains(PRIV), "{m}"),
                    _ => panic!("not refused: {line}"),
                }
            }
        }
    }

    /// Windscribe and ExpressVPN.
    mod key_providers_2 {
        use super::*;
        use crate::catalog::{self, Entry};
        use crate::manual;
        use crate::providers::expressvpn::{self, ExpressVpn};
        use crate::providers::windscribe::{self, Row, ServerList, Windscribe};
        use regex::Regex;

        const PRIV: &str = "cHJpdmF0ZS1wcml2YXRlLXByaXZhdGUtcHJpdmF0ZTE=";
        const PSK: &str = "cHJlc2hhcmVkLXByZXNoYXJlZC1wcmVzaGFyZWQtMTI=";
        const PEER_KEY: &str = "c2VydmVyLXNlcnZlci1zZXJ2ZXItc2VydmVyLTEyMzQ=";

        fn list() -> ServerList {
            windscribe::parse(&fixture("providers/windscribe_serverlist.json")).unwrap()
        }
        fn rows() -> Vec<Row> {
            windscribe::rows(&list())
        }
        fn express() -> Vec<Entry> {
            catalog::parse(&fixture("catalog/catalog_expressvpn.json"), "openvpn").unwrap()
        }
        fn login(user: &str, pass: &str) -> expressvpn::Account {
            expressvpn::Account { username: user.into(), password: pass.into() }
        }
        /// An ISO 3166 country code.
        fn iso(code: &str) -> bool {
            catalog::name(code).is_some()
        }

        fn ws_config(port: i32, extra: &str) -> String {
            format!(
                "[Interface]\nPrivateKey = {PRIV}\nAddress = 100.96.12.34/32\nDNS = 10.255.255.1\n\n[Peer]\nPublicKey = {PEER_KEY}\n{extra}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = us-central-117.whiskergalaxy.com:{port}"
            )
        }

        /// Signed in with a config on `port`; the caller holds [`offline`], so only the endpoint's form is checked.
        fn ws(port: i32) -> windscribe::Account {
            let blob =
                Windscribe.sign_in(&input(&[("config", &ws_config(port, &format!("PresharedKey = {PSK}")))])).unwrap();
            windscribe::account(&blob).unwrap()
        }

        #[test]
        fn windscribe_countries_carry_iso_codes_and_cities() {
            let rows = rows();
            let cs = windscribe::countries(&rows);
            let names: Vec<&str> = cs.iter().map(|c| c.name.as_str()).collect();
            let mut sorted = names.clone();
            sorted.sort();
            assert_eq!(sorted, names);
            assert_eq!(
                vec!["Canada East", "Fake Antarctica", "Italy", "Japan", "Netherlands", "US Central", "US East"],
                names
            );
            assert!(cs.iter().all(|c| iso(&c.code)));
            assert_eq!(cs.len(), cs.iter().map(|c| c.id).collect::<HashSet<_>>().len());
            let italy = cs.iter().find(|c| c.name == "Italy").unwrap();
            assert_eq!(vec!["Milan", "Palermo"], italy.cities.iter().map(|c| c.name.as_str()).collect::<Vec<_>>());
            assert_eq!(
                vec![Some("Milan"), Some("Palermo")],
                italy.cities.iter().map(|c| c.key.as_deref()).collect::<Vec<_>>()
            );
            assert_eq!("US", cs.iter().find(|c| c.name == "US East").unwrap().code);
            assert_eq!(rows.len() as i32, cs.iter().map(|c| c.server_count).sum::<i32>());
        }

        #[test]
        fn windscribe_uses_ip3_and_group_key() {
            let list = list();
            let rows = windscribe::rows(&list);
            let g = &list.data.iter().find(|r| r.name == "Italy").unwrap().groups[0];
            let n = &g.nodes[0];
            let row = rows.iter().find(|r| r.node.hostname == n.hostname).unwrap();
            assert_eq!(n.ip3, row.node.ip3);
            assert_eq!(g.public_key, row.public_key);
            assert!(rows.iter().all(|r| r.node.ip3 != r.node.hostname && r.node.ip3.contains('.')));
        }

        #[test]
        fn windscribe_sign_in_keeps_the_configs_fields() {
            let _held = offline();
            let a = ws(443);
            assert_eq!(PRIV, a.private_key);
            assert_eq!(vec!["100.96.12.34/32"], a.address);
            assert_eq!(PSK, a.preshared_key);
            assert_eq!(vec!["10.255.255.1"], a.dns);
            assert_eq!(443, a.port);
            assert_eq!(65142, ws(65142).port);
            assert_eq!(1194, ws(51820).port);
        }

        #[test]
        fn windscribe_sign_in_rejects_configs_without_a_preshared_key_or_a_peer() {
            let _held = offline();
            for bad in [
                ws_config(443, ""),
                String::new(),
                format!("[Interface]\nPrivateKey = {PRIV}\nAddress = 10.0.0.2/32"),
                "PrivateKey = SECRET-KEY-TEXT".into(),
            ] {
                match Windscribe.sign_in(&input(&[("config", &bad)])) {
                    Err(Error::Invalid(m)) => assert!(!m.contains("SECRET") && !m.contains(PRIV), "{m}"),
                    _ => panic!("not refused"),
                }
            }
        }

        #[test]
        fn windscribe_country_link_picks_the_least_loaded_node() {
            let _held = offline();
            let rows = rows();
            let loc = Location { country_code: Some("NL".into()), ..by_country("windscribe", "Netherlands") };
            let l = windscribe::link(Some(&rows), &loc, &ws(443), &mut rand::rng()).unwrap();
            let best = rows.iter().filter(|r| r.region == "Netherlands").map(|r| r.node.health).min().unwrap();
            assert_eq!(best, l.server().load);
            let p = peer(&l);
            assert_eq!(format!("{}:443", l.server().ip), p.endpoint);
            assert_eq!(vec!["0.0.0.0/0"], p.allowed_ips);
            assert_eq!(vec!["100.96.12.34/32"], p.address);
            assert_eq!(vec!["10.255.255.1"], p.dns);
            assert_eq!(PRIV, p.private_key);
            assert_eq!(Some(PSK), p.preshared_key.as_deref());
            assert_eq!(l.server().public_key, p.public_key);
            assert_eq!("NL", l.server().country);
            assert_eq!(1420, p.mtu);
        }

        #[test]
        fn windscribe_city_and_region_filters() {
            let _held = offline();
            let (rows, a, rnd) = (rows(), ws(443), &mut rand::rng());
            let milan = windscribe::link(
                Some(&rows),
                &Location { region: Some("Milan".into()), ..by_country("windscribe", "Italy") },
                &a,
                rnd,
            )
            .unwrap();
            assert_eq!("Milan", milan.server().city);
            let east = windscribe::link(
                Some(&rows),
                &Location { country_code: Some("US".into()), ..by_country("windscribe", "US East") },
                &a,
                rnd,
            )
            .unwrap();
            assert!(east.server().host.starts_with("us-east"));
            assert_eq!(2, windscribe::countries(&rows).iter().filter(|c| c.code == "US").count());
            let by_code = windscribe::link(Some(&rows), &by_code("windscribe", "CA"), &a, rnd).unwrap();
            assert_eq!("CA", by_code.server().country);
            let rome = windscribe::link(
                Some(&rows),
                &Location { region: Some("Rome".into()), ..by_country("windscribe", "Italy") },
                &a,
                rnd,
            );
            assert!(rome.is_err_and(|e| is_io(&e)));
        }

        #[test]
        fn windscribe_and_express_pinned_servers_are_refreshed() {
            let _held = offline();
            let (rows, a, rnd) = (rows(), ws(443), &mut rand::rng());
            let sv = windscribe::link(Some(&rows), &by_code("windscribe", "JP"), &a, rnd).unwrap().server().clone();
            let moved = Server { ip: "203.0.113.9".into(), ..sv.clone() };
            assert_eq!(
                sv.ip,
                windscribe::link(Some(&rows), &pinned_to("windscribe", moved), &a, rnd).unwrap().server().ip
            );
            let gone = Server { host: "gone.whiskergalaxy.com".into(), ..sv.clone() };
            assert!(matches!(
                windscribe::link(Some(&rows), &pinned_to("windscribe", gone), &a, rnd),
                Err(Error::NoLongerOffered(_))
            ));
            let (express, login) = (express(), login("u", "p"));
            let ex =
                expressvpn::link(Some(&express), &by_code("expressvpn", "SE"), &login, rnd).unwrap().server().clone();
            // Its old address while the server still has it, else a current one.
            assert_eq!(
                ex.ip,
                expressvpn::link(Some(&express), &pinned_to("expressvpn", ex.clone()), &login, rnd)
                    .unwrap()
                    .server()
                    .ip
            );
            let moved = Server { ip: "203.0.113.9".into(), ..ex.clone() };
            assert_ne!(
                "203.0.113.9",
                expressvpn::link(Some(&express), &pinned_to("expressvpn", moved), &login, rnd).unwrap().server().ip
            );
            let gone = Server { host: "gone.expressnetw.com".into(), ..ex.clone() };
            assert!(matches!(
                expressvpn::link(Some(&express), &pinned_to("expressvpn", gone), &login, rnd),
                Err(Error::NoLongerOffered(_))
            ));
            // Nothing but a dotted IPv4 goes into the profile, a saved pinned address included.
            for bad in ["1.2.3.4\nscript-security 2", "1.2.3", "1.2.3.256", "a.b.c.d", " 1.2.3.4", "١.2.3.4"] {
                let pinned = pinned_to("expressvpn", Server { ip: bad.into(), ..ex.clone() });
                assert!(matches!(expressvpn::link(None, &pinned, &login, rnd), Err(Error::Invalid(_))), "{bad}");
            }
        }

        #[test]
        fn windscribe_pinned_server_needs_no_list() {
            let _held = offline();
            let sv = windscribe::link(Some(&rows()), &by_code("windscribe", "JP"), &ws(443), &mut rand::rng())
                .unwrap()
                .server()
                .clone();
            let again =
                windscribe::link(None, &pinned_to("windscribe", sv.clone()), &ws(80), &mut rand::rng()).unwrap();
            assert_eq!(&sv, again.server());
            assert_eq!(format!("{}:80", sv.ip), peer(&again).endpoint);
        }

        #[test]
        fn windscribe_skips_nodes_without_wireguard() {
            let body = format!(
                r#"{{"data":[{{"name":"X","country_code":"nl","status":1,"groups":[
                {{"city":"A","wg_pubkey":"","nodes":[{{"hostname":"x-1.w.com","ip3":"1.2.3.4","health":1}}]}},
                {{"city":"B","wg_pubkey":"{PEER_KEY}","nodes":[{{"hostname":"x-2.w.com","ip3":"","health":1}},{{"hostname":"x-3.w.com","ip3":"1.2.3.5","health":2}}]}}]}},
                {{"name":"Down","country_code":"de","status":0,"groups":[{{"city":"C","wg_pubkey":"{PEER_KEY}","nodes":[{{"hostname":"d.w.com","ip3":"1.2.3.6"}}]}}]}}]}}"#
            );
            let r = windscribe::rows(&windscribe::parse(&body).unwrap());
            assert_eq!(vec!["x-3.w.com"], r.iter().map(|r| r.node.hostname.as_str()).collect::<Vec<_>>());
            assert_eq!("NL", r[0].code);
            let e = windscribe::parse("SECRET-LIST").unwrap_err();
            assert!(is_io(&e) && !e.to_string().contains("SECRET"));
        }

        #[test]
        fn express_skips_entries_without_strict_ipv4() {
            let dotted = Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$").unwrap();
            let valid = express().into_iter().find(|e| e.ips.iter().any(|ip| dotted.is_match(ip))).unwrap();
            let invalid =
                Entry { hostname: "bad.example".into(), ips: vec!["1.2.3.999".into()], load: 0, ..valid.clone() };
            let (loc, login) = (Location::of("expressvpn"), login("u", "p"));
            assert_eq!(
                valid.hostname,
                expressvpn::link(Some(&[invalid.clone(), valid.clone()]), &loc, &login, &mut rand::rng())
                    .unwrap()
                    .server()
                    .host
            );
            match expressvpn::link(Some(&[invalid]), &loc, &login, &mut rand::rng()) {
                Err(e @ Error::Io(_)) => assert!(e.to_string().starts_with("No ExpressVPN server")),
                other => panic!("{other:?}"),
            }
        }

        #[test]
        fn express_countries_carry_iso_codes() {
            let express = express();
            let cs = expressvpn::countries(&express);
            let names: Vec<&str> = cs.iter().map(|c| c.name.as_str()).collect();
            let mut sorted = names.clone();
            sorted.sort();
            assert_eq!(sorted, names);
            let bad: Vec<_> = cs.iter().filter(|c| !iso(&c.code)).collect();
            assert!(bad.is_empty(), "not ISO: {bad:?}");
            let code = |name: &str| cs.iter().find(|c| c.name == name).unwrap().code.clone();
            assert_eq!("US", code("USA"));
            assert_eq!("GB", code("UK"));
            assert_eq!("IN", code("India (via UK)"));
            assert_eq!("HK", code("Hong Kong"));
            assert_eq!("TR", code("Turkey"));
            assert!(cs.iter().find(|c| c.name == "USA").unwrap().cities.len() >= 3);
            assert_eq!(express.len() as i32, cs.iter().map(|c| c.server_count).sum::<i32>());
        }

        #[test]
        fn express_link_parses_into_an_openvpn_endpoint() {
            let (express, login, rnd) = (express(), login("user1", "pass1"), &mut rand::rng());
            let l = expressvpn::link(
                Some(&express),
                &Location { region: Some("Amsterdam".into()), ..by_country("expressvpn", "Netherlands") },
                &login,
                rnd,
            )
            .unwrap();
            assert_eq!("Amsterdam", l.server().city);
            assert_eq!("NL", l.server().country);
            assert_eq!(
                "NL",
                expressvpn::link(Some(&express), &by_code("expressvpn", "NL"), &login, rnd).unwrap().server().country
            );
            assert!(l.server().host.ends_with(".expressnetw.com"));
            assert!(express.iter().find(|e| e.hostname == l.server().host).unwrap().ips.contains(&l.server().ip));
            let Link::Ovpn { profile, .. } = &l else { panic!("not OpenVPN") };
            assert_eq!(("user1", "pass1"), (profile.username.as_str(), profile.password.as_str()));
            let e = manual::ovpn_endpoint("express", profile).unwrap();
            assert_eq!("openvpn-client", text(&e, "type"));
            assert_eq!(l.server().ip, text(&e, "server"));
            assert_eq!("1195", text(&e, "server_port"));
            assert_eq!("udp", text(&e, "network"));
            assert_eq!("user1", text(&e, "username"));
            assert_eq!("SHA512", text(&e, "auth"));
            assert_eq!(
                vec!["AES-256-GCM", "AES-256-CBC", "AES-128-GCM"],
                e["data_ciphers"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect::<Vec<_>>()
            );
            assert_eq!("AES-256-GCM", text(&e, "data_ciphers_fallback"));
            assert_eq!("1200", text(&e, "mss_fix"));
            assert_eq!("1300", text(&e, "fragment"));
            let tls = e["tls"].as_object().unwrap();
            assert_eq!("Server", text(tls, "server_name"));
            assert_eq!("name-prefix", text(tls, "server_name_type"));
            assert_eq!("server", text(tls, "remote_certificate_tls"));
            assert!(tls.contains_key("client_certificate"));
            assert!(text(tls, "client_key").starts_with("-----BEGIN RSA PRIVATE KEY-----"));
            assert_eq!(2, text(tls, "certificate").matches("BEGIN CERTIFICATE").count());
            let wrap = tls["control_wrap"].as_object().unwrap();
            assert_eq!("tls_auth", text(wrap, "type"));
            assert_eq!("client", text(wrap, "direction"));
            let hex = Regex::new("^[0-9a-f]{32}$").unwrap();
            assert_eq!(16, text(wrap, "key").lines().filter(|l| hex.is_match(l)).count());
        }

        #[test]
        fn express_sign_in_checks_the_format_only() {
            let a = expressvpn::account(
                &ExpressVpn.sign_in(&input(&[("username", " abc123 "), ("password", "pw")])).unwrap(),
            )
            .unwrap();
            assert_eq!("abc123", a.username);
            for bad in [
                [("username", ""), ("password", "x")],
                [("username", "a"), ("password", "b c")],
                [("username", "a\nb"), ("password", "SECRET")],
            ] {
                match ExpressVpn.sign_in(&input(&bad)) {
                    Err(Error::Invalid(m)) => assert!(!m.contains("SECRET")),
                    _ => panic!("not refused"),
                }
            }
        }

        #[test]
        fn express_pinned_server_keeps_its_address() {
            let (login, rnd) = (login("u", "p"), &mut rand::rng());
            let sv =
                expressvpn::link(Some(&express()), &by_code("expressvpn", "SE"), &login, rnd).unwrap().server().clone();
            let l = expressvpn::link(None, &pinned_to("expressvpn", sv.clone()), &login, rnd).unwrap();
            assert_eq!(&sv, l.server());
            let Link::Ovpn { profile, .. } = &l else { panic!("not OpenVPN") };
            assert!(profile.config.contains(&format!("remote {} 1195", sv.ip)));
        }

        #[test]
        fn sing_box_accepts_windscribe_endpoints() {
            let _held = offline();
            let rows = rows();
            for (name, loc) in [("us", by_country("windscribe", "US East")), ("nl", by_code("windscribe", "NL"))] {
                let l = windscribe::link(Some(&rows), &loc, &ws(443), &mut rand::rng()).unwrap();
                let tag = format!("ws-{name}");
                sing_box_check(&sing_box_config(&format!("windscribe-{name}"), &tag, wg(&tag, peer(&l))));
            }
        }

        #[test]
        fn sing_box_accepts_expressvpn_endpoints() {
            let express = express();
            for (name, loc) in [
                ("nl", by_country("expressvpn", "Netherlands")),
                ("us", Location { region: Some("Atlanta".into()), ..by_country("expressvpn", "USA") }),
            ] {
                let l = expressvpn::link(Some(&express), &loc, &login("user1", "pass1"), &mut rand::rng()).unwrap();
                let Link::Ovpn { profile, .. } = &l else { panic!("not OpenVPN") };
                let tag = format!("ev-{name}");
                sing_box_check(&sing_box_config(
                    &format!("expressvpn-{name}"),
                    &tag,
                    Value::Object(manual::ovpn_endpoint(&tag, profile).unwrap()),
                ));
            }
        }
    }
}
