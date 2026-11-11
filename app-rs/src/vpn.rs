//! The connection: compiles the setup, runs it on the engine, watches its tunnels and statistics. What the window shows
//! and what the speed tests, statistics and checks read of it live here, written only by the connection.

use crate::model::{Server, Setup};
use indexmap::{IndexMap, IndexSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, RwLock};
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct TsNode {
    pub name: String,
    pub ip: String,
    pub online: bool,
    pub id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum Phase {
    #[default]
    Off,
    Connecting,
    On,
    Paused,
}

/// What the window shows. Lives in-process; the connection is the only writer.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct VpnState {
    pub phase: Phase,
    pub since: i64,
    pub servers: IndexMap<String, Server>,
    pub error: Option<String>,
    pub ts_login_url: Option<String>,
    pub ts_state: Option<String>,
    /// The DNS suffix the tailnet reports (usable form); whether apps may use it is the home's `ts_suffix_allowed`.
    pub ts_suffix: Option<String>,
    /// Tailnet peers that offer themselves as exit nodes.
    pub ts_exit_nodes: Vec<TsNode>,
    /// While paused: when the connection comes back (epoch ms), 0 = only when resumed by hand.
    pub paused_until: i64,
    /// While paused: when the pause began (epoch ms), for the countdown ring.
    pub paused_at: i64,
    /// While paused: it may resume somewhat after `paused_until`. Always false on Linux, where the timer is exact.
    pub paused_about: bool,
    /// Android's "Block connections without VPN"; Linux has none, so apps simply go out directly while paused.
    pub lockdown: bool,
    /// Android's "Always-on VPN"; on Linux the app starts at login instead ([`crate::autostart`]).
    pub always_on: bool,
    /// Providers whose routes have no tunnel right now: provider id → whether it refused the account (sign in again).
    pub stuck: IndexMap<String, bool>,
    /// Routes whose tunnel keeps dropping ([`crate::health`]).
    pub dropping: IndexSet<String>,
    /// Counts engine starts, each of which restarts every tunnel: what was observed of an earlier one no longer holds.
    pub engine: i32,
    /// [`setup_hash`] of the setup the engine runs in full (no route still waiting for a server): a profile switch is done.
    pub applied: u64,
    /// [`setup_hash`] of the last setup the engine refused (the one before it still runs): a profile switch is undone.
    pub refused: u64,
}

/// A start (`on`) or a stop or pause the connection hasn't handled yet, numbered in the order asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    pub n: i32,
    pub on: bool,
}

/// What the connection publishes for the rest of the app.
pub struct Live {
    pub state: watch::Sender<VpnState>,
    /// Route id → engine tunnel tag of the running setup (speed tests dial through it).
    pub tags: RwLock<IndexMap<String, String>>,
    /// Tunnel tag → the DNS server that tunnel's own lookups use (health checks look their servers up there).
    pub tunnel_dns: RwLock<IndexMap<String, String>>,
    /// The setup the engine runs (not the one being edited): statistics attribute traffic against it.
    pub running: RwLock<Option<Setup>>,
    /// Loopback port and password of the app's own way into each exit ([`crate::compiler::PROBE`]); see [`crate::probe`].
    pub probe: RwLock<Option<(u16, String)>>,
    /// The computer's own network is metered; Linux doesn't say so to the app, so a combined speed test never asks first.
    pub metered: AtomicBool,
    /// Servers ("provider|ip") that failed the last health check: the next connect, even a manual one, avoids them.
    pub failing: RwLock<IndexSet<String>>,
    /// The newest start, stop or pause the connection hasn't handled yet; see [`vpn_on`].
    pub asked: watch::Sender<Option<Ask>>,
    /// One line on what runs, for the tray and the command line.
    pub summary: watch::Sender<String>,
}

static LIVE: LazyLock<Live> = LazyLock::new(|| Live {
    state: watch::Sender::new(VpnState::default()),
    tags: RwLock::new(IndexMap::new()),
    tunnel_dns: RwLock::new(IndexMap::new()),
    running: RwLock::new(None),
    probe: RwLock::new(None),
    metered: AtomicBool::new(false),
    failing: RwLock::new(IndexSet::new()),
    asked: watch::Sender::new(None),
    summary: watch::Sender::new(String::new()),
});

pub fn live() -> &'static Live {
    &LIVE
}

impl Live {
    pub fn state(&self) -> VpnState {
        self.state.borrow().clone()
    }
    pub fn tags(&self) -> IndexMap<String, String> {
        self.tags.read().unwrap().clone()
    }
    pub fn tag(&self, route: &str) -> Option<String> {
        self.tags.read().unwrap().get(route).cloned()
    }
    pub fn running(&self) -> Option<Setup> {
        self.running.read().unwrap().clone()
    }
    pub fn probe(&self) -> Option<(u16, String)> {
        self.probe.read().unwrap().clone()
    }
    pub fn set_probe(&self, p: Option<(u16, String)>) {
        *self.probe.write().unwrap() = p;
    }
    pub fn metered(&self) -> bool {
        self.metered.load(Ordering::Relaxed)
    }
    pub fn failing(&self) -> IndexSet<String> {
        self.failing.read().unwrap().clone()
    }
}

/// A setup's identity for following a switch: equal setups hash alike, whatever order their maps were filled in, and a
/// copy read back from disk hashes as the one in memory. The routes up only for a speed test count too.
pub fn setup_hash(s: &Setup) -> u64 {
    // serde_json's own maps are sorted, so the text is the same for equal setups.
    let canonical = serde_json::to_value(s).map(|v| v.to_string()).unwrap_or_default();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut h);
    let mut testing: Vec<&String> = s.testing.iter().collect();
    testing.sort();
    testing.hash(&mut h);
    h.finish()
}

/// For a profile switch to the setup hashed `h`: true once the engine runs it (or runs nothing), false if it refused
/// it, none meanwhile.
pub fn switch_done(v: &VpnState, h: u64) -> Option<bool> {
    if v.phase != Phase::On || v.applied == h {
        Some(true)
    } else if v.refused == h {
        Some(false)
    } else {
        None
    }
}

/// Whether the VPN is on or about to be, for toggles: the newest request the connection hasn't handled yet wins over
/// the phase, so a second quick click undoes the first instead of repeating it, however long the first one takes.
pub fn vpn_on(phase: Phase, ask: Option<Ask>) -> bool {
    ask.map(|a| a.on).unwrap_or(phase == Phase::On || phase == Phase::Connecting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DIRECT, Location, Route};

    fn base() -> Setup {
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route::new("us", Location::country("nord", 228, "US", "United States")),
                Route::new("it", Location::country("nord", 106, "IT", "Italy")),
            ],
            default_route: "nl".into(),
            apps: [("netflix".to_string(), "us".to_string())].into_iter().collect(),
            ..Setup::default()
        }
    }

    fn state(phase: Phase, applied: u64, refused: u64) -> VpnState {
        VpnState { phase, applied, refused, ..Default::default() }
    }

    /// A switch is done once the engine runs that exact setup in full, undone once it refused it, and waits otherwise.
    #[test]
    fn switch_outcome() {
        let h = setup_hash(&base().save_as("Home"));
        assert_eq!(Some(true), switch_done(&state(Phase::On, h, 0), h));
        assert_eq!(Some(false), switch_done(&state(Phase::On, 1, h), h));
        assert_eq!(None, switch_done(&state(Phase::On, 1, 2), h)); // still waiting (e.g. a server being found)
        assert_eq!(None, switch_done(&state(Phase::On, 0, 0), h));
        assert_eq!(Some(true), switch_done(&state(Phase::Paused, 0, 0), h)); // nothing runs: nothing to wait for
        assert_eq!(Some(true), switch_done(&state(Phase::Off, 0, h), h));
    }

    /// The hash a switch waits for survives saving and loading (it compares a fresh copy with the one in memory).
    #[test]
    fn hash_survives_saving() {
        let s = base().save_as("Home").save_as("Travel");
        let again: Setup = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(setup_hash(&s), setup_hash(&again));
        // Equal setups hash alike whatever order their apps were added in.
        let mut a = base();
        a.apps.insert("bank".into(), DIRECT.into());
        let mut b = base();
        b.apps.shift_remove("netflix");
        b.apps.insert("bank".into(), DIRECT.into());
        b.apps.insert("netflix".into(), "us".into());
        assert_eq!(a, b);
        assert_eq!(setup_hash(&a), setup_hash(&b));
    }

    /// With nothing waiting, the phase decides: connecting already counts as on.
    #[test]
    fn phase_decides_without_request() {
        assert!(vpn_on(Phase::On, None));
        assert!(vpn_on(Phase::Connecting, None));
        assert!(!vpn_on(Phase::Off, None));
        assert!(!vpn_on(Phase::Paused, None));
    }

    /// A second quick tap undoes the first: a start not yet handled reads as on, a stop or pause as off.
    #[test]
    fn waiting_request_wins() {
        assert!(vpn_on(Phase::Off, Some(Ask { n: 1, on: true })));
        assert!(vpn_on(Phase::Paused, Some(Ask { n: 1, on: true })));
        assert!(!vpn_on(Phase::On, Some(Ask { n: 2, on: false })));
        assert!(!vpn_on(Phase::Connecting, Some(Ask { n: 2, on: false })));
    }
}
