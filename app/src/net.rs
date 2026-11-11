//! Which network the computer is on: the default route's interface, watched for changes.

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

/// Tracks the computer's own default network (the main routing table's IPv4 default route, which the engine's routes
/// leave alone) as "interface gateway". The engine follows the interface by itself; the app only needs to know when the
/// network changed, to retry blocked routes and to stop judging servers by checks made on another network.
// shortcut: IPv4 default route only, polled every 3 s; follow netlink or NetworkManager events if IPv6-only networks matter.
pub struct NetMonitor {
    routes: PathBuf,
    network: Mutex<Option<String>>,
    /// Called when the computer moves to another network (not on the first one).
    on_change: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Dropping it ends the running poll at once.
    job: Mutex<Option<mpsc::Sender<()>>>,
}

impl Default for NetMonitor {
    fn default() -> Self {
        NetMonitor::new("/proc/net/route")
    }
}

impl NetMonitor {
    pub fn new(routes: impl Into<PathBuf>) -> Self {
        NetMonitor {
            routes: routes.into(),
            network: Mutex::new(None),
            on_change: Mutex::new(None),
            job: Mutex::new(None),
        }
    }

    pub fn network(&self) -> Option<String> {
        lock(&self.network).clone()
    }

    pub fn set_on_change(&self, f: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.on_change) = f;
    }

    pub fn start(self: &Arc<Self>) {
        let mut job = lock(&self.job);
        *lock(&self.network) = self.read();
        let (stop, stopped) = mpsc::channel::<()>();
        *job = Some(stop);
        let me = Arc::clone(self);
        thread::spawn(move || {
            let mut lost_at: Option<Instant> = None;
            while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(Duration::from_secs(3)) {
                let now = me.read();
                let mut network = lock(&me.network);
                if now == *network {
                    lost_at = None;
                } else if now.is_none() {
                    // A loss waits briefly for the network to come back, as Android's monitor does.
                    match lost_at {
                        None => lost_at = Some(Instant::now()),
                        Some(t) if t.elapsed() > Duration::from_secs(3) => *network = None,
                        Some(_) => {}
                    }
                } else {
                    let had = std::mem::replace(&mut *network, now);
                    lost_at = None;
                    drop(network);
                    let f = lock(&me.on_change).clone();
                    if let (Some(_), Some(f)) = (had, f) {
                        f();
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        *lock(&self.job) = None;
    }

    /// The default route with the lowest metric, tunnels aside: "interface gateway", or none without one.
    pub fn read(&self) -> Option<String> {
        let text = std::fs::read_to_string(&self.routes).ok()?;
        let best = text
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .filter(|f| f.len() >= 8 && f[1] == "00000000" && f[7] == "00000000" && !f[0].starts_with("tun"))
            .min_by_key(|f| f[6].parse::<i32>().unwrap_or(i32::MAX))?;
        Some(format!("{} {}", best[0], gateway(best[2])?))
    }
}

/// /proc/net/route's gateway: an IPv4 address in little-endian hex.
fn gateway(hex: &str) -> Option<String> {
    let v = i64::from_str_radix(hex, 16).ok()?;
    Some((0..4).map(|i| (v >> (i * 8) & 255).to_string()).collect::<Vec<_>>().join("."))
}

/// The lock, even if a thread panicked while holding it: what it guards stays usable.
fn lock<T: ?Sized>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";

    /// The computer's own default network, from the main routing table: tunnels aside, the lowest metric wins.
    #[test]
    fn default_network() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("route");
        std::fs::write(&f, format!("{HEADER}\ntun0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\nwlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\nenp3s0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\nenp3s0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")).unwrap();
        assert_eq!(Some("enp3s0 10.0.0.1".to_string()), NetMonitor::new(&f).read());
        std::fs::write(&f, format!("{HEADER}\nwlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"))
            .unwrap();
        assert_eq!(None, NetMonitor::new(&f).read());
        assert_eq!(None, NetMonitor::new(dir.path().join("missing")).read());
    }
}
