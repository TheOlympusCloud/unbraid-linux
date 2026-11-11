//! What the whole process shares: the store, the async runtime, and what follows the connection.

use crate::store::Store;
use crate::vpn::{self, Phase};
use crate::{catalog, keyring, providers, snapshot, stats};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tokio::runtime::Handle;

/// The logo, only inside the app (Settings header, About, sign-in), its slash always in the accent.
pub const WORDMARK: &str = "un/braid";

static STORE: OnceLock<Arc<Store>> = OnceLock::new();
static RUNTIME: OnceLock<Handle> = OnceLock::new();

/// The store, opened once at start ([`set_store`]).
pub fn store() -> &'static Arc<Store> {
    STORE.get().expect("the store is opened at start")
}

/// Makes `store` the one the whole process shares; a later call keeps the first.
pub fn set_store(store: Arc<Store>) -> &'static Arc<Store> {
    STORE.get_or_init(|| store)
}

/// The async runtime the app made at start ([`init`]): the connection, statistics and the engine's streams run on it.
pub fn runtime() -> &'static Handle {
    RUNTIME.get().expect("the runtime is made at start")
}

/// Opens the store in `dir` (the data folder, [`crate::paths::data`]) and starts what follows the connection, on the
/// runtime `rt`. Once, at start, before the window and the command line ask anything.
pub fn init(rt: &Handle, dir: &Path) {
    let _ = RUNTIME.set(rt.clone());
    let key_dir = dir.to_path_buf();
    let store = set_store(Store::new(dir, Box::new(move || keyring::key(&key_dir))));
    let s = store.clone();
    catalog::set_published(move |name, published| s.catalog_date(name, published));
    let s = store.clone();
    providers::set_opt(move |provider, key| s.setup().borrow().opt(provider, key));
    snapshot::set_dir(Some(dir.to_path_buf()));
    let _inside = rt.enter();
    vpn::profiles::watch(store.clone());
    // Statistics follow the connection while they're on: sessions from the phase, traffic from the running engine.
    stats::init(dir);
    let (mut state, mut setup) = (vpn::live().state.subscribe(), store.setup());
    tokio::spawn(async move {
        let mut last = None;
        loop {
            let now = (state.borrow_and_update().phase, setup.borrow_and_update().prefs.stats);
            if last != Some(now) {
                last = Some(now);
                let (phase, on) = now;
                stats::phase(if on { phase } else { Phase::Off });
                if on && phase == Phase::On { stats::start() } else { stats::stop() }
            }
            tokio::select! {
                _ = state.changed() => {}
                _ = setup.changed() => {}
            }
        }
    });
}
