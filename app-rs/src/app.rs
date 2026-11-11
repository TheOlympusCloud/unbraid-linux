//! What the whole process shares: the store, and what follows the connection.

use crate::store::Store;
use std::sync::{Arc, OnceLock};

/// The logo, only inside the app (Settings header, About, sign-in), its slash always in the accent.
pub const WORDMARK: &str = "un/braid";

static STORE: OnceLock<Arc<Store>> = OnceLock::new();

/// The store, opened once at start ([`set_store`]).
pub fn store() -> &'static Arc<Store> {
    STORE.get().expect("the store is opened at start")
}

/// Makes `store` the one the whole process shares; a later call keeps the first.
pub fn set_store(store: Arc<Store>) -> &'static Arc<Store> {
    STORE.get_or_init(|| store)
}
