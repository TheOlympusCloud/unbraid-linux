//! Everything unbraid persists. Plain JSON files in private storage; secrets AES-GCM sealed with a key from the desktop
//! keyring ([`crate::keyring`]). The folder and the key can be swapped for tests. The files are the ones the earlier
//! app wrote: an IV of 12 bytes, then AES-256-GCM with a 128-bit tag, over the same JSON.

use crate::error::{Error, Result};
use crate::model::{Country, Link, Setup, VERSION};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use indexmap::IndexMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use tokio::sync::watch;

/// Where the key comes from: the keyring, or a test's own.
pub type KeySource = Box<dyn Fn() -> Result<[u8; 32]> + Send + Sync>;

const TS_USED: &str = "tailscale.used";

enum Job {
    Save,
    Flush(mpsc::Sender<()>),
}

pub struct Store {
    dir: PathBuf,
    key_of: KeySource,
    key: Mutex<Option<[u8; 32]>>,
    /// Set when a change applied but couldn't be written: it would be gone after a restart, so the window says so.
    pub unsaved: watch::Sender<bool>,
    failures: Mutex<(bool, bool)>,
    // Sealed: it can hold imported WireGuard private keys and a Tailscale auth key.
    setup: watch::Sender<Setup>,
    /// Signed-in providers: provider id → the sealed account blob its sign-in returned.
    accounts: watch::Sender<IndexMap<String, String>>,
    /// When each gluetun catalogue last read was published (epoch seconds); kept across restarts.
    pub catalog_dates: watch::Sender<IndexMap<String, i64>>,
    /// What the Kotlin store's @Synchronized methods held: one writer of files at a time.
    sync: Mutex<()>,
    // Its own lock, not the one saves hold: a tap's edit never waits for a write under way. Changes still apply one at a time.
    changing: Mutex<()>,
    queued: Arc<AtomicBool>,
    writer: Mutex<mpsc::Sender<Job>>,
}

impl Store {
    /// The store in `dir`, sealed with the key `key_of` gives; it reads the saved setup and accounts at once.
    pub fn new(dir: &Path, key_of: KeySource) -> Arc<Store> {
        let (tx, rx) = mpsc::channel::<Job>();
        let queued = Arc::new(AtomicBool::new(false));
        let store = Arc::new_cyclic(|weak: &Weak<Store>| {
            let weak = weak.clone();
            let flag = queued.clone();
            std::thread::Builder::new()
                .name("store".into())
                .spawn(move || {
                    for job in rx {
                        match job {
                            Job::Save => {
                                flag.store(false, Ordering::SeqCst);
                                if let Some(s) = weak.upgrade() {
                                    let _g = s.sync.lock().unwrap();
                                    s.save_setup();
                                }
                            }
                            Job::Flush(ack) => {
                                let _ = ack.send(());
                            }
                        }
                    }
                })
                .expect("start the store's writer");
            Store {
                dir: dir.to_path_buf(),
                key_of,
                key: Mutex::new(None),
                unsaved: watch::Sender::new(false),
                failures: Mutex::new((false, false)),
                setup: watch::Sender::new(Setup::default()),
                accounts: watch::Sender::new(IndexMap::new()),
                catalog_dates: watch::Sender::new(IndexMap::new()),
                sync: Mutex::new(()),
                changing: Mutex::new(()),
                queued,
                writer: Mutex::new(tx),
            }
        });
        let setup = store
            .load("setup.bin", |t| serde_json::from_str::<Setup>(t).ok().map(|s| s.migrated()))
            .unwrap_or_else(|| Setup { version: VERSION, ..Setup::default() });
        store.setup.send_replace(setup);
        let accounts = store
            .load("accounts.bin", |t| serde_json::from_str::<IndexMap<String, String>>(t).ok())
            .unwrap_or_else(|| store.migrate_nord());
        store.accounts.send_replace(accounts);
        let dates = store
            .read("catalog-dates.json")
            .and_then(|t| serde_json::from_str::<IndexMap<String, i64>>(&t).ok())
            .unwrap_or_default();
        store.catalog_dates.send_replace(dates);
        store
    }

    fn key(&self) -> Result<[u8; 32]> {
        let mut k = self.key.lock().unwrap();
        if let Some(key) = *k {
            return Ok(key);
        }
        let key = (self.key_of)()?;
        *k = Some(key);
        Ok(key)
    }

    fn failed(&self, setup: Option<bool>, accounts: Option<bool>) {
        let mut f = self.failures.lock().unwrap();
        if let Some(s) = setup {
            f.0 = s;
        }
        if let Some(a) = accounts {
            f.1 = a;
        }
        self.unsaved.send_replace(f.0 || f.1);
    }

    /// The setup as it stands, and its changes to come.
    pub fn setup(&self) -> watch::Receiver<Setup> {
        self.setup.subscribe()
    }

    pub fn current(&self) -> Setup {
        self.setup.borrow().clone()
    }

    pub fn accounts(&self) -> watch::Receiver<IndexMap<String, String>> {
        self.accounts.subscribe()
    }

    pub fn current_accounts(&self) -> IndexMap<String, String> {
        self.accounts.borrow().clone()
    }

    /// Applies `f`; false when it couldn't be written (see `unsaved`), so callers keep a pasted secret on the clipboard.
    pub fn update(&self, f: impl FnOnce(&Setup) -> Setup) -> bool {
        let _g = self.sync.lock().unwrap();
        self.change(f);
        self.save_setup()
    }

    /// Applies `f` at once and writes it on the store's writer, so a tap never waits for the keyring and the disk. Each
    /// write takes the newest setup, so the last one on disk is always the latest; a failed one shows `unsaved`, as
    /// [`Store::update`].
    pub fn edit(&self, f: impl FnOnce(&Setup) -> Setup) {
        self.change(f);
        if !self.queued.swap(true, Ordering::SeqCst) {
            let _ = self.writer.lock().unwrap().send(Job::Save);
        }
    }

    /// Waits for the writes [`Store::edit`] queued so far.
    pub fn flush(&self) {
        let (ack, done) = mpsc::channel();
        if self.writer.lock().unwrap().send(Job::Flush(ack)).is_ok() {
            let _ = done.recv();
        }
    }

    // Wherever a route is removed, profiles that used it are mended here.
    fn change(&self, f: impl FnOnce(&Setup) -> Setup) {
        let _c = self.changing.lock().unwrap();
        self.setup.send_modify(|s| *s = f(s).tidy());
    }

    // A keyring hiccup must not crash a tap: the change stays in memory, the banner says so, and a retry writes it.
    fn save_setup(&self) -> bool {
        let text = serde_json::to_string(&*self.setup.borrow()).ok();
        let ok = text.is_some_and(|t| self.seal("setup.bin", Some(&t)));
        if !ok {
            crate::log::e("Unbraid", "store: setup not saved");
        }
        self.failed(Some(!ok), None);
        ok
    }

    fn save_accounts(&self) -> bool {
        let text = serde_json::to_string(&*self.accounts.borrow()).ok();
        let ok = text.is_some_and(|t| self.seal("accounts.bin", Some(&t)));
        if !ok {
            crate::log::e("Unbraid", "store: accounts not saved");
        }
        self.failed(None, Some(!ok));
        ok
    }

    /// Writes what is in memory again, after a failed save (the user's retry). True if all of it is on disk now.
    pub fn save_again(&self) -> bool {
        let _g = self.sync.lock().unwrap();
        let setup = self.save_setup();
        let accounts = self.save_accounts();
        setup && accounts
    }

    /// Cached server catalogue per provider.
    pub fn countries(&self, provider: &str) -> Vec<Country> {
        self.read(&format!("countries-{provider}.json")).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// True when `provider`'s cached catalogue is under a day old.
    pub fn countries_fresh(&self, provider: &str) -> bool {
        fs::metadata(self.dir.join(format!("countries-{provider}.json")))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_millis() < 86_400_000)
    }

    pub fn set_countries(&self, provider: &str, v: &[Country]) -> bool {
        let _g = self.sync.lock().unwrap();
        serde_json::to_string(v).is_ok_and(|t| self.write(&format!("countries-{provider}.json"), &t))
    }

    pub fn catalog_date(&self, name: &str, epoch_seconds: i64) {
        let _g = self.sync.lock().unwrap();
        let d = self.catalog_dates.borrow().clone();
        if d.get(name) != Some(&epoch_seconds) {
            let mut next = d;
            next.insert(name.into(), epoch_seconds);
            if serde_json::to_string(&next).is_ok_and(|t| self.write("catalog-dates.json", &t)) {
                self.catalog_dates.send_replace(next);
            }
        }
    }

    /// Last tunnel that worked per "provider|location", used when a provider's API is unreachable. Holds keys, so sealed.
    pub fn last_links(&self) -> IndexMap<String, Link> {
        self.open("links.bin").and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    /// Merges `add`, keeping only providers still signed in (a sign-out may have raced a connect). Only a cache: never fails.
    pub fn remember_links(&self, add: &IndexMap<String, Link>) {
        let _g = self.sync.lock().unwrap();
        self.remember_links_locked(add);
    }

    fn remember_links_locked(&self, add: &IndexMap<String, Link>) {
        let live: Vec<String> = self.accounts.borrow().keys().cloned().collect();
        let mut all = self.last_links();
        all.extend(add.iter().map(|(k, v)| (k.clone(), v.clone())));
        all.retain(|k, _| live.iter().any(|p| p == k.split('|').next().unwrap_or(k)));
        let ok = serde_json::to_string(&all).is_ok_and(|t| self.seal("links.bin", Some(&t)));
        if !ok {
            crate::log::w("Unbraid", "store: last servers not saved");
        }
    }

    /// False when the change couldn't be written. It applies in memory anyway: a new sign-in holds a device slot the
    /// provider just gave, which only this copy knows; `unsaved` tells the user, and [`Store::save_again`] retries.
    pub fn account(&self, provider: &str, blob: Option<&str>) -> bool {
        let _g = self.sync.lock().unwrap();
        self.account_locked(provider, blob)
    }

    fn account_locked(&self, provider: &str, blob: Option<&str>) -> bool {
        self.accounts.send_modify(|a| match blob {
            Some(b) => {
                a.insert(provider.into(), b.into());
            }
            None => {
                a.shift_remove(provider);
            }
        });
        let ok = self.save_accounts();
        if blob.is_none() {
            self.remember_links_locked(&IndexMap::new());
        }
        ok
    }

    /// Preview builds kept the Nord token and key in their own files.
    fn migrate_nord(&self) -> IndexMap<String, String> {
        let (Some(token), Some(key)) = (self.open("token.bin"), self.open("nlk.bin")) else { return IndexMap::new() };
        let account = serde_json::json!({ "token": token, "key": key }).to_string();
        let m: IndexMap<String, String> = [("nord".to_string(), account)].into_iter().collect();
        if serde_json::to_string(&m).is_ok_and(|t| self.seal("accounts.bin", Some(&t))) {
            for f in ["token.bin", "nlk.bin", "servers.json"] {
                let _ = fs::remove_file(self.dir.join(f));
            }
        }
        m
    }

    /// The tailnet's MagicDNS domain, learned once Tailscale is signed in.
    pub fn ts_suffix(&self) -> Option<String> {
        self.read("tssuffix")
    }

    pub fn set_ts_suffix(&self, v: Option<&str>) {
        match v {
            None => {
                let _ = fs::remove_file(self.dir.join("tssuffix"));
            }
            Some(v) => {
                self.write("tssuffix", v);
            }
        }
    }

    /// A Tailscale node may be kept for this user: on Linux its state lives in the engine's own root-only folder, so the
    /// app only notes that it started one, until the engine forgets it.
    pub fn ts_stored(&self) -> bool {
        self.dir.join(TS_USED).exists()
    }

    pub fn set_ts_stored(&self, v: bool) {
        if v {
            self.write(TS_USED, "1");
        } else {
            let _ = fs::remove_file(self.dir.join(TS_USED));
        }
    }

    /// Which block of the fake-IP pool the engine's last domain table used ([`crate::compiler::fake_ranges`]).
    pub fn fake_block(&self) -> i32 {
        self.read("fakeblock")
            .and_then(|t| t.parse().ok())
            .unwrap_or_else(|| crate::compiler::block_after_half(self.read("fakehalf").and_then(|t| t.parse().ok())))
    }

    pub fn set_fake_block(&self, v: i32) -> Result<()> {
        if self.write("fakeblock", &v.to_string()) { Ok(()) } else { Err(Error::State("Check failed.".into())) }
    }

    /// The user agreed to M-Lab's terms for speed tests (results, with the exit's IP address, are published).
    pub fn mlab_consent(&self) -> bool {
        self.dir.join("mlab").exists()
    }

    pub fn set_mlab_consent(&self, v: bool) {
        if v {
            self.write("mlab", "1");
        } else {
            let _ = fs::remove_file(self.dir.join("mlab"));
        }
    }

    fn epoch_day() -> i64 {
        let today = chrono::Local::now().date_naive();
        (today - chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap()).num_days()
    }

    /// Speed tests run today, for M-Lab's limit of 40 a day per user: "epochDay count".
    pub fn tests_today(&self) -> i32 {
        let day = Self::epoch_day().to_string();
        self.read("mlabday")
            .and_then(|t| {
                let parts: Vec<&str> = t.split(' ').collect();
                (parts.first() == Some(&day.as_str())).then(|| parts.get(1).and_then(|n| n.parse().ok())).flatten()
            })
            .unwrap_or(0)
    }

    pub fn set_tests_today(&self, v: i32) {
        self.write("mlabday", &format!("{} {v}", Self::epoch_day()));
    }

    /// A speed test switched Tailscale to another exit node and hasn't switched it back yet: the stable ID of the node in
    /// use before ("" for none); none when nothing is to be undone. Older versions wrote "1", which is no node ID.
    pub fn ts_test_from(&self) -> Option<String> {
        match self.read("tstest") {
            Some(t) if t != "1" => Some(t),
            _ if self.dir.join("tstest").exists() => Some(String::new()),
            _ => None,
        }
    }

    pub fn set_ts_test_from(&self, v: Option<&str>) {
        match v {
            Some(v) => {
                self.write("tstest", v);
            }
            None => {
                let _ = fs::remove_file(self.dir.join("tstest"));
            }
        }
    }

    pub fn sign_out_all(&self) {
        {
            let _g = self.sync.lock().unwrap();
            let providers: Vec<String> = self.accounts.borrow().keys().cloned().collect();
            for p in providers {
                self.account_locked(&p, None);
            }
            // Also over a file that didn't open (then nothing was in memory to remove): it must not come back later.
            self.accounts.send_replace(IndexMap::new());
            self.save_accounts();
        }
        self.update(|s| {
            let mut s = s.clone();
            s.home.ts_auth_key = None;
            s
        });
        let _ = fs::remove_file(self.dir.join("expiry")); // left by older versions
        self.set_ts_suffix(None);
        // Copies of files that once failed to open hold accounts and keys too.
        for f in ["links.bin", "cache.db", "setup.bin.bad", "accounts.bin.bad", "links.bin.bad", TS_USED] {
            let _ = fs::remove_file(self.dir.join(f));
        }
    }

    fn read(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.dir.join(name)).ok()
    }

    fn write(&self, name: &str, text: &str) -> bool {
        self.durable(name, text.as_bytes())
    }

    /// Replaces `name` with `bytes` in one rename, the data synced to disk first so a crash can't leave it half written.
    fn durable(&self, name: &str, bytes: &[u8]) -> bool {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let ok = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            fs::rename(&tmp, self.dir.join(name))
        })()
        .is_ok();
        let _ = fs::remove_file(&tmp);
        ok
    }

    /// Reads a sealed file. One that exists but won't open (keyring reset, corruption) is kept as "<name>.bad" rather
    /// than silently replaced by defaults on the next write.
    fn load<T>(&self, name: &str, decode: impl FnOnce(&str) -> Option<T>) -> Option<T> {
        let v = self.open(name).and_then(|t| decode(&t));
        let path = self.dir.join(name);
        if v.is_none() && path.exists() {
            let _ = fs::copy(&path, self.dir.join(format!("{name}.bad")));
        }
        v
    }

    fn seal(&self, name: &str, value: Option<&str>) -> bool {
        let Some(value) = value else { return fs::remove_file(self.dir.join(name)).is_ok() };
        let Ok(key) = self.key() else { return false };
        let cipher = Aes256Gcm::new(&key.into());
        let iv: [u8; 12] = rand::random();
        let Ok(sealed) = cipher.encrypt(&Nonce::from(iv), value.as_bytes()) else { return false };
        let mut bytes = iv.to_vec();
        bytes.extend(sealed);
        self.durable(name, &bytes)
    }

    fn open(&self, name: &str) -> Option<String> {
        let b = fs::read(self.dir.join(name)).ok()?;
        if b.len() < 12 {
            return None;
        }
        let key = self.key().ok()?;
        let cipher = Aes256Gcm::new(&key.into());
        let iv: [u8; 12] = b[..12].try_into().ok()?;
        let plain = cipher.decrypt(&Nonce::from(iv), &b[12..]).ok()?;
        String::from_utf8(plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn key() -> [u8; 32] {
        static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        *KEY.get_or_init(rand::random)
    }

    fn store(dir: &Path) -> Arc<Store> {
        Store::new(dir, Box::new(|| Ok(key())))
    }

    fn writable(dir: &Path, yes: bool) {
        fs::set_permissions(dir, fs::Permissions::from_mode(if yes { 0o755 } else { 0o555 })).unwrap();
    }

    #[test]
    fn unreadable_link_cache_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        fs::create_dir(dir.path().join("links.bin")).unwrap();
        assert!(s.last_links().is_empty());
    }

    #[test]
    fn catalog_date_retries_after_failed_write() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        let target = dir.path().join("catalog-dates.json");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("block"), "x").unwrap();
        s.catalog_date("provider", 123);
        assert!(s.catalog_dates.borrow().is_empty());
        fs::remove_dir_all(&target).unwrap();
        s.catalog_date("provider", 123);
        assert_eq!(Some(&123), s.catalog_dates.borrow().get("provider"));
        assert_eq!(Some(&123), store(dir.path()).catalog_dates.borrow().get("provider"));
    }

    #[test]
    fn sealed_files_round_trip_and_no_temp_file_stays() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = store(dir.path());
            assert!(s.account("nord", Some("blob-1")));
            assert!(s.update(|s| Setup { default_route: "x".into(), ..s.clone() }));
        }
        let again = store(dir.path());
        assert_eq!(
            vec![("nord".to_string(), "blob-1".to_string())],
            again.current_accounts().into_iter().collect::<Vec<_>>()
        );
        assert_eq!("x", again.current().default_route);
        assert!(fs::read_dir(dir.path()).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        let raw = fs::read(dir.path().join("accounts.bin")).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"blob-1")); // sealed, not plain
    }

    /// A tap's edit applies at once and reaches the disk on the writer thread; the newest setup is the one saved.
    #[test]
    fn edits_apply_at_once_and_the_last_one_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.edit(|s| Setup { default_route: "a".into(), ..s.clone() });
        assert_eq!("a", s.current().default_route);
        for i in 0..50 {
            s.edit(|s| Setup { default_route: format!("r{i}"), ..s.clone() });
        }
        s.flush();
        assert_eq!("r49", store(dir.path()).current().default_route);
        assert!(!*s.unsaved.borrow());
        // A failed background write says so, as a failed update does, and a later one that works clears it.
        writable(dir.path(), false);
        s.edit(|s| Setup { default_route: "b".into(), ..s.clone() });
        s.flush();
        assert!(*s.unsaved.borrow());
        writable(dir.path(), true);
        s.edit(|s| Setup { default_route: "c".into(), ..s.clone() });
        s.flush();
        assert!(!*s.unsaved.borrow());
        assert_eq!("c", store(dir.path()).current().default_route);
    }

    /// A failed write keeps the change in memory (a new sign-in's device slot lives only there), says so, and retries.
    #[test]
    fn a_failed_save_is_kept_shown_and_retried() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        assert!(s.account("a", Some("one")));
        // Make the next write fail: the folder refuses new files.
        writable(dir.path(), false);
        assert!(!s.account("b", Some("two")));
        assert!(*s.unsaved.borrow());
        let keys = |s: &Store| s.current_accounts().keys().cloned().collect::<Vec<_>>();
        assert_eq!(vec!["a", "b"], keys(&s));
        // A later setup change that saves doesn't hide the unsaved account.
        writable(dir.path(), true);
        assert!(s.update(|s| Setup { default_route: "y".into(), ..s.clone() }));
        assert!(*s.unsaved.borrow());
        assert!(s.save_again());
        assert!(!*s.unsaved.borrow());
        assert_eq!(vec!["a", "b"], keys(&store(dir.path())));
        // The link cache never fails.
        writable(dir.path(), false);
        s.remember_links(&IndexMap::new());
        writable(dir.path(), true);
    }

    /// Signing out of everything also removes the copies kept of files that once failed to open.
    #[test]
    fn sign_out_all_removes_bad_copies() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("accounts.bin"), "not sealed").unwrap();
        let s = store(dir.path());
        assert!(dir.path().join("accounts.bin.bad").exists());
        s.sign_out_all();
        assert!(!dir.path().join("accounts.bin.bad").exists());
        // The undecodable file is replaced too: reopening finds no account and makes no new copy.
        assert!(store(dir.path()).current_accounts().is_empty());
        assert!(!dir.path().join("accounts.bin.bad").exists());
    }

    /// What the earlier (JVM) app sealed opens here as it was: the setup, the accounts, the link cache, the countries.
    /// The fixture was written by that app's own store with the key 0, 1, …, 31.
    #[test]
    fn opens_what_the_earlier_app_sealed() {
        let dir = tempfile::tempdir().unwrap();
        for e in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/store/kotlin")).unwrap() {
            let e = e.unwrap();
            fs::copy(e.path(), dir.path().join(e.file_name())).unwrap();
        }
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let s = Store::new(dir.path(), Box::new(move || Ok(key)));
        let setup = s.current();
        assert_eq!("us", setup.default_route);
        assert_eq!(vec!["nl", "us"], setup.routes.iter().map(|r| r.id.as_str()).collect::<Vec<_>>());
        assert_eq!(1, setup.routes[1].hue);
        assert_eq!(Some(&"nl".to_string()), setup.apps.get("firefox"));
        assert_eq!(Some(&crate::model::DIRECT.to_string()), setup.apps.get("code"));
        assert_eq!("Home", setup.profiles[0].name);
        assert_eq!(Some(&"us".to_string()), setup.profiles[0].apps.get("firefox"));
        assert_eq!(VERSION, setup.version);
        assert_eq!(Some(&r#"{"token":"t","key":"k"}"#.to_string()), s.current_accounts().get("nord"));
        match s.last_links().get("nord|nl") {
            Some(Link::Wg { server, peer, ports, .. }) => {
                assert_eq!("nl1", server.name);
                assert_eq!("1.2.3.4:51820", peer.endpoint);
                assert_eq!(vec![51820, 443], *ports);
            }
            other => panic!("not the saved WireGuard link: {other:?}"),
        }
        assert_eq!("Amsterdam", s.countries("nord")[0].cities[0].name);
        assert!(!dir.path().join("setup.bin.bad").exists());
    }

    /// Linux keeps the Tailscale node in the engine: the store only remembers one may be there, until a full sign-out.
    #[test]
    fn tailscale_node_is_noted_until_sign_out() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        assert!(!s.ts_stored());
        s.set_ts_stored(true);
        assert!(store(dir.path()).ts_stored());
        s.sign_out_all();
        assert!(!store(dir.path()).ts_stored());
    }
}
