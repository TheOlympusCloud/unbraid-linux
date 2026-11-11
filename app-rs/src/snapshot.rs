//! The last good copy of a provider's own server list, in app storage. Its WireGuard keys came from the provider over
//! HTTPS, so it stands in when that list can't be read; gluetun's catalogue never supplies a key for these providers.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

type Load = Box<dyn Fn() -> Option<String> + Send + Sync>;
type Save = Box<dyn Fn(&str) -> std::io::Result<()> + Send + Sync>;

pub struct Snapshot {
    load: Load,
    save: Save,
    /// The copy last written in this process: still used if saving it to storage failed.
    held: Mutex<Option<String>>,
}

/// App storage, set once at start ([`crate::app`]); none in unit tests, where nothing is kept.
static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);
static LOCK: Mutex<()> = Mutex::new(());

pub fn set_dir(dir: Option<PathBuf>) {
    *DIR.write().unwrap() = dir;
}

impl Snapshot {
    pub fn new(load: Load, save: Save) -> Snapshot {
        Snapshot { load, save, held: Mutex::new(None) }
    }

    pub fn read(&self) -> Option<String> {
        self.held.lock().unwrap().clone().or_else(|| (self.load)())
    }

    pub fn write(&self, body: &str) {
        *self.held.lock().unwrap() = Some(body.to_string());
        if (self.save)(body).is_err() {
            crate::log::w("Unbraid", "snapshot: not saved");
        }
    }

    /// Writes go to a synced temporary file that replaces the old copy in one rename, so a reader never sees half a list.
    pub fn file(name: &str) -> Snapshot {
        let (n1, n2) = (name.to_string(), name.to_string());
        Snapshot::new(
            Box::new(move || {
                let _g = LOCK.lock().unwrap();
                let d = DIR.read().unwrap().clone()?;
                fs::read_to_string(d.join(&n1)).ok()
            }),
            Box::new(move |body| {
                let _g = LOCK.lock().unwrap();
                let Some(d) = DIR.read().unwrap().clone() else { return Ok(()) };
                let tmp = d.join(format!("{n2}.tmp"));
                let mut out = fs::File::create(&tmp)?;
                out.write_all(body.as_bytes())?;
                out.sync_all()?;
                fs::rename(&tmp, d.join(&n2)).inspect_err(|_| {
                    let _ = fs::remove_file(&tmp);
                })
            }),
        )
    }

    pub fn memory(initial: Option<&str>) -> Snapshot {
        let v = std::sync::Arc::new(Mutex::new(initial.map(str::to_string)));
        let (r, w) = (v.clone(), v);
        Snapshot::new(
            Box::new(move || r.lock().unwrap().clone()),
            Box::new(move |body| {
                *w.lock().unwrap() = Some(body.to_string());
                Ok(())
            }),
        )
    }
}
