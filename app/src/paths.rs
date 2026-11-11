//! Where unbraid keeps its files, as the XDG base directories say.
//! It also says where the engine is.

use crate::error::Result;
use std::ffi::CStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

/// The setup, sealed secrets, caches and statistics: $XDG_DATA_HOME/unbraid, which only this user may open.
pub fn data() -> Result<&'static Path> {
    static DATA: OnceLock<PathBuf> = OnceLock::new();
    once(&DATA, || {
        private(env("XDG_DATA_HOME").map_or_else(|| home().join(".local/share"), PathBuf::from).join("unbraid"))
    })
}

/// The running app's socket, one instance per user: $XDG_RUNTIME_DIR/unbraid (the data folder without one).
pub fn runtime() -> Result<&'static Path> {
    static RUNTIME: OnceLock<PathBuf> = OnceLock::new();
    once(&RUNTIME, || match env("XDG_RUNTIME_DIR") {
        Some(dir) => private(PathBuf::from(dir).join("unbraid")),
        None => data().map(Path::to_path_buf),
    })
}

/// The engine's socket, which the system service (unbraid-engine.service) listens on.
pub fn engine() -> String {
    env("UNBRAID_ENGINE_SOCKET").unwrap_or_else(|| "/run/unbraid-engine/engine.sock".into())
}

/// The engine's program, which also runs the app's own unprivileged worker.
pub fn engine_binary() -> String {
    env("UNBRAID_ENGINE_BIN").unwrap_or_else(|| "/usr/lib/unbraid/unbraid-engine".into())
}

/// The user's home folder, where unbraid's files have always been: the account's own (from the user database), or
/// $HOME when that is missing or just "/".
pub fn home() -> &'static Path {
    static HOME: LazyLock<PathBuf> = LazyLock::new(|| {
        let account = account_home();
        PathBuf::from(match account {
            Some(dir) if dir.len() >= 2 => dir,
            other => env("HOME").or(other).unwrap_or_else(|| "?".into()),
        })
    });
    &HOME
}

/// The environment variable `name`, unless it is unset or empty.
pub(crate) fn env(name: &str) -> Option<String> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(|v| v.to_string_lossy().into_owned())
}

/// This user's home folder in the user database (passwd, or what NSS serves), if it has one.
fn account_home() -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: passwd is plain data that getpwuid_r fills in; all-zero is a valid empty value.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and pw's strings point into buf, which outlives their use below.
    let rc = unsafe { libc::getpwuid_r(libc::getuid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string in buf.
    Some(unsafe { CStr::from_ptr(pw.pw_dir) }.to_string_lossy().into_owned())
}

/// `cell`'s folder, made by `make` the first time it succeeds (a failure is tried again on the next call).
fn once(cell: &'static OnceLock<PathBuf>, make: impl FnOnce() -> Result<PathBuf>) -> Result<&'static Path> {
    if let Some(dir) = cell.get() {
        return Ok(dir);
    }
    let dir = make()?;
    Ok(cell.get_or_init(|| dir))
}

/// `dir`, made if it is missing, which only this user may open.
fn private(dir: PathBuf) -> Result<PathBuf> {
    let _ = fs::create_dir_all(&dir);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
