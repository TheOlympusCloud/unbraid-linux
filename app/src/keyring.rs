//! The key that seals the store: in the desktop keyring (Secret Service), else a file only this user can read.
//! The keyring is reached through secret-tool, as the Android Keystore held the key. `key.where` remembers which of the
//! two holds it, so a keyring that is locked or gone later fails the read instead of starting a new key that would leave
//! the sealed files unreadable.

use crate::error::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

const WHERE: &str = "key.where";
const FILE: &str = "key";
const ATTRS: [&str; 4] = ["application", "unbraid", "kind", "store-key"];

/// The store's key for `dir`, through secret-tool, which may take a minute to answer (an unlock prompt).
pub fn key(dir: &Path) -> Result<[u8; 32]> {
    key_using(dir, "secret-tool", 60)
}

/// [`key`] through `tool`, which may take up to `seconds` to answer.
pub fn key_using(dir: &Path, tool: &str, seconds: u64) -> Result<[u8; 32]> {
    let lookup = [&["lookup"][..], &ATTRS[..]].concat();
    let at = dir.join(WHERE);
    let kept = if at.exists() { Some(fs::read_to_string(&at)?) } else { None };
    match kept.as_deref().map(str::trim) {
        Some("keyring") => decode(&run(tool, &lookup, None, seconds).ok_or_else(|| {
            Error::State("The desktop keyring didn't give unbraid its key. Unlock it and try again.".into())
        })?),
        Some("file") => decode(&fs::read_to_string(dir.join(FILE))?),
        _ => {
            let key: [u8; 32] = rand::random();
            let text = STANDARD.encode(key);
            // Stored, then read back: only a key the keyring really returns may seal anything.
            let store = [&["store", "--label", "unbraid storage key"][..], &ATTRS[..]].concat();
            let in_keyring = run(tool, &store, Some(&text), seconds).is_some()
                && run(tool, &lookup, None, seconds).is_some_and(|t| t.trim() == text);
            if !in_keyring {
                private(&dir.join(FILE), &text)?;
            }
            private(&at, if in_keyring { "keyring" } else { "file" })?;
            Ok(key)
        }
    }
}

/// The key sits in a file beside what it seals: there was no desktop keyring when it was made.
pub fn in_file(dir: &Path) -> bool {
    fs::read_to_string(dir.join(WHERE)).is_ok_and(|t| t.trim() == "file")
}

/// An AES-256 key, as it was saved (Base64).
fn decode(text: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(text.trim()).map_err(|e| Error::Invalid(e.to_string()))?;
    <[u8; 32]>::try_from(bytes).map_err(|b| Error::Invalid(format!("Invalid AES key length: {} bytes", b.len())))
}

/// Writes `text` to `f`, a new file only this user can read or write.
fn private(f: &Path, text: &str) -> Result<()> {
    let _ = fs::remove_file(f);
    fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(f)?.write_all(text.as_bytes())?;
    Ok(())
}

/// `tool`'s output, or none if it is missing, fails, says nothing to a lookup or takes longer than `seconds`.
fn run(tool: &str, args: &[&str], input: Option<&str>, seconds: u64) -> Option<String> {
    let cmd = [&[tool][..], args].concat();
    crate::desktop::run(&cmd, input, Duration::from_secs(seconds))
        .filter(|out| input.is_some() || !out.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    fn tool(f: &Path, body: &str) -> String {
        fs::write(f, body).unwrap();
        fs::set_permissions(f, fs::Permissions::from_mode(0o755)).unwrap();
        f.to_string_lossy().into_owned()
    }

    /// A secret-tool that keeps the secret in `store`, or one that says no to everything (`fail`).
    fn fake_tool(root: &Path, store: &Path, fail: bool) -> String {
        let s = store.display();
        let body = format!(
            "#!/bin/sh\n{}case \"$1\" in store) cat > '{s}';; lookup) [ -s '{s}' ] && cat '{s}' || exit 1;; esac\n",
            if fail { "exit 1\n" } else { "" }
        );
        tool(&root.join("secret-tool"), &body)
    }

    fn folder(root: &Path, name: &str) -> std::path::PathBuf {
        let dir = root.join(name);
        fs::create_dir(&dir).unwrap();
        dir
    }

    /// The store's key goes into the keyring when there is one, and comes back from it; never a new one over an old.
    #[test]
    fn keyring_keeps_the_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = folder(tmp.path(), "dir");
        let kept = tmp.path().join("kept");
        let tool = fake_tool(tmp.path(), &kept, false);
        let k = key_using(&dir, &tool, 60).unwrap();
        assert_eq!("keyring", fs::read_to_string(dir.join("key.where")).unwrap());
        assert!(!in_file(&dir));
        assert!(!dir.join("key").exists() && fs::metadata(&kept).unwrap().len() > 0);
        assert_eq!(k, key_using(&dir, &tool, 60).unwrap());
        // The keyring said no (locked, gone): fail, don't start a key the sealed files can't be read with.
        assert!(key_using(&dir, &fake_tool(tmp.path(), &kept, true), 60).is_err());
    }

    /// A keyring that never answers (an unlock prompt left open) fails in time instead of holding the app's start.
    #[test]
    fn keyring_that_hangs_times_out() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = folder(tmp.path(), "dir");
        fs::write(dir.join("key.where"), "keyring").unwrap();
        let hang = tool(&tmp.path().join("hang"), "#!/bin/sh\nsleep 30\n");
        let start = Instant::now();
        assert!(key_using(&dir, &hang, 1).is_err());
        assert!(start.elapsed() < Duration::from_secs(10), "took {:?}", start.elapsed());
    }

    /// No keyring: a key file only this user can read.
    #[test]
    fn key_file_without_keyring() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = folder(tmp.path(), "dir");
        let k = key_using(&dir, &tmp.path().join("no-such-tool").to_string_lossy(), 60).unwrap();
        assert_eq!("file", fs::read_to_string(dir.join("key.where")).unwrap());
        assert!(in_file(&dir)); // Settings says so
        assert_eq!(0o600, fs::metadata(dir.join("key")).unwrap().permissions().mode() & 0o777);
        assert_eq!(k, key_using(&dir, "no-such-tool", 60).unwrap());
    }
}
