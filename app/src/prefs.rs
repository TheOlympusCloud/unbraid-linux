//! Small settings kept as key=value pairs, as Android's SharedPreferences held them.
//! The files are Java properties files (java.util.Properties' store and load), so the ones already written keep
//! working: comments, escapes and `\uXXXX`.

use crate::error::Result;
use crate::{log, paths};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

/// Android's SharedPreferences, as the onboarding and the UI use it: small values in a properties file, written at once.
pub struct SharedPreferences {
    file: PathBuf,
    p: Mutex<BTreeMap<String, String>>,
}

impl SharedPreferences {
    /// The preferences in `file`; none yet if it can't be read.
    pub fn new(file: PathBuf) -> Self {
        let p = fs::read(&file).map(|bytes| load(&bytes)).unwrap_or_default();
        SharedPreferences { file, p: Mutex::new(p) }
    }

    /// The named preferences in the app's folder, one object per name as on Android.
    pub fn named(name: &str) -> Result<&'static SharedPreferences> {
        static OPEN: Mutex<BTreeMap<String, &'static SharedPreferences>> = Mutex::new(BTreeMap::new());
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = open.get(name) {
            return Ok(p);
        }
        let p: &'static SharedPreferences =
            Box::leak(Box::new(SharedPreferences::new(paths::data()?.join(format!("{name}.properties")))));
        open.insert(name.into(), p);
        Ok(p)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.p().contains_key(key)
    }

    pub fn get_boolean(&self, key: &str, def: bool) -> bool {
        match self.p().get(key).map(String::as_str) {
            Some("true") => true,
            Some("false") => false,
            _ => def,
        }
    }

    pub fn get_int(&self, key: &str, def: i32) -> i32 {
        self.p().get(key).and_then(|v| v.parse().ok()).unwrap_or(def)
    }

    pub fn get_long(&self, key: &str, def: i64) -> i64 {
        self.p().get(key).and_then(|v| v.parse().ok()).unwrap_or(def)
    }

    /// Applies `f` and writes the file in one rename; a failed write keeps the change in memory, as Android's apply().
    pub fn edit(&self, f: impl FnOnce(&mut Editor)) {
        let mut p = self.p();
        f(&mut Editor(&mut p));
        let mut tmp = self.file.clone().into_os_string();
        tmp.push(".tmp");
        if fs::write(&tmp, store(&p)).and_then(|()| fs::rename(&tmp, &self.file)).is_err() {
            log::w("Unbraid", "prefs: not saved");
        }
    }

    fn p(&self) -> MutexGuard<'_, BTreeMap<String, String>> {
        self.p.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The changes [`SharedPreferences::edit`] applies.
pub struct Editor<'a>(&'a mut BTreeMap<String, String>);

impl Editor<'_> {
    pub fn put_boolean(&mut self, key: &str, v: bool) {
        self.0.insert(key.into(), v.to_string());
    }

    pub fn put_int(&mut self, key: &str, v: i32) {
        self.0.insert(key.into(), v.to_string());
    }

    pub fn put_long(&mut self, key: &str, v: i64) {
        self.0.insert(key.into(), v.to_string());
    }
}

/// The entries of a properties file: ISO-8859-1 text; comments from '#' or '!'; `key=value`, `key:value` or
/// `key value`; backslash escapes (`\t`, `\n`, `\uXXXX`…); a line ending in a backslash goes on in the next. A malformed
/// `\uXXXX` ends the reading there, and what came before it stays.
fn load(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let text: Vec<char> = bytes.iter().map(|&b| char::from(b)).collect();
    for line in logical_lines(&text) {
        // The key ends at the first unescaped '=', ':' or space; the separator may have spaces around it.
        let (mut key_len, mut value_start, mut has_sep, mut backslash) = (0, line.len(), false, false);
        while key_len < line.len() {
            let c = line[key_len];
            if !backslash && (c == '=' || c == ':') {
                (value_start, has_sep) = (key_len + 1, true);
                break;
            }
            if !backslash && blank(c) {
                value_start = key_len + 1;
                break;
            }
            backslash = c == '\\' && !backslash;
            key_len += 1;
        }
        while value_start < line.len() {
            let c = line[value_start];
            if !blank(c) {
                if has_sep || (c != '=' && c != ':') {
                    break;
                }
                has_sep = true;
            }
            value_start += 1;
        }
        let (Some(key), Some(value)) = (unescape(&line[..key_len]), unescape(&line[value_start..])) else { break };
        out.insert(key, value);
    }
    out
}

/// The text's entries, one per line once comments, blank lines and leading spaces are gone and continued lines are
/// joined (their final backslash dropped).
fn logical_lines(text: &[char]) -> Vec<Vec<char>> {
    let mut lines = Vec::new();
    let mut line = Vec::new();
    // At a line's start, spaces are skipped, and empty lines too unless the line continues another.
    let (mut skip, mut continued, mut backslash) = (true, false, false);
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        i += 1;
        if skip {
            if blank(c) || (!continued && (c == '\n' || c == '\r')) {
                continue;
            }
            (skip, continued) = (false, false);
        }
        if line.is_empty() && (c == '#' || c == '!') {
            while i < text.len() && text[i] != '\n' && text[i] != '\r' {
                i += 1;
            }
            skip = true;
            continue;
        }
        if c != '\n' && c != '\r' {
            line.push(c);
            backslash = c == '\\' && !backslash;
        } else if backslash {
            line.pop();
            (skip, continued, backslash) = (true, true, false);
            if c == '\r' && text.get(i) == Some(&'\n') {
                i += 1;
            }
        } else {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            skip = true;
        }
    }
    if backslash {
        line.pop();
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn blank(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\x0c'
}

/// `s` with its escapes read; none for a malformed `\uXXXX`.
fn unescape(s: &[char]) -> Option<String> {
    let mut out: Vec<u16> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        i += 1;
        if c != '\\' {
            out.push(c as u16);
            continue;
        }
        let Some(&e) = s.get(i) else { break };
        i += 1;
        match e {
            'u' => {
                let hex = s.get(i..i + 4).filter(|h| h.iter().all(char::is_ascii_hexdigit))?;
                out.push(u16::from_str_radix(&hex.iter().collect::<String>(), 16).ok()?);
                i += 4;
            }
            't' => out.push(u16::from(b'\t')),
            'r' => out.push(u16::from(b'\r')),
            'n' => out.push(u16::from(b'\n')),
            'f' => out.push(0x0c),
            other => out.push(other as u16),
        }
    }
    Some(String::from_utf16_lossy(&out))
}

/// `p` as a properties file, written the way Java writes one: a date comment, then each entry with its special
/// characters escaped and anything outside printable ASCII as `\uXXXX`.
fn store(p: &BTreeMap<String, String>) -> String {
    let mut out = format!("#{}\n", chrono::Local::now().format("%a %b %d %H:%M:%S %Z %Y"));
    for (k, v) in p {
        out += &format!("{}={}\n", escape(k, true), escape(v, false));
    }
    out
}

/// `s` escaped for a key (every space) or a value (a leading space only).
fn escape(s: &str, key: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' if i == 0 || key => out.push_str("\\ "),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\x0c' => out.push_str("\\f"),
            '=' | ':' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => {
                for u in c.encode_utf16(&mut [0; 2]) {
                    out += &format!("\\u{u:04X}");
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// A file Java wrote (store) with hand-written lines after it reads as Java reads it; what is written reads back.
    #[test]
    fn reads_and_writes_java_properties() {
        let java = map(&[
            ("a=b:c#d!e", "x=y:z#w!v"),
            ("after", "comment"),
            ("back\\slash", "C:\\path\\"),
            ("close_to_tray", "false"),
            ("colon", "separated"),
            ("continued", "first, second, third"),
            ("cr", "yes"),
            ("crlf", "yes"),
            ("ctrl", "\u{1}\u{7f}"),
            ("dup", "two"),
            ("empty", ""),
            ("escaped key", "A\u{e9}"),
            ("indented", "padded  "),
            ("key with spaces", " value with  spaces "),
            ("last", "no newline"),
            ("latin1", "\u{e9}"),
            ("onlykey", ""),
            ("space", "separated value"),
            ("tab\there", "new\nline\rcr\u{c}ff"),
            ("theme", "2"),
            ("unicode", "caf\u{e9} \u{1F600} \u{fc}"),
            ("width", "1280"),
        ]);
        let bytes = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/prefs/java.properties")).unwrap();
        assert_eq!(java, load(&bytes));
        let written = store(&java);
        assert!(written.starts_with('#') && written.is_ascii());
        assert!(written.contains("\nkey\\ with\\ spaces=\\ value with  spaces \n"));
        assert!(written.contains("\nunicode=caf\\u00E9 \\uD83D\\uDE00 \\u00FC\n"));
        assert_eq!(java, load(written.as_bytes()));
        // A malformed escape: what came before it stays.
        assert_eq!(map(&[("a", "1")]), load(b"a=1\nb=\\u12\nc=3\n"));
    }

    #[test]
    fn edits_are_written_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("desktop.properties");
        let p = SharedPreferences::new(file.clone());
        assert!(!p.contains("width") && p.get_int("width", 1280) == 1280);
        p.edit(|e| {
            e.put_int("width", 1100);
            e.put_boolean("maximized", true);
            e.put_long("at", 1 << 40);
        });
        let again = SharedPreferences::new(file);
        assert_eq!(
            (1100, true, 1 << 40),
            (again.get_int("width", 0), again.get_boolean("maximized", false), again.get_long("at", 0))
        );
        assert!(!dir.path().join("desktop.properties.tmp").exists());
    }
}
