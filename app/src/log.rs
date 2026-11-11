//! The app's log: warnings to stderr, never a secret.
//! One line per entry, which the session's journal keeps. Callers redact what they log: an address or a key never
//! goes in.

use std::io::Write;

pub fn i(tag: &str, msg: &str) {
    line("I", tag, msg);
}

pub fn w(tag: &str, msg: &str) {
    line("W", tag, msg);
}

pub fn e(tag: &str, msg: &str) {
    line("E", tag, msg);
}

// A log line that can't be written (stderr closed) is dropped, never a reason to stop.
fn line(level: &str, tag: &str, msg: &str) {
    let _ = writeln!(std::io::stderr(), "{level}/{tag}: {msg}");
}
