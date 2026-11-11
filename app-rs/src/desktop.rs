//! The desktop around the app: links, notifications, the clipboard and the light or dark theme.
//! What Android gives an app through its Context and intents, from the Linux desktop's own tools.

use crate::paths;
use std::fs;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long a desktop setting may take to read.
const SETTING: Duration = Duration::from_secs(3);

/// Opens `url` in the user's browser, as Android's ACTION_VIEW.
pub fn open(url: &str) {
    start("xdg-open", &[url]);
}

/// A desktop notification (freedesktop.org), as Android's: through notify-send when it is installed; nothing otherwise.
pub fn notify(title: &str, text: &str) {
    start("notify-send", &["--app-name=unbraid", "--icon=unbraid", title, text]);
}

/// Animations, unless the desktop asks for reduced motion (GNOME's or KDE's setting), as Android's animator scale 0.
pub fn animations() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| {
        let gnome = run(&["gsettings", "get", "org.gnome.desktop.interface", "enable-animations"], None, SETTING);
        let kde = fs::read_to_string(paths::home().join(".config/kdeglobals")).ok().and_then(|text| {
            text.lines().find(|l| l.starts_with("AnimationDurationFactor="))?.split_once('=')?.1.trim().parse::<f64>().ok()
        });
        gnome.as_deref().map(str::trim) != Some("false") && kde != Some(0.0)
    });
    *ON
}

/// The desktop's dark or light preference: true dark, false light, none when it states none. The XDG portal's
/// org.freedesktop.appearance color-scheme, as GNOME and KDE both set it, else GNOME's own setting.
pub fn system_dark() -> Option<bool> {
    ["ReadOne", "Read"]
        .into_iter()
        .find_map(|m| {
            // A portal still starting (a login start) answers late: never hold the app's start for it.
            portal_dark(
                run(
                    &["busctl", "--user", "--timeout=2", "call", "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.portal.Settings", m, "ss", "org.freedesktop.appearance", "color-scheme"],
                    None,
                    SETTING,
                )
                .as_deref(),
            )
        })
        .or_else(|| gnome_dark(run(&["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"], None, SETTING).as_deref()))
}

/// busctl's answer, "v u 1" (ReadOne) or "v v u 1" (Read): 1 prefers dark, 2 light, 0 nothing.
pub(crate) fn portal_dark(out: Option<&str>) -> Option<bool> {
    let words: Vec<&str> = out?.trim().split(' ').collect();
    if words.first() != Some(&"v") {
        return None;
    }
    match words.last() {
        Some(&"1") => Some(true),
        Some(&"2") => Some(false),
        _ => None,
    }
}

pub(crate) fn gnome_dark(out: Option<&str>) -> Option<bool> {
    match out?.trim().trim_matches('\'') {
        "prefer-dark" => Some(true),
        "prefer-light" => Some(false),
        _ => None,
    }
}

/// The clipboard's text, if any.
pub fn clip_text() -> Option<String> {
    clipboard(|c| c.get_text())
}

/// Puts `text` on the clipboard.
pub fn copy(text: &str) {
    clipboard(|c| c.set_text(text));
}

/// Empties the clipboard (a secret must not stay there for the next app to read).
pub fn clear_clip() {
    clipboard(|c| c.set_text(""));
}

/// `f` on the app's clipboard, kept while the app runs: on Linux what it copies is served from it, and is gone with it.
fn clipboard<T>(f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>) -> Option<T> {
    static HELD: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if held.is_none() {
        *held = arboard::Clipboard::new().ok();
    }
    f(held.as_mut()?).ok()
}

/// Starts `prog` and leaves it running; a thread reaps it once it exits. Nothing happens if it can't start.
fn start(prog: &str, args: &[&str]) {
    if let Ok(mut child) = Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        thread::spawn(move || child.wait());
    }
}

/// `cmd`'s output, or none if it is missing, fails or takes longer than `timeout` (it is stopped then: an unlock prompt
/// left open must not hold the app's start). `input`, a secret say, goes in on stdin, never on the command line; the
/// little that comes out is read once it has exited.
pub(crate) fn run(cmd: &[&str], input: Option<&str>, timeout: Duration) -> Option<String> {
    let (prog, args) = cmd.split_first()?;
    let mut p = Command::new(prog).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    // Closed once written, so the tool sees the end of its input.
    let fed = p.stdin.take().is_some_and(|mut o| input.is_none_or(|text| o.write_all(text.as_bytes()).is_ok()));
    let deadline = Instant::now() + timeout;
    let exited = loop {
        match p.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = p.kill();
                let _ = p.wait();
                break false;
            }
        }
    };
    let mut out = Vec::new();
    (fed && exited && p.stdout.take()?.read_to_end(&mut out).is_ok()).then(|| String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_settings::{Theme, dark};

    /// The desktop's light or dark: the portal's answer (ReadOne or Read), else GNOME's setting; one that says nothing is none.
    #[test]
    fn system_theme() {
        assert_eq!(Some(true), portal_dark(Some("v u 1")));
        assert_eq!(Some(false), portal_dark(Some("v v u 2\n")));
        for out in [Some("v u 0"), None, Some("Call failed: No such interface"), Some("")] {
            assert_eq!(None, portal_dark(out), "{out:?}");
        }
        assert_eq!(Some(true), gnome_dark(Some("'prefer-dark'\n")));
        assert_eq!(Some(false), gnome_dark(Some("'prefer-light'")));
        assert_eq!(None, gnome_dark(Some("'default'")));
        // System follows the desktop; a desktop that says nothing gets the app's own dark.
        assert!(!dark(Theme::System, Some(false)));
        assert!(dark(Theme::System, None));
        assert!(!dark(Theme::Light, Some(true)));
        assert!(dark(Theme::Dark, Some(false)));
    }
}
