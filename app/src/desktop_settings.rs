//! The window's own settings: theme, start at login, the tray and the window's place.
//! Settings › Desktop keeps them in `desktop.properties`; the window decisions that follow from them are here too.

use crate::prefs::{Editor, SharedPreferences};
use std::sync::LazyLock;
use tokio::sync::watch;

fn prefs() -> Option<&'static SharedPreferences> {
    SharedPreferences::named("desktop").ok()
}

fn edit(f: impl FnOnce(&mut Editor)) {
    if let Some(p) = prefs() {
        p.edit(f);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    System,
    Dark,
    Light,
}

impl Theme {
    /// Every theme, in the order the setting saves them (by index).
    pub const ENTRIES: [Theme; 3] = [Theme::System, Theme::Dark, Theme::Light];
}

pub fn theme() -> &'static watch::Sender<Theme> {
    static THEME: LazyLock<watch::Sender<Theme>> = LazyLock::new(|| {
        let saved = prefs().map_or(0, |p| p.get_int("theme", 0));
        watch::Sender::new(
            usize::try_from(saved).ok().and_then(|i| Theme::ENTRIES.get(i).copied()).unwrap_or(Theme::System),
        )
    });
    &THEME
}

/// Closing the window leaves unbraid in the tray; off, closing quits and the connection ends.
pub fn close_to_tray() -> &'static watch::Sender<bool> {
    static ON: LazyLock<watch::Sender<bool>> =
        LazyLock::new(|| watch::Sender::new(prefs().map(|p| p.get_boolean("close_to_tray", true)).unwrap_or(true)));
    &ON
}

pub fn remember_window() -> &'static watch::Sender<bool> {
    static ON: LazyLock<watch::Sender<bool>> =
        LazyLock::new(|| watch::Sender::new(prefs().map(|p| p.get_boolean("remember_window", true)).unwrap_or(true)));
    &ON
}

pub fn set_theme(t: Theme) {
    theme().send_replace(t);
    edit(|e| e.put_int("theme", t as i32));
}

pub fn set_close_to_tray(on: bool) {
    close_to_tray().send_replace(on);
    edit(|e| e.put_boolean("close_to_tray", on));
}

pub fn set_remember_window(on: bool) {
    remember_window().send_replace(on);
    edit(|e| e.put_boolean("remember_window", on));
}

/// Dark or light for `t`, `system_dark` being the desktop's own preference (none: it states none, so the app's dark).
pub fn dark(t: Theme, system_dark: Option<bool>) -> bool {
    match t {
        Theme::Dark => true,
        Theme::Light => false,
        Theme::System => system_dark.unwrap_or(true),
    }
}

/// The window's size and place when it last closed, in dp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub maximized: bool,
}

pub fn placement() -> Option<Placement> {
    let p = prefs()?;
    if !*remember_window().borrow() || !p.contains("width") {
        return None;
    }
    Some(Placement {
        x: p.get_int("x", 0),
        y: p.get_int("y", 0),
        width: p.get_int("width", 1280),
        height: p.get_int("height", 800),
        maximized: p.get_boolean("maximized", false),
    })
}

pub fn save(p: Placement) {
    edit(|e| {
        e.put_int("x", p.x);
        e.put_int("y", p.y);
        e.put_int("width", p.width);
        e.put_int("height", p.height);
        e.put_boolean("maximized", p.maximized);
    });
}

/// What closing the window does: hide it (true) or quit. Hidden, unbraid needs a way back: the tray, or, without one,
/// a connection still running (the launcher or the command line brings the window back).
pub fn close_hides(close_to_tray: bool, tray: bool, connected: bool) -> bool {
    close_to_tray && (tray || connected)
}

/// Whether unbraid quits, at a redraw, once its window is hidden and nothing runs any more: it was on (`was_on`, kept
/// between redraws), then was disconnected from the tray or the command line. With a tray there's a way back, whatever
/// closing the window does. A connection's end is looked at once: a tray that goes away later (its host restarting)
/// doesn't end unbraid.
pub fn quits_when_hidden(visible: bool, on: bool, was_on: &mut bool, tray: bool) -> bool {
    if on {
        *was_on = true;
        return false;
    }
    std::mem::take(was_on) && !visible && !tray
}

/// The place to remember for a window at `x`, `y` (none until the desktop has placed it) and of this size: maximized
/// keeps the size it had before, to come back to; full screen and a place not set yet aren't remembered.
pub fn to_save(
    was: Option<Placement>,
    x: Option<i32>,
    y: Option<i32>,
    width: i32,
    height: i32,
    maximized: bool,
    floating: bool,
) -> Option<Placement> {
    if maximized {
        Some(Placement {
            maximized: true,
            ..was.unwrap_or(Placement { x: 0, y: 0, width: 1280, height: 800, maximized: false })
        })
    } else if let (true, Some(x), Some(y)) = (floating, x, y) {
        Some(Placement { x, y, width, height, maximized: false })
    } else {
        None
    }
}

/// Whether a start shows the window: not for the background (`background`, at login) or to connect. Without a tray,
/// a background start that doesn't connect would be nothing at all, so it shows the window instead.
pub fn shows_at_start(background: bool, connect: bool, command: &str, tray: bool) -> bool {
    !background && command != "connect" || background && !connect && !tray
}

/// A screen's area, in the units of [`Placement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// A remembered place still on one of `screens` (one may have gone since).
pub fn on_screen(p: Placement, screens: &[Rect]) -> bool {
    screens.iter().any(|s| overlaps(*s, Rect { x: p.x, y: p.y, width: p.width, height: p.height }))
}

/// Whether two areas share some of their surface; an empty one shares none.
fn overlaps(a: Rect, b: Rect) -> bool {
    let end = |at: i32, len: i32| i64::from(at) + i64::from(len);
    a.width > 0
        && a.height > 0
        && b.width > 0
        && b.height > 0
        && end(a.x, a.width) > i64::from(b.x)
        && end(b.x, b.width) > i64::from(a.x)
        && end(a.y, a.height) > i64::from(b.y)
        && end(b.y, b.height) > i64::from(a.y)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Closing hides the window only where there's a way back to it; a hidden unbraid quits only without a tray.
    #[test]
    fn window_close_and_quit() {
        assert!(close_hides(true, true, false));
        assert!(close_hides(true, false, true));
        assert!(!close_hides(true, false, false));
        assert!(!close_hides(false, true, true));
        // Disconnected from the tray while hidden: with a tray it stays, whatever closing the window does; without, it ends.
        let quits = |visible, was_on, tray| quits_when_hidden(visible, false, &mut { was_on }, tray);
        assert!(!quits(false, true, true));
        assert!(quits(false, true, false));
        assert!(!quits(true, true, false));
        assert!(!quits(false, false, false));
        // The end is looked at once: a tray host that restarts after a connect and a disconnect doesn't end it.
        let mut was_on = false;
        assert!(!quits_when_hidden(false, true, &mut was_on, true));
        assert!(was_on);
        assert!(!quits_when_hidden(false, false, &mut was_on, true));
        assert!(!quits_when_hidden(false, false, &mut was_on, false));
    }

    /// The window's place: floating as it is, maximized with the size it had, nothing before the desktop places it or full screen.
    #[test]
    fn window_placement() {
        let was = Placement { x: 100, y: 80, width: 1100, height: 700, maximized: false };
        assert_eq!(
            Some(Placement { x: 40, y: 30, width: 1280, height: 800, maximized: false }),
            to_save(Some(was), Some(40), Some(30), 1280, 800, false, true)
        );
        assert_eq!(
            Some(Placement { maximized: true, ..was }),
            to_save(Some(was), Some(0), Some(0), 1920, 1080, true, false)
        );
        assert_eq!(
            Some(Placement { x: 0, y: 0, width: 1280, height: 800, maximized: true }),
            to_save(None, Some(0), Some(0), 1920, 1080, true, false)
        );
        assert_eq!(None, to_save(Some(was), None, None, 1280, 800, false, true));
        assert_eq!(None, to_save(Some(was), Some(0), Some(0), 1920, 1080, false, false));
        // A place on a screen that has gone isn't used: the window opens where the desktop puts it.
        let screens = [Rect { x: 0, y: 0, width: 1920, height: 1080 }];
        assert!(on_screen(was, &screens));
        assert!(!on_screen(Placement { x: 2500, y: 100, width: 1280, height: 800, maximized: false }, &screens));
        assert!(!on_screen(was, &[]));
    }

    /// A start shows the window unless it's for the background or to connect; without a tray, one that won't connect does.
    #[test]
    fn start_shows_the_window() {
        assert!(shows_at_start(false, false, "show", true));
        assert!(!shows_at_start(false, false, "connect", true));
        assert!(!shows_at_start(true, false, "", true));
        assert!(shows_at_start(true, false, "", false));
        assert!(!shows_at_start(true, true, "", false));
    }
}
