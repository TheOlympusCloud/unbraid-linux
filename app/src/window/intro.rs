//! The first start's introduction over the window ([`crate::intro`]). A new install's first start with the window
//! showing plays it once, unless the desktop's animations are off. A click, Esc or closing the window skips it; its end
//! fades into the welcome. Without a film GStreamer can play, the window simply opens, and a later start tries again.

use super::{Win, locked, post, with};
use crate::ui::tour;
use crate::{desktop, intro, log, paths};
use slint::{Image, Rgba8Pixel, SharedPixelBuffer};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const TAG: &str = "Unbraid";

/// Asks the player to stop: the film was skipped.
static STOP: AtomicBool = AtomicBool::new(false);
/// A picture of the film has shown.
static SHOWN: AtomicBool = AtomicBool::new(false);
/// The newest picture not yet shown, and whether the window was asked to show it: only the newest ever waits.
static NEWEST: Mutex<Option<SharedPixelBuffer<Rgba8Pixel>>> = Mutex::new(None);
static ASKED: AtomicBool = AtomicBool::new(false);

/// Plays the introduction over `win` if it is due and the window is `shown` at start ([`intro::gate`]).
pub(super) fn start(win: &Win, shown: bool) {
    let film = paths::intro();
    let player = || {
        let gst = intro::Gst::load().filter(intro::Gst::can_play);
        if gst.is_none() {
            log::i(TAG, "intro: GStreamer here can't play it (gst-plugins-good), so not this time");
        }
        gst
    };
    let Some(gst) = intro::gate(tour::intro_due(), shown, desktop::animations(), film.exists(), player) else {
        return;
    };
    // Counted before it plays, so a film that takes the app down isn't tried at every start.
    tour::intro_trying();
    win.w.set_intro_on(true);
    let thread = std::thread::Builder::new().name("intro".into()).spawn(move || {
        if let Err(e) = intro::play(&gst, &film, &STOP, show) {
            log::i(TAG, &format!("intro: {e}"));
        }
        post(end);
    });
    if thread.is_err() {
        win.w.set_intro_on(false);
    }
}

/// A picture from the player, shown on the window's thread as soon as it can be. The first makes the film seen.
fn show(p: SharedPixelBuffer<Rgba8Pixel>) {
    if !SHOWN.swap(true, Ordering::SeqCst) {
        tour::intro_seen();
    }
    *locked(&NEWEST) = Some(p);
    if !ASKED.swap(true, Ordering::SeqCst) {
        let _ = slint::invoke_from_event_loop(|| {
            ASKED.store(false, Ordering::SeqCst);
            if let Some(p) = locked(&NEWEST).take() {
                with(|win| win.w.set_intro_frame(Image::from_rgba8(p)));
            }
        });
    }
}

/// The film ended, failed or was skipped: the player stops, and the window fades in from its last picture.
pub(super) fn end(win: &Win) {
    STOP.store(true, Ordering::SeqCst);
    if win.w.get_intro_on() {
        win.w.set_intro_on(false);
        win.w.invoke_refocus();
        slint::Timer::single_shot(Duration::from_secs(1), || {
            with(|win| win.w.set_intro_frame(Image::default()));
        });
    }
}
