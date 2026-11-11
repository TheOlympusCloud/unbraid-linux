//! What the UI tests share: Slint without a display, a clock the test moves, and shots as PNGs in
//! `app-rs/target/screenshots/`. `render()` takes any Slint window component: the gallery or a screen.
// Each test crate uses only part of it.
#![allow(dead_code)]

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, PhysicalSize, Rgb8Pixel};

thread_local! {
    // The thread's one window. Every component shows in it, one at a time, and a popup (a menu, a tooltip) draws into
    // it at its place, as it does on a backend without popup windows of its own.
    static WINDOW: Rc<MinimalSoftwareWindow> = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    // The platform's clock. It moves only when a shot moves it, so a shot shows animations where the test wants them.
    static CLOCK: Cell<Duration> = const { Cell::new(Duration::ZERO) };
}

struct Headless;

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(WINDOW.with(Rc::clone))
    }

    fn duration_since_start(&self) -> Duration {
        CLOCK.get()
    }
}

/// Makes Slint render without a display on this thread. Call it before creating a component; the platform is per
/// thread, and each test runs on its own. Components share the thread's window: drop one before creating the next.
pub fn headless() {
    // Already set on this thread is fine: the platform stays as it was.
    let _ = slint::platform::set_platform(Box::new(Headless));
}

/// Where shots go: `app-rs/target/screenshots/`.
pub fn shots_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/screenshots");
    std::fs::create_dir_all(&dir).expect("create target/screenshots");
    dir
}

/// Shows `component` in a `width` × `height` window, lets its timers and animations run to their end, draws it and
/// writes the pixels to `path` as a PNG. Returns them, row by row, for checks.
pub fn render(component: &impl ComponentHandle, width: u32, height: u32, path: &Path) -> Vec<Rgb8Pixel> {
    let pixels = shoot(component, width, height, Duration::from_secs(20));
    let bytes = pixels.iter().flat_map(|p| [p.r, p.g, p.b]).collect();
    image::RgbImage::from_raw(width, height, bytes).expect("pixel buffer size").save(path).expect("write the PNG");
    pixels
}

/// Shows `component` at `width` × `height`, moves the clock on by `after` and draws what it shows then, without
/// writing a file: for a frame mid-animation, or two frames to compare.
pub fn shoot(component: &impl ComponentHandle, width: u32, height: u32, after: Duration) -> Vec<Rgb8Pixel> {
    let window = WINDOW.with(Rc::clone);
    assert!(std::ptr::eq(window.window(), component.window()), "call headless() before creating the component");
    window.set_size(PhysicalSize::new(width, height));
    component.show().expect("show the component");
    // In two steps: what the first starts (a focus, a reveal after its delay) runs in the second.
    for _ in 0..2 {
        CLOCK.set(CLOCK.get() + after / 2);
        slint::platform::update_timers_and_animations();
    }
    let mut pixels = vec![Rgb8Pixel::default(); (width * height) as usize];
    window.request_redraw();
    window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, width as usize);
    });
    pixels
}
