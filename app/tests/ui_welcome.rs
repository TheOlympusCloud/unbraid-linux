//! The welcome in its card in the middle of the window, with the data of the approved screenshots (1-welcome.png,
//! 2-welcome-routes.png), and the tour over a plain page beside the sidebar, rendered headless to
//! `target/screenshots/welcome-*.png` and `tour-*.png`; and what a still picture can't show: the clicks, Esc, and the
//! window behind the tour taking none.

mod common;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, Global, LogicalPosition, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::ui::{tour, welcome};

slint::slint! {
    import { WelcomeScreen } from "../ui/welcome.slint";
    import { TourOverlay } from "../ui/tour.slint";
    import { Sidebar, PageHeader, PillButton, PillKind } from "../ui/shell.slint";
    import { Shapes } from "../ui/icons.slint";
    import { Ink } from "../ui/theme.slint";
    import { Motion } from "../ui/motion.slint";
    export { WelcomePage, WelcomeStep, Strand } from "../ui/welcome.slint";
    export { TourPage } from "../ui/tour.slint";
    export { Ink, Motion }

    // A step before the app proper, as the window shows it: a card in the middle, as wide as reading wants.
    export component WelcomeWindow inherits Window {
        background: Ink.ground;
        Rectangle {
            x: (parent.width - self.width) / 2;
            y: 24px;
            width: min(600px, parent.width - 48px);
            height: parent.height - 48px;
            border-radius: 28px;
            border-width: 1px;
            border-color: Ink.surface-high;
            WelcomeScreen {
                x: 0;
                y: 0;
                width: 100%;
                height: 100%;
            }
        }
    }

    // The tour over a plain page beside the sidebar: the page has a stand-in for the power button and the default
    // route's card where Routes has them, for the stops that point at them.
    export component TourWindow inherits Window {
        in property <bool> wide: true;
        // The element the stop is about: 0 the power button, 1 the default route, anything else none.
        in property <int> anchor;
        in property <bool> touring: true;
        out property <int> page-clicked: -1;
        background: Ink.ground;
        HorizontalLayout {
            Sidebar {
                wide: root.wide;
                current: 0;
                version: "2.8.2";
                profiles: [{ name: "Work" }, { name: "Home" }];
                page-clicked(i) => {
                    root.page-clicked = i;
                }
            }
            Rectangle {
                PageHeader {
                    x: 30px;
                    y: 24px;
                    width: parent.width - 60px;
                    overline: "Every app, its own exit";
                    title: "Routes";
                    PillButton {
                        text: "New route";
                        kind: PillKind.primary;
                    }
                }
                band := Rectangle {
                    x: 30px;
                    y: 113px;
                    width: parent.width - 60px;
                    height: 148px;
                    border-radius: 28px;
                    background: Ink.surface;
                    power := Path {
                        x: parent.width - 72px - 52px;
                        y: 22px;
                        width: 104px;
                        height: 104px;
                        commands: Shapes.cookie;
                        viewbox-width: 100;
                        viewbox-height: 100;
                        fill: Ink.bad;
                    }
                }
                card := Rectangle {
                    x: 46px;
                    y: 337px;
                    width: min(547px, parent.width - 92px);
                    height: 124px;
                    border-radius: 26px;
                    background: Ink.surface-top;
                }
            }
        }
        if root.touring: TourOverlay {
            x: 0;
            y: 0;
            width: root.width;
            height: root.height;
            spot: root.anchor == 0 ? { x: power.absolute-position.x, y: power.absolute-position.y, width: power.width, height: power.height }
                : root.anchor == 1 ? { x: card.absolute-position.x, y: card.absolute-position.y, width: card.width, height: card.height }
                : { x: 0, y: 0, width: 0, height: 0 };
        }
    }
}

fn text(s: &str) -> SharedString {
    s.into()
}

fn model<T: Clone + 'static>(items: impl Iterator<Item = T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items.collect::<Vec<_>>()))
}

/// The view, as the window's code hands it to the page.
fn show_welcome(w: &WelcomeWindow, v: &welcome::WelcomeView) {
    let page = WelcomePage::get(w);
    page.set_steps(model(v.steps.iter().map(|s| WelcomeStep {
        overline: text(&s.overline),
        title: text(&s.title),
        lead: text(&s.lead),
    })));
    page.set_strands(model(v.strands.iter().map(|s| Strand { path: text(&s.path), colour: s.colour, front: s.front })));
}

fn show_tour(w: &TourWindow, v: &tour::TourView) {
    let page = TourPage::get(w);
    page.set_overline(text(&v.overline));
    page.set_title(text(&v.title));
    page.set_body(text(&v.body));
    page.set_next_label(text(&v.next_label));
    page.set_has_back(v.has_back);
    page.set_round(v.round);
    page.set_step(v.step);
    page.set_stops(v.stops);
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

/// Close to `want` within a few levels: antialiasing and rounding differ by a step or two.
fn near(got: [u8; 3], want: [u8; 3]) -> bool {
    got.iter().zip(want).all(|(g, w)| g.abs_diff(w) <= 3)
}

fn click(window: &slint::Window, x: f32, y: f32) {
    let position = LogicalPosition::new(x, y);
    let button = PointerEventButton::Left;
    window.dispatch_event(WindowEvent::PointerMoved { position });
    window.dispatch_event(WindowEvent::PointerPressed { position, button });
    window.dispatch_event(WindowEvent::PointerReleased { position, button });
}

fn press(window: &slint::Window, key: Key) {
    let text: SharedString = key.into();
    window.dispatch_event(WindowEvent::KeyPressed { text: text.clone() });
    window.dispatch_event(WindowEvent::KeyReleased { text });
}

fn counter() -> (Rc<Cell<i32>>, impl Fn() + 'static) {
    let n = Rc::new(Cell::new(0));
    let m = n.clone();
    (n, move || m.set(m.get() + 1))
}

const GROUND: [u8; 3] = [0x0f, 0x12, 0x14];
const SURFACE_HIGH: [u8; 3] = [0x1e, 0x24, 0x28];
const SURFACE_TOP: [u8; 3] = [0x23, 0x2a, 0x2e];
const ACCENT: [u8; 3] = [0xff, 0xa6, 0x6b];
const BLUE: [u8; 3] = [0x7c, 0xc4, 0xff];
const BAR: [u8; 3] = [0x13, 0x17, 0x1a];
/// On the last page at 1280 × 800: the first fact's icon tile, Get started, and the privacy policy's link.
const START_TILE: (u32, u32) = (367, 203);
const START: (u32, u32) = (788, 736);
const PRIVACY: (f32, f32) = (433.0, 371.0);

/// A new install, as approved: the idea with the braid, the four places, then what to know before starting; each page
/// reached by its Next, and Get started at once, with nothing to tick. Dark and light, and the idea at the smallest
/// window.
#[test]
fn welcome_as_approved() {
    headless();
    let dir = shots_dir();
    let w = WelcomeWindow::new().expect("create the welcome");
    show_welcome(&w, &welcome::view());
    let (done, finish) = counter();
    WelcomePage::get(&w).on_done(finish);

    let px = render(&w, 1280, 800, &dir.join("welcome-dark.png"));
    assert_eq!(GROUND, at(&px, 1280, 100, 400), "the window's ground");
    assert_eq!(SURFACE_HIGH, at(&px, 1280, 640, 24), "the card's edge");
    assert_eq!(ACCENT, at(&px, 1280, 880, 738), "Next, in the accent");
    assert_eq!(SURFACE_TOP, at(&px, 1280, 390, 452), "the computer the strands leave");
    assert_eq!(ACCENT, at(&px, 1280, 906, 321), "the accent strand ends at the top exit");
    assert_eq!(BLUE, at(&px, 1280, 906, 452), "the blue one at the middle exit");
    Ink::get(&w).set_light(true);
    let px = render(&w, 1280, 800, &dir.join("welcome-light.png"));
    assert_eq!([0xf5, 0xf2, 0xee], at(&px, 1280, 100, 400), "the light ground");
    Ink::get(&w).set_light(false);

    click(w.window(), 873.0, 738.0);
    let px = render(&w, 1280, 800, &dir.join("welcome-places.png"));
    assert_eq!(BAR, at(&px, 1280, 640, 512), "the bar the four places live in");
    assert_eq!(SURFACE_TOP, at(&px, 1280, 433, 512), "Routes' icon pill");
    assert_eq!(SURFACE_HIGH, at(&px, 1280, 780, 736), "Back, filled");

    click(w.window(), 873.0, 736.0);
    let px = render(&w, 1280, 800, &dir.join("welcome-start-dark.png"));
    assert_eq!(SURFACE_TOP, at(&px, 1280, START_TILE.0, START_TILE.1), "the first fact's tile");
    // Under the pointer that pressed Next, so in the accent's hover shade.
    let start = at(&px, 1280, START.0, START.1);
    assert!(near(start, [0xeb, 0x99, 0x62]), "Get started, in the accent from the first: {start:?}");
    click(w.window(), START.0 as f32, START.1 as f32);
    assert_eq!(1, done.get(), "done");
    Ink::get(&w).set_light(true);
    render(&w, 1280, 800, &dir.join("welcome-start-light.png"));
    drop(w);

    let w = WelcomeWindow::new().expect("create the welcome");
    show_welcome(&w, &welcome::view());
    let px = render(&w, 880, 600, &dir.join("welcome-small.png"));
    assert_eq!(ACCENT, at(&px, 880, 680, 538), "Next stays in reach at the bottom of the card");
}

/// The braid draws in and the page fades in; with the desktop's animations off both are there from the first frame.
#[test]
fn reduced_motion_draws_at_once() {
    headless();
    for reduced in [false, true] {
        let w = WelcomeWindow::new().expect("create the welcome");
        show_welcome(&w, &welcome::view());
        Motion::get(&w).set_reduced(reduced);
        let early = shoot(&w, 1280, 800, Duration::from_millis(60));
        let settled = shoot(&w, 1280, 800, Duration::from_secs(20));
        assert_eq!(reduced, early == settled, "reduced motion {reduced}: the first frames are the last");
    }
}

/// Skip goes straight to the last page; Esc and Back step back a page; the privacy policy asks for its page.
#[test]
fn skip_back_and_links() {
    headless();
    let w = WelcomeWindow::new().expect("create the welcome");
    show_welcome(&w, &welcome::view());
    let (privacy, open_privacy) = counter();
    WelcomePage::get(&w).on_open_privacy(open_privacy);
    let dir = shots_dir().join("welcome-check.png");
    render(&w, 1280, 800, &dir);
    click(w.window(), 368.0, 54.0);
    let px = render(&w, 1280, 800, &dir);
    assert_eq!(SURFACE_TOP, at(&px, 1280, START_TILE.0, START_TILE.1), "Skip opens the last page");
    click(w.window(), PRIVACY.0, PRIVACY.1);
    assert_eq!(1, privacy.get(), "the privacy policy opens its page");
    press(w.window(), Key::Escape);
    let px = render(&w, 1280, 800, &dir);
    assert_eq!(BAR, at(&px, 1280, 640, 512), "Esc steps back to the four places");
    click(w.window(), 798.0, 736.0);
    let px = render(&w, 1280, 800, &dir);
    assert_eq!(SURFACE_TOP, at(&px, 1280, 390, 452), "Back steps back to the idea");
    std::fs::remove_file(dir).ok();
}

/// The tour: the first stop around the power button, dark and light; the default route at the smallest window; a
/// stop with nothing on the page, centred.
#[test]
fn tour_stops() {
    headless();
    let dir = shots_dir();
    let w = TourWindow::new().expect("create the tour");
    show_tour(&w, &tour::view(0, true));
    let px = render(&w, 1280, 800, &dir.join("tour-dark.png"));
    assert_eq!(ACCENT, at(&px, 1280, 1178, 129), "the spot's ring, 6 px around the power button");
    assert!(
        near(at(&px, 1280, 1178, 187), [0xff, 0x8a, 0x80]),
        "the power button, not dimmed: {:?}",
        at(&px, 1280, 1178, 187)
    );
    assert!(at(&px, 1280, 1000, 600)[0] < GROUND[0], "the page around it, dimmed");
    Ink::get(&w).set_light(true);
    render(&w, 1280, 800, &dir.join("tour-light.png"));
    drop(w);

    let w = TourWindow::new().expect("create the tour");
    w.set_wide(false);
    w.set_anchor(1);
    show_tour(&w, &tour::view(1, true));
    render(&w, 880, 600, &dir.join("tour-small.png"));
    w.set_anchor(2);
    show_tour(&w, &tour::view(2, true));
    let px = render(&w, 880, 600, &dir.join("tour-centred.png"));
    assert_eq!(SURFACE_HIGH, at(&px, 880, 440, 300 - 40), "the note, in the middle");
}

/// Next, Back and Close ask the window; Esc goes back, or closes on the first stop; the page behind takes no clicks.
#[test]
fn tour_keys_and_clicks() {
    headless();
    let w = TourWindow::new().expect("create the tour");
    show_tour(&w, &tour::view(1, true));
    let page = TourPage::get(&w);
    let (back, on_back) = counter();
    let (next, on_next) = counter();
    let (close, on_close) = counter();
    page.on_back(on_back);
    page.on_next(on_next);
    page.on_close(on_close);
    render(&w, 1280, 800, &shots_dir().join("tour-check.png"));
    press(w.window(), Key::Escape);
    assert_eq!((1, 0), (back.get(), close.get()), "Esc goes back from the second stop");
    show_tour(&w, &tour::view(0, true));
    press(w.window(), Key::Escape);
    assert_eq!((1, 1), (back.get(), close.get()), "and closes the tour on the first");
    click(w.window(), 124.0, 237.0);
    assert_eq!(-1, w.get_page_clicked(), "the sidebar behind takes no clicks");
    assert_eq!(0, next.get());
    std::fs::remove_file(shots_dir().join("tour-check.png")).ok();
}
