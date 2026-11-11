//! Renders the component gallery headless, in the dark and the light theme, to `target/screenshots/` for a look next to
//! the approved screenshots, and checks what a still picture can't show: reduced motion and the keyboard.

mod common;

use std::time::Duration;

use common::{headless, render, shoot, shots_dir};
use slint::platform::{Key, WindowEvent};
use slint::{ComponentHandle, Global};

slint::slint! {
    export { Gallery } from "../ui/gallery.slint";
    export { Motion } from "../ui/motion.slint";
}

/// The gallery's size: its full height, at the width it's laid out for.
fn gallery_size(gallery: &Gallery) -> (u32, u32) {
    slint::platform::update_timers_and_animations();
    (1600, gallery.get_full_height().ceil() as u32)
}

#[test]
fn gallery_renders_in_both_themes() {
    headless();
    let dir = shots_dir();
    // (light, file, the theme's ground: Ink.ground)
    for (light, file, ground) in [(false, "gallery-dark.png", [0x0f, 0x12, 0x14]), (true, "gallery-light.png", [0xf5, 0xf2, 0xee])] {
        let gallery = Gallery::new().expect("create the gallery");
        gallery.set_light(light);
        let (width, height) = gallery_size(&gallery);
        assert!(height > 1000, "the gallery lays out its samples ({height} px)");
        let pixels = render(&gallery, width, height, &dir.join(file));
        let corner = pixels[(height - 1) as usize * width as usize];
        assert_eq!([corner.r, corner.g, corner.b], ground, "{file}: the window's ground is the theme's");
        let distinct: std::collections::HashSet<_> = pixels.iter().map(|p| (p.r, p.g, p.b)).collect();
        assert!(distinct.len() > 1000, "{file}: something was drawn ({} colours)", distinct.len());
    }
}

#[test]
fn reduced_motion_snaps_every_animation() {
    headless();
    let gallery = Gallery::new().expect("create the gallery");
    Motion::get(&gallery).set_reduced(true);
    let (width, height) = gallery_size(&gallery);
    // 60 ms in, the charts would still be drawing in and the rows rising; with the desktop's animations off they're done.
    let early = shoot(&gallery, width, height, Duration::from_millis(60));
    let settled = shoot(&gallery, width, height, Duration::from_secs(20));
    assert!(early == settled, "with reduced motion, nothing moves after the first frame");
}

mod controls {
    slint::slint! {
        import { PillButton } from "../ui/shell.slint";
        import { Toggle } from "../ui/components.slint";
        export component Controls inherits Window {
            in-out property <int> clicks;
            in-out property <bool> on;
            width: 300px;
            height: 100px;
            HorizontalLayout {
                button := PillButton {
                    text: "Go";
                    clicked => {
                        root.clicks += 1;
                    }
                }
                Toggle {
                    label: "Switch";
                    on: root.on;
                    toggled(on) => {
                        root.on = on;
                    }
                }
            }
            public function focus-button() {
                button.focus();
            }
        }
    }
}

#[test]
fn enter_and_space_work_controls_and_tab_moves_between_them() {
    headless();
    let controls = controls::Controls::new().expect("create the controls");
    controls.show().expect("show");
    let press = |key: slint::SharedString| {
        controls.window().dispatch_event(WindowEvent::KeyPressed { text: key.clone() });
        controls.window().dispatch_event(WindowEvent::KeyReleased { text: key });
    };
    controls.invoke_focus_button();
    press(Key::Return.into());
    press(Key::Space.into());
    assert_eq!(controls.get_clicks(), 2, "Enter and Space click the focused button");
    press(Key::Tab.into());
    press(Key::Space.into());
    assert!(controls.get_on(), "Tab reaches the switch, and Space turns it on");
    assert_eq!(controls.get_clicks(), 2, "the button no longer has the focus");
}
