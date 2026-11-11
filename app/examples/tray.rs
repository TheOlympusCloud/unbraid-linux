//! Shows the tray icon in the given states, an icon for each, and prints what each click asks for; Quit ends it.
//!
//!     cargo run --example tray -- [on|connecting|paused|off]...    (default: on)

use unbraid::tray::{Action, State, Tray};
use unbraid::vpn::Phase;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut trays = vec![];
    for name in if args.is_empty() { vec!["on".to_string()] } else { args } {
        let phase = match name.as_str() {
            "on" => Phase::On,
            "connecting" => Phase::Connecting,
            "paused" => Phase::Paused,
            "off" => Phase::Off,
            _ => {
                eprintln!("usage: tray [on|connecting|paused|off]...");
                std::process::exit(2)
            }
        };
        // Paused for 12 minutes from now, as `unbraid pause 12` would.
        let until = chrono::Local::now() + chrono::Duration::minutes(12);
        let state = State {
            phase,
            route: "Netherlands".into(),
            summary: match phase {
                Phase::On => "NL default  ·  US 1".into(),
                Phase::Paused => format!("Paused until {}", until.format("%H:%M")),
                Phase::Connecting | Phase::Off => String::new(),
            },
            paused_until: if phase == Phase::Paused { until.timestamp_millis() } else { 0 },
            profiles: vec!["Home".into(), "Work".into()],
            profile: Some("Home".into()),
        };
        let tag = name.clone();
        let tray = Tray::start(state, move |a| {
            println!("{tag}: {a:?}");
            if a == Action::Quit {
                std::process::exit(0);
            }
        });
        println!("{name}: {}", if tray.shown() { "shown" } else { "no tray yet" });
        trays.push(tray);
    }
    loop {
        std::thread::park();
    }
}
