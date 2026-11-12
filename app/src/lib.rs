//! Unbraid by TheOlympus: every app its own VPN exit, on Linux. The app around the engine (sing-box's Linux daemon,
//! `unbraid-engine`): the setup and its store, providers, the engine's config, statistics and the window.

pub mod app;
pub mod apps;
pub mod autostart;
pub mod catalog;
pub mod clock;
pub mod compiler;
pub mod desktop;
pub mod desktop_settings;
pub mod engine;
pub mod error;
pub mod exit_check;
pub mod health;
pub mod http;
pub mod instance;
pub mod intro;
pub mod keyring;
pub mod limits;
pub mod link_picker;
pub mod linux_pass;
pub mod log;
pub mod manual;
pub mod model;
pub mod ndt7;
pub mod net;
pub mod paths;
pub mod prefs;
pub mod probe;
pub mod providers;
pub mod redact;
pub mod snapshot;
pub mod speed_test;
pub mod sqlite;
pub mod stats;
pub mod store;
pub mod taildrop;
pub mod tray;
pub mod ts_login;
pub mod ui;
pub mod vpn;
pub mod wg_conf;
pub mod window;

/// The engine's gRPC services (`unbraid-engine`), generated from its own .proto files.
pub mod engine_api {
    pub mod daemon {
        tonic::include_proto!("daemon");
    }
    pub mod desktop {
        tonic::include_proto!("desktop");
    }
}

/// The app's name as people see it, in the window title, the sidebar, the launcher and About.
pub const TITLE: &str = "Unbraid by TheOlympus";
/// The app's name in sentences and on the command line.
pub const APP: &str = "unbraid";
pub const VERSION_NAME: &str = env!("CARGO_PKG_VERSION");
