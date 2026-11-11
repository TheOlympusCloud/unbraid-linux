use std::sync::Arc;
use unbraid::instance::{self, Args};

slint::include_modules!();

/// The user's runtime folder for unbraid's sockets, private to the user.
fn runtime_dir() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = base.join("unbraid");
    let _ = std::fs::create_dir_all(&dir);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    dir
}

fn main() {
    let args = Args::parse(&std::env::args().skip(1).collect::<Vec<_>>());
    if args.help {
        println!("{}", instance::USAGE);
        return;
    }
    if args.version {
        println!("{} {}", unbraid::APP, unbraid::VERSION_NAME);
        return;
    }
    if !args.known() {
        eprintln!("{}", instance::USAGE);
        std::process::exit(2);
    }
    let socket = instance::socket(&runtime_dir());
    // Another instance runs: it does what was asked.
    let line = if args.command.is_empty() { "ping" } else { args.command.as_str() };
    if let Some(answer) = instance::send(&socket, line) {
        if !answer.is_empty() && answer != "ok" {
            println!("{answer}");
        }
        return;
    }
    if args.needs_running() {
        println!("{}", if args.command == "status" { "off".to_string() } else { format!("{} isn't running", unbraid::APP) });
        return;
    }
    if !instance::serve(&socket, Arc::new(|line: &str| match line.split(' ').next().unwrap_or("") {
        "ping" | "show" | "" => "ok".into(),
        "status" => "off".into(),
        _ => "unknown command".into(),
    })) {
        return; // lost a race with another start
    }
    // The launcher entry's StartupWMClass and the desktop's app id.
    let _ = slint::set_xdg_app_id("unbraid");
    let window = AppWindow::new().expect("open the window");
    window.run().expect("run the window");
}
