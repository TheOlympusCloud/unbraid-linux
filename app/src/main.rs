use unbraid::instance::{self, Args};

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
    let fail = |e: unbraid::error::Error| -> ! {
        eprintln!("{}: {e}", unbraid::APP);
        std::process::exit(1)
    };
    let socket = instance::socket(unbraid::paths::runtime().unwrap_or_else(|e| fail(e)));
    // Another instance runs: it does what was asked.
    let line = if args.command.is_empty() { "ping" } else { args.command.as_str() };
    if let Some(answer) = instance::send(&socket, line) {
        if !answer.is_empty() && answer != "ok" {
            println!("{answer}");
        }
        return;
    }
    if args.needs_running() {
        println!(
            "{}",
            if args.command == "status" { "off".to_string() } else { format!("{} isn't running", unbraid::APP) }
        );
        return;
    }
    // Kept for the whole run: the connection, statistics and the engine's streams live on it.
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap_or_else(|e| fail(e.into()));
    // Onboarding first: the app's start may read what it settles.
    unbraid::ui::tour::init();
    unbraid::app::init(rt.handle(), unbraid::paths::data().unwrap_or_else(|e| fail(e)));
    unbraid::window::run(&args, &socket);
}
