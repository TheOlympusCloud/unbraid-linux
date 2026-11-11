//! One unbraid at a time: a second start, the launcher's actions and the command line ask the running one over a local
//! socket in the user's runtime folder (it alone drives the engine). A line in, a line out.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const USAGE: &str = "Usage: unbraid [command]

  (none)            open the window (or bring the running one to the front)
  connect           connect, starting unbraid in the background if needed
  disconnect        end the connection
  pause [minutes]   pause for 5 to 60 minutes (15 by default; 0 = until resumed)
  profile <name>    open Routes on a saved profile (switching needs Use there)
  status            print the connection state
  quit              disconnect and close unbraid
  --background      start without a window (for starting at login); with --connect, connect too
  --version";

const COMMANDS: [&str; 9] = ["", "show", "connect", "disconnect", "pause", "profile", "status", "quit", "ping"];

/// What the command line asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    /// The command and its argument, as one line for the running instance ("" = start for the background).
    pub command: String,
    pub background: bool,
    pub connect: bool,
    pub help: bool,
    pub version: bool,
}

impl Args {
    pub fn parse(args: &[String]) -> Args {
        let has = |f: &str| args.iter().any(|a| a == f);
        let words: Vec<&str> =
            args.iter().filter(|a| !a.starts_with("--") && a.as_str() != "-h").map(String::as_str).collect();
        let command = if words.is_empty() {
            if has("--background") { String::new() } else { "show".into() }
        } else {
            words.join(" ")
        };
        Args {
            command,
            background: has("--background"),
            connect: has("--connect"),
            help: has("--help") || has("-h"),
            version: has("--version"),
        }
    }

    /// The first word is one this program knows.
    pub fn known(&self) -> bool {
        COMMANDS.contains(&self.command.split(' ').next().unwrap_or(""))
    }

    /// A command only a running unbraid can carry out: without one there is nothing to do.
    pub fn needs_running(&self) -> bool {
        matches!(self.command.split(' ').next().unwrap_or(""), "disconnect" | "pause" | "quit" | "status")
    }
}

/// The running app's socket, in the user's runtime folder.
pub fn socket(runtime: &Path) -> PathBuf {
    runtime.join("app.sock")
}

/// `line`'s answer from the running app, or none when none runs.
pub fn send(path: &Path, line: &str) -> Option<String> {
    let mut ch = UnixStream::connect(path).ok()?;
    ch.write_all(format!("{line}\n").as_bytes()).ok()?;
    ch.shutdown(std::net::Shutdown::Write).ok()?;
    let mut answer = String::new();
    ch.read_to_string(&mut answer).ok()?;
    Some(answer.trim().to_string())
}

/// Serves later starts; false if another instance already does.
pub fn serve(path: &Path, handle: Arc<dyn Fn(&str) -> String + Send + Sync>) -> bool {
    if send(path, "ping").is_some() {
        return false;
    }
    let _ = std::fs::remove_file(path); // left by one that was killed
    let Ok(server) = UnixListener::bind(path) else { return false };
    std::thread::Builder::new()
        .name("instance".into())
        .spawn(move || {
            for ch in server.incoming() {
                let Ok(mut ch) = ch else { continue };
                let mut line = String::new();
                let _ = BufReader::new(&ch).read_line(&mut line);
                let h = handle.clone();
                let answer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| h(line.trim_end_matches('\n'))))
                    .unwrap_or_else(|_| "error".into());
                let _ = ch.write_all(format!("{answer}\n").as_bytes());
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Args {
        Args::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_command_line_reads_as_before() {
        assert_eq!("show", args(&[]).command);
        assert_eq!("", args(&["--background"]).command);
        let a = args(&["--background", "--connect"]);
        assert!(a.background && a.connect && a.known());
        assert_eq!("pause 30", args(&["pause", "30"]).command);
        assert!(args(&["pause", "30"]).needs_running());
        assert!(!args(&["frobnicate"]).known());
        assert!(args(&["-h"]).help);
        assert!(args(&["--version"]).version);
    }

    /// A later start reaches the running one; a socket left by one that was killed doesn't stop a new one serving.
    #[test]
    fn a_later_start_asks_the_running_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = socket(dir.path());
        assert_eq!(None, send(&path, "ping"));
        std::fs::write(&path, "").unwrap(); // a stale socket file
        assert!(serve(&path, Arc::new(|line: &str| if line == "ping" { "ok".into() } else { format!("got {line}") })));
        assert_eq!(Some("ok".into()), send(&path, "ping"));
        assert_eq!(Some("got status".into()), send(&path, "status"));
        assert!(!serve(&path, Arc::new(|_: &str| String::new()))); // one at a time
    }
}
