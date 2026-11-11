//! The desktop around the app: links, notifications, the clipboard and the light or dark theme.
//! What Android gives an app through its Context and intents, from the Linux desktop's own tools.

use crate::paths;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long a desktop setting may take to read.
const SETTING: Duration = Duration::from_secs(3);

/// Opens `url` in the user's browser, as Android's ACTION_VIEW.
pub fn open(url: &str) {
    start("xdg-open", &[url]);
}

/// A desktop notification (freedesktop.org), as Android's: through notify-send when it is installed; nothing otherwise.
pub fn notify(title: &str, text: &str) {
    start("notify-send", &["--app-name=unbraid", "--icon=unbraid", title, text]);
}

/// Animations, unless the desktop asks for reduced motion (GNOME's or KDE's setting), as Android's animator scale 0.
pub fn animations() -> bool {
    static ON: LazyLock<bool> = LazyLock::new(|| {
        let gnome = run(&["gsettings", "get", "org.gnome.desktop.interface", "enable-animations"], None, SETTING);
        let kde = fs::read_to_string(paths::home().join(".config/kdeglobals")).ok().and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("AnimationDurationFactor="))?
                .split_once('=')?
                .1
                .trim()
                .parse::<f64>()
                .ok()
        });
        gnome.as_deref().map(str::trim) != Some("false") && kde != Some(0.0)
    });
    *ON
}

/// The desktop's dark or light preference: true dark, false light, none when it states none. The XDG portal's
/// org.freedesktop.appearance color-scheme, as GNOME and KDE both set it, else GNOME's own setting.
pub fn system_dark() -> Option<bool> {
    ["ReadOne", "Read"]
        .into_iter()
        .find_map(|m| {
            // A portal still starting (a login start) answers late: never hold the app's start for it.
            portal_dark(
                run(
                    &[
                        "busctl",
                        "--user",
                        "--timeout=2",
                        "call",
                        "org.freedesktop.portal.Desktop",
                        "/org/freedesktop/portal/desktop",
                        "org.freedesktop.portal.Settings",
                        m,
                        "ss",
                        "org.freedesktop.appearance",
                        "color-scheme",
                    ],
                    None,
                    SETTING,
                )
                .as_deref(),
            )
        })
        .or_else(|| {
            gnome_dark(
                run(&["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"], None, SETTING).as_deref(),
            )
        })
}

/// busctl's answer, "v u 1" (ReadOne) or "v v u 1" (Read): 1 prefers dark, 2 light, 0 nothing.
pub(crate) fn portal_dark(out: Option<&str>) -> Option<bool> {
    let words: Vec<&str> = out?.trim().split(' ').collect();
    if words.first() != Some(&"v") {
        return None;
    }
    match words.last() {
        Some(&"1") => Some(true),
        Some(&"2") => Some(false),
        _ => None,
    }
}

pub(crate) fn gnome_dark(out: Option<&str>) -> Option<bool> {
    match out?.trim().trim_matches('\'') {
        "prefer-dark" => Some(true),
        "prefer-light" => Some(false),
        _ => None,
    }
}

/// The pictures a QR code can be read from, as the desktop's file choosers know them.
const PICTURES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/bmp"];
const PICTURE_NAMES: [&str; 5] = ["png", "jpg", "jpeg", "gif", "bmp"];

/// The desktop's file chooser, as Android's document picker: the XDG portal's (GNOME's, KDE's, the one a sandbox
/// allows), else zenity's or kdialog's. `images` offers pictures only. None when cancelled, or when the desktop has
/// none. On the app's runtime.
pub async fn pick_file(title: &str, images: bool) -> Option<PathBuf> {
    pick(title, images, false).await.into_iter().next()
}

/// The file chooser for several files at once; none when cancelled.
pub async fn pick_files(title: &str) -> Vec<PathBuf> {
    pick(title, false, true).await
}

async fn pick(title: &str, images: bool, multiple: bool) -> Vec<PathBuf> {
    match portal_pick(title, images, multiple).await {
        Ok(picked) => return picked,
        Err(e) => crate::log::i("Unbraid", &format!("file chooser: no portal ({e})")),
    }
    for (prog, args) in [
        ("zenity", zenity_args(title, images, multiple)),
        ("kdialog", kdialog_args(title, images, paths::home(), multiple)),
    ] {
        // Plain arguments, never a shell: the title is ours, but a path is the user's.
        let run = tokio::process::Command::new(prog)
            .args(&args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output();
        let Ok(out) = run.await else { continue };
        // Cancelled: no other chooser opens.
        return chosen(out.status.success(), &out.stdout);
    }
    vec![]
}

/// What the portal's chooser answers on the request it made for `token` (made before it is asked, so the answer can't
/// come first).
async fn portal_pick(title: &str, images: bool, multiple: bool) -> zbus::Result<Vec<PathBuf>> {
    use tokio_stream::StreamExt;
    use zbus::{Connection, MatchRule, MessageStream, OwnedObjectPath, OwnedVariant, Variant};
    const PORTAL: &str = "org.freedesktop.portal.Desktop";
    // The request's Response, on the handle it answers on.
    async fn responses(conn: &Connection, handle: &str) -> zbus::Result<MessageStream> {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("org.freedesktop.portal.Request")
            .member("Response")
            .path(handle)
            .build()?;
        MessageStream::for_match_rule(rule, conn, None).await
    }
    let conn = Connection::session().await?;
    let token = format!("unbraid{}", rand::random::<u32>());
    let sender = conn.unique_name().map(|n| n.as_str().to_string()).unwrap_or_default();
    let path = request_path(&sender, &token);
    let mut answers = responses(&conn, &path).await?;
    let mut options: HashMap<&str, Variant> = HashMap::from([
        ("handle_token", Variant::from(token.as_str())),
        ("modal", Variant::from(true)),
        ("multiple", Variant::from(multiple)),
    ]);
    if images {
        options.insert(
            "filters",
            Variant::from(vec![("Pictures", PICTURES.iter().map(|m| (1u32, *m)).collect::<Vec<_>>())]),
        );
    }
    let reply = conn
        .call_method(
            Some(PORTAL),
            "/org/freedesktop/portal/desktop",
            Some("org.freedesktop.portal.FileChooser"),
            "OpenFile",
            &("", title, options),
        )
        .await?;
    let handle: OwnedObjectPath = reply.body().deserialize()?;
    // A portal older than handle tokens answers on a path of its own.
    if handle.as_str() != path {
        answers = responses(&conn, handle.as_str()).await?;
    }
    let Some(answer) = answers.next().await.transpose()? else { return Ok(vec![]) };
    let (response, mut results): (u32, HashMap<String, OwnedVariant>) = answer.body().deserialize()?;
    let uris = results.remove("uris").and_then(|v| Vec::<String>::try_from(v).ok()).unwrap_or_default();
    Ok(portal_files(response, &uris))
}

/// Where the portal answers a request made with `token` by the bus name `sender` (":1.42").
fn request_path(sender: &str, token: &str) -> String {
    format!("/org/freedesktop/portal/desktop/request/{}/{token}", sender.trim_start_matches(':').replace('.', "_"))
}

/// The files the portal's answer names: 0 picked (file:// URIs), 1 cancelled, 2 ended otherwise.
fn portal_files(response: u32, uris: &[String]) -> Vec<PathBuf> {
    if response != 0 {
        return vec![];
    }
    uris.iter().filter_map(|u| url::Url::parse(u).ok().filter(|u| u.scheme() == "file")?.to_file_path().ok()).collect()
}

fn zenity_args(title: &str, images: bool, multiple: bool) -> Vec<String> {
    let mut a = vec!["--file-selection".into(), format!("--title={title}")];
    if multiple {
        a.extend(["--multiple".into(), "--separator=\n".into()]);
    }
    if images {
        let names: Vec<String> =
            PICTURE_NAMES.iter().flat_map(|e| [format!("*.{e}"), format!("*.{}", e.to_uppercase())]).collect();
        a.push(format!("--file-filter=Pictures | {}", names.join(" ")));
    }
    a
}

fn kdialog_args(title: &str, images: bool, home: &Path, multiple: bool) -> Vec<String> {
    let mut a = vec!["--title".into(), title.into(), "--getopenfilename".into(), home.to_string_lossy().into_owned()];
    if images {
        a.push(PICTURES.join(" "));
    }
    if multiple {
        a.extend(["--multiple".into(), "--separate-output".into()]);
    }
    a
}

/// A dialog program's answer: the paths it printed, one a line, if any was picked.
fn chosen(picked: bool, out: &[u8]) -> Vec<PathBuf> {
    if !picked {
        return vec![];
    }
    String::from_utf8_lossy(out).split('\n').filter(|p| !p.is_empty()).map(PathBuf::from).collect()
}

/// The clipboard's text, if any.
pub fn clip_text() -> Option<String> {
    clipboard(|c| c.get_text())
}

/// Puts `text` on the clipboard.
pub fn copy(text: &str) {
    clipboard(|c| c.set_text(text));
}

/// Empties the clipboard (a secret must not stay there for the next app to read).
pub fn clear_clip() {
    clipboard(|c| c.set_text(""));
}

/// `f` on the app's clipboard, kept while the app runs: on Linux what it copies is served from it, and is gone with it.
fn clipboard<T>(f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>) -> Option<T> {
    static HELD: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if held.is_none() {
        *held = arboard::Clipboard::new().ok();
    }
    f(held.as_mut()?).ok()
}

/// Starts `prog` and leaves it running; a thread reaps it once it exits. Nothing happens if it can't start.
fn start(prog: &str, args: &[&str]) {
    if let Ok(mut child) =
        Command::new(prog).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
    {
        thread::spawn(move || child.wait());
    }
}

/// `cmd`'s output, or none if it is missing, fails or takes longer than `timeout` (it is stopped then: an unlock prompt
/// left open must not hold the app's start). `input`, a secret say, goes in on stdin, never on the command line; the
/// little that comes out is read once it has exited.
pub(crate) fn run(cmd: &[&str], input: Option<&str>, timeout: Duration) -> Option<String> {
    let (prog, args) = cmd.split_first()?;
    let mut p = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Closed once written, so the tool sees the end of its input.
    let fed = p.stdin.take().is_some_and(|mut o| input.is_none_or(|text| o.write_all(text.as_bytes()).is_ok()));
    let deadline = Instant::now() + timeout;
    let exited = loop {
        match p.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = p.kill();
                let _ = p.wait();
                break false;
            }
        }
    };
    let mut out = Vec::new();
    (fed && exited && p.stdout.take()?.read_to_end(&mut out).is_ok())
        .then(|| String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop_settings::{Theme, dark};

    /// The file choosers: the portal's answer names the file picked, cancelled is none; the dialog programs get the
    /// title and the pictures' filter as their own arguments.
    #[test]
    fn file_chooser() {
        assert_eq!("/org/freedesktop/portal/desktop/request/1_42/unbraid7", request_path(":1.42", "unbraid7"));
        assert_eq!(
            vec![PathBuf::from("/home/u/Home lab.conf")],
            portal_files(0, &["file:///home/u/Home%20lab.conf".into()])
        );
        assert!(portal_files(1, &["file:///home/u/a.conf".into()]).is_empty());
        assert!(portal_files(2, &[]).is_empty());
        assert!(portal_files(0, &[]).is_empty());
        assert!(portal_files(0, &["https://example.com/a.conf".into()]).is_empty());
        assert_eq!(
            vec![PathBuf::from("/a"), PathBuf::from("/b c")],
            portal_files(0, &["file:///a".into(), "https://x/y".into(), "file:///b%20c".into()])
        );
        assert_eq!(vec!["--file-selection", "--title=Choose a program"], zenity_args("Choose a program", false, false));
        assert_eq!(
            vec!["--file-selection", "--title=t", "--multiple", "--separator=\n"],
            zenity_args("t", false, true)
        );
        let z = zenity_args("Choose a picture of the QR code", true, false);
        assert!(
            z[2].starts_with("--file-filter=Pictures | *.png *.PNG *.jpg") && z[2].ends_with("*.bmp *.BMP"),
            "{z:?}"
        );
        assert_eq!(
            vec!["--title", "It's \"mine\"; rm -rf ~", "--getopenfilename", "/home/u"],
            kdialog_args("It's \"mine\"; rm -rf ~", false, Path::new("/home/u"), false)
        );
        assert_eq!("image/png image/jpeg image/gif image/bmp", kdialog_args("t", true, Path::new("/h"), false)[4]);
        assert_eq!(
            vec!["--title", "t", "--getopenfilename", "/h", "--multiple", "--separate-output"],
            kdialog_args("t", false, Path::new("/h"), true)
        );
        assert_eq!(vec![PathBuf::from("/home/u/a b.conf")], chosen(true, b"/home/u/a b.conf\n"));
        assert_eq!(vec![PathBuf::from("/a"), PathBuf::from("/b")], chosen(true, b"/a\n/b\n"));
        assert!(chosen(false, b"/a\n").is_empty());
        assert!(chosen(true, b"\n").is_empty());
    }

    /// The desktop's light or dark: the portal's answer (ReadOne or Read), else GNOME's setting; one that says nothing is none.
    #[test]
    fn system_theme() {
        assert_eq!(Some(true), portal_dark(Some("v u 1")));
        assert_eq!(Some(false), portal_dark(Some("v v u 2\n")));
        for out in [Some("v u 0"), None, Some("Call failed: No such interface"), Some("")] {
            assert_eq!(None, portal_dark(out), "{out:?}");
        }
        assert_eq!(Some(true), gnome_dark(Some("'prefer-dark'\n")));
        assert_eq!(Some(false), gnome_dark(Some("'prefer-light'")));
        assert_eq!(None, gnome_dark(Some("'default'")));
        // System follows the desktop; a desktop that says nothing gets the app's own dark.
        assert!(!dark(Theme::System, Some(false)));
        assert!(dark(Theme::System, None));
        assert!(!dark(Theme::Light, Some(true)));
        assert!(dark(Theme::Dark, Some(false)));
    }
}
