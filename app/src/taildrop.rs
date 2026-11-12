//! Taildrop: files sent between this computer and the user's other devices on their tailnet, through the engine's
//! Tailscale node. A file a device sends waits in the engine's own folder, which only root can read; while the
//! connection runs, the app moves each one to the user's Downloads folder as it arrives, and the engine forgets it.

use crate::compiler::TS_TAG;
use crate::engine::Engine;
use crate::engine_api::daemon::{
    DownloadTaildropFileChunk, TaildropFile, TaildropFileChunk, TaildropFileDone, TaildropOutgoingFile,
    TaildropSendClientMessage, TaildropSendStart, taildrop_send_client_message::Message as Out,
    taildrop_send_server_message::Message as In,
};
use crate::{desktop, log, paths, redact};
use regex::Regex;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_stream::{Stream, StreamExt};
use tonic::Status;

const TAG: &str = "Taildrop";

/// A chunk of a file sent: the engine's own size, which keeps each one inside a single gRPC frame.
const CHUNK: usize = 16 * 1024 - 64;

/// A send, as Settings shows it: to which device, how far it got, and how it ended.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sending {
    pub to: String,
    pub files: usize,
    /// Bytes the device has, of `total`.
    pub sent: u64,
    pub total: u64,
    pub done: bool,
    pub error: Option<String>,
}

impl Sending {
    pub fn running(&self) -> bool {
        !self.done && self.error.is_none()
    }
}

/// The last send, while the app runs.
pub fn sending() -> &'static watch::Sender<Option<Sending>> {
    static SENDING: LazyLock<watch::Sender<Option<Sending>>> = LazyLock::new(watch::Sender::default);
    &SENDING
}

static TASK: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Whether the engine takes `name` for a file: one name, not a path, as Tailscale checks it.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && !name.contains(['/', '\0'])
        && !name.ends_with(".partial")
        && !name.ends_with(".deleted")
}

/// Sends `files` to the device with Tailscale ID `to` (`name` as people know it), on the app's runtime; [`sending`]
/// follows it. One send at a time: a new one while another runs is ignored.
pub fn send(engine: &'static Engine, to: String, name: String, files: Vec<PathBuf>) {
    let mut task = TASK.lock().unwrap();
    if files.is_empty() || task.as_ref().is_some_and(|t| !t.is_finished()) {
        return;
    }
    sending().send_replace(Some(Sending { to: name, files: files.len(), ..Sending::default() }));
    *task = Some(crate::app::runtime().spawn(async move {
        let r = send_files(engine, &to, files).await;
        sending().send_modify(|s| {
            if let Some(s) = s {
                match r {
                    Ok(()) => (s.done, s.sent) = (true, s.total),
                    Err(e) => s.error = Some(e),
                }
            }
        });
    }));
}

/// Stops the send that runs: the engine gives up on the device as the call ends.
pub fn cancel() {
    if let Some(t) = TASK.lock().unwrap().take() {
        t.abort();
    }
    sending().send_modify(|s| {
        if let Some(s) = s.as_mut().filter(|s| s.running()) {
            s.error = Some("Cancelled".into());
        }
    });
}

async fn send_files(engine: &Engine, to: &str, paths: Vec<PathBuf>) -> Result<(), String> {
    let mut files = vec![];
    for p in &paths {
        let name = p.file_name().and_then(|n| n.to_str()).filter(|n| valid_name(n));
        let size = tokio::fs::metadata(p).await.ok().filter(|m| m.is_file()).map(|m| m.len());
        let (Some(name), Some(size)) = (name, size) else {
            return Err(format!("{} can't be sent", p.file_name().unwrap_or_default().to_string_lossy()));
        };
        files.push(TaildropOutgoingFile { name: name.into(), size: size as i64 });
    }
    let sizes: Vec<u64> = files.iter().map(|f| f.size as u64).collect();
    sending().send_modify(|s| {
        if let Some(s) = s {
            s.total = sizes.iter().sum();
        }
    });
    let failed = Arc::new(Mutex::new(None));
    let start = TaildropSendStart { endpoint_tag: TS_TAG.into(), peer_stable_id: to.into(), files };
    let mut replies = engine.send_taildrop(messages(start, paths, failed.clone())).await.map_err(|e| told(&e))?;
    loop {
        match replies.message().await {
            Ok(Some(m)) => {
                if let Some(In::Progress(p)) = m.message {
                    let sent = sent(&sizes, p.file_index, p.sent_bytes);
                    sending().send_modify(|s| {
                        if let Some(s) = s {
                            s.sent = sent;
                        }
                    });
                }
            }
            Ok(None) => return Ok(()),
            // A file that couldn't be read ends what the app sends: that is the reason, not what the engine made of it.
            Err(e) => return Err(failed.lock().unwrap().take().unwrap_or_else(|| told(&e))),
        }
    }
}

/// Bytes the device has: the files before `index` whole, and `of_file` of that one.
fn sent(sizes: &[u64], index: i32, of_file: i64) -> u64 {
    sizes.iter().take(index.max(0) as usize).sum::<u64>() + of_file.max(0) as u64
}

/// What the engine reads for a send: the start, then each file's content in chunks and its end. A file that can't be
/// read ends it early, its reason in `failed`.
fn messages(
    start: TaildropSendStart,
    paths: Vec<PathBuf>,
    failed: Arc<Mutex<Option<String>>>,
) -> impl Stream<Item = TaildropSendClientMessage> + Send + 'static {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let out = |m| TaildropSendClientMessage { message: Some(m) };
        if tx.send(out(Out::Start(start))).await.is_err() {
            return;
        }
        let mut buf = vec![0; CHUNK];
        for p in paths {
            let unread = || format!("{} couldn't be read", p.file_name().unwrap_or_default().to_string_lossy());
            let Ok(mut f) = tokio::fs::File::open(&p).await else {
                *failed.lock().unwrap() = Some(unread());
                return;
            };
            loop {
                match f.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(out(Out::Chunk(TaildropFileChunk { data: buf[..n].to_vec() }))).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => {
                        *failed.lock().unwrap() = Some(unread());
                        return;
                    }
                }
            }
            if tx.send(out(Out::FileDone(TaildropFileDone {}))).await.is_err() {
                return;
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

/// The engine's reason, as a sentence: "taildrop: peer not found" → "Peer not found".
fn told(e: &Status) -> String {
    let m = redact::clean(e.message());
    let m = m.strip_prefix("taildrop: ").unwrap_or(&m);
    let mut c = m.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => "The engine couldn't send it".into(),
    }
}

/// The user's Downloads folder: XDG_DOWNLOAD_DIR from user-dirs.dirs, else ~/Downloads.
pub fn downloads() -> PathBuf {
    let config = paths::env("XDG_CONFIG_HOME").map_or_else(|| paths::home().join(".config"), PathBuf::from);
    std::fs::read_to_string(config.join("user-dirs.dirs"))
        .ok()
        .and_then(|t| download_dir(&t, paths::home()))
        .unwrap_or_else(|| paths::home().join("Downloads"))
}

/// XDG_DOWNLOAD_DIR as user-dirs.dirs writes it: "$HOME/Downloads" or an absolute path, in double quotes.
fn download_dir(text: &str, home: &Path) -> Option<PathBuf> {
    let value = text.lines().find_map(|l| l.trim().strip_prefix("XDG_DOWNLOAD_DIR="))?;
    let value = value.trim().strip_prefix('"')?.strip_suffix('"')?;
    let path = match value.strip_prefix("$HOME") {
        Some(rest) => home.join(rest.trim_start_matches('/')),
        None => PathBuf::from(value),
    };
    path.is_absolute().then_some(path)
}

/// `name`, or with " (n)" before its extension as Tailscale numbers a name that is taken: "a.tar.gz" → "a (1).tar.gz".
fn numbered(name: &str, n: u32) -> String {
    static EXTENSION: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\.[a-zA-Z0-9]{0,3}[a-zA-Z][a-zA-Z0-9]{0,3})*$").unwrap());
    if n == 0 {
        return name.into();
    }
    // A leading dot is part of the name, never an extension.
    let skip = usize::from(name.starts_with('.'));
    let at = EXTENSION.find(&name[skip..]).map_or(name.len(), |m| m.start() + skip);
    format!("{} ({n}){}", &name[..at], &name[at..])
}

/// Why a received file isn't in Downloads: the engine broke off (it restarted with a reload, say), which its next
/// update tries again, or this computer can't take it, which the user is told.
#[derive(Debug, PartialEq)]
pub enum Unsaved {
    Engine(String),
    Here(String),
}

fn here(e: std::io::Error) -> Unsaved {
    Unsaved::Here(e.to_string())
}

/// A received file's hidden copy while it is written, removed however the save ends: also when the connection's watcher
/// is aborted mid-file (a disconnect, a pause, a reload). Once linked to its own name, only the hidden name goes.
struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Writes a file the engine received into `dir`, under `name` or, if that is taken, the first free "name (n)": never
/// over a file the user has. The engine's first chunk says the size; the rest is the content. A file that doesn't
/// arrive whole, or a save cut off, leaves nothing behind.
pub async fn save<S>(chunks: S, dir: &Path, name: &str) -> Result<PathBuf, Unsaved>
where
    S: Stream<Item = Result<DownloadTaildropFileChunk, Status>> + Unpin,
{
    if !valid_name(name) {
        return Err(Unsaved::Here("Its name isn't a file name".into()));
    }
    tokio::fs::create_dir_all(dir).await.map_err(here)?;
    // Written under a hidden name of its own, then linked to the free name at once: no half file ever shows. Made and
    // guarded with no await in between, so no abort comes between the two.
    let path = dir.join(format!(".unbraid-{:08x}.part", rand::random::<u32>()));
    let f = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(here)?;
    let temp = Temp(path);
    write(chunks, tokio::fs::File::from_std(f)).await?;
    place(&temp.0, dir, name)
}

async fn write<S>(mut chunks: S, mut f: tokio::fs::File) -> Result<(), Unsaved>
where
    S: Stream<Item = Result<DownloadTaildropFileChunk, Status>> + Unpin,
{
    let (mut size, mut written) = (None, 0u64);
    while let Some(c) = chunks.next().await {
        let c = c.map_err(|e| Unsaved::Engine(told(&e)))?;
        size.get_or_insert(c.size);
        f.write_all(&c.data).await.map_err(here)?;
        written += c.data.len() as u64;
    }
    f.sync_all().await.map_err(here)?;
    if size != Some(written as i64) {
        return Err(Unsaved::Engine("It didn't arrive whole".into()));
    }
    Ok(())
}

/// Links `temp` to the first free name in `dir`.
fn place(temp: &Path, dir: &Path, name: &str) -> Result<PathBuf, Unsaved> {
    for n in 0..1000 {
        let to = dir.join(numbered(name, n));
        match std::fs::hard_link(temp, &to) {
            Ok(()) => return Ok(to),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            // shortcut: a folder without hard links (FAT, some network shares) gets a rename, which could replace a file
            // made in between; upgrade to renameat2(RENAME_NOREPLACE) if that matters.
            Err(_) if !to.exists() => return std::fs::rename(temp, &to).map(|()| to).map_err(here),
            Err(e) => return Err(here(e)),
        }
    }
    Err(Unsaved::Here("Downloads has too many files of that name".into()))
}

/// While the connection runs (beside its Tailscale status): every file the tailnet sends is saved in Downloads, then
/// deleted from the engine, and the desktop is told. One this computer can't take stays in the engine, and isn't tried
/// again until the next connection.
pub async fn watch_inbox(engine: &'static Engine) {
    let mut failed = HashSet::new();
    loop {
        match engine.taildrop_inbox(TS_TAG).await {
            Ok(mut updates) => loop {
                match updates.message().await {
                    Ok(Some(inbox)) => receive(engine, &inbox.files, &mut failed).await,
                    Ok(None) => break,
                    Err(e) => {
                        log::w(TAG, &format!("inbox: {}", redact::log(&e)));
                        break;
                    }
                }
            },
            Err(e) => log::w(TAG, &format!("inbox: {}", redact::log(&e))),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn receive(engine: &Engine, files: &[TaildropFile], failed: &mut HashSet<String>) {
    for f in files {
        if failed.contains(&f.name) {
            continue;
        }
        let from = if f.sender_name.is_empty() { String::new() } else { format!(" from {}", f.sender_name) };
        let saved = match engine.taildrop_file(TS_TAG, &f.name).await {
            Ok(chunks) => save(chunks, &downloads(), &f.name).await,
            Err(e) => Err(Unsaved::Engine(told(&e))),
        };
        match saved {
            Ok(path) => {
                // Not deleted: it would be saved again with the next update.
                if let Err(e) = engine.delete_taildrop_file(TS_TAG, &f.name).await {
                    log::w(TAG, &format!("delete: {}", redact::log(&e)));
                    failed.insert(f.name.clone());
                }
                let shown = path.file_name().unwrap_or_default().to_string_lossy();
                notify("File received", &format!("{shown}{from} is in Downloads"));
            }
            Err(Unsaved::Engine(e)) => log::w(TAG, &format!("save, tried again with the next update: {e}")),
            Err(Unsaved::Here(e)) => {
                log::w(TAG, &format!("save: {e}"));
                failed.insert(f.name.clone());
                notify("A file couldn't be saved", &format!("{}{from}: {e}", f.name));
            }
        }
    }
}

fn notify(title: &str, text: &str) {
    // Unit tests never reach the desktop.
    if !cfg!(test) {
        desktop::notify(title, text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names are one file's, as the engine takes them: no path, no folder of its own, none of its working names.
    #[test]
    fn file_names() {
        let (longest, over) = ("x".repeat(255), "x".repeat(256));
        for ok in ["photo.jpg", ".bashrc", "a b (1).tar.gz", "ñandú.png", longest.as_str()] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "../x", "/etc/passwd", "nul\0", "x.partial", "x.deleted", over.as_str()] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    /// A taken name is numbered before its extension, as Tailscale does; a leading dot stays the name's.
    #[test]
    fn numbering() {
        assert_eq!("photo.jpg", numbered("photo.jpg", 0));
        assert_eq!("photo (1).jpg", numbered("photo.jpg", 1));
        assert_eq!("backup (2).tar.gz", numbered("backup.tar.gz", 2));
        assert_eq!("README (1)", numbered("README", 1));
        assert_eq!(".bashrc (1)", numbered(".bashrc", 1));
        assert_eq!("report v2 (3).pdf", numbered("report v2.pdf", 3));
        assert_eq!("ñandú (1).png", numbered("ñandú.png", 1));
    }

    /// Downloads as user-dirs.dirs names it: under the home folder or absolute; anything else is no answer.
    #[test]
    fn downloads_folder() {
        let home = Path::new("/home/u");
        let dirs = "# written by xdg-user-dirs-update\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/Descargas\"\n";
        assert_eq!(Some(PathBuf::from("/home/u/Descargas")), download_dir(dirs, home));
        assert_eq!(Some(PathBuf::from("/data/dl")), download_dir("XDG_DOWNLOAD_DIR=\"/data/dl\"", home));
        assert_eq!(None, download_dir("XDG_DOWNLOAD_DIR=\"relative\"", home));
        assert_eq!(None, download_dir("XDG_DOWNLOAD_DIR=$HOME/x", home));
        assert_eq!(None, download_dir("XDG_DESKTOP_DIR=\"$HOME/Desktop\"", home));
    }

    fn chunk(size: i64, data: &[u8]) -> Result<DownloadTaildropFileChunk, Status> {
        Ok(DownloadTaildropFileChunk { size, data: data.to_vec() })
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    /// A received file is saved whole under a free name, never over the user's own; a short or failed one leaves
    /// nothing, and a name that is a path is refused before anything is written.
    #[tokio::test]
    async fn saving() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Downloads");
        let got = save(tokio_stream::iter(vec![chunk(5, b""), chunk(0, b"hel"), chunk(0, b"lo")]), &dir, "a.txt").await;
        assert_eq!(Ok(dir.join("a.txt")), got);
        assert_eq!("hello", std::fs::read_to_string(dir.join("a.txt")).unwrap());
        let again = save(tokio_stream::iter(vec![chunk(2, b""), chunk(0, b"hi")]), &dir, "a.txt").await;
        assert_eq!(Ok(dir.join("a (1).txt")), again);
        assert_eq!("hello", std::fs::read_to_string(dir.join("a.txt")).unwrap());

        // The engine breaking off is tried again; what this computer can't take is said.
        let short = save(tokio_stream::iter(vec![chunk(9, b""), chunk(0, b"abc")]), &dir, "b.txt").await;
        assert_eq!(Err(Unsaved::Engine("It didn't arrive whole".into())), short);
        let cut =
            save(tokio_stream::iter(vec![chunk(9, b"abc"), Err(Status::unavailable("gone"))]), &dir, "c.txt").await;
        assert_eq!(Err(Unsaved::Engine("Gone".into())), cut);
        let bad = save(tokio_stream::iter(vec![]), &dir, "../x").await;
        assert_eq!(Err(Unsaved::Here("Its name isn't a file name".into())), bad);
        std::fs::write(tmp.path().join("file"), b"").unwrap();
        let blocked = save(tokio_stream::iter(vec![chunk(1, b"x")]), &tmp.path().join("file"), "d.txt").await;
        assert!(matches!(blocked, Err(Unsaved::Here(_))), "{blocked:?}");
        assert_eq!(vec!["a (1).txt", "a.txt"], files(&dir));
        assert!(!tmp.path().join("x").exists());
    }

    /// A save cut off mid-file, as the connection's watcher is when it disconnects, pauses or reloads, leaves nothing in
    /// Downloads.
    #[tokio::test]
    async fn aborted_save_leaves_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Downloads");
        let chunks = tokio_stream::iter(vec![chunk(10, b"abc")]).chain(tokio_stream::pending());
        let d = dir.clone();
        let saving = tokio::spawn(async move { save(chunks, &d, "a.txt").await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(1, files(&dir).len(), "the hidden file is being written");
        saving.abort();
        assert!(saving.await.unwrap_err().is_cancelled());
        assert!(files(&dir).is_empty(), "{:?}", files(&dir));
    }

    /// What a send streams: the start with every file's name and size, then each file in chunks and its end.
    #[tokio::test]
    async fn send_stream() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = (tmp.path().join("a.bin"), tmp.path().join("b.txt"));
        std::fs::write(&a, vec![7u8; CHUNK + 10]).unwrap();
        std::fs::write(&b, b"hi").unwrap();
        let start = TaildropSendStart { endpoint_tag: TS_TAG.into(), peer_stable_id: "n1".into(), files: vec![] };
        let failed = Arc::new(Mutex::new(None));
        let sent: Vec<_> = messages(start.clone(), vec![a, b], failed.clone()).collect().await;
        let kinds: Vec<String> = sent
            .iter()
            .map(|m| match m.message.as_ref().unwrap() {
                Out::Start(s) => format!("start {}", s.peer_stable_id),
                Out::Chunk(c) => format!("chunk {}", c.data.len()),
                Out::FileDone(_) => "done".into(),
            })
            .collect();
        assert_eq!(vec!["start n1", &format!("chunk {CHUNK}"), "chunk 10", "done", "chunk 2", "done"], kinds);
        assert_eq!(None, *failed.lock().unwrap());

        // A file gone before it is read ends the stream, with the reason kept.
        let gone: Vec<_> = messages(start, vec![tmp.path().join("gone.txt")], failed.clone()).collect().await;
        assert_eq!(1, gone.len());
        assert_eq!(Some("gone.txt couldn't be read".into()), *failed.lock().unwrap());
    }

    /// Progress counts the files the device has whole, and what it has of the one being sent.
    #[test]
    fn progress() {
        assert_eq!(0, sent(&[10, 20], 0, 0));
        assert_eq!(7, sent(&[10, 20], 0, 7));
        assert_eq!(15, sent(&[10, 20], 1, 5));
        assert_eq!(30, sent(&[10, 20], 1, 20));
        assert_eq!(
            "Peer is not a permitted file target",
            told(&Status::unknown("taildrop: peer is not a permitted file target"))
        );
    }
}
