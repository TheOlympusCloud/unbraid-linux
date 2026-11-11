//! Desktop apps: the entries a launcher lists, resolved to the programs they run, and how the engine knows them.
//! The installed apps come from their desktop entries (XDG), and the engine knows each one's processes. A program
//! without an entry (something seen connecting, a command-line tool) is routed by its own path, which is then its key.

use crate::APP;
use crate::paths::{self, env};
use indexmap::{IndexMap, IndexSet};
use regex::{Captures, Regex};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How the engine knows a Linux app by its process: exact programs, folders it runs from (ending in '/'), program names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Matchers {
    pub paths: Vec<String>,
    pub dirs: Vec<String>,
    pub names: Vec<String>,
}

impl Matchers {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.dirs.is_empty() && self.names.is_empty()
    }
}

/// An app the Apps page lists: `key` is what the setup routes (a desktop entry's id, or a program's path). Apps the
/// engine can't tell apart share one `group` of keys and their matchers (`share_routes`); `argc` counts its Exec line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesktopApp {
    pub key: String,
    pub label: String,
    pub system: bool,
    pub icon: Option<PathBuf>,
    pub matchers: Matchers,
    pub group: Vec<String>,
    pub argc: usize,
    pub kind: &'static str,
}

/// The last scan's apps, and when it ran (none before the first).
struct Scanned {
    apps: Vec<DesktopApp>,
    at: Option<Instant>,
}

static CACHE: Mutex<Scanned> = Mutex::new(Scanned { apps: Vec::new(), at: None });

fn cache() -> MutexGuard<'static, Scanned> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The app with this key in the last scan.
fn cached(key: &str) -> Option<DesktopApp> {
    cache().apps.iter().find(|a| a.key == key).cloned()
}

/// Data folders, most important first: XDG_DATA_HOME, XDG_DATA_DIRS, then Flatpak and Snap exports some sessions leave out.
pub fn data_dirs() -> Vec<PathBuf> {
    let home = paths::home().to_string_lossy();
    let mut all = vec![env("XDG_DATA_HOME").unwrap_or_else(|| format!("{home}/.local/share"))];
    all.extend(env("XDG_DATA_DIRS").unwrap_or_else(|| "/usr/local/share:/usr/share".into()).split(':').map(String::from));
    all.extend([format!("{home}/.local/share/flatpak/exports/share"), "/var/lib/flatpak/exports/share".into(), "/var/lib/snapd/desktop".into()]);
    all.into_iter().filter(|d| !d.is_empty()).collect::<IndexSet<_>>().into_iter().map(PathBuf::from).collect()
}

pub fn search_path() -> Vec<PathBuf> {
    let path = env("PATH").unwrap_or_default();
    path.split(':').chain(["/usr/local/bin", "/usr/bin", "/bin", "/usr/games", "/snap/bin"]).filter(|d| !d.is_empty()).collect::<IndexSet<_>>().into_iter().map(PathBuf::from).collect()
}

pub fn flatpak_installs() -> Vec<PathBuf> {
    vec![paths::home().join(".local/share/flatpak"), PathBuf::from("/var/lib/flatpak")]
}

/// Every app with a desktop entry, read afresh from the usual folders.
pub fn scan() -> Vec<DesktopApp> {
    scan_in(&data_dirs(), &search_path(), &flatpak_installs())
}

/// Every app with a desktop entry in `dirs`, read afresh. Entries earlier in `dirs` hide later ones with the same id.
pub fn scan_in(dirs: &[PathBuf], path: &[PathBuf], installs: &[PathBuf]) -> Vec<DesktopApp> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for d in dirs {
        let root = d.join("applications");
        if !root.is_dir() {
            continue;
        }
        let mut files = desktop_files(&root);
        files.sort_by(|a, b| a.as_os_str().cmp(b.as_os_str()));
        for f in files {
            let relative = f.strip_prefix(&root).unwrap_or(&f).to_string_lossy().replace('/', "-");
            let id = relative.strip_suffix(".desktop").unwrap_or(&relative);
            if !seen.insert(id.to_string()) {
                continue;
            }
            // One that can't be read is left out, as one that isn't an app.
            let Ok(bytes) = fs::read(&f) else { continue };
            out.extend(entry(id, &String::from_utf8_lossy(&bytes), dirs, path, installs));
        }
    }
    let mut apps = share_routes(out);
    apps.sort_by_cached_key(|a| a.label.to_lowercase());
    *cache() = Scanned { apps: apps.clone(), at: Some(Instant::now()) };
    apps
}

/// The .desktop files under `root`, in its subfolders too.
fn desktop_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for f in list(&d) {
            if f.is_dir() {
                dirs.push(f);
            } else if f.is_file() && name(&f).ends_with(".desktop") {
                out.push(f);
            }
        }
    }
    out
}

/// Apps the engine can't tell apart (LibreOffice's Writer and Calc, a browser and its web apps, two Firefoxes) are one
/// app to it, so they share one route: each gets all their matchers and the group's keys, plainest launcher first (not a
/// system one, the shortest Exec line). The first of them with a route leads in a setup ([`matchers`]); with none, any of
/// them can take one. Otherwise whichever rule came first would route them all, whatever their rows said.
pub(crate) fn share_routes(apps: Vec<DesktopApp>) -> Vec<DesktopApp> {
    let mut left: Vec<DesktopApp> = apps.iter().filter(|a| !a.matchers.is_empty()).cloned().collect();
    let mut out: IndexMap<String, DesktopApp> = apps.into_iter().map(|a| (a.key.clone(), a)).collect();
    while !left.is_empty() {
        let mut group = vec![left.remove(0)];
        let mut i = 0;
        while i < group.len() {
            let (joined, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut left).into_iter().partition(|a| overlap(&group[i].matchers, &a.matchers));
            left = rest;
            group.extend(joined);
            i += 1;
        }
        if group.len() == 1 {
            continue;
        }
        let mut order: Vec<&DesktopApp> = group.iter().collect();
        order.sort_by_cached_key(|a| (a.system, a.argc, a.label.to_lowercase(), a.key.clone()));
        let keys: Vec<String> = order.iter().map(|a| a.key.clone()).collect();
        let distinct = |f: fn(&Matchers) -> &Vec<String>| group.iter().flat_map(|a| f(&a.matchers)).cloned().collect::<IndexSet<_>>().into_iter().collect();
        let all = Matchers { paths: distinct(|m| &m.paths), dirs: distinct(|m| &m.dirs), names: distinct(|m| &m.names) };
        for a in group {
            out.insert(a.key.clone(), DesktopApp { matchers: all.clone(), group: keys.clone(), ..a });
        }
    }
    out.into_values().collect()
}

/// Whether one process could match both `a` and `b`. A name is a program file's name; one in a matched folder counts too.
fn overlap(a: &Matchers, b: &Matchers) -> bool {
    let in_dirs = |n: &str, m: &Matchers| m.dirs.iter().any(|d| Path::new(d).join(n).is_file() || Path::new(d).join("bin").join(n).is_file());
    a.paths.iter().any(|p| matches(b, p))
        || b.paths.iter().any(|p| matches(a, p))
        || a.dirs.iter().any(|d| b.dirs.iter().any(|e| e.starts_with(d.as_str()) || d.starts_with(e.as_str())))
        || a.names.iter().any(|n| b.names.contains(n) || in_dirs(n, b))
        || b.names.iter().any(|n| in_dirs(n, a))
}

/// How the engine knows `key`, routed in a setup whose routed keys are `routed`: a program path is itself, an entry's
/// processes come from its Exec line. Of apps that run as one program only the first routed one is matched, so the
/// group takes the route the user set, whichever entries come and go. A program an app runs (added before that app was
/// installed) matches the app while none of its group is routed.
pub fn matchers(key: &str, routed: &[&str]) -> Matchers {
    if key.starts_with('/') {
        // Before any scan (a login start), the apps aren't known yet: read them, so the app's folder counts too.
        let unscanned = cache().at.is_none();
        if unscanned {
            scan();
        }
        let owner = cache().apps.iter().find(|a| matches(&a.matchers, key)).cloned();
        let Some(app) = owner else { return Matchers { paths: vec![key.into()], ..Matchers::default() } };
        let group = if app.group.is_empty() { std::slice::from_ref(&app.key) } else { &app.group[..] };
        return if group.iter().all(|k| !routed.contains(&k.as_str())) { app.matchers } else { Matchers::default() };
    }
    // An app installed since the last scan is found by reading the entries again, at most every 10 s (an uninstalled one never is).
    let fresh = cache().at.is_some_and(|at| at.elapsed() < Duration::from_secs(10));
    let Some(app) = cached(key).or_else(|| if fresh { None } else { scan().into_iter().find(|a| a.key == key) }) else { return Matchers::default() };
    if app.group.is_empty() || app.group.iter().find(|k| routed.contains(&k.as_str())).is_some_and(|k| k == key) { app.matchers } else { Matchers::default() }
}

/// The program `key` runs as, to show or copy: itself for a program, an entry's first program file.
pub fn program_of(key: &str) -> Option<String> {
    if key.starts_with('/') { Some(key.into()) } else { cached(key)?.matchers.paths.into_iter().next() }
}

/// `key`'s icon file, from the last scan.
pub fn icon_file(key: &str) -> Option<PathBuf> {
    cached(key)?.icon
}

/// The app `process_path` belongs to, for statistics: one of `routed` first, then any entry (its group's first), else the path.
pub fn key_of(process_path: &str, routed: &[&str]) -> String {
    if process_path.is_empty() {
        return "?".into();
    }
    if let Some(k) = routed.iter().find(|k| matches(&matchers(k, routed), process_path)) {
        return k.to_string();
    }
    let owner = cache().apps.iter().find(|a| matches(&a.matchers, process_path)).map(|a| a.group.first().unwrap_or(&a.key).clone());
    owner.unwrap_or_else(|| process_path.into())
}

/// What the engine does with `m` ([`crate::linux_pass`]): an exact path, a folder prefix or a program name.
pub fn matches(m: &Matchers, path: &str) -> bool {
    m.paths.iter().any(|p| p == path) || m.dirs.iter().any(|d| path.starts_with(d.as_str())) || m.names.contains(&name(Path::new(path)))
}

/// A desktop entry's app, or none for one that isn't a launchable application.
pub(crate) fn entry(id: &str, text: &str, dirs: &[PathBuf], path: &[PathBuf], installs: &[PathBuf]) -> Option<DesktopApp> {
    let e = parse(text);
    let get = |k: &str| e.get(k).map(String::as_str);
    if get("Type") != Some("Application") || get("Hidden") == Some("true") || id == "unbraid" {
        return None;
    }
    let exec = exec(get("Exec")?);
    if exec.is_empty() {
        return None;
    }
    if let Some(t) = get("TryExec") {
        which(t, path)?;
    }
    let flatpak = get("X-Flatpak").map(String::from).or_else(|| {
        if name(Path::new(&exec[0])) != "flatpak" {
            return None;
        }
        let from = exec.iter().position(|a| a == "run").map_or(0, |i| i + 1);
        exec[from..].iter().find(|a| !a.starts_with('-')).cloned()
    });
    let m = match &flatpak {
        None => resolve(&exec, path),
        Some(id) => Matchers { names: flatpak_names(id, exec.iter().find_map(|a| a.strip_prefix("--command=")), installs), ..Matchers::default() },
    };
    let kind = if flatpak.is_some() {
        "Flatpak"
    } else if m.dirs.iter().any(|d| d.starts_with("/snap/")) {
        "Snap"
    } else {
        "App"
    };
    let icon = get("Icon").and_then(|i| icon(i, dirs));
    Some(DesktopApp { key: id.into(), label: get("Name").unwrap_or(id).into(), system: get("NoDisplay") == Some("true"), icon, matchers: m, group: vec![], argc: exec.len(), kind })
}

/// The [Desktop Entry] group's keys (unlocalized: the app is English only).
pub(crate) fn parse(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut in_entry = false;
    for raw in text.split(['\n', '\r']) {
        let line = raw.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.starts_with('#') {
            continue;
        }
        let Some(i) = line.find('=').filter(|&i| i > 0) else { continue };
        let k = line[..i].trim();
        if !k.contains('[') {
            out.entry(k.to_string()).or_insert_with(|| line[i + 1..].trim().to_string());
        }
    }
    out
}

static FIELD_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new("^%[a-zA-Z]$").unwrap());

/// An Exec line's arguments, as the desktop entry spec quotes them, without field codes (%f, %U…).
pub(crate) fn exec(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut any) = (false, false);
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => (quoted, any) = (!quoted, true),
            '\\' if quoted => cur.push(chars.next().unwrap_or('\\')),
            ' ' if !quoted => {
                if !cur.is_empty() || any {
                    args.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() || any {
        args.push(cur);
    }
    args.into_iter().filter(|a| !FIELD_CODE.is_match(a)).map(|a| a.replace("%%", "%")).collect()
}

/// The processes `argv` starts, as far as the engine can tell them apart: it knows a process by its program file (its
/// /proc exe), which for a script is its interpreter, for a Windows program Wine and for an AppImage a program in a
/// mount of its own. Those give no matcher, so the app is shown following the default route rather than on one it
/// would never take, or one that would move every other program they run.
pub(crate) fn resolve(argv: &[String], path: &[PathBuf]) -> Matchers {
    let Some(prog) = argv.first() else { return Matchers::default() };
    // A snap runs from /snap/<name>/<revision>/…, whichever revision is installed.
    if prog.starts_with("/snap/bin/") {
        return snap(&name(Path::new(prog)));
    }
    if prog == "snap"
        && argv.get(1).is_some_and(|a| a == "run")
        && let Some(s) = argv.get(2)
    {
        return snap(s);
    }
    let found = which(prog, path);
    let real = found.as_ref().and_then(|f| fs::canonicalize(f).ok());
    if wrapper(Path::new(prog)) || real.as_deref().is_some_and(wrapper) {
        // firejail's links (firecfg): /usr/local/bin/firefox runs the next firefox on the PATH, in its sandbox.
        if let Some(found) = found.as_ref().filter(|f| !wrapper(f)) {
            let after: Vec<PathBuf> = path.iter().skip_while(|d| Some(d.as_path()) != found.parent()).skip(1).cloned().collect();
            return resolve(&[&[name(found)][..], &argv[1..]].concat(), &after);
        }
        // "env A=1 prog", "nice -n 5 prog", "prime-run prog": the program they start; none for "gtk-launch app.desktop".
        let at = (1..argv.len()).find(|&i| {
            let a = &argv[i];
            a.starts_with("/snap/bin/") || !a.starts_with('-') && !a.contains('=') && which(a, path).is_some()
        });
        return at.map_or_else(Matchers::default, |i| resolve(&argv[i..], path));
    }
    let (Some(found), Some(real)) = (found, real) else { return Matchers::default() };
    if runtime(&found) || runtime(&real) {
        return Matchers::default();
    }
    if elf(&real) {
        return program(&real);
    }
    // A launcher script: the programs it starts by path, and the folder it is installed in when its programs live there.
    let Some(text) = script(&real) else { return Matchers::default() };
    let dir = install_dir(real.parent());
    // One whose own work runs on an interpreter other apps share (#!/usr/bin/python3, "exec java -jar app.jar") is that
    // interpreter's traffic, whatever else its folder holds.
    if runs_shared(&text, dir.as_deref()) {
        return Matchers::default();
    }
    let targets: IndexSet<PathBuf> = script_targets(&text)
        .into_iter()
        .filter(|t| !runtime(t) && !wrapper(t))
        .filter_map(|t| fs::canonicalize(t).ok())
        .filter(|t| program(t) != Matchers::default())
        .collect();
    let own = dir.filter(|d| holds_programs(Path::new(d)));
    Matchers {
        paths: targets.iter().map(|t| t.to_string_lossy().into_owned()).collect(),
        dirs: targets.iter().filter_map(|t| install_dir(t.parent())).chain(own).collect::<IndexSet<_>>().into_iter().collect(),
        names: vec![],
    }
}

/// A snap's folder, /snap/<name>/, for a command named `command` (or `command.app`).
fn snap(command: &str) -> Matchers {
    let snap = command.split_once('.').map_or(command, |(s, _)| s);
    Matchers { dirs: vec![format!("/snap/{snap}/")], ..Matchers::default() }
}

/// A program file as the engine knows it: none for an interpreter or a wrapper (every program it runs would match) or an AppImage.
fn program(f: &Path) -> Matchers {
    if runtime(f) || wrapper(f) || app_image(f) {
        return Matchers::default();
    }
    Matchers { paths: vec![f.to_string_lossy().into_owned()], dirs: install_dir(f.parent()).into_iter().collect(), names: vec![] }
}

/// Why the engine couldn't tell `f`'s traffic apart from other programs', or none for a program file it can.
pub fn unroutable(f: &Path) -> Option<String> {
    let n = name(f);
    let Some(real) = fs::canonicalize(f).ok().filter(|r| r.is_file()) else { return Some(format!("{n} isn't a program this computer can run.")) };
    if app_image(&real) {
        Some(format!("{n} is an AppImage: its programs run from a new folder each time, so {APP} can't recognize them."))
    } else if head(&real, 2) == b"MZ" {
        Some(format!("{n} is a Windows program: Wine runs it, as it runs every other one, so {APP} can't tell them apart."))
    } else if !can_execute(&real) {
        Some(format!("{n} isn't a program this computer can run."))
    } else if !elf(&real) && script(&real).is_some() {
        Some(format!("{n} is a script: its traffic comes from the interpreter that runs it, which other programs share."))
    } else if !elf(&real) {
        Some(format!("{n} isn't a Linux program: what runs it runs other programs too, so {APP} can't tell them apart."))
    } else if runtime(f) || runtime(&real) {
        Some(format!("{n} runs other programs too: routing it would move them all."))
    } else if wrapper(f) || wrapper(&real) {
        Some(format!("{n} only starts other programs: add the program it starts instead."))
    } else {
        None
    }
}

/// A whole-name pattern.
fn whole(pattern: &str) -> Regex {
    Regex::new(&format!("^(?:{pattern})$")).unwrap()
}

/// Interpreters and runtimes, whose processes are every program they run: scripts, Windows programs (Wine, whose loader
/// is the process on Arch), .NET and Mono programs, Electron apps on a shared Electron, guests of qemu, programs started
/// through the dynamic loader. A version may follow the name (python3.13, guile-3.0, electron37).
static RUNTIMES: LazyLock<Regex> = LazyLock::new(|| {
    whole(
        r"(python|pypy|perl|ruby|lua|luajit|php|tclsh|wish|node|nodejs|deno|bun|java|pwsh|gjs|gjs-console|cjs|cjs-console|R|Rscript|julia|guile|wine|wine64|wine-preloader|wine64-preloader|mono|mono-sgen|dotnet|electron|qemu-[a-z0-9_-]+|ld-linux[a-z0-9_-]*\.so|ld-musl-[a-z0-9_]+\.so)[0-9.-]*",
    )
});

/// Shells and awk: interpreters too, but also the tools launcher scripts are written in, so only their own files count.
static SHELLS: LazyLock<Regex> = LazyLock::new(|| whole("(sh|bash|dash|zsh|fish|ksh|mksh|tcsh|csh|busybox|gawk|mawk|awk)[0-9.-]*"));

/// Programs that start another one and carry none of its traffic: the environment, priority, GPU, game, sandbox and
/// proxy wrappers, and launchers that hand the start to the desktop (gtk-launch, kioclient, xdg-open).
static WRAPPERS: LazyLock<Regex> = LazyLock::new(|| {
    whole(
        "env|nice|ionice|taskset|chrt|nohup|setsid|stdbuf|timeout|sudo|pkexec|doas|firejail|bwrap|flatpak|flatpak-spawn|zypak-wrapper|\
         systemd-run|systemd-inhibit|dbus-run-session|dbus-launch|xvfb-run|prime-run|optirun|primusrun|pvkrun|gamemoderun|mangohud|obs-gamecapture|gamescope|\
         strace|ltrace|torsocks|proxychains4?|unshare|kstart[56]?|gtk-launch|kioclient[56]?|kde-open[56]?|gio|gapplication|dex|exo-open|xdg-open|\
         toolbox|distrobox-enter|podman|docker",
    )
});

fn runtime(f: &Path) -> bool {
    let n = name(f);
    RUNTIMES.is_match(&n) || SHELLS.is_match(&n)
}

fn wrapper(f: &Path) -> bool {
    WRAPPERS.is_match(&name(f))
}

static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t\n\x0B\x0C\r]+").unwrap());
static ASSIGN: LazyLock<Regex> = LazyLock::new(|| whole("[A-Za-z_][A-Za-z0-9_]*=.*"));
static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&&|\|\||[;|&]").unwrap());
const SKIP: [&str; 7] = ["then", "do", "else", "exec", "env", "nohup", "command"];

/// Whether a launcher script's own work runs on an interpreter other apps share: its shebang's, or one it starts by
/// name, or by a path outside `dir`, its own folder (an app's bundled Java is its own). Shells and awk don't count.
fn runs_shared(text: &str, dir: Option<&str>) -> bool {
    let lines: Vec<&str> = text.split(['\n', '\r']).collect();
    let first = lines[0];
    let bang: Vec<&str> = WS.split(first.strip_prefix("#!").unwrap_or(first).trim()).collect();
    let skip = usize::from(name(Path::new(bang[0])) == "env");
    if bang.iter().skip(skip).find(|w| !w.starts_with('-')).is_some_and(|w| RUNTIMES.is_match(&name(Path::new(w)))) {
        return true;
    }
    lines[1..].iter().filter(|l| !l.trim_start().starts_with('#')).flat_map(|l| SEPARATORS.split(l)).any(|cmd| {
        let Some(w) = WS.split(cmd.trim()).find(|w| !SKIP.contains(w) && !ASSIGN.is_match(w)) else { return false };
        let w = w.trim_matches(['"', '\'']);
        RUNTIMES.is_match(&name(Path::new(w))) && (!w.contains('/') || w.starts_with('/') && dir.is_none_or(|d| !w.starts_with(d)))
    })
}

/// An AppImage (types 1 and 2): an ELF file marked "AI" and its type at byte 8.
fn app_image(f: &Path) -> bool {
    let h = head(f, 11);
    h.len() == 11 && &h[8..10] == b"AI" && (1..=2).contains(&h[10])
}

/// A folder with an app's own programs in it (or in its bin/), which a launcher script there starts.
fn holds_programs(d: &Path) -> bool {
    list(d).into_iter().chain(list(&d.join("bin"))).take(500).any(|f| {
        f.is_file() && can_execute(&f) && !runtime(&f) && !wrapper(&f) && elf(&f) && fs::canonicalize(&f).is_ok_and(|c| program(&c) != Matchers::default())
    })
}

/// `prog` as the shell would find it on `path`.
pub(crate) fn which(prog: &str, path: &[PathBuf]) -> Option<PathBuf> {
    if prog.contains('/') {
        Some(file(prog)).filter(|f| f.is_file() && can_execute(f))
    } else {
        path.iter().map(|d| d.join(prog)).find(|f| f.is_file() && can_execute(f))
    }
}

fn elf(f: &Path) -> bool {
    head(f, 4) == b"\x7fELF"
}

/// The first `n` bytes of `f` (fewer if it is shorter), none if it can't be read.
fn head(f: &Path, n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if fs::File::open(f).and_then(|h| h.take(n).read_to_end(&mut out)).is_err() {
        out.clear();
    }
    out
}

static ASSIGNMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?m)^[ \t\n\x0B\x0C\r]*(?:export[ \t\n\x0B\x0C\r]+)?([A-Za-z_][A-Za-z0-9_]*)=["']?([A-Za-z0-9._+/${}-]*)["']?[ \t\n\x0B\x0C\r]*$"#).unwrap());
static VARIABLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").unwrap());

/// A script's text (its first 64 KB), or none for a file that isn't one. Its plain assignments are put in where they
/// are used (APPNAME=chromium, LIBDIR=/usr/lib/$APPNAME, then "exec $LIBDIR/$APPNAME"), the first of each name.
fn script(f: &Path) -> Option<String> {
    let text = String::from_utf8_lossy(&head(f, 65_536)).into_owned();
    if !text.starts_with("#!") {
        return None;
    }
    let mut vars = HashMap::new();
    for c in ASSIGNMENT.captures_iter(&text) {
        vars.entry(c[1].to_string()).or_insert_with(|| c[2].to_string());
    }
    let mut out = text;
    for _ in 0..3 {
        out = VARIABLE.replace_all(&out, |m: &Captures| vars.get(&m[1]).cloned().unwrap_or_else(|| m[0].to_string())).into_owned();
    }
    Some(out)
}

static ABSOLUTE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/[A-Za-z0-9._+\-/]+").unwrap());

/// Programs a launcher script names by absolute path, outside the shared system folders (where /bin/sh and friends live).
fn script_targets(text: &str) -> Vec<PathBuf> {
    ABSOLUTE
        .find_iter(text)
        .map(|m| file(m.as_str()))
        .collect::<IndexSet<_>>()
        .into_iter()
        .filter(|f| f.is_file() && can_execute(f) && install_dir(f.parent()).is_some() && elf(f))
        .collect()
}

/// The folder an app is installed in, so its helper programs follow it too ("…/bin" counts as its parent); none for
/// folders many programs share, where only exact paths are safe.
pub(crate) fn install_dir(d: Option<&Path>) -> Option<String> {
    let d = file(&d?.to_string_lossy());
    let dir = match d.parent() {
        Some(parent) if name(&d) == "bin" && !shared(Some(parent)) => parent.to_path_buf(),
        _ => d,
    };
    (!shared(Some(&dir))).then(|| format!("{}/", dir.to_string_lossy().trim_end_matches('/')))
}

const SHARED: [&str; 26] = [
    "/", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/usr/bin", "/usr/sbin", "/usr/games", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec", "/usr/share", "/usr/local", "/usr/local/bin",
    "/usr/local/sbin", "/usr/local/games", "/usr/local/lib", "/usr/local/share", "/opt", "/snap", "/snap/bin", "/var/lib/flatpak/exports/bin", "/tmp", "/var/tmp",
];
const HOME_SHARED: [&str; 7] = ["bin", ".local", ".local/bin", ".local/share", "Applications", "Downloads", "Desktop"];
static MULTIARCH: LazyLock<Regex> = LazyLock::new(|| whole("/usr/lib(32|64)?/[a-z0-9_]+-linux-gnu[a-z0-9_]*"));

fn shared(d: Option<&Path>) -> bool {
    let Some(d) = d else { return true };
    let text = d.to_string_lossy();
    let p = match text.trim_end_matches('/') {
        "" => "/",
        p => p,
    };
    let home = paths::home().to_string_lossy();
    SHARED.contains(&p)
        || p == home
        || p.strip_prefix(&*format!("{home}/")).is_some_and(|r| HOME_SHARED.contains(&r))
        || MULTIARCH.is_match(p)
        || p.matches('/').count() < 2
}

/// A Flatpak's programs as the engine sees their processes, by name (inside its sandbox they run from /app): its command
/// (`command`, else its metadata's), or the programs a launcher script there starts by path (Discord's, Signal's). None
/// for a command on an interpreter, nor for an app whose command isn't known (no guessing from its id).
/// shortcut: matched by name only, so another program of that name matches too; match by app id once the engine can.
fn flatpak_names(app_id: &str, command: Option<&str>, installs: &[PathBuf]) -> Vec<String> {
    let app = installs.iter().map(|i| i.join(format!("app/{app_id}/current/active"))).find(|a| a.join("metadata").is_file());
    let from_metadata = || {
        let text = fs::read_to_string(app.as_ref()?.join("metadata")).ok()?;
        text.split(['\n', '\r']).find_map(|l| l.strip_prefix("command=")).map(|c| c.trim().to_string())
    };
    let Some(cmd) = command.map(String::from).or_else(from_metadata) else { return vec![] };
    let own = vec![name(Path::new(&cmd))].into_iter().filter(|n| !runtime(Path::new(n)) && !wrapper(Path::new(n))).collect();
    let Some(app) = app else { return own };
    let files = app.join("files");
    let host = |p: &str| files.join(file(p.strip_prefix("/app/").unwrap_or(p).trim_start_matches('/')));
    let f = if cmd.starts_with("/app/") { host(&cmd) } else { files.join(format!("bin/{cmd}")) };
    let Some(text) = (f.is_file() && !elf(&f)).then(|| script(&f)).flatten() else { return own };
    // By name, even an interpreter inside /app is every other one of its name.
    if runs_shared(&text, None) {
        return vec![];
    }
    let targets: IndexSet<String> = APP_FILE.find_iter(&text).map(|m| host(m.as_str())).filter(|t| t.is_file() && elf(t) && !runtime(t) && !wrapper(t) && !app_image(t)).map(|t| name(&t)).collect();
    if targets.is_empty() { own } else { targets.into_iter().collect() }
}

static APP_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/app/[A-Za-z0-9._+\-/]+").unwrap());

/// An entry's icon file: an absolute path, else the hicolor theme (the one every app installs into) or pixmaps.
pub(crate) fn icon(icon_name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    if icon_name.starts_with('/') {
        return Some(file(icon_name)).filter(|f| f.is_file());
    }
    let roots: Vec<PathBuf> = std::iter::once(paths::home().join(".icons")).chain(dirs.iter().map(|d| d.join("icons"))).collect();
    for size in ["128x128", "96x96", "64x64", "256x256", "48x48", "scalable", "512x512", "32x32"] {
        for root in &roots {
            for ext in ["png", "svg"] {
                let f = root.join(format!("hicolor/{size}/apps/{icon_name}.{ext}"));
                if f.is_file() {
                    return Some(f);
                }
            }
        }
    }
    dirs.iter().flat_map(|d| ["png", "svg"].map(|ext| d.join("pixmaps").join(format!("{icon_name}.{ext}")))).find(|f| f.is_file())
}

/// A path as given in an entry or a script, its doubled and final '/' dropped (as the files' paths were compared).
fn file(s: &str) -> PathBuf {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !(c == '/' && out.ends_with('/')) {
            out.push(c);
        }
    }
    if out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    PathBuf::from(out)
}

/// The last part of `f`'s path ("" for "/").
fn name(f: &Path) -> String {
    let text = f.to_string_lossy();
    text.trim_end_matches('/').rsplit('/').next().unwrap_or_default().to_string()
}

/// What's in folder `d`, nothing if it can't be read.
fn list(d: &Path) -> Vec<PathBuf> {
    fs::read_dir(d).into_iter().flatten().flatten().map(|e| e.path()).collect()
}

/// Whether this user may run `f`, as the system decides it (access(2)).
fn can_execute(f: &Path) -> bool {
    // SAFETY: c is a valid NUL-terminated path for the call.
    CString::new(f.as_os_str().as_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// The tests that scan share the scan's cache, as the app does: they run one at a time.
    fn one_scan_at_a_time() -> MutexGuard<'static, ()> {
        static SCANS: Mutex<()> = Mutex::new(());
        SCANS.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn executable(f: &Path, bytes: &[u8]) -> PathBuf {
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(f, bytes).unwrap();
        fs::set_permissions(f, fs::Permissions::from_mode(0o755)).unwrap();
        f.to_path_buf()
    }
    fn make_elf(f: &Path) -> PathBuf {
        executable(f, b"\x7fELF\x02\x01")
    }
    /// An AppImage (type 2): an ELF file with "AI" and 2 at byte 8.
    fn make_app_image(f: &Path) -> PathBuf {
        executable(f, b"\x7fELF\x02\x01\x01\x00AI\x02\x00")
    }
    fn make_script(f: &Path, body: &str) -> PathBuf {
        executable(f, format!("#!/bin/sh\n{body}\n").as_bytes())
    }
    fn make_link(f: &Path, to: &Path) -> PathBuf {
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        symlink(to, f).unwrap();
        f.to_path_buf()
    }
    fn desktop(exec: &str, extra: &str) -> String {
        format!("[Desktop Entry]\nType=Application\nName=Thing\nName[de]=Ding\nExec={exec}\n{extra}\n[Desktop Action new]\nExec=other\n")
    }
    /// `entry` with the usual data folders and Flatpak installs.
    fn entry_on(id: &str, text: &str, path: &[PathBuf]) -> Option<DesktopApp> {
        entry(id, text, &data_dirs(), path, &flatpak_installs())
    }
    fn s(f: &Path) -> String {
        f.to_string_lossy().into_owned()
    }
    fn canonical(f: &Path) -> String {
        s(&fs::canonicalize(f).unwrap())
    }
    fn dirs(dirs: &[String]) -> Matchers {
        Matchers { dirs: dirs.to_vec(), ..Matchers::default() }
    }

    #[test]
    fn parses_only_the_main_group_unlocalized() {
        let e = parse(&desktop("thing %U", "Icon=thing\n# Comment=x"));
        assert_eq!(Some("Thing"), e.get("Name").map(String::as_str));
        assert_eq!(Some("thing %U"), e.get("Exec").map(String::as_str));
        assert_eq!(Some("thing"), e.get("Icon").map(String::as_str));
    }

    #[test]
    fn exec_line_as_the_spec_quotes_it() {
        assert_eq!(vec!["/opt/a b/run", "--flag", "x\"y", "100%"], exec(r#""/opt/a b/run" --flag "x\"y" %F 100%% %u"#));
        assert_eq!(vec!["env", "A=1", "prog", ""], exec(r#"env A=1 prog """#));
    }

    /// A program in its own folder: its path, and the folder (its helpers run from there too).
    #[test]
    fn binary_in_its_own_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = make_elf(&tmp.path().join("opt/game/bin/game"));
        let m = entry_on("game", &desktop(&s(&bin), ""), &[]).unwrap().matchers;
        assert_eq!(vec![canonical(&bin)], m.paths);
        assert_eq!(vec![canonical(&tmp.path().join("opt/game")) + "/"], m.dirs); // ".../bin" counts as its parent
    }

    /// A launcher script on the PATH: the program it starts and that program's folder (the script itself runs as its shell).
    #[test]
    fn launcher_script_follows_its_program() {
        let tmp = tempfile::tempdir().unwrap();
        let real = make_elf(&tmp.path().join("lib/firefox/firefox"));
        let bin = tmp.path().join("bin");
        make_script(&bin.join("firefox"), &format!("exec {} \"$@\"", s(&real)));
        let m = entry_on("firefox", &desktop("env MOZ_X=1 firefox %u", ""), &[bin]).unwrap().matchers;
        assert_eq!(vec![canonical(&real)], m.paths);
        assert!(m.dirs.contains(&(canonical(real.parent().unwrap()) + "/")));
        assert!(m.names.is_empty());
    }

    /// Debian's Chromium starts its program through the launcher's own variables: "exec $LIBDIR/$APPNAME".
    #[test]
    fn launcher_variables_are_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let real = make_elf(&tmp.path().join("usr/lib/chromium/chromium"));
        let launcher = make_script(
            &tmp.path().join("usr/bin/chromium"),
            &format!("APPNAME=chromium\nLIBDIR={}/usr/lib/$APPNAME\nexport CHROMIUM_FLAGS=\"\"\nexec $LIBDIR/$APPNAME $CHROMIUM_FLAGS \"$@\"", s(tmp.path())),
        );
        let want = Matchers { paths: vec![canonical(&real)], dirs: vec![canonical(real.parent().unwrap()) + "/"], names: vec![] };
        assert_eq!(want, entry_on("c", &desktop(&format!("{} %U", s(&launcher)), ""), &[]).unwrap().matchers);
    }

    /// The engine knows a process by its program file: a script's is its interpreter, shared with every other script it
    /// runs. Such apps get no matcher, so they show as following the default route, never on one they wouldn't take.
    #[test]
    fn scripts_and_interpreters_match_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        make_link(&bin.join("python3"), &make_elf(&bin.join("python3.13")));
        make_link(&bin.join("sh"), &make_elf(&bin.join("dash")));
        executable(&bin.join("yt-dlp"), b"#!/usr/bin/env python3\nimport yt_dlp\n");
        for (id, exec) in [("a", "python3 /opt/foo/foo.py"), ("b", "sh -c \"exec foo\""), ("c", "yt-dlp %U"), ("d", "env LANG=C python3 -m http.server"), ("e", "missing-program")] {
            assert_eq!(Matchers::default(), entry_on(id, &desktop(exec, ""), std::slice::from_ref(&bin)).unwrap().matchers, "{exec}");
        }
    }

    /// An AppImage's programs run from a mount of their own: no matcher either.
    #[test]
    fn app_images_match_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let app = make_app_image(&tmp.path().join("Applications/Obsidian-1.6.AppImage"));
        assert_eq!(Matchers::default(), entry_on("obsidian", &desktop(&s(&app), ""), &[]).unwrap().matchers);
    }

    /// A launcher script in the app's own folder (Chrome's, VS Code's) keeps that folder, where its programs live.
    #[test]
    fn launcher_keeps_the_folder_its_programs_live_in() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("opt/google/chrome");
        make_elf(&dir.join("chrome"));
        let launcher = make_script(&dir.join("google-chrome"), "HERE=\"${0%/*}\"\nexec -a \"$0\" \"$HERE/chrome\" \"$@\"");
        assert_eq!(dirs(&[canonical(&dir) + "/"]), entry_on("chrome", &desktop(&s(&launcher), ""), &[]).unwrap().matchers);
        // A script folder with only scripts (and interpreters) in it holds nothing the engine could match.
        let py = tmp.path().join("opt/tool");
        make_elf(&py.join("bin/python3"));
        let tool = make_script(&py.join("tool"), "exec python3 -m tool");
        assert_eq!(Matchers::default(), entry_on("tool", &desktop(&s(&tool), ""), &[]).unwrap().matchers);
    }

    /// Add a program says why it can't route a script, an interpreter, a wrapper or an AppImage, and takes an ordinary program.
    #[test]
    fn unroutable_programs_say_why() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(None, unroutable(&make_elf(&root.join("opt/game/game"))));
        assert!(unroutable(&make_script(&root.join("bin/tool"), "echo")).unwrap().contains("is a script"));
        assert!(unroutable(&make_elf(&root.join("bin/python3.12"))).unwrap().contains("runs other programs too"));
        assert!(unroutable(&make_elf(&root.join("bin/nice"))).unwrap().contains("only starts other programs"));
        assert!(unroutable(&make_app_image(&root.join("App.AppImage"))).unwrap().contains("is an AppImage"));
        fs::write(root.join("Setup.exe"), "MZ\u{90}\u{0}").unwrap();
        assert!(unroutable(&root.join("Setup.exe")).unwrap().contains("Windows program"));
        assert!(unroutable(&root.join("nothing")).unwrap().contains("isn't a program"));
    }

    /// Runtimes that run other programs as their own process: one app's route on them would move every program they run.
    /// On Arch, every Windows program under Wine is /usr/bin/wine; Debian's gjs and guile are links to gjs-console and
    /// guile-3.0; Arch's Electron apps share electron37.
    #[test]
    fn shared_runtimes_match_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        make_elf(&bin.join("wine"));
        make_link(&bin.join("gjs"), &make_elf(&bin.join("gjs-console")));
        make_link(&bin.join("guile"), &make_elf(&bin.join("guile-3.0")));
        for n in ["mono", "dotnet", "R", "pwsh", "wine64-preloader"] {
            make_elf(&bin.join(n));
        }
        make_link(&bin.join("electron37"), &make_elf(&tmp.path().join("lib/electron37/electron")));
        make_elf(&bin.join("qemu-x86_64-static"));
        make_elf(&bin.join("ld-linux-x86-64.so.2"));
        for exec in [
            "env WINEPREFIX=/x wine C:/a.lnk",
            "gjs /usr/share/org.gnome.Maps/main.js",
            "guile -s tool.scm",
            "mono x.exe",
            "dotnet app.dll",
            "electron37 /usr/lib/signal-desktop/app.asar %U",
            "R",
            "pwsh -File x.ps1",
            "wine64-preloader x.exe",
            "qemu-x86_64-static ./arm-app",
            "ld-linux-x86-64.so.2 /opt/app/app",
        ] {
            assert_eq!(Matchers::default(), entry_on("x", &desktop(exec, ""), std::slice::from_ref(&bin)).unwrap().matchers, "{exec}");
        }
        for n in ["wine", "gjs", "guile", "mono", "dotnet", "electron37", "R", "pwsh", "wine64-preloader", "qemu-x86_64-static", "ld-linux-x86-64.so.2"] {
            assert!(unroutable(&bin.join(n)).unwrap().contains("runs other programs too"), "{n}");
        }
    }

    /// A wrapper runs the program after it, which is what the engine sees; one that hands the start to the desktop gives none.
    #[test]
    fn wrappers_run_the_program_they_start() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let game = s(&make_elf(&tmp.path().join("opt/game/game")));
        make_elf(&bin.join("nice"));
        make_elf(&bin.join("gtk-launch"));
        make_elf(&bin.join("firejail"));
        make_script(&bin.join("prime-run"), "__NV_PRIME_RENDER_OFFLOAD=1 exec \"$@\"");
        make_script(&bin.join("xdg-open"), "exec /usr/bin/gio open \"$1\"");
        let path = [bin.clone()];
        let own = entry_on("g", &desktop(&game, ""), &path).unwrap().matchers;
        for exec in [format!("nice -n 10 {game}"), format!("prime-run {game} %U"), format!("env A=1 nice {game}"), format!("firejail --private {game}")] {
            assert_eq!(own, entry_on("x", &desktop(&exec, ""), &path).unwrap().matchers, "{exec}");
        }
        for exec in ["gtk-launch org.example.App", "xdg-open https://example.org", "nice"] {
            assert_eq!(Matchers::default(), entry_on("x", &desktop(exec, ""), &path).unwrap().matchers, "{exec}");
        }
        // firejail's links (firecfg): firefox on the PATH is firejail, which runs the next firefox there.
        let ff = make_elf(&tmp.path().join("usr/bin/firefox"));
        make_link(&tmp.path().join("local/bin/firefox"), &bin.join("firejail"));
        let path = [tmp.path().join("local/bin"), tmp.path().join("usr/bin")];
        assert_eq!(vec![canonical(&ff)], entry_on("f", &desktop("firefox %u", ""), &path).unwrap().matchers.paths);
    }

    /// A launcher whose own work runs on a shared interpreter is that interpreter's traffic, even in a folder with programs
    /// of its own: its shebang's, one it runs by name, or one by a path outside its folder. A bundled Java is the app's own.
    #[test]
    fn launchers_on_a_shared_interpreter_match_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let python = s(&make_elf(&tmp.path().join("usr/bin/python3")));
        let dir = tmp.path().join("opt/foo");
        make_elf(&dir.join("helper"));
        for body in [
            format!("exec {python} {}/main.py \"$@\"", s(&dir)),
            "cd \"${0%/*}\" && exec python3 main.py".into(),
            "LANG=C python3 -m foo".into(),
            format!("exec \"{python}\" main.py"),
            format!("PY={python}\nexec \"$PY\" main.py"),
        ] {
            assert_eq!(Matchers::default(), entry_on("x", &desktop(&s(&make_script(&dir.join("run.sh"), &body)), ""), &[]).unwrap().matchers, "{body}");
        }
        let run_py = executable(&dir.join("run.py"), b"#!/usr/bin/env python3\nimport foo\n");
        assert_eq!(Matchers::default(), entry_on("p", &desktop(&s(&run_py), ""), &[]).unwrap().matchers);
        let app = tmp.path().join("opt/app");
        make_elf(&app.join("jre/bin/java"));
        make_elf(&app.join("bin/helper"));
        let launcher = make_script(&app.join("app.sh"), &format!("exec {0}/jre/bin/java -jar {0}/app.jar \"$@\"", s(&app)));
        assert_eq!(dirs(&[canonical(&app) + "/"]), entry_on("a", &desktop(&s(&launcher), ""), &[]).unwrap().matchers);
        // JetBrains' and VS Code's launchers start the app's own programs through variables, and stay routed.
        let idea = tmp.path().join("opt/idea");
        make_elf(&idea.join("bin/fsnotifier"));
        let idea_sh = make_script(
            &idea.join("bin/idea.sh"),
            "# Try $IDEA_JDK, then \"java\" in $PATH.\nJAVA_BIN=$(command -v java)\n[ -x \"$IDE_HOME/jbr/bin/java\" ] && JAVA_BIN=\"$IDE_HOME/jbr/bin/java\"\nexec \"$JAVA_BIN\" -classpath \"$CLASS_PATH\" com.intellij.idea.Main \"$@\"",
        );
        assert_eq!(dirs(&[canonical(&idea) + "/"]), entry_on("i", &desktop(&s(&idea_sh), ""), &[]).unwrap().matchers);
        let code = tmp.path().join("opt/code");
        make_elf(&code.join("code"));
        let code_sh = make_script(&code.join("bin/code"), "ELECTRON=\"$VSCODE_PATH/code\"\nELECTRON_RUN_AS_NODE=1 \"$ELECTRON\" \"$CLI\" --ms-enable-electron-run-as-node \"$@\"\nexit $?");
        assert_eq!(dirs(&[canonical(&code) + "/"]), entry_on("c", &desktop(&s(&code_sh), ""), &[]).unwrap().matchers);
    }

    /// Apps that run as one program (LibreOffice's Writer and Calc, a browser's web apps, a Flatpak of the same name) are one
    /// app to the engine: they share their matchers, plainest launcher first, and only the first of them with a route is
    /// matched, so the group keeps the route the user set. Statistics name it, or the group's first.
    #[test]
    fn apps_on_one_program_share_a_route() {
        let _one = one_scan_at_a_time();
        let tmp = tempfile::tempdir().unwrap();
        let office = s(&make_elf(&tmp.path().join("opt/office/program/soffice")));
        let chrome = make_elf(&tmp.path().join("opt/chrome/chrome"));
        let other = make_elf(&tmp.path().join("opt/other/other"));
        let apps = tmp.path().join("share/applications");
        fs::create_dir_all(&apps).unwrap();
        let add = |id: &str, label: &str, exec: &str, extra: &str| fs::write(apps.join(format!("{id}.desktop")), desktop(exec, extra).replace("Name=Thing", &format!("Name={label}"))).unwrap();
        add("office", "Office", &format!("{office} %U"), "");
        add("writer", "Writer", &format!("{office} --writer %U"), "");
        add("calc", "Calc", &format!("{office} --calc %U"), "");
        add("chrome", "Chrome", &format!("{} %U", s(&chrome)), "");
        add("chrome-yt", "YouTube", &format!("{} --profile-directory=Default --app-id=abc", s(&chrome)), "");
        add("chrome-flatpak", "Chrome Flatpak", "flatpak run --command=chrome com.google.Chrome", "");
        add("other", "Other", &s(&other), "");
        add("helper", "Office helper", &format!("{office} --headless"), "NoDisplay=true");
        let all: HashMap<String, DesktopApp> = scan_in(&[tmp.path().join("share")], &[], &[]).into_iter().map(|a| (a.key.clone(), a)).collect();
        assert_eq!(vec!["office", "calc", "writer", "helper"], all["writer"].group);
        assert_eq!(vec!["chrome", "chrome-yt", "chrome-flatpak"], all["chrome-flatpak"].group);
        assert!(all["other"].group.is_empty());
        let both = Matchers { paths: vec![canonical(&chrome)], dirs: vec![canonical(chrome.parent().unwrap()) + "/"], names: vec!["chrome".into()] };
        assert_eq!(both, all["chrome-yt"].matchers);
        assert_eq!(vec![canonical(&other)], matchers("other", &[]).paths);
        // The first routed one is matched, the others never: the web app routed alone takes the browser with it.
        assert_eq!(both, matchers("chrome-yt", &["chrome-yt"]));
        assert_eq!(both, matchers("chrome", &["chrome", "chrome-yt"]));
        assert_eq!(Matchers::default(), matchers("chrome-yt", &["chrome", "chrome-yt"]));
        assert_eq!(Matchers::default(), matchers("writer", &[]));
        assert_eq!("office", key_of(&canonical(Path::new(&office)), &[]));
        assert_eq!("writer", key_of(&canonical(Path::new(&office)), &["writer"]));
        // A program an app runs (added before the app was installed) is matched only while none of the app's group is routed.
        let program = canonical(&chrome);
        assert_eq!(both, matchers(&program, &[&program]));
        assert_eq!(Matchers::default(), matchers(&program, &["chrome", &program]));
        let lone = s(&tmp.path().join("elsewhere/tool"));
        assert_eq!(vec![lone.clone()], matchers(&lone, &[]).paths);
    }

    /// A new entry for a routed app's program (a menu editor's "Browser" running firefox, whose label sorts first) leads the
    /// group only while nothing in it is routed: the app that has the route keeps it.
    #[test]
    fn a_new_entry_does_not_take_the_route() {
        let _one = one_scan_at_a_time();
        let tmp = tempfile::tempdir().unwrap();
        let ff = make_elf(&tmp.path().join("usr/lib/firefox/firefox"));
        let apps = tmp.path().join("share/applications");
        fs::create_dir_all(&apps).unwrap();
        fs::write(apps.join("firefox.desktop"), desktop(&format!("{} %u", s(&ff)), "").replace("Name=Thing", "Name=Firefox")).unwrap();
        fs::write(apps.join("alacarte-made-1.desktop"), desktop(&s(&ff), "").replace("Name=Thing", "Name=Browser")).unwrap();
        let all: HashMap<String, DesktopApp> = scan_in(&[tmp.path().join("share")], &[], &[]).into_iter().map(|a| (a.key.clone(), a)).collect();
        assert_eq!(vec!["alacarte-made-1", "firefox"], all["firefox"].group);
        assert_eq!(vec![canonical(&ff)], matchers("firefox", &["firefox"]).paths);
        assert_eq!(Matchers::default(), matchers("alacarte-made-1", &["firefox"]));
    }

    /// A Flatpak is known by its command's name inside its sandbox, or by the programs its launcher script starts there;
    /// one on an interpreter, or whose command can't be known, has none.
    #[test]
    fn flatpak_commands_as_the_engine_sees_them() {
        let tmp = tempfile::tempdir().unwrap();
        let inst = tmp.path().join("flatpak");
        // An installed Flatpak's files folder, its /app.
        let app = |id: &str, command: &str| {
            let a = inst.join(format!("app/{id}/current/active"));
            fs::create_dir_all(&a).unwrap();
            fs::write(a.join("metadata"), format!("[Application]\nname={id}\ncommand={command}\n")).unwrap();
            a.join("files")
        };
        let files = app("com.discordapp.Discord", "com.discordapp.Discord");
        make_script(&files.join("bin/com.discordapp.Discord"), "exec zypak-wrapper /app/discord/Discord \"$@\"");
        make_elf(&files.join("discord/Discord"));
        let files = app("org.example.Tool", "tool");
        fs::create_dir_all(files.join("bin")).unwrap();
        fs::write(files.join("bin/tool"), "#!/usr/bin/python3\nimport tool\n").unwrap();
        let files = app("org.example.Java", "jtool");
        make_script(&files.join("bin/jtool"), "exec /app/jre/bin/java -jar /app/jtool.jar");
        make_elf(&files.join("jre/bin/java"));
        make_elf(&app("org.telegram.desktop", "telegram-desktop").join("bin/telegram-desktop"));
        let names = |id: &str, extra: &str| entry("x", &desktop(&format!("/usr/bin/flatpak run {extra}{id}"), &format!("X-Flatpak={id}")), &data_dirs(), &[], std::slice::from_ref(&inst)).unwrap().matchers.names;
        assert_eq!(vec!["Discord"], names("com.discordapp.Discord", ""));
        assert!(names("org.example.Tool", "").is_empty());
        assert!(names("org.example.Java", "").is_empty());
        assert_eq!(vec!["telegram-desktop"], names("org.telegram.desktop", ""));
        // Not installed where it can be read: its explicit command, never a guess from its id.
        assert_eq!(vec!["firefox"], names("org.mozilla.firefox", "--command=firefox "));
        assert!(names("com.spotify.Client", "").is_empty());
    }

    #[test]
    fn snap_and_flatpak() {
        let spotify = desktop("env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/spotify_spotify.desktop /snap/bin/spotify %U", "");
        assert_eq!(dirs(&["/snap/spotify/".into()]), entry("s", &spotify, &data_dirs(), &search_path(), &flatpak_installs()).unwrap().matchers);
        let firefox = desktop("/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox --file-forwarding org.mozilla.firefox @@u %u @@", "");
        assert_eq!(Matchers { names: vec!["firefox".into()], ..Matchers::default() }, entry("f", &firefox, &data_dirs(), &search_path(), &[]).unwrap().matchers);
    }

    #[test]
    fn hidden_ones_and_helpers() {
        let usual = |id: &str, text: &str| entry(id, text, &data_dirs(), &search_path(), &flatpak_installs());
        assert_eq!(None, usual("x", &desktop("thing", "Hidden=true")));
        assert_eq!(None, usual("x", &desktop("thing", "TryExec=/nonexistent/thing")));
        assert_eq!(None, usual("x", "[Desktop Entry]\nType=Link\nURL=https://example.org\n"));
        assert_eq!(None, usual("unbraid", &desktop("unbraid", "")));
        assert!(entry_on("x", &desktop("thing", "NoDisplay=true"), &[]).unwrap().system);
    }

    /// Shared system folders never become a folder match: only exact programs there.
    #[test]
    fn shared_folders_are_never_matched_whole() {
        let local_bin = format!("{}/.local/bin", paths::home().to_string_lossy());
        for d in ["/usr/bin", "/usr/lib", "/usr/lib/x86_64-linux-gnu", "/opt", "/usr/share", "/snap/bin", "/tmp", &local_bin] {
            assert_eq!(None, install_dir(Some(Path::new(d))), "{d}");
        }
        assert_eq!(Some("/opt/spotify/".to_string()), install_dir(Some(Path::new("/opt/spotify"))));
        assert_eq!(Some("/usr/share/code/".to_string()), install_dir(Some(Path::new("/usr/share/code/bin"))));
    }

    /// Statistics name a connection by the routed app its process belongs to, else by its program.
    #[test]
    fn processes_name_their_app() {
        let _one = one_scan_at_a_time();
        assert_eq!("/usr/bin/curl", key_of("/usr/bin/curl", &["/usr/bin/wget"]));
        assert_eq!("/usr/bin/wget", key_of("/usr/bin/wget", &["/usr/bin/wget"]));
        assert_eq!("?", key_of("", &[]));
        assert!(matches(&dirs(&["/opt/game/".into()]), "/opt/game/lib/helper"));
        assert!(matches(&Matchers { names: vec!["firefox".into()], ..Matchers::default() }, "/app/lib/firefox/firefox"));
    }

    #[test]
    fn scan_finds_entries_once_by_priority() {
        let _one = one_scan_at_a_time();
        let tmp = tempfile::tempdir().unwrap();
        let hi = tmp.path().join("hi/applications/sub");
        let lo = tmp.path().join("lo/applications");
        fs::create_dir_all(&hi).unwrap();
        fs::create_dir_all(&lo).unwrap();
        fs::write(hi.join("a.desktop"), desktop("/bin/true", "").replace("Name=Thing", "Name=High")).unwrap();
        fs::write(lo.join("sub-a.desktop"), desktop("/bin/true", "").replace("Name=Thing", "Name=Low")).unwrap();
        fs::write(lo.join("b.desktop"), desktop("/bin/true", "").replace("Name=Thing", "Name=Beta")).unwrap();
        let apps = scan_in(&[tmp.path().join("hi"), tmp.path().join("lo"), tmp.path().join("missing")], &[], &flatpak_installs());
        assert_eq!(vec![("b", "Beta"), ("sub-a", "High")], apps.iter().map(|a| (a.key.as_str(), a.label.as_str())).collect::<Vec<_>>());
    }
}
