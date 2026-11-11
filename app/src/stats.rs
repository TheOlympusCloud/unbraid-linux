//! Local traffic statistics. Off until the user agrees; then the engine's per-connection byte counts are summed per
//! hour, day, app and exit into an app-private SQLite file. Never uploaded; no destinations kept.
//!
//! One ordered worker thread owns all state and every write ([`Worker`]): engine callbacks, lifecycle (start, stop,
//! delete) and sessions are queued to it, so nothing needs a lock, and a callback from a stopped or deleted recording (an
//! older `generation`) is dropped. Reads run on the worker too, through [`read`].

use crate::app::store;
use crate::clock::elapsed_realtime;
use crate::compiler::{PROBE, TS_TAG};
use crate::engine_api::daemon::ConnectionEvents;
use crate::error::{Error, Result};
use crate::model::{DIRECT, Route, Server, Setup};
use crate::sqlite::{Cursor, Schema, SqliteDatabase, SqliteOpenHelper};
use crate::vpn::{self, Phase};
use crate::{apps, log, manual, probe, speed_test};
use chrono::{Local, TimeZone};
use indexmap::{IndexMap, IndexSet};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock, mpsc};
use std::thread;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const FILE: &str = "stats.db";
pub const HOME: &str = "home";
const HOUR: i64 = 3_600_000;
const TESTS_KEPT: i32 = 100;
/// A test's combined run: its start (0 = tested alone) and how many exits shared the line.
const RUN_COLUMNS: &str = "grp INTEGER NOT NULL DEFAULT 0, n INTEGER NOT NULL DEFAULT 1";

/// The app's own traffic (speed tests, health checks), by the package name the earlier app recorded it under.
pub const SELF: &str = "app.unbraid";

static DIR: OnceLock<PathBuf> = OnceLock::new();
/// The async runtime the engine's streams are read on ([`init`]).
static RT: OnceLock<Handle> = OnceLock::new();

type Job = Box<dyn FnOnce(&mut Worker) + Send>;

static WORKER: LazyLock<mpsc::Sender<Job>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel::<Job>();
    thread::Builder::new()
        .name("stats".into())
        .spawn(move || {
            let mut w = Worker::new(None);
            for job in rx {
                // A job that panics is lost, never the worker.
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| job(&mut w)));
            }
        })
        .expect("start the statistics worker");
    tx
});

/// Runs `f` on the worker; failures are logged, never thrown into the app.
pub(crate) fn post(f: impl FnOnce(&mut Worker) -> Result<()> + Send + 'static) {
    let _ = WORKER.send(Box::new(move |w: &mut Worker| {
        if let Err(e) = f(w) {
            log::w("Unbraid", &format!("stats: {}", probe::kind(&e)));
        }
    }));
}

/// Also when recording is off: what was kept goes when the consent text says, not only when Stats is used. Call it at
/// start, inside the async runtime: the engine's streams are read on it.
pub fn init(folder: &Path) {
    let _ = DIR.set(folder.to_path_buf());
    if let Ok(rt) = Handle::try_current() {
        let _ = RT.set(rt);
    }
    maintain();
}

/// Retention, once a day (the app start and every return to the app ask; a long-running process keeps asking).
pub fn maintain() {
    post(Worker::maybe_prune);
}

/// Local hour and day numbers, so "today" and "Monday" match the computer's calendar.
pub fn hour_of(ms: i64) -> i64 {
    let offset = Local.timestamp_millis_opt(ms).single().map_or(0, |t| t.offset().local_minus_utc() as i64 * 1000);
    (ms + offset) / HOUR
}

pub fn day_of(ms: i64) -> i64 {
    hour_of(ms).div_euclid(24)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn recording() -> bool {
    store().setup().borrow().prefs.stats
}

/// The tables, as the earlier app made and upgraded them.
struct Tables;

impl Schema for Tables {
    fn on_create(&mut self, d: &SqliteDatabase) -> Result<()> {
        for sql in [
            "CREATE TABLE hourly(h INTEGER, exit TEXT, up INTEGER, down INTEGER, PRIMARY KEY(h, exit)) WITHOUT ROWID",
            "CREATE TABLE daily(d INTEGER, app TEXT, exit TEXT, up INTEGER, down INTEGER, PRIMARY KEY(d, app, exit)) WITHOUT ROWID",
            "CREATE TABLE server(d INTEGER, exit TEXT, name TEXT, bytes INTEGER, PRIMARY KEY(d, exit, name)) WITHOUT ROWID",
            "CREATE TABLE peak(d INTEGER, exit TEXT, bps INTEGER, at INTEGER, up INTEGER NOT NULL DEFAULT 0, up_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(d, exit)) WITHOUT ROWID",
            "CREATE TABLE span(start INTEGER PRIMARY KEY, end INTEGER, paused INTEGER)",
            "CREATE TABLE exit(id TEXT PRIMARY KEY, code TEXT, name TEXT, hue INTEGER, via TEXT)",
            &format!(
                "CREATE TABLE test(at INTEGER PRIMARY KEY, exit TEXT, via TEXT, server TEXT, ip TEXT, down INTEGER, up INTEGER, idle INTEGER, busy_down INTEGER, busy_up INTEGER, {RUN_COLUMNS})"
            ),
        ] {
            d.exec_sql(sql, [])?;
        }
        Ok(())
    }

    // 2: peaks keep upload apart from download (bps/at stay the download's). 3: tests remember a combined run.
    fn on_upgrade(&mut self, d: &SqliteDatabase, old: i32, _new: i32) -> Result<()> {
        if old < 2 {
            d.exec_sql("ALTER TABLE peak ADD COLUMN up INTEGER NOT NULL DEFAULT 0", [])?;
            d.exec_sql("ALTER TABLE peak ADD COLUMN up_at INTEGER NOT NULL DEFAULT 0", [])?;
        }
        if old < 3 {
            for column in RUN_COLUMNS.split(", ") {
                d.exec_sql(&format!("ALTER TABLE test ADD COLUMN {column}"), [])?;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct Sum {
    up: i64,
    down: i64,
}

/// What the worker thread owns: the database, the sums not yet written, the open session and the engine's streams.
pub struct Worker {
    /// None = the app's folder ([`init`]).
    dir: Option<PathBuf>,
    helper: Option<SqliteOpenHelper<Tables>>,
    hourly: HashMap<(i64, String), Sum>,
    daily: HashMap<(i64, String, String), Sum>,
    servers: HashMap<(i64, String, String), i64>,
    pruned_day: i64,
    open: Option<(i64, bool)>,
    /// Bumped by every new or stopped subscription: callbacks carrying an older value are dropped.
    generation: i32,
    c: Collector,
}

/// The database in the worker's folder, opened (made or upgraded) on first use.
fn db(helper: &mut Option<SqliteOpenHelper<Tables>>, file: Option<PathBuf>) -> Result<&SqliteDatabase> {
    let file = file.ok_or_else(|| Error::State("Statistics have no folder".into()))?;
    helper.get_or_insert_with(|| SqliteOpenHelper::new(file, 3, Tables)).writable_database()
}

/// Exits keep the label they had when used, so history survives renames and removed routes.
fn label_exits(d: &SqliteDatabase, ids: impl IntoIterator<Item = String>) -> Result<()> {
    for id in ids.into_iter().collect::<IndexSet<_>>() {
        let Some(e) = lock(&LABELS).get(&id).cloned() else { continue };
        d.exec_sql("INSERT OR REPLACE INTO exit VALUES(?,?,?,?,?)", params![id, e.code, e.name, e.hue, e.via])?;
    }
    Ok(())
}

impl Worker {
    fn new(dir: Option<PathBuf>) -> Worker {
        Worker {
            dir,
            helper: None,
            hourly: HashMap::new(),
            daily: HashMap::new(),
            servers: HashMap::new(),
            pruned_day: -1,
            open: None,
            generation: 0,
            c: Collector { count_from: i64::MAX, ..Collector::default() },
        }
    }

    fn file(&self) -> Option<PathBuf> {
        self.dir.as_deref().or(DIR.get().map(PathBuf::as_path)).map(|d| d.join(FILE))
    }

    fn db(&mut self) -> Result<&SqliteDatabase> {
        let file = self.file();
        db(&mut self.helper, file)
    }

    pub(crate) fn add(&mut self, now: i64, app: &str, exit: &str, server: Option<&str>, up: i64, down: i64) {
        if up <= 0 && down <= 0 {
            return;
        }
        let h = self.hourly.entry((hour_of(now), exit.to_string())).or_default();
        h.up += up;
        h.down += down;
        let d = day_of(now);
        let s = self.daily.entry((d, app.to_string(), exit.to_string())).or_default();
        s.up += up;
        s.down += down;
        if let Some(server) = server {
            *self.servers.entry((d, exit.to_string(), server.to_string())).or_default() += up + down;
        }
    }

    /// Pending sums and the exits' labels in one transaction (explicit conflict targets, as older SQLite needs).
    pub(crate) fn flush_now(&mut self, force: bool) -> Result<()> {
        if (!force && !recording()) || (self.hourly.is_empty() && self.daily.is_empty()) {
            return Ok(());
        }
        let file = self.file();
        let d = db(&mut self.helper, file)?;
        let (hourly, daily, servers) = (&self.hourly, &self.daily, &self.servers);
        d.transaction(|d| {
            for ((h, exit), s) in hourly {
                d.exec_sql("INSERT INTO hourly VALUES(?,?,?,?) ON CONFLICT(h, exit) DO UPDATE SET up=up+excluded.up, down=down+excluded.down", params![h, exit, s.up, s.down])?;
            }
            for ((day, app, exit), s) in daily {
                d.exec_sql("INSERT INTO daily VALUES(?,?,?,?,?) ON CONFLICT(d, app, exit) DO UPDATE SET up=up+excluded.up, down=down+excluded.down", params![day, app, exit, s.up, s.down])?;
            }
            for ((day, exit, name), b) in servers {
                d.exec_sql("INSERT INTO server VALUES(?,?,?,?) ON CONFLICT(d, exit, name) DO UPDATE SET bytes=bytes+excluded.bytes", params![day, exit, name, b])?;
            }
            label_exits(d, daily.keys().map(|k| k.2.clone()).chain(hourly.keys().map(|k| k.1.clone())))
        })?;
        self.clear_pending();
        self.maybe_prune()
    }

    /// Retention runs once a day whatever else happens: on writes and before reads.
    fn maybe_prune(&mut self) -> Result<()> {
        let d = day_of(now_ms());
        if d != self.pruned_day {
            self.prune_now()?;
            self.pruned_day = d;
        }
        Ok(())
    }

    fn clear_pending(&mut self) {
        self.hourly.clear();
        self.daily.clear();
        self.servers.clear();
    }

    /// Keeps what the consent text promises, whatever else happens.
    pub(crate) fn prune_now(&mut self) -> Result<()> {
        if !self.file().is_some_and(|f| f.exists()) {
            return Ok(());
        }
        let now = now_ms();
        let today = day_of(now);
        let d = self.db()?;
        d.exec_sql("DELETE FROM hourly WHERE h < ?", params![(today - 8) * 24])?;
        for table in ["daily", "server"] {
            d.exec_sql(&format!("DELETE FROM {table} WHERE d < ?"), params![today - 400])?;
        }
        d.exec_sql("DELETE FROM peak", [])?; // speeds seen in use, no longer kept (the table stays for older databases)
        d.exec_sql("DELETE FROM span WHERE start < ?", params![now - 400 * 24 * HOUR])?;
        // The last 100 tests, a combined run counting once and kept or dropped whole.
        d.exec_sql(
            &format!(
                "DELETE FROM test WHERE at < ? OR (CASE grp WHEN 0 THEN at ELSE grp END) NOT IN (SELECT DISTINCT CASE grp WHEN 0 THEN at ELSE grp END k FROM test ORDER BY k DESC LIMIT {TESTS_KEPT})"
            ),
            params![now - 400 * 24 * HOUR],
        )?;
        // An exit's name and colour go with the last row that needs them.
        d.exec_sql("DELETE FROM exit WHERE id NOT IN (SELECT exit FROM hourly UNION SELECT exit FROM daily UNION SELECT exit FROM server UNION SELECT exit FROM test)", [])
    }

    fn write_span(&mut self, start: i64, end: i64, paused: bool) -> Result<()> {
        self.db()?.exec_sql("INSERT OR REPLACE INTO span VALUES(?,?,?)", params![start, end, paused as i32])
    }

    /// Keeps the open span's end current, so a killed process loses at most half a minute.
    pub(crate) fn checkpoint_now(&mut self) -> Result<()> {
        match self.open {
            Some((start, paused)) if recording() => self.write_span(start, now_ms(), paused),
            _ => Ok(()),
        }
    }

    // ---- reading (call through `read`) ----------------------------------------------------------------------------

    fn rows<T>(&mut self, sql: &str, args: &[&str], read: impl Fn(&Cursor) -> Result<T>) -> Vec<T> {
        if !self.file().is_some_and(|f| f.exists()) {
            return vec![];
        }
        let mut all = || -> Result<Vec<T>> {
            let mut c = self.db()?.raw_query(sql, args)?;
            let mut all = vec![];
            while c.move_to_next() {
                all.push(read(&c)?);
            }
            Ok(all)
        };
        all().unwrap_or_default()
    }

    pub fn exits(&mut self) -> IndexMap<String, Exit> {
        let all = self.rows("SELECT id, code, name, hue, via FROM exit", &[], |c| {
            Ok(Exit {
                id: c.get_string(0)?,
                code: c.get_string(1)?,
                name: c.get_string(2)?,
                hue: c.get_int(3)?,
                via: c.get_string(4)?,
            })
        });
        all.into_iter().map(|e| (e.id.clone(), e)).collect()
    }

    /// Bytes per exit per day, for days [from, to].
    pub fn per_day(&mut self, from: i64, to: i64) -> IndexMap<i64, IndexMap<String, Bytes>> {
        by_key(self.rows(
            "SELECT d, exit, SUM(up), SUM(down) FROM daily WHERE d BETWEEN ? AND ? GROUP BY d, exit",
            &[&from.to_string(), &to.to_string()],
            |c| Ok((c.get_long(0)?, c.get_string(1)?, Bytes { up: c.get_long(2)?, down: c.get_long(3)? })),
        ))
    }

    /// Bytes per exit per hour of one day (the Day view).
    pub fn per_hour(&mut self, day: i64) -> IndexMap<i64, IndexMap<String, Bytes>> {
        by_key(self.rows(
            "SELECT h, exit, up, down FROM hourly WHERE h BETWEEN ? AND ?",
            &[&(day * 24).to_string(), &(day * 24 + 23).to_string()],
            |c| Ok((c.get_long(0)? - day * 24, c.get_string(1)?, Bytes { up: c.get_long(2)?, down: c.get_long(3)? })),
        ))
    }

    /// Bytes per app and exit over days [from, to], largest first.
    pub fn apps(&mut self, from: i64, to: i64) -> Vec<(String, String, i64)> {
        self.rows("SELECT app, exit, SUM(up)+SUM(down) b FROM daily WHERE d BETWEEN ? AND ? GROUP BY app, exit ORDER BY b DESC", &[&from.to_string(), &to.to_string()], |c| {
            Ok((c.get_string(0)?, c.get_string(1)?, c.get_long(2)?))
        })
    }

    pub fn servers(&mut self, exit: &str, from: i64, to: i64) -> Vec<(String, i64)> {
        self.rows(
            "SELECT name, SUM(bytes) b FROM server WHERE exit = ? AND d BETWEEN ? AND ? GROUP BY name ORDER BY b DESC",
            &[exit, &from.to_string(), &to.to_string()],
            |c| Ok((c.get_string(0)?, c.get_long(1)?)),
        )
    }

    /// Spans overlapping [from, to) ms: start, end, paused. The open span counts up to now.
    pub fn spans(&mut self, from: i64, to: i64) -> Vec<(i64, i64, bool)> {
        let stored = self.rows(
            "SELECT start, end, paused FROM span WHERE end > ? AND start < ? ORDER BY start",
            &[&from.to_string(), &to.to_string()],
            |c| Ok((c.get_long(0)?, c.get_long(1)?, c.get_int(2)? == 1)),
        );
        let live = self.open.map(|(s, p)| (s, now_ms(), p));
        stored
            .into_iter()
            .filter(|s| Some(s.0) != live.map(|l| l.0))
            .chain(live)
            .map(|(s, e, p)| (s.max(from), e.min(to), p))
            .filter(|s| s.1 > s.0)
            .collect()
    }

    pub fn tests(&mut self) -> Vec<Test> {
        self.rows(
            "SELECT at, exit, via, server, ip, down, up, idle, busy_down, busy_up, grp, n FROM test ORDER BY at DESC",
            &[],
            |c| {
                Ok(Test {
                    at: c.get_long(0)?,
                    exit: c.get_string(1)?,
                    via: c.get_string(2)?,
                    server: c.get_string(3)?,
                    ip: c.get_string(4)?,
                    down: c.get_long(5)?,
                    up: c.get_long(6)?,
                    idle: c.get_int(7)?,
                    busy_down: c.get_int(8)?,
                    busy_up: c.get_int(9)?,
                    grp: c.get_long(10)?,
                    n: c.get_int(11)?,
                })
            },
        )
    }
}

fn by_key(rows: Vec<(i64, String, Bytes)>) -> IndexMap<i64, IndexMap<String, Bytes>> {
    let mut all: IndexMap<i64, IndexMap<String, Bytes>> = IndexMap::new();
    for (k, exit, b) in rows {
        all.entry(k).or_default().insert(exit, b);
    }
    all
}

/// Each exit's label as last noted, taken when its connections open or its test starts, not when the bytes are written.
static LABELS: LazyLock<Mutex<HashMap<String, Exit>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Notes the label of exit `route_id` as `setup` has it, and returns the id its usage is recorded under ([`id_of`]).
pub fn note(route_id: &str, setup: &Setup) -> String {
    let r = setup.route(Some(route_id));
    let id = r.map_or_else(|| route_id.to_string(), id_of);
    let label = if let Some(r) = r {
        Some(Exit { id: id.clone(), code: r.code(), name: r.name(), hue: r.hue, via: r.source() })
    } else if id == HOME {
        let via = [setup.tailscale().then_some("Tailscale"), setup.home.wg.is_some().then_some("WireGuard")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" & ");
        Some(Exit {
            id: id.clone(),
            code: "HM".into(),
            name: "Home network".into(),
            hue: 3,
            via: if via.is_empty() { "Tailscale".into() } else { via },
        })
    } else if let Some(ip) = id.strip_prefix(speed_test::NODE) {
        let name = vpn::live()
            .state()
            .ts_exit_nodes
            .iter()
            .find(|n| n.ip == ip)
            .map_or_else(|| ip.to_string(), |n| n.name.clone());
        Some(Exit { id: id.clone(), code: "TS".into(), name, hue: -1, via: "Tailscale".into() })
    } else {
        None
    };
    if let Some(l) = label {
        lock(&LABELS).insert(id.clone(), l);
    }
    id
}

/// The id route `route_id` of `setup` is recorded under.
pub fn id_in(route_id: &str, setup: &Setup) -> String {
    setup.route(Some(route_id)).map_or_else(|| route_id.to_string(), id_of)
}

/// A route's id plus a digest of what carries it (provider and place, or the imported server), so a route moved to
/// another provider or server starts a new history instead of relabelling the old one. Name, colour and the filter
/// don't count. Only addresses, names and public keys go in, never a private key or password.
pub fn id_of(r: &Route) -> String {
    let l = &r.loc;
    let text = |v: Option<String>| v.unwrap_or_else(|| "null".into());
    let what: Vec<String> = if let Some(wg) = &r.wg {
        vec!["wg".into(), wg.endpoint.clone(), wg.public_key.clone()]
    } else if let Some(o) = &r.ovpn {
        [vec!["ovpn".to_string()], manual::ovpn_servers(o)].concat()
    } else if let Some(ss) = &r.ss {
        vec!["ss".into(), ss.server.clone(), ss.port.to_string()]
    } else if let Some(ts) = &r.ts_exit {
        vec!["ts".into(), ts.clone()]
    } else {
        vec![
            l.provider.clone(),
            text(l.country_code.clone()),
            text(l.country_id.map(|v| v.to_string())),
            text(l.city_id.map(|v| v.to_string())),
            text(l.city.clone()),
            text(l.region.clone()),
            text(l.group.clone()),
            text(l.protocol.clone()),
            text(l.pinned.as_ref().map(|p| p.host.clone())),
        ]
    };
    let digest = Sha256::digest(what.join("\u{0}").as_bytes());
    format!("{}@{}", r.id, digest[..5].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Recorded before ids carried [`id_of`]'s digest: which provider or server carried it isn't known.
pub fn legacy(id: &str) -> bool {
    !id.contains('@') && id != HOME && id != DIRECT && !id.starts_with(speed_test::NODE)
}

// ---- sessions: protected and paused spans, from the service state ------------------------------------------------

/// On every phase change (Off when stats are turned off): closes the running span, opens the next while recording.
pub fn phase(p: Phase) {
    post(move |w| {
        let now = now_ms();
        if let Some((start, paused)) = w.open {
            w.write_span(start, now, paused)?;
        }
        w.open = match p {
            Phase::On if recording() => Some((now, false)),
            Phase::Paused if recording() => Some((now, true)),
            _ => None,
        };
        Ok(())
    });
}

// ---- lifecycle -------------------------------------------------------------------------------------------------------

pub fn start() {
    post(|w| {
        w.start_now(false);
        w.prune_now()
    });
}

/// Bytes accepted while recording are kept even if recording was just turned off.
pub fn stop() {
    post(|w| {
        w.stop_now();
        w.flush_now(true)
    });
}

static EPOCH: AtomicI32 = AtomicI32::new(0);

/// Bumped by every delete: a speed test started before one must not write its result after it.
pub fn epoch() -> i32 {
    EPOCH.load(Ordering::SeqCst)
}

/// Erases everything: the file and its journal. Recording, if on, carries on from now.
pub fn delete() {
    post(|w| {
        EPOCH.fetch_add(1, Ordering::SeqCst);
        let was_on = w.c.client.is_some();
        w.stop_now();
        w.clear_pending();
        w.open = w.open.map(|(_, paused)| (now_ms(), paused));
        w.helper = None;
        if let Some(f) = w.file() {
            for suffix in ["", "-journal", "-wal", "-shm"] {
                let mut name = f.clone().into_os_string();
                name.push(suffix);
                let _ = fs::remove_file(name);
            }
        }
        if was_on && recording() {
            w.start_now(false);
        }
        Ok(())
    });
}

/// Saves a test, or a combined run's tests, together; a key already taken moves to the next free millisecond.
pub fn save_tests(ts: Vec<Test>, started_in: i32) {
    post(move |w| {
        if !recording() || started_in != epoch() {
            return Ok(());
        }
        w.db()?.transaction(|d| {
            for t in &ts {
                d.exec_sql(
                    "INSERT INTO test(at, exit, via, server, ip, down, up, idle, busy_down, busy_up, grp, n) VALUES((SELECT MAX(?, IFNULL(MAX(at), 0) + 1) FROM test),?,?,?,?,?,?,?,?,?,?,?)",
                    params![t.at, t.exit, t.via, t.server, t.ip, t.down, t.up, t.idle, t.busy_down, t.busy_up, t.grp, t.n],
                )?;
            }
            label_exits(d, ts.iter().map(|t| t.exit.clone()))
        })?;
        w.prune_now()
    });
}

/// The file's size in bytes, 0 without one.
pub fn size() -> u64 {
    DIR.get().and_then(|d| fs::metadata(d.join(FILE)).ok()).map_or(0, |m| m.len())
}

/// Runs a read on the worker after writing pending sums, so it sees the latest and never races a delete. It blocks: call
/// it off the window's thread, and never from the worker itself.
pub fn read<T: Send + 'static>(f: impl FnOnce(&mut Worker) -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    let _ = WORKER.send(Box::new(move |w: &mut Worker| {
        let r = (|| -> Result<T> {
            w.flush_now(false)?;
            w.maybe_prune()?;
            Ok(f(w))
        })();
        let _ = tx.send(r.ok());
    }));
    rx.recv().ok().flatten()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub id: String,
    pub code: String,
    pub name: String,
    pub hue: i32,
    pub via: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Bytes {
    pub up: i64,
    pub down: i64,
}

impl Bytes {
    pub fn total(&self) -> i64 {
        self.up + self.down
    }
}

/// `idle` is the ping in ms; `grp` the combined run it was part of (0 = alone), with `n` exits sharing the line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Test {
    pub at: i64,
    pub exit: String,
    pub via: String,
    pub server: String,
    pub ip: String,
    pub down: i64,
    pub up: i64,
    pub idle: i32,
    pub busy_down: i32,
    pub busy_up: i32,
    pub grp: i64,
    pub n: i32,
}

// ---- live view -----------------------------------------------------------------------------------------------------

/// The last 60 one-second samples of download per exit (bits/s), plus the current totals; only while watched.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Live {
    pub down: IndexMap<String, Vec<f32>>,
    pub down_now: i64,
    pub up_now: i64,
}

static LIVE: LazyLock<watch::Sender<Live>> = LazyLock::new(|| watch::Sender::new(Live::default()));

pub fn live() -> watch::Receiver<Live> {
    LIVE.subscribe()
}

static WATCHING: AtomicBool = AtomicBool::new(false);

pub fn watching() -> bool {
    WATCHING.load(Ordering::SeqCst)
}

/// Stats is on screen with the app in front: sample every second (live chart), else every 15 s.
pub fn set_watching(v: bool) {
    if WATCHING.swap(v, Ordering::SeqCst) != v {
        post(|w| {
            w.retime_now();
            Ok(())
        });
    }
}

// ---- the engine's status and connection streams, reconciled per connection ------------------------------------------

#[derive(Clone)]
struct Conn {
    app: String,
    exit: String,
    server: Option<String>,
    up: i64,
    down: i64,
}

/// A connection event, copied out of the engine's message.
struct Ev {
    kind: i32,
    id: String,
    total: Option<(i64, i64)>,
    delta: (i64, i64),
    tag: Option<String>,
    closed: bool,
    created: i64,
    own: bool,
    path: Option<String>,
}

const NEW: i32 = 0;
const UPDATE: i32 = 1;
const CLOSED: i32 = 2;

/// The worker's side of the engine's streams. Callbacks copy what they need and queue it to the worker.
#[derive(Default)]
struct Collector {
    client: Option<JoinHandle<()>>,
    /// What the engine ran when this subscription began (the connection resubscribes after each engine start): events
    /// still queued from the engine before are labelled by its setup, not the next one's.
    engine: (Setup, IndexMap<String, String>, IndexMap<String, Server>),
    interval: i64,
    seen: HashMap<String, Conn>,
    last_flush: i64,
    last_tick: i64,
    window: IndexMap<String, i64>,
    window_up: i64,
    /// Drawn on the live chart but never a peak: bytes reported at a close (they span an unknown time), and our own.
    closing: IndexMap<String, i64>,
    closing_up: i64,
    /// Connections first seen in a replay are counted in full if they began after this (a resubscription gap), else baselined.
    count_from: i64,
    /// When this subscription began, and last heard from the engine (wall ms).
    started_at: i64,
    heard: i64,
    retries: u32,
    /// Connections counted up to their close: a replay lists recently closed ones again, and they mustn't count twice.
    done: IndexSet<String>,
}

fn done_add(done: &mut IndexSet<String>, id: &str) {
    done.insert(id.to_string());
    if done.len() > 4096 {
        done.shift_remove_index(0);
    }
}

impl Worker {
    fn fast(&self) -> bool {
        self.c.interval == 1_000_000_000
    }

    pub(crate) fn start_now(&mut self, retime: bool) {
        let now = now_ms();
        // A resubscription counts what began since the last one stopped hearing (kept across failed attempts until a
        // replay lands); a fresh start baselines what's open.
        self.c.count_from = if retime && self.c.client.is_some() {
            self.c.count_from.min((if self.c.heard > 0 { self.c.heard } else { now }) - 2_000)
        } else {
            i64::MAX
        };
        self.stop_client();
        let v = vpn::live();
        self.c.engine = (v.running().unwrap_or_else(|| store().current()), v.tags(), v.state().servers);
        self.c.started_at = now;
        self.c.interval = if watching() { 1_000_000_000 } else { 15_000_000_000 };
        let (generation, every) = (self.generation, self.c.interval);
        let Some(rt) = RT.get() else {
            log::w("Unbraid", "stats: no engine connection");
            return;
        };
        self.c.client = Some(rt.spawn(async move {
            let engine = crate::engine::get();
            let both = tokio::try_join!(
                async {
                    let mut s = engine.connections(every).await?;
                    while let Some(m) = s.message().await? {
                        write_connection_events(generation, m);
                    }
                    Ok::<_, tonic::Status>(())
                },
                async {
                    let mut s = engine.status(every).await?;
                    while s.message().await?.is_some() {
                        write_status(generation);
                    }
                    Ok::<_, tonic::Status>(())
                },
            );
            if both.is_err() {
                log::w("Unbraid", "stats: no engine connection");
            }
            post(move |w| {
                w.retry(generation);
                Ok(())
            });
        }));
    }

    /// A subscription the engine dropped (not one we stopped) comes back after a growing pause, the ledger kept.
    fn retry(&mut self, generation: i32) {
        let wait = 2_000u64 << self.c.retries.min(5);
        if let Some(rt) = RT.get() {
            rt.spawn(async move {
                tokio::time::sleep(Duration::from_millis(wait)).await;
                post(move |w| {
                    if generation == w.generation && w.c.client.is_some() {
                        w.c.retries += 1;
                        w.start_now(true);
                    }
                    Ok(())
                });
            });
        }
    }

    fn stop_client(&mut self) {
        if let Some(c) = self.c.client.take() {
            c.abort();
        }
        self.generation += 1;
        self.c.last_tick = 0;
        self.c.heard = 0;
        self.c.window.clear();
        self.c.window_up = 0;
        self.c.closing.clear();
        self.c.closing_up = 0;
        LIVE.send_replace(Live::default());
    }

    /// Recording ends: the ledger goes too (a later start baselines whatever is open then).
    pub(crate) fn stop_now(&mut self) {
        self.stop_client();
        self.c.seen.clear();
        self.c.done.clear();
        self.c.retries = 0;
    }

    /// A new sampling rate needs a new subscription. The ledger stays: its replay reconciles, nothing is lost.
    pub(crate) fn retime_now(&mut self) {
        if self.c.client.is_some() {
            self.start_now(true);
        }
    }

    /// New and Closed carry a connection's totals, Update the change since the last one. A connection's app, exit and
    /// server are fixed when it is first seen, against the configuration the engine actually runs.
    fn apply(&mut self, events: Vec<Ev>, reset: bool) {
        let now = now_ms();
        let engine = std::mem::take(&mut self.c.engine);
        let (setup, tags, servers) = &engine;
        let mut ids = HashMap::<String, String>::new(); // the recorded id of each exit, worked out once per batch (a replay lists hundreds)
        let open = |e: &Ev, ids: &mut HashMap<String, String>| {
            let app = if e.own { SELF.to_string() } else { app_of(e, setup) };
            let exit = e
                .own
                .then(|| speed_test::exit_on(e.tag.as_deref()))
                .flatten()
                .unwrap_or_else(|| exit_of(e.tag.as_deref(), &app, setup, tags));
            let id = ids.entry(exit.clone()).or_insert_with(|| note(&exit, setup)).clone();
            Conn { app, exit: id, server: servers.get(&exit).map(|s| s.name.clone()), up: 0, down: 0 }
        };
        let mut replayed = HashSet::new();
        let mut batch = false;
        for e in &events {
            let (c, up, down) = match e.kind {
                NEW => {
                    let Some(t) = e.total else { continue };
                    replayed.insert(e.id.clone());
                    if let Some(known) = self.c.seen.get_mut(&e.id) {
                        // Replayed and already counted: add only what it did while we weren't listening.
                        let counted = (known.clone(), (t.0 - known.up).max(0), (t.1 - known.down).max(0));
                        known.up = t.0;
                        known.down = t.1;
                        if e.closed {
                            self.c.seen.remove(&e.id);
                            done_add(&mut self.c.done, &e.id);
                        }
                        counted
                    } else {
                        if self.c.done.contains(&e.id) {
                            continue;
                        }
                        // Unknown in a replay: born during a resubscription gap → count it; open since before recording → baseline.
                        let fresh = !reset || e.created >= self.c.count_from;
                        if e.closed && !fresh {
                            continue;
                        }
                        let c = Conn { up: t.0, down: t.1, ..open(e, &mut ids) };
                        if e.closed {
                            done_add(&mut self.c.done, &e.id);
                        } else {
                            self.c.seen.insert(e.id.clone(), c.clone());
                        }
                        if !fresh {
                            continue;
                        }
                        (c, t.0, t.1)
                    }
                }
                UPDATE => {
                    batch = true;
                    let Some(c) = self.c.seen.get_mut(&e.id) else { continue };
                    c.up += e.delta.0;
                    c.down += e.delta.1;
                    (c.clone(), e.delta.0, e.delta.1)
                }
                CLOSED => {
                    let Some(t) = e.total else { continue };
                    // The engine's event queue can drop a New: a connection born while listening still counts in full.
                    let c = match self.c.seen.remove(&e.id) {
                        Some(c) => c,
                        None if !self.c.done.contains(&e.id) && e.created >= self.c.started_at => open(e, &mut ids),
                        None => continue,
                    };
                    done_add(&mut self.c.done, &e.id);
                    let (up, down) = ((t.0 - c.up).max(0), (t.1 - c.down).max(0));
                    (c, up, down)
                }
                _ => continue,
            };
            self.add(now, &c.app, &c.exit, c.server.as_deref(), up, down);
            // The live window takes only what flowed just now: never a replay's catch-up or a New's backlog.
            // unbraid's own traffic (speed tests, health checks) is drawn but counted apart: the live chart is your apps'.
            if self.fast() && !reset && c.exit != DIRECT {
                if c.app == SELF || e.kind == CLOSED {
                    *self.c.closing.entry(c.exit).or_default() += down;
                    self.c.closing_up += up;
                } else if e.kind == UPDATE {
                    *self.c.window.entry(c.exit).or_default() += down;
                    self.c.window_up += up;
                }
            }
        }
        // After a reload the old engine's connections never close: a full replay says which ones still exist.
        if reset {
            self.c.seen.retain(|id, _| replayed.contains(id));
            self.c.count_from = i64::MAX;
        }
        self.c.engine = engine;
        if self.fast() && batch {
            self.sample(1);
        }
    }

    /// Closes the live window: the series and headline come from it. The engine sends one traffic batch per second with
    /// that second's bytes, so a batch is one sample whenever it arrives (timing it here would turn a late batch and the
    /// one after into a spike and a gap). Quiet seconds send none: status ticks fill them in.
    fn sample(&mut self, seconds: i64) {
        self.c.last_tick = elapsed_realtime();
        let prev = LIVE.borrow().down.clone();
        let n = seconds.min(60) as usize;
        let keys: IndexSet<&String> = prev.keys().chain(self.c.window.keys()).chain(self.c.closing.keys()).collect();
        let down: IndexMap<String, Vec<f32>> = keys
            .into_iter()
            .map(|k| {
                let bps = self.c.window.get(k).copied().unwrap_or(0) * 8 / seconds;
                let shown = bps + self.c.closing.get(k).copied().unwrap_or(0) * 8 / seconds;
                let mut series = prev.get(k).map_or_else(|| vec![0.0; 60 - n], |s| s[n..].to_vec());
                series.extend(std::iter::repeat_n(shown as f32, n));
                (k.clone(), series)
            })
            .collect();
        let down_now = down.values().map(|s| s.last().map_or(0.0, |v| *v as f64)).sum::<f64>() as i64;
        LIVE.send_replace(Live { down, down_now, up_now: (self.c.window_up + self.c.closing_up) * 8 / seconds });
        self.c.window.clear();
        self.c.window_up = 0;
        self.c.closing.clear();
        self.c.closing_up = 0;
    }
}

/// The engine's streams arrive on the runtime: copy the values out and queue them with this subscription's generation.
fn write_connection_events(generation: i32, events: ConnectionEvents) {
    let list: Vec<Ev> = events
        .events
        .iter()
        .map(|e| {
            let c = e.connection.as_ref();
            Ev {
                kind: e.r#type,
                id: e.id.clone(),
                total: c.map(|x| (x.uplink_total, x.downlink_total)),
                delta: (e.uplink_delta, e.downlink_delta),
                tag: c.and_then(|x| first(&x.chain_list)),
                closed: c.is_some_and(|x| x.closed_at > 0),
                created: c.map_or(0, |x| x.created_at),
                own: c.is_some_and(|x| x.inbound == PROBE),
                path: c.and_then(|x| x.process_info.as_ref()).map(|p| p.process_path.clone()),
            }
        })
        .collect();
    let reset = events.reset;
    post(move |w| {
        if generation == w.generation {
            w.c.heard = now_ms();
            w.c.retries = 0;
            w.apply(list, reset);
        }
        Ok(())
    });
}

fn write_status(generation: i32) {
    post(move |w| {
        if generation != w.generation {
            return Ok(());
        }
        let now = now_ms();
        w.c.heard = now;
        // Quiet seconds bring no traffic batch: the status tick moves the live chart on by the seconds missed.
        if w.c.last_tick == 0 {
            w.c.last_tick = elapsed_realtime();
        }
        let quiet = elapsed_realtime() - w.c.last_tick;
        if w.fast() && quiet > 1_600 {
            w.sample((quiet + 500) / 1000);
        }
        if now - w.c.last_flush > 25_000 {
            w.c.last_flush = now;
            w.flush_now(false)?;
            w.checkpoint_now()?;
        }
        Ok(())
    });
}

/// The app the engine found the connection's process to be: the routed app it belongs to, else its program.
fn app_of(e: &Ev, setup: &Setup) -> String {
    let routed: Vec<&str> = setup.apps.keys().map(String::as_str).collect();
    e.path.as_deref().map_or_else(|| "?".into(), |p| apps::key_of(p, &routed))
}

/// The tunnel tag says which tunnel; when routes share it, the app's own route among them says which route.
fn exit_of(tag: Option<&str>, app: &str, setup: &Setup, tags: &IndexMap<String, String>) -> String {
    let Some(tag) = tag.filter(|t| *t != "direct") else { return DIRECT.into() };
    if tag == "home-wg" {
        return HOME.into();
    }
    let candidates: Vec<&String> = tags.iter().filter(|(_, t)| *t == tag).map(|(id, _)| id).collect();
    if candidates.is_empty() {
        return if tag == TS_TAG { HOME.into() } else { tag.strip_prefix("r-").unwrap_or(tag).into() };
    }
    let own = setup.route_of(app); // the running setup's assignment, not one still being edited
    if candidates.contains(&&own) {
        own
    } else if tag == TS_TAG {
        HOME.into()
    } else {
        candidates[0].clone()
    }
}

fn first(chain: &[String]) -> Option<String> {
    chain.iter().find(|t| t.starts_with("r-") || t.starts_with("home-") || *t == "direct").cloned()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, OvpnProfile, SsProfile, WgPeer};

    fn nl() -> Route {
        Route::new("r1", Location::country("nord", 153, "nl", "Netherlands"))
    }

    fn with_loc(r: &Route, loc: Location) -> Route {
        Route { loc, ..r.clone() }
    }

    #[test]
    fn provider_and_place_make_a_new_history() {
        let nl = nl();
        let id = id_of(&nl);
        assert!(id.starts_with("r1@"));
        assert_ne!(id, id_of(&with_loc(&nl, Location { provider: "mullvad".into(), ..nl.loc.clone() })));
        assert_ne!(
            id,
            id_of(&with_loc(&nl, Location { country_code: Some("de".into()), country_id: Some(81), ..nl.loc.clone() }))
        );
        assert_ne!(
            id,
            id_of(&with_loc(&nl, Location { city_id: Some(1), city: Some("Amsterdam".into()), ..nl.loc.clone() }))
        );
        let pinned = Server {
            name: "nl1".into(),
            host: "nl1.example".into(),
            ip: "1.2.3.4".into(),
            public_key: "k".into(),
            load: 0,
            ..Server::default()
        };
        assert_ne!(id, id_of(&with_loc(&nl, Location { pinned: Some(pinned), ..nl.loc.clone() })));
        assert_ne!(id, id_of(&Route { id: "r2".into(), ..nl.clone() }));
    }

    #[test]
    fn cosmetics_keep_the_history() {
        let nl = nl();
        assert_eq!(id_of(&nl), id_of(&Route { hue: 5, filter: Some(true), ..nl.clone() }));
    }

    #[test]
    fn imported_servers_by_address_not_secret() {
        let bare = Route::new("r1", Location::default());
        let wg = Route {
            wg: Some(WgPeer::new(
                "home",
                "PRIVATE",
                vec!["10.0.0.2/32".into()],
                "PUB",
                "1.2.3.4:51820",
                vec!["0.0.0.0/0".into()],
            )),
            ..bare.clone()
        };
        let peer = wg.wg.clone().unwrap();
        assert_eq!(
            id_of(&wg),
            id_of(&Route {
                wg: Some(WgPeer { private_key: "OTHER".into(), name: "renamed".into(), ..peer.clone() }),
                ..wg.clone()
            })
        );
        assert_ne!(
            id_of(&wg),
            id_of(&Route { wg: Some(WgPeer { endpoint: "5.6.7.8:51820".into(), ..peer }), ..wg.clone() })
        );
        let profile = OvpnProfile {
            name: "x".into(),
            config: "client\nremote a.example 1194\n<auth-user-pass>\nremote x\nSECRET\n</auth-user-pass>".into(),
            username: "u".into(),
            password: "p".into(),
        };
        let ov = Route { ovpn: Some(profile.clone()), ..bare.clone() };
        let with = |p: OvpnProfile| Route { ovpn: Some(p), ..ov.clone() };
        let config = |c: &str| OvpnProfile { config: c.into(), ..profile.clone() };
        assert_eq!(
            id_of(&ov),
            id_of(&with(OvpnProfile {
                name: "renamed".into(),
                config: "client\nremote a.example 1194\n<auth-user-pass>\nremote y\nNEW\n</auth-user-pass>".into(),
                password: "q".into(),
                ..profile.clone()
            }))
        );
        assert_ne!(id_of(&ov), id_of(&with(config("client\nremote b.example 1194"))));
        assert_ne!(id_of(&ov), id_of(&with(config("client\nremote a.example 443"))));
        assert_ne!(id_of(&ov), id_of(&with(config("client\nremote a.example 1194\nproto tcp"))));
        let shadow = SsProfile {
            name: "s".into(),
            server: "9.9.9.9".into(),
            port: 8388,
            method: "aes".into(),
            password: "pw".into(),
            plugin: None,
            plugin_opts: None,
        };
        let ss = Route { ss: Some(shadow.clone()), ..bare.clone() };
        assert_eq!(
            id_of(&ss),
            id_of(&Route { ss: Some(SsProfile { password: "other".into(), ..shadow }), ..ss.clone() })
        );
        assert_ne!(id_of(&ss), id_of(&Route { ts_exit: Some("100.64.0.1".into()), ..bare }));
        for r in [&wg, &ov, &ss] {
            for secret in ["PRIVATE", "SECRET", "pw", "PUB"] {
                assert!(!id_of(r).contains(secret));
            }
        }
    }

    #[test]
    fn older_rows_are_legacy() {
        assert!(legacy("r1"));
        assert!(!legacy(&id_of(&nl())));
        assert!(!legacy(HOME));
        assert!(!legacy("direct"));
        assert!(!legacy("ts:100.64.0.1"));
    }

    /// Each connection counts once: in full when it opens while listening, then by its changes and the rest at its
    /// close; a replay adds only what happened unheard, and baselines what was open before recording began.
    #[test]
    fn connections_count_once() {
        let ev = |kind, id: &str, total: Option<(i64, i64)>, delta, closed, created| Ev {
            kind,
            id: id.into(),
            total,
            delta,
            tag: Some("r-nl".into()),
            closed,
            created,
            own: false,
            path: None,
        };
        // Its own route id: labels are the whole process's.
        let r7 = Route { id: "r7".into(), ..nl() };
        let setup = Setup { routes: vec![r7.clone()], default_route: "r7".into(), ..Setup::default() };
        let mut w = Worker::new(None);
        w.c.engine = (setup, [("r7".to_string(), "r-nl".to_string())].into_iter().collect(), IndexMap::new());
        w.c.started_at = 1_000;
        w.apply(
            vec![
                ev(NEW, "a", Some((100, 1000)), (0, 0), false, 2_000),
                ev(UPDATE, "a", None, (10, 20), false, 0),
                ev(CLOSED, "a", Some((150, 1100)), (0, 0), true, 2_000),
            ],
            false,
        );
        // A close whose New the engine dropped: in full if it began while listening, else not at all.
        w.apply(
            vec![ev(CLOSED, "b", Some((1, 2)), (0, 0), true, 3_000), ev(CLOSED, "c", Some((1, 2)), (0, 0), true, 500)],
            false,
        );
        // A replay: "a" was counted to its close, "d" was open before recording began, "e" began unheard.
        w.c.count_from = 2_500;
        w.apply(
            vec![
                ev(NEW, "a", Some((150, 1100)), (0, 0), true, 2_000),
                ev(NEW, "d", Some((7, 7)), (0, 0), false, 0),
                ev(NEW, "e", Some((3, 3)), (0, 0), false, 2_600),
            ],
            true,
        );
        w.apply(vec![ev(UPDATE, "d", None, (5, 5), false, 0)], false);
        let sums: Vec<(i64, i64)> = w
            .daily
            .iter()
            .map(|((_, app, exit), s)| {
                assert_eq!(("?", id_of(&r7)), (app.as_str(), exit.clone()));
                (s.up, s.down)
            })
            .collect();
        assert_eq!(vec![(100 + 10 + 40 + 1 + 3 + 5, 1000 + 20 + 80 + 2 + 3 + 5)], sums);
        assert_eq!(i64::MAX, w.c.count_from);
        assert_eq!(vec!["d", "e"], {
            let mut seen: Vec<&str> = w.c.seen.keys().map(String::as_str).collect();
            seen.sort();
            seen
        });
    }

    /// A history the earlier app kept opens unchanged: its ids, its database (made at an older version and upgraded in
    /// place) and the rows it wrote, which the app reads and adds to as before.
    #[test]
    fn the_earlier_apps_history_reads_on() {
        // The earlier app's ids: the same digest of the same fields.
        assert_eq!("r1@ac9778c8bc", id_of(&nl()));
        let wg = WgPeer::new(
            "home",
            "PRIVATE",
            vec!["10.0.0.2/32".into()],
            "PUB",
            "1.2.3.4:51820",
            vec!["0.0.0.0/0".into()],
        );
        assert_eq!("r1@87f9bc57d1", id_of(&Route { wg: Some(wg), ..Route::new("r1", Location::default()) }));

        // A version 1 database, as the earlier app first made it (no upload peaks, no combined runs), and its rows.
        let tmp = tempfile::tempdir().unwrap();
        let earlier = rusqlite::Connection::open(tmp.path().join("stats.db")).unwrap();
        let (now, nl) = (now_ms(), "r1@ac9778c8bc");
        let (h, d) = (hour_of(now), day_of(now));
        earlier
            .execute_batch(
                "CREATE TABLE hourly(h INTEGER, exit TEXT, up INTEGER, down INTEGER, PRIMARY KEY(h, exit)) WITHOUT ROWID;
                 CREATE TABLE daily(d INTEGER, app TEXT, exit TEXT, up INTEGER, down INTEGER, PRIMARY KEY(d, app, exit)) WITHOUT ROWID;
                 CREATE TABLE server(d INTEGER, exit TEXT, name TEXT, bytes INTEGER, PRIMARY KEY(d, exit, name)) WITHOUT ROWID;
                 CREATE TABLE peak(d INTEGER, exit TEXT, bps INTEGER, at INTEGER, PRIMARY KEY(d, exit)) WITHOUT ROWID;
                 CREATE TABLE span(start INTEGER PRIMARY KEY, end INTEGER, paused INTEGER);
                 CREATE TABLE exit(id TEXT PRIMARY KEY, code TEXT, name TEXT, hue INTEGER, via TEXT);
                 CREATE TABLE test(at INTEGER PRIMARY KEY, exit TEXT, via TEXT, server TEXT, ip TEXT, down INTEGER, up INTEGER, idle INTEGER, busy_down INTEGER, busy_up INTEGER);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        let upsert = |sql: &str, p: &[&dyn rusqlite::ToSql]| earlier.execute(sql, p).unwrap();
        for _ in 0..2 {
            upsert(
                "INSERT INTO hourly VALUES(?,?,?,?) ON CONFLICT(h, exit) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                &[&h, &nl, &10i64, &100i64],
            );
            upsert(
                "INSERT INTO daily VALUES(?,?,?,?,?) ON CONFLICT(d, app, exit) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                &[&d, &"firefox", &nl, &10i64, &100i64],
            );
            upsert(
                "INSERT INTO server VALUES(?,?,?,?) ON CONFLICT(d, exit, name) DO UPDATE SET bytes=bytes+excluded.bytes",
                &[&d, &nl, &"nl812.nordvpn.com", &110i64],
            );
        }
        upsert(
            "INSERT INTO daily VALUES(?,?,?,?,?) ON CONFLICT(d, app, exit) DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
            &[&d, &"?", &"direct", &1i64, &2i64],
        );
        upsert("INSERT OR REPLACE INTO exit VALUES(?,?,?,?,?)", &[&nl, &"NL", &"Netherlands", &2, &"NordVPN"]);
        upsert("INSERT INTO peak VALUES(?,?,?,?)", &[&d, &nl, &5_000_000i64, &now]);
        upsert("INSERT OR REPLACE INTO span VALUES(?,?,?)", &[&(now - 60_000), &(now - 30_000), &0]);
        upsert("INSERT OR REPLACE INTO span VALUES(?,?,?)", &[&(now - 30_000), &(now - 10_000), &1]);
        upsert(
            "INSERT INTO test(at, exit, via, server, ip, down, up, idle, busy_down, busy_up) VALUES((SELECT MAX(?, IFNULL(MAX(at), 0) + 1) FROM test),?,?,?,?,?,?,?,?,?)",
            &[&(now - 5_000), &nl, &"NordVPN", &"nl812", &"203.0.113.7", &90_000_000i64, &20_000_000i64, &14, &0, &0],
        );
        drop(earlier);

        // Read by this app: upgraded in place to version 3, everything where it was.
        let mut w = Worker::new(Some(tmp.path().to_path_buf()));
        let exit = Exit { id: nl.into(), code: "NL".into(), name: "Netherlands".into(), hue: 2, via: "NordVPN".into() };
        assert_eq!(Some(&exit), w.exits().get(nl));
        let per_day = w.per_day(d - 1, d);
        assert_eq!(Some(&Bytes { up: 20, down: 200 }), per_day[&d].get(nl));
        assert_eq!(Some(&Bytes { up: 1, down: 2 }), per_day[&d].get("direct"));
        assert_eq!(Some(&Bytes { up: 20, down: 200 }), w.per_hour(d)[&(h - d * 24)].get(nl));
        assert_eq!(
            vec![("firefox".to_string(), nl.to_string(), 220), ("?".to_string(), "direct".to_string(), 3)],
            w.apps(d, d)
        );
        assert_eq!(vec![("nl812.nordvpn.com".to_string(), 220)], w.servers(nl, d, d));
        assert_eq!(
            vec![(now - 60_000, now - 30_000, false), (now - 30_000, now - 10_000, true)],
            w.spans(now - 3_600_000, now)
        );
        let test = Test {
            at: now - 5_000,
            exit: nl.into(),
            via: "NordVPN".into(),
            server: "nl812".into(),
            ip: "203.0.113.7".into(),
            down: 90_000_000,
            up: 20_000_000,
            idle: 14,
            busy_down: 0,
            busy_up: 0,
            grp: 0,
            n: 1,
        };
        assert_eq!(vec![test], w.tests());
        assert_eq!(3, w.db().unwrap().version().unwrap());

        // Added to as the earlier app did: the same rows grow.
        w.add(now, "firefox", nl, Some("nl812.nordvpn.com"), 5, 50);
        w.flush_now(true).unwrap();
        assert_eq!(Some(&Bytes { up: 25, down: 250 }), w.per_day(d, d)[&d].get(nl));
        assert_eq!(vec![("nl812.nordvpn.com".to_string(), 275)], w.servers(nl, d, d));
        w.prune_now().unwrap();
        assert_eq!(1, w.tests().len());
        assert_eq!(Some(&exit), w.exits().get(nl));
    }
}
