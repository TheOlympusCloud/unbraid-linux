//! The Stats page: what went where, how fast, and the speed tests.
//!
//! A hub of tiles, each opening its section (Usage, Live, App flows, Journal, Tunnels and one tunnel); the speed test
//! and its History hang off Live and Tunnels. Everything is read from the local stats file ([`read`]); nothing exists
//! while statistics are off.

use crate::model::{DIRECT, Route, Setup};
use crate::speed_test::{self, ALL, All, Leg, Phase as Stage, Run};
use crate::stats::{self, Bytes, Exit, Live, Test};
use crate::vpn::{Phase, TsNode, VpnState};
use crate::{APP, catalog, providers};
use chrono::{Datelike, Local, Months, NaiveDate, NaiveDateTime, TimeDelta, TimeZone, Timelike};
use indexmap::{IndexMap, IndexSet};

const GB: f64 = 1e9;
const HOUR_MS: f32 = 3_600_000.0;
/// The app list of App flows shows this many until asked for all.
const LIST: usize = 12;

/// An exit's colour as rows give it: a route's hue (0 and up), or one of these inks.
pub const INK_TEXT: i32 = -1;
pub const INK_DIRECT: i32 = -2;
pub const INK_FAINT: i32 = -3;
/// Neutral bars and meters: the text's ink at 75 %.
pub const INK_NEUTRAL: i32 = -4;
pub const INK_ACCENT: i32 = -5;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Period {
    Day,
    #[default]
    Week,
    Month,
}

impl Period {
    /// In the picker's order, which is also the page's index for them.
    pub const ALL: [Period; 3] = [Period::Day, Period::Week, Period::Month];

    pub fn label(self) -> &'static str {
        match self {
            Period::Day => "Day",
            Period::Week => "Week",
            Period::Month => "Month",
        }
    }
}

// ---- figures ---------------------------------------------------------------------------------------------------------

/// `v` with `places` decimals, rounded half up as the approved figures are.
fn fixed(v: f64, places: usize) -> String {
    let f = 10f64.powi(places as i32);
    format!("{:.*}", places, (v * f).round() / f)
}

/// Data as a figure and its unit: ("4.4", "GB"), ("293", "MB"), ("980", "kB").
pub fn bytes(b: i64) -> (String, String) {
    let v = b as f64;
    if v >= GB {
        (fixed(v / GB, 1), "GB".into())
    } else if b >= 1_000_000 {
        (fixed(v / 1e6, 0), "MB".into())
    } else {
        (fixed(v / 1e3, 0), "kB".into())
    }
}

/// Data in words: "4.4 GB".
pub fn bytes_text(b: i64) -> String {
    let (n, u) = bytes(b);
    format!("{n} {u}")
}

/// A live speed: kbps under 1 Mbps, so small transfers don't read as zero.
pub fn rate(bps: i64) -> (String, String) {
    if bps >= 1_000_000 {
        (mbps(bps), "Mbps".into())
    } else if bps >= 100 {
        let k = fixed(bps as f64 / 1e3, 0);
        (if k == "0" { "0.1".into() } else { k }, "kbps".into())
    } else {
        ("0".into(), "kbps".into())
    }
}

/// Mbps, with a decimal below 100: "9.4", "940".
pub fn mbps(bps: i64) -> String {
    let m = bps as f64 / 1e6;
    if m < 100.0 { fixed(m, 1) } else { (m as i64).to_string() }
}

/// Several exits added up: Gbps from 1000 Mbps on.
fn total(bps: i64) -> (String, String) {
    if bps >= 1_000_000_000 { (fixed(bps as f64 / 1e9, 2), "Gbps".into()) } else { (mbps(bps), "Mbps".into()) }
}

/// A duration in words: "3 h 20 m", or "45 m" under an hour.
fn hm(ms: i64) -> String {
    let m = ms / 60_000;
    if m >= 60 { format!("{} h {} m", m / 60, m % 60) } else { format!("{m} m") }
}

/// One part of a measurement: its figure, large, and its unit, small ("3" "h").
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NumPart {
    pub value: String,
    pub unit: String,
}

fn part(value: impl Into<String>, unit: impl Into<String>) -> NumPart {
    NumPart { value: value.into(), unit: unit.into() }
}

/// A duration as measurement parts: 3 h 20 m, or 45 m under an hour.
fn hm_parts(ms: i64) -> Vec<NumPart> {
    let m = ms / 60_000;
    if m >= 60 {
        vec![part((m / 60).to_string(), "h"), part((m % 60).to_string(), "m")]
    } else {
        vec![part(m.to_string(), "m")]
    }
}

/// The next round scale value at or above `x`: 1, 2, 2.5 or 5 times a power of ten.
fn nice_ceil(x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    let m = 10f64.powf(x.log10().floor());
    [1.0, 2.0, 2.5, 5.0, 10.0].into_iter().find(|s| s * m >= x * 0.999).unwrap_or(10.0) * m
}

/// The unit a chart of byte counts up to `max` reads best in, with its divisor.
fn unit_for(max: i64) -> (f64, &'static str) {
    if max as f64 >= GB {
        (GB, "GB")
    } else if max >= 1_000_000 {
        (1e6, "MB")
    } else {
        (1e3, "kB")
    }
}

/// A scale's top as its label says it: whole numbers bare, others with one decimal.
fn scale_text(v: f32) -> String {
    if v == v.trunc() { (v as i64).to_string() } else { fixed(v as f64, 1) }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

// ---- days ------------------------------------------------------------------------------------------------------------

/// Days since 1970-01-01, as the stats file numbers them.
pub fn epoch_day(d: NaiveDate) -> i64 {
    d.signed_duration_since(NaiveDate::default()).num_days()
}

fn date(epoch_day: i64) -> NaiveDate {
    NaiveDate::default() + TimeDelta::days(epoch_day)
}

fn days(d: NaiveDate, n: i64) -> NaiveDate {
    d + TimeDelta::days(n)
}

/// Local midnight of `d`, in epoch ms; where a clock change skips midnight, the first time the day has.
pub fn start_ms(d: NaiveDate) -> i64 {
    (0..3)
        .find_map(|h| Local.from_local_datetime(&d.and_hms_opt(h, 0, 0)?).earliest())
        .map_or(0, |t| t.timestamp_millis())
}

fn monday(d: NaiveDate) -> NaiveDate {
    days(d, -(d.weekday().num_days_from_monday() as i64))
}

/// The first and last day of `p` around `today`.
pub fn range(p: Period, today: NaiveDate) -> (NaiveDate, NaiveDate) {
    match p {
        Period::Day => (today, today),
        Period::Week => (monday(today), days(monday(today), 6)),
        Period::Month => {
            let first = today.with_day(1).unwrap_or(today);
            (first, first.checked_add_months(Months::new(1)).map_or(today, |next| days(next, -1)))
        }
    }
}

/// "TODAY · 11 NOV", "9–15 NOV", "1–30 NOV".
pub fn range_label(p: Period, today: NaiveDate) -> String {
    let (a, b) = range(p, today);
    match p {
        Period::Day => format!("Today · {}", today.format("%-d %b")),
        _ => format!("{}–{}", a.day(), b.format("%-d %b")),
    }
    .to_uppercase()
}

/// Weekdays' initials, Monday first.
const WEEKDAYS: [&str; 7] = ["M", "T", "W", "T", "F", "S", "S"];

/// The Journal's 13 weeks start on this Monday.
fn heat_start(today: NaiveDate) -> NaiveDate {
    days(monday(today), -7 * 12)
}

// ---- what the stats file holds ---------------------------------------------------------------------------------------

/// What the page reads from the stats file for one period ([`read`]).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Data {
    /// Every exit's label as last noted, by stats id.
    pub exits: IndexMap<String, Exit>,
    /// Bytes per exit for each day of the period.
    pub days: IndexMap<i64, IndexMap<String, Bytes>>,
    /// Bytes per exit for each hour of today: the Day view only.
    pub hours: IndexMap<i64, IndexMap<String, Bytes>>,
    /// Bytes per app and exit over the period, largest first.
    pub apps: Vec<(String, String, i64)>,
    /// Every speed test kept, newest first.
    pub tests: Vec<Test>,
    /// Connected and paused spans of the Journal's 13 weeks, up to now.
    pub spans: Vec<(i64, i64, bool)>,
    /// The servers of the tunnel open, with their bytes in the period.
    pub servers: Vec<(String, i64)>,
}

/// Reads [`Data`] for `period` as of `today`, with the servers of `tunnel` (a stats id) when one is open. It blocks on
/// the statistics worker: call it off the window's thread. None when the file can't be read.
pub fn read(period: Period, today: NaiveDate, tunnel: Option<&str>) -> Option<Data> {
    let (a, b) = range(period, today);
    let (from, to) = (epoch_day(a), epoch_day(b));
    let (lo, hi) = (start_ms(heat_start(today)), start_ms(days(today, 1)));
    let tunnel = tunnel.map(String::from);
    stats::read(move |w| Data {
        exits: w.exits(),
        days: w.per_day(from, to),
        hours: if period == Period::Day { w.per_hour(from) } else { IndexMap::new() },
        apps: w.apps(from, to),
        tests: w.tests(),
        spans: w.spans(lo, hi),
        servers: tunnel.map(|t| w.servers(&t, from, to)).unwrap_or_default(),
    })
}

// ---- inputs ----------------------------------------------------------------------------------------------------------

/// What the page reads besides the stats file: the store, the connection, and what the window keeps for the page.
pub struct Inputs<'a> {
    /// Read for `period`; none until the first read is in.
    pub data: Option<&'a Data>,
    pub period: Period,
    /// The section open: "" for the hub, or "usage", "live", "flows", "journal", "tunnels", "tunnel:<id>", "speed",
    /// "history".
    pub section: &'a str,
    /// The computer's clock: today, and the hour the Day view marks.
    pub now: NaiveDateTime,
    pub setup: &'a Setup,
    /// The setup the connection runs ([`crate::vpn::Live::running`]); none while off.
    pub running: Option<&'a Setup>,
    pub vpn: &'a VpnState,
    /// Route ids with a tunnel, and its tag ([`crate::vpn::Live::tags`]).
    pub tags: &'a IndexMap<String, String>,
    /// The live samples ([`stats::live`]).
    pub live: &'a Live,
    /// The installed apps' names, by key.
    pub labels: &'a IndexMap<String, String>,
    /// The stats file holds something ([`stats::size`] above 0).
    pub has_data: bool,
    /// App flows: the exit its list is filtered to, and whether the whole list is open.
    pub flows_exit: Option<&'a str>,
    pub flows_all: bool,
    /// The Journal's day, as an epoch day; none for the last day with data.
    pub journal_day: Option<i64>,
    pub speed: SpeedInputs<'a>,
}

/// What the speed test reads besides the page's inputs: the tests under way and the window's choices for them.
#[derive(Clone, Copy, Default)]
pub struct SpeedInputs<'a> {
    /// The test of one exit ([`speed_test::run`]) and the combined run ([`speed_test::all`]).
    pub run: Option<&'a Run>,
    pub all: Option<&'a All>,
    /// Tailscale exit nodes no route uses, which a test switches to ([`speed_test::nodes`]).
    pub nodes: &'a [TsNode],
    /// A test or a combined run is under way ([`speed_test::testing`]).
    pub testing: bool,
    /// The exit picked: a route's id, a node's ([`speed_test::NODE`] and its address) or [`ALL`]; none until one is.
    pub chosen: Option<&'a str>,
    /// Routes unticked for a combined run.
    pub unticked: &'a [String],
    /// Exits without a test server in their country that the sheet before a combined run leaves out.
    pub leave_out: &'a [String],
    /// Tests counted today on this computer ([`crate::store::Store::tests_today`]).
    pub tests_today: i32,
}

/// An exit as stats show it: the route's current look if it still exists, else the label it had when used.
#[derive(Clone, Debug, PartialEq)]
struct Ex {
    code: String,
    name: String,
    via: String,
    hue: i32,
}

/// Everything the hub and the sections read for one period.
struct Loaded<'a> {
    from: i64,
    to: i64,
    exits: IndexMap<String, Ex>,
    by_exit: Vec<(String, Bytes)>,
    total: Bytes,
    columns: Vec<IndexMap<String, Bytes>>,
    selected: i32,
    apps: &'a [(String, String, i64)],
    /// Each exit's fastest solo speed test in the period (by download).
    tests: IndexMap<String, &'a Test>,
    week: Vec<f32>,
    week_ms: i64,
    heat: Vec<f32>,
    heat_start: NaiveDate,
}

impl Loaded<'_> {
    fn ex(&self, id: &str) -> Option<&Ex> {
        self.exits.get(id)
    }

    fn name(&self, id: &str) -> String {
        self.ex(id).map_or_else(|| id.to_string(), |e| e.name.clone())
    }

    fn code(&self, id: &str) -> String {
        self.ex(id).map_or_else(|| "?".into(), |e| e.code.clone())
    }

    fn hue(&self, id: &str) -> i32 {
        self.ex(id).map_or(INK_FAINT, |e| e.hue)
    }

    /// An exit's speed in the period: its best speed test. Speeds seen in use are not shown.
    fn fastest(&self, id: &str) -> i64 {
        self.tests.get(id).map_or(0, |t| t.down)
    }

    /// Data by who carried it, largest first.
    fn by_provider(&self) -> Vec<(String, i64)> {
        let mut all: IndexMap<String, i64> = IndexMap::new();
        for (id, b) in &self.by_exit {
            *all.entry(provider_of(id, self.ex(id))).or_default() += b.total();
        }
        let mut all: Vec<(String, i64)> = all.into_iter().collect();
        all.sort_by_key(|p| std::cmp::Reverse(p.1));
        all
    }
}

/// Who carried an exit's data: its provider's name, "Own servers" for imported configs (only their protocol is known),
/// Tailscale, or the home network.
fn provider_of(id: &str, ex: Option<&Ex>) -> String {
    match ex {
        // Apps following a Direct default, and Direct apps under lockdown.
        _ if id == DIRECT => "Direct, no VPN".into(),
        _ if id == stats::HOME => "Home network".into(),
        None => "Other".into(),
        Some(e) if e.via.is_empty() => "Other".into(),
        Some(e) if ["WireGuard", "OpenVPN", "Shadowsocks"].contains(&e.via.as_str()) => "Own servers".into(),
        Some(e) => providers::all()
            .into_iter()
            .find(|p| providers::short(p.id()) == e.via)
            .map_or_else(|| e.via.clone(), |p| p.name().to_string()),
    }
}

fn load<'a>(d: &'a Data, i: &Inputs) -> Loaded<'a> {
    let today = i.now.date();
    let (a, b) = range(i.period, today);
    let (from, to) = (epoch_day(a), epoch_day(b));
    // History is keyed by what carried it: today's routes label only their own ids, older ones keep their stored label.
    let mut current: IndexMap<String, &Route> = IndexMap::new();
    for r in i.setup.routes.iter().chain(i.running.map_or(&[][..], |s| &s.routes[..])) {
        current.insert(stats::id_of(r), r);
    }
    let ids: IndexSet<String> = d.exits.keys().chain(current.keys()).cloned().chain([DIRECT.to_string()]).collect();
    let exits = ids
        .into_iter()
        .map(|id| {
            let stored = d.exits.get(&id);
            let hue = |s: &Exit| if s.hue < 0 { INK_TEXT } else { s.hue };
            let ex = match (current.get(&id), stored) {
                (Some(r), _) => Ex { code: r.code(), name: r.name(), via: r.source(), hue: r.hue },
                _ if id == DIRECT => {
                    Ex { code: "··".into(), name: "Direct".into(), via: "outside the VPN".into(), hue: INK_DIRECT }
                }
                // Older rows of a route sit beside its new history: their name says so, or both would read the same.
                (None, Some(s)) if stats::legacy(&id) => Ex {
                    code: s.code.clone(),
                    name: format!("{} (older data)", s.name),
                    via: "Unknown (older data)".into(),
                    hue: hue(s),
                },
                (None, Some(s)) => Ex { code: s.code.clone(), name: s.name.clone(), via: s.via.clone(), hue: hue(s) },
                (None, None) => Ex { code: "?".into(), name: id.clone(), via: String::new(), hue: INK_FAINT },
            };
            (id, ex)
        })
        .collect();
    let mut by_exit: IndexMap<String, Bytes> = IndexMap::new();
    for day in d.days.values() {
        for (e, v) in day {
            let b = by_exit.entry(e.clone()).or_default();
            b.up += v.up;
            b.down += v.down;
        }
    }
    let total = by_exit.values().fold(Bytes::default(), |x, y| Bytes { up: x.up + y.up, down: x.down + y.down });
    let mut by_exit: Vec<(String, Bytes)> = by_exit.into_iter().collect();
    by_exit.sort_by_key(|e| std::cmp::Reverse(e.1.total()));
    let columns = if i.period == Period::Day {
        (0..24).map(|h| d.hours.get(&h).cloned().unwrap_or_default()).collect()
    } else {
        (from..=to).map(|e| d.days.get(&e).cloned().unwrap_or_default()).collect()
    };
    // Solo tests only: an exit sharing the line with others in a combined run reads lower than it is.
    let (lo, hi) = (start_ms(a), start_ms(days(b, 1)));
    let mut tests: IndexMap<String, &Test> = IndexMap::new();
    for t in d.tests.iter().filter(|t| t.grp == 0 && t.at >= lo && t.at < hi) {
        let best = tests.entry(t.exit.clone()).or_insert(t);
        if t.down > best.down {
            *best = t;
        }
    }
    // Hours connected per day, the last 13 weeks ending this Sunday; this week's days for the hub.
    let start = heat_start(today);
    let on: Vec<&(i64, i64, bool)> = d.spans.iter().filter(|s| !s.2).collect();
    let heat: Vec<f32> = (0..91)
        .map(|k| {
            let day = days(start, k);
            if day > today {
                return -1.0;
            }
            let (lo, hi) = (start_ms(day), start_ms(days(day, 1)));
            on.iter().map(|s| (s.1.min(hi) - s.0.max(lo)).max(0)).sum::<i64>() as f32 / HOUR_MS
        })
        .collect();
    let week = heat[84..].to_vec();
    let week_ms = (week.iter().filter(|h| **h > 0.0).sum::<f32>() * HOUR_MS) as i64;
    Loaded {
        from,
        to,
        exits,
        by_exit,
        total,
        columns,
        selected: if i.period == Period::Day { i.now.hour() as i32 } else { (epoch_day(today) - from) as i32 },
        apps: &d.apps,
        tests,
        week,
        week_ms,
        heat,
        heat_start: start,
    }
}

// ---- what the page shows ---------------------------------------------------------------------------------------------

/// A bar's slice, or a chart's part: its value and its exit's colour ([`INK_TEXT`] and the like, or a route's hue).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Part {
    pub value: f32,
    pub hue: i32,
}

/// The colour and name of an exit in a chart's key.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Legend {
    pub name: String,
    pub hue: i32,
}

/// A provider's share of the period's data: its name, its data and share ("4.4 GB  100%"), the share alone and as a
/// fraction.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Share {
    pub name: String,
    pub value: String,
    pub pct: String,
    pub frac: f32,
}

/// An exit's speed beside the fastest: its code and colour, and its fraction of the fastest.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedBar {
    pub code: String,
    pub hue: i32,
    pub frac: f32,
}

/// One app of the hub's Apps card: its name, the exit that carried most of it, its share of the biggest, its data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AppBar {
    pub name: String,
    pub code: String,
    pub hue: i32,
    pub frac: f32,
    pub bytes: String,
}

/// One exit of the hub's Exits card: its mark, name, how many apps used it ("2 apps"), its data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExitBar {
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub apps: String,
    pub bytes: String,
}

/// The hub: four tiles (Usage, Live, Journal, Tunnels), the period's data by exit, then the apps and the exits.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HubView {
    pub overline: String,
    pub usage: NumPart,
    /// "↓ 4.1 GB · ↑ 293 MB".
    pub usage_line: String,
    /// Who carried it, by provider: the first two.
    pub providers: Vec<Share>,
    /// Connected: Live shows the download now and the last minute.
    pub live: bool,
    pub live_now: NumPart,
    pub spark: Vec<f32>,
    pub week: Vec<NumPart>,
    /// Hours connected each day this week (none yet: 0), and today's index, Monday 0.
    pub week_hours: Vec<f32>,
    pub today: i32,
    /// A speed test in the period: the best download, whose it is, and the two fastest exits.
    pub tested: bool,
    pub best: String,
    pub best_line: String,
    pub fastest: Vec<SpeedBar>,
    /// The chart's key (five exits at most) and its bars, each in its exits' colours.
    pub legend: Vec<Legend>,
    pub columns: Vec<Vec<Part>>,
    pub summary: String,
    pub apps: Vec<AppBar>,
    pub exits: Vec<ExitBar>,
}

/// Usage: the period's data per hour or day, and who carried it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UsageView {
    /// "Week · per day".
    pub over: String,
    pub value: NumPart,
    pub sub: String,
    /// "today 60 MB", or "now 60 MB" by hour.
    pub trailing: String,
    /// Bars in one ink: how much, when (which exit is App flows' subject).
    pub columns: Vec<Vec<Part>>,
    pub summary: String,
    pub label: String,
    pub providers: Vec<Share>,
}

/// One exit's live line: its series in Mbps and its colour.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Series {
    pub values: Vec<f32>,
    pub hue: i32,
}

/// One exit in Live: its mark, name and provider, and its download now.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LiveRow {
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub via: String,
    pub now: NumPart,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct LiveView {
    pub overline: String,
    /// Why nothing is measured ("Connect to see live speeds."); empty when it is.
    pub empty: String,
    pub now: NumPart,
    pub sub: String,
    pub series: Vec<Series>,
    pub cap: f32,
    pub summary: String,
    pub rows: Vec<LiveRow>,
}

/// An app's name and data on its exit's lane: "Firefox" "1.8 GB".
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Named {
    pub name: String,
    pub bytes: String,
}

/// One exit as a lane of App flows: its data and share, how many apps use it, a bar as long as its data (against the
/// biggest exit) split by its five biggest apps and the rest, and one line naming them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Lane {
    pub id: String,
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub apps: String,
    pub bytes: String,
    pub pct: String,
    /// The bar's length, against the biggest exit.
    pub frac: f32,
    /// The bar's segments: the five biggest apps, fading, then the rest.
    pub segments: Vec<Segment>,
    pub names: Vec<Named>,
    /// "+3 apps 120 MB"; empty when none.
    pub rest: String,
    pub selected: bool,
}

/// A part of a lane's bar, in the lane's colour at `alpha`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Segment {
    pub weight: f32,
    pub alpha: f32,
}

/// A filter pill over the app list: the exit (none for All), its words ("Netherlands 2") and whether it's on.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pill {
    pub id: String,
    pub code: String,
    pub hue: i32,
    pub text: String,
    pub on: bool,
}

/// One app in App flows: its key (for its icon), initial and name, its exit, its data and its share of the first.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowRow {
    pub pkg: String,
    pub letter: String,
    pub name: String,
    pub code: String,
    pub hue: i32,
    pub bytes: String,
    pub frac: f32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FlowsView {
    pub sub: String,
    /// No app used an exit in the period.
    pub empty: bool,
    /// The exits' shares of all data, as one thin bar.
    pub share: Vec<Part>,
    pub lanes: Vec<Lane>,
    pub pills: Vec<Pill>,
    pub rows: Vec<FlowRow>,
    /// "Show all 14" or "Show fewer"; empty when the list is short.
    pub more: String,
}

/// A month's name over the heatmap's week it starts in.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MonthMark {
    pub week: i32,
    pub name: String,
}

/// A stretch of the Journal's day, as fractions of it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DaySpan {
    pub from: f32,
    pub to: f32,
    pub paused: bool,
}

/// One of the Journal day's three figures and what it counts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fact {
    pub parts: Vec<NumPart>,
    pub label: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct JournalView {
    pub week: Vec<NumPart>,
    pub sub: String,
    /// Hours connected per day, 13 weeks from a Monday; negative: not yet.
    pub heat: Vec<f32>,
    pub months: Vec<MonthMark>,
    /// The day shown: its index in `heat`, its epoch day and its date in words.
    pub index: i32,
    pub day: i32,
    pub date: String,
    pub has_prev: bool,
    pub has_next: bool,
    pub spans: Vec<DaySpan>,
    pub summary: String,
    pub facts: Vec<Fact>,
}

/// One exit in Tunnels: its stats id, look, and its fastest test ("↓1080 ↑940") with its fraction of the fastest.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TunnelRow {
    pub id: String,
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub via: String,
    pub tested: bool,
    pub test: String,
    pub frac: f32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TunnelsView {
    /// The fastest test of the period, if any: its download and the line under it.
    pub tested: bool,
    pub best: String,
    pub sub: String,
    pub rows: Vec<TunnelRow>,
}

/// One server of a tunnel: its name and share of the exit's data.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerRow {
    pub name: String,
    pub pct: String,
    pub frac: f32,
}

/// One exit, from Tunnels.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TunnelView {
    pub id: String,
    pub overline: String,
    pub title: String,
    pub hue: i32,
    pub tested: bool,
    pub best: String,
    pub sub: String,
    pub servers: Vec<ServerRow>,
}

/// One of a combined run's exits, under its History row.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Member {
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub down: String,
    pub up: String,
    pub ping: String,
}

/// One test in History: alone, or a combined run (`all`) with its exits under it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HistoryRow {
    pub all: bool,
    pub code: String,
    pub hue: i32,
    pub when: String,
    pub down: String,
    pub up: String,
    pub ping: String,
    /// The provider and VPN server, or "3 exits together".
    pub line: String,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HistoryView {
    pub overline: String,
    pub tested: bool,
    pub best: String,
    pub sub: String,
    pub rows: Vec<HistoryRow>,
}

/// While statistics are off and none were opened: the page that offers them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OffView {
    pub overline: String,
    pub title: String,
    pub text: String,
    pub button: String,
    /// Statistics kept from before: they can be opened.
    pub saved: bool,
}

/// Everything the Stats page shows.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StatsView {
    pub recording: bool,
    pub off: OffView,
    /// The first read is in: the sections have something to show.
    pub loaded: bool,
    pub period: i32,
    pub section: String,
    /// Where Back and Esc go from the section.
    pub back: String,
    /// The period's days, as the sections' overline says them ("9–15 NOV").
    pub range: String,
    /// The period's chart: its labels, the top of its scale and that in words ("2.5 GB"), the column now. `empty`:
    /// no data in the period yet.
    pub labels: Vec<String>,
    pub cap: f32,
    pub scale: String,
    pub selected: i32,
    pub empty: bool,
    pub weekdays: Vec<String>,
    pub hub: HubView,
    pub usage: UsageView,
    pub live: LiveView,
    pub flows: FlowsView,
    pub journal: JournalView,
    pub tunnels: TunnelsView,
    pub tunnel: TunnelView,
    pub history: HistoryView,
    pub speed: SpeedView,
}

/// Where Back (and Esc) goes from `section`: History to the speed test, a tunnel to Tunnels, the speed test to Live,
/// the rest to the hub ("").
pub fn back(section: &str) -> &'static str {
    match section {
        "history" => "speed",
        "speed" => "live",
        s if s.starts_with("tunnel:") => "tunnels",
        _ => "",
    }
}

/// The Stats page as `i` has it.
pub fn view(i: &Inputs) -> StatsView {
    let empty = Data::default();
    let d = i.data.unwrap_or(&empty);
    let v = load(d, i);
    let today = i.now.date();
    let p = i.period;
    let max = v.columns.iter().map(|c| c.values().map(Bytes::total).sum::<i64>()).max().unwrap_or(0);
    let (div, unit) = unit_for(max);
    let cap = nice_ceil(max as f64 / div);
    let labels = if p == Period::Day {
        (0..24).map(|h| if h % 6 == 0 { format!("{h:02}") } else { String::new() }).collect()
    } else {
        (v.from..=v.to)
            .map(|e| {
                let d = date(e);
                match p {
                    Period::Week => WEEKDAYS[d.weekday().num_days_from_monday() as usize].to_string(),
                    _ if d.day() % 7 == 1 => d.day().to_string(),
                    _ => String::new(),
                }
            })
            .collect()
    };
    StatsView {
        recording: i.setup.prefs.stats,
        off: off(i.has_data),
        loaded: i.data.is_some(),
        period: Period::ALL.iter().position(|x| *x == p).unwrap_or(1) as i32,
        section: i.section.into(),
        back: back(i.section).into(),
        range: range_label(p, today),
        labels,
        cap: cap as f32,
        scale: format!("{} {unit}", scale_text(cap as f32)),
        selected: v.selected,
        empty: v.total.total() == 0,
        weekdays: WEEKDAYS.iter().map(|d| d.to_string()).collect(),
        hub: hub(i, &v, div),
        usage: usage(&v, p, div),
        live: live(i, &v),
        flows: flows(i, &v),
        journal: journal(i, &v),
        tunnels: tunnels(i, &v),
        tunnel: tunnel(i, &v),
        history: history(d, &v),
        speed: speed(i, &v),
    }
}

fn off(saved: bool) -> OffView {
    OffView {
        overline: if saved { "Recording off" } else { "Not set up" }.into(),
        title: if saved { "Stats are paused" } else { "See where your traffic goes" }.into(),
        text: if saved {
            "Nothing new is recorded. Statistics kept so far are still on this computer; delete them in Settings."
        } else {
            "Data per app and per exit, time connected and speeds. Statistics aren't uploaded, and no browsing destinations are recorded."
        }
        .into(),
        button: if saved { "Turn back on" } else { "Turn on stats" }.into(),
        saved,
    }
}

fn share(name: &str, b: i64, total: i64) -> Share {
    let total = total.max(1);
    Share {
        name: name.into(),
        value: format!("{}  {}%", bytes_text(b), 100 * b / total),
        pct: format!("{}%", 100 * b / total),
        frac: b as f32 / total as f32,
    }
}

fn hub(i: &Inputs, v: &Loaded, div: f64) -> HubView {
    let t = v.total.total();
    let (n, u) = bytes(t);
    let live_on = i.vpn.phase == Phase::On;
    let (rn, ru) = rate(i.live.down_now);
    // Each exit's fastest download test.
    let mut fastest: Vec<(&String, i64)> = v.tests.keys().map(|id| (id, v.fastest(id))).filter(|f| f.1 > 0).collect();
    let best = fastest
        .iter()
        .fold(None, |b: Option<(&String, i64)>, f| if b.is_none_or(|b| f.1 > b.1) { Some(*f) } else { b });
    fastest.sort_by_key(|f| std::cmp::Reverse(f.1));
    let order: Vec<&String> = v.by_exit.iter().map(|e| &e.0).collect();
    // The apps by data, each with the exit that carried most of it.
    let mut by_app: IndexMap<&str, (&str, i64, i64)> = IndexMap::new();
    for (app, exit, b) in v.apps {
        let e = by_app.entry(app).or_insert((exit, *b, 0));
        if *b > e.1 {
            *e = (exit, *b, e.2);
        }
        e.2 += b;
    }
    let mut by_app: Vec<(&str, &str, i64)> = by_app.into_iter().map(|(a, (e, _, b))| (a, e, b)).collect();
    by_app.sort_by_key(|a| std::cmp::Reverse(a.2));
    let most = by_app.first().map_or(1, |a| a.2.max(1));
    HubView {
        overline: if i.setup.prefs.stats {
            range_label(i.period, i.now.date())
        } else {
            "Recording off · saved statistics".into()
        },
        usage: part(n, u),
        usage_line: format!("↓ {} · ↑ {}", bytes_text(v.total.down), bytes_text(v.total.up)),
        providers: v.by_provider().iter().take(2).map(|(name, b)| share(name, *b, t)).collect(),
        live: live_on,
        live_now: part(rn, ru),
        spark: (0..60)
            .map(|k| i.live.down.values().map(|s| s.get(k).copied().unwrap_or(0.0) as f64).sum::<f64>() as f32)
            .collect(),
        week: hm_parts(v.week_ms),
        week_hours: v.week.iter().map(|h| h.max(0.0)).collect(),
        today: i.now.date().weekday().num_days_from_monday() as i32,
        tested: best.is_some(),
        best: best.map(|b| mbps(b.1)).unwrap_or_default(),
        best_line: best.map(|b| format!("best test · {}", v.name(b.0))).unwrap_or_default(),
        fastest: fastest
            .iter()
            .take(2)
            .map(|(id, b)| SpeedBar {
                code: v.code(id),
                hue: v.hue(id),
                frac: *b as f32 / best.map_or(1, |b| b.1) as f32,
            })
            .collect(),
        legend: order.iter().take(5).map(|id| Legend { name: v.name(id), hue: v.hue(id) }).collect(),
        columns: v
            .columns
            .iter()
            .map(|c| {
                order
                    .iter()
                    .filter_map(|id| {
                        c.get(*id).map(|b| Part { value: (b.total() as f64 / div) as f32, hue: v.hue(id) })
                    })
                    .collect()
            })
            .collect(),
        summary: format!("Data per {}, by exit", if i.period == Period::Day { "hour" } else { "day" }),
        apps: by_app
            .iter()
            .take(8)
            .map(|(app, exit, b)| AppBar {
                name: i.labels.get(*app).cloned().unwrap_or_else(|| {
                    if *app == "?" { "Other".into() } else { app.rsplit('/').next().unwrap_or(app).to_string() }
                }),
                code: v.code(exit),
                hue: v.hue(exit),
                frac: *b as f32 / most as f32,
                bytes: bytes_text(*b),
            })
            .collect(),
        exits: v
            .by_exit
            .iter()
            .take(8)
            .map(|(id, b)| {
                let n = v.apps.iter().filter(|a| a.1 == *id).map(|a| &a.0).collect::<IndexSet<_>>().len();
                ExitBar {
                    code: v.code(id),
                    hue: v.hue(id),
                    name: v.name(id),
                    apps: plural(n, "app", "apps"),
                    bytes: bytes_text(b.total()),
                }
            })
            .collect(),
    }
}

fn usage(v: &Loaded, p: Period, div: f64) -> UsageView {
    let per = if p == Period::Day { "hour" } else { "day" };
    let sel = v.columns.get(v.selected as usize).map_or(0, |c| c.values().map(Bytes::total).sum());
    let (n, u) = bytes(v.total.total());
    UsageView {
        over: format!("{} · per {per}", p.label()),
        value: part(n, u),
        sub: format!("↓ {} download · ↑ {} upload", bytes_text(v.total.down), bytes_text(v.total.up)),
        trailing: format!("{} {}", if p == Period::Day { "now" } else { "today" }, bytes_text(sel)),
        // In the text's ink: the chart dims all but today's bar.
        columns: v
            .columns
            .iter()
            .map(|c| {
                vec![Part { value: (c.values().map(Bytes::total).sum::<i64>() as f64 / div) as f32, hue: INK_TEXT }]
            })
            .collect(),
        summary: format!("Data per {per}"),
        label: format!("By provider · share of the {}", p.label().to_lowercase()),
        providers: v.by_provider().iter().map(|(name, b)| share(name, *b, v.total.total())).collect(),
    }
}

fn live(i: &Inputs, v: &Loaded) -> LiveView {
    let down = &i.live.down;
    let mut ids: Vec<&String> = down.keys().filter(|id| *id != DIRECT).collect();
    ids.sort_by_key(|id| v.ex(id).map(|e| e.name.clone()));
    let last = |id: &str| down.get(id).and_then(|s| s.last()).copied().unwrap_or(0.0) as i64;
    let empty = if !i.setup.prefs.stats {
        "Live speeds are measured while statistics are on."
    } else if i.vpn.phase != Phase::On {
        "Connect to see live speeds."
    } else {
        ""
    };
    // Nothing measured: no chart and no rows, only why.
    let shown: Vec<&String> = if empty.is_empty() { ids.clone() } else { vec![] };
    let max_total = (0..60)
        .map(|k| ids.iter().map(|id| down[*id].get(k).copied().unwrap_or(0.0) as f64).sum::<f64>())
        .fold(0.0, f64::max);
    let (n, u) = rate(i.live.down_now);
    let (un, uu) = rate(i.live.up_now);
    LiveView {
        overline: format!("Now · {}", plural(ids.len(), "exit", "exits")),
        empty: empty.into(),
        now: part(n, u),
        sub: format!("↑ {un} {uu} upload · every second"),
        series: shown
            .iter()
            .map(|id| Series { values: down[*id].iter().map(|s| s / 1e6).collect(), hue: v.hue(id) })
            .collect(),
        cap: nice_ceil(max_total / 1e6).max(1.0) as f32,
        summary: format!(
            "Download per exit, last minute: {}",
            ids.iter().map(|id| format!("{} {} Mbps", v.name(id), mbps(last(id)))).collect::<Vec<_>>().join(", ")
        ),
        rows: shown
            .iter()
            .map(|id| {
                let (n, u) = rate(last(id));
                LiveRow {
                    code: v.code(id),
                    hue: v.hue(id),
                    name: v.name(id),
                    via: v.ex(id).map(|e| e.via.clone()).unwrap_or_default(),
                    now: part(n, u),
                }
            })
            .collect(),
    }
}

/// An app's name in App flows: its label, the app itself for its own traffic, or the last part of its key.
fn flow_name(labels: &IndexMap<String, String>, pkg: &str) -> String {
    match pkg {
        "?" => "Unknown app".into(),
        // Its own: speed tests, health checks.
        stats::SELF => APP.into(),
        _ => labels.get(pkg).cloned().unwrap_or_else(|| pkg.rsplit('.').next().unwrap_or(pkg).to_string()),
    }
}

fn flows(i: &Inputs, v: &Loaded) -> FlowsView {
    let name = |pkg: &str| flow_name(i.labels, pkg);
    let apps: Vec<&(String, String, i64)> = v.apps.iter().filter(|a| a.1 != DIRECT).collect();
    let exits: Vec<&(String, Bytes)> = v.by_exit.iter().filter(|e| e.0 != DIRECT).collect();
    let total = exits.iter().map(|e| e.1.total()).sum::<i64>().max(1);
    let biggest = exits.first().map_or(1, |e| e.1.total().max(1));
    // An exit with no data in this period filters nothing.
    let only = i.flows_exit.filter(|id| exits.iter().any(|e| e.0 == *id));
    let distinct = |a: &[&(String, String, i64)]| a.iter().map(|a| &a.0).collect::<IndexSet<_>>().len();
    let shown: Vec<&&(String, String, i64)> = apps.iter().filter(|a| only.is_none_or(|o| a.1 == o)).collect();
    let first = shown.first().map_or(1, |a| a.2.max(1));
    let list = if i.flows_all { shown.len() } else { shown.len().min(LIST) };
    let mut pills = vec![Pill {
        id: String::new(),
        code: String::new(),
        hue: INK_ACCENT,
        text: format!("All {}", distinct(&apps)),
        on: only.is_none(),
    }];
    pills.extend(exits.iter().map(|(e, _)| Pill {
        id: e.clone(),
        code: v.code(e),
        hue: v.hue(e),
        text: format!("{} {}", v.name(e), apps.iter().filter(|a| a.1 == *e).count()),
        on: only == Some(e.as_str()),
    }));
    FlowsView {
        sub: format!("{} apps into {} exits · Direct traffic not shown", distinct(&apps), exits.len()),
        empty: apps.is_empty(),
        share: exits.iter().map(|(e, b)| Part { value: b.total().max(1) as f32, hue: v.hue(e) }).collect(),
        lanes: exits
            .iter()
            .map(|(e, b)| {
                let mine: Vec<&&(String, String, i64)> = apps.iter().filter(|a| a.1 == *e).collect();
                let rest: i64 = mine.iter().skip(5).map(|a| a.2).sum();
                let mut segments: Vec<Segment> = mine
                    .iter()
                    .take(5)
                    .enumerate()
                    .map(|(j, a)| Segment { weight: a.2.max(1) as f32, alpha: 0.95 - j as f32 * 0.12 })
                    .collect();
                if rest > 0 {
                    segments.push(Segment { weight: rest as f32, alpha: 0.25 });
                }
                Lane {
                    id: e.clone(),
                    code: v.code(e),
                    hue: v.hue(e),
                    name: v.ex(e).map_or_else(|| "?".into(), |x| x.name.clone()),
                    apps: plural(mine.len(), "app", "apps"),
                    bytes: bytes_text(b.total()),
                    pct: format!("{}%", 100 * b.total() / total),
                    frac: b.total() as f32 / biggest as f32,
                    segments,
                    names: mine.iter().take(5).map(|a| Named { name: name(&a.0), bytes: bytes_text(a.2) }).collect(),
                    rest: if mine.len() > 5 {
                        format!("+{} apps {}", mine.len() - 5, bytes_text(rest))
                    } else {
                        String::new()
                    },
                    selected: only == Some(e.as_str()),
                }
            })
            .collect(),
        pills,
        rows: shown
            .iter()
            .take(list)
            .map(|(pkg, exit, b)| {
                let n = name(pkg);
                FlowRow {
                    pkg: pkg.clone(),
                    letter: n.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default(),
                    name: n,
                    code: v.code(exit),
                    hue: v.hue(exit),
                    bytes: bytes_text(*b),
                    frac: *b as f32 / first as f32,
                }
            })
            .collect(),
        more: match (shown.len() > LIST, i.flows_all) {
            (false, _) => String::new(),
            (true, true) => "Show fewer".into(),
            (true, false) => format!("Show all {}", shown.len()),
        },
    }
}

fn journal(i: &Inputs, v: &Loaded) -> JournalView {
    // The chosen day (the 13-week window moves); until one is chosen, the last with data.
    let last = v.heat.iter().rposition(|h| *h >= 0.0).unwrap_or(0) as i64;
    let start = epoch_day(v.heat_start);
    let day = i.journal_day.map_or(last, |d| (d - start).clamp(0, last));
    let shown = days(v.heat_start, day);
    let (lo, hi) = (start_ms(shown), start_ms(days(shown, 1))); // 23 or 25 h on DST days
    let spans: Vec<(i64, i64, bool)> = i
        .data
        .map_or(&[][..], |d| &d.spans[..])
        .iter()
        .map(|s| (s.0.max(lo), s.1.min(hi), s.2))
        .filter(|s| s.1 > s.0)
        .collect();
    let len = (hi - lo) as f32;
    let on: Vec<i64> = spans.iter().filter(|s| !s.2).map(|s| s.1 - s.0).collect();
    let pauses: Vec<i64> = spans.iter().filter(|s| s.2).map(|s| s.1 - s.0).collect();
    let connected: i64 = on.iter().sum();
    // A month's name over the week it starts in; the first column only if no month starts in the next two.
    let starts: Vec<i64> = (0..13).filter(|w| days(v.heat_start, 7 * w).day() <= 7).collect();
    let mut weeks: IndexSet<i64> = IndexSet::new();
    if !starts.iter().any(|s| (1..=2).contains(s)) {
        weeks.insert(0);
    }
    weeks.extend(starts);
    JournalView {
        week: hm_parts(v.week_ms),
        sub: format!("{} of 7 days with at least 4 h connected", v.week.iter().filter(|h| **h >= 4.0).count()),
        heat: v.heat.clone(),
        months: weeks
            .into_iter()
            .map(|w| MonthMark { week: w as i32, name: days(v.heat_start, 7 * w + 6).format("%b").to_string() })
            .collect(),
        index: day as i32,
        day: epoch_day(shown) as i32,
        date: shown.format("%A %-d %B").to_string(),
        has_prev: day > 0,
        has_next: v.heat.get(day as usize + 1).is_some_and(|h| *h >= 0.0),
        spans: spans
            .iter()
            .map(|s| DaySpan { from: (s.0 - lo) as f32 / len, to: (s.1 - lo) as f32 / len, paused: s.2 })
            .collect(),
        summary: format!("{} connected, {} pauses", hm(connected), pauses.len()),
        facts: vec![
            Fact { parts: hm_parts(connected), label: "connected".into() },
            Fact { parts: hm_parts(on.iter().copied().max().unwrap_or(0)), label: "longest".into() },
            Fact {
                parts: vec![part(pauses.len().to_string(), "")],
                label: if pauses.is_empty() {
                    "pauses".into()
                } else {
                    format!("pauses · {}", hm(pauses.iter().sum()))
                },
            },
        ],
    }
}

/// A download and an upload speed side by side, in Mbps; a missing upload shows as a dash: "↓1080 ↑940".
fn speed_pair(down: i64, up: i64) -> String {
    format!("↓{} ↑{}", mbps(down), if up > 0 { mbps(up) } else { "—".into() })
}

fn tunnels(i: &Inputs, v: &Loaded) -> TunnelsView {
    // Every exit in use or tested: fastest download test first, the rest by name.
    let in_use: Vec<String> = i
        .running
        .map(|r| i.tags.keys().filter(|t| *t != DIRECT).map(|t| stats::id_in(t, r)).collect())
        .unwrap_or_default();
    let mut ids: Vec<String> =
        in_use.into_iter().chain(v.tests.keys().cloned()).collect::<IndexSet<_>>().into_iter().collect();
    ids.sort_by(|a, b| v.fastest(b).cmp(&v.fastest(a)).then_with(|| v.name(a).cmp(&v.name(b))));
    let top = ids.iter().map(|id| v.fastest(id)).max().unwrap_or(1).max(1);
    let best =
        v.tests.values().fold(None, |b: Option<&&Test>, t| if b.is_none_or(|b| t.down > b.down) { Some(t) } else { b });
    TunnelsView {
        tested: best.is_some(),
        best: best.map(|t| mbps(t.down)).unwrap_or_default(),
        sub: best
            .map(|t| format!("↓ download · ↑ {} Mbps upload · {}", mbps(t.up), v.name(&t.exit)))
            .unwrap_or_default(),
        rows: ids
            .iter()
            .map(|id| {
                let t = v.tests.get(id);
                TunnelRow {
                    id: id.clone(),
                    code: v.code(id),
                    hue: v.hue(id),
                    name: v.name(id),
                    via: v.ex(id).map(|e| e.via.clone()).unwrap_or_default(),
                    tested: t.is_some(),
                    test: t.map(|t| speed_pair(t.down, t.up)).unwrap_or_default(),
                    frac: v.fastest(id) as f32 / top as f32,
                }
            })
            .collect(),
    }
}

fn tunnel(i: &Inputs, v: &Loaded) -> TunnelView {
    let id = i.section.strip_prefix("tunnel:").unwrap_or_default();
    let ex = v.ex(id);
    let t = v.tests.get(id);
    let servers = i.data.map_or(&[][..], |d| &d.servers[..]);
    let total = servers.iter().map(|s| s.1).sum::<i64>().max(1);
    TunnelView {
        id: id.into(),
        overline: format!(
            "{} · {}",
            ex.map(|e| e.via.as_str()).unwrap_or_default(),
            range_label(i.period, i.now.date())
        ),
        title: v.name(id),
        hue: v.hue(id),
        tested: t.is_some(),
        best: t.map(|t| mbps(t.down)).unwrap_or_default(),
        sub: t
            .map(|t| format!("↓ download · ↑ {} Mbps upload", if t.up > 0 { mbps(t.up) } else { "—".into() }))
            .unwrap_or_default(),
        servers: servers
            .iter()
            .map(|(name, b)| ServerRow {
                name: name.clone(),
                pct: format!("{}%", 100 * b / total),
                frac: *b as f32 / total as f32,
            })
            .collect(),
    }
}

/// A test's time as History says it: "11 Nov · 14:30".
fn when(at: i64) -> String {
    Local.timestamp_millis_opt(at).single().map(|t| t.format("%-d %b · %H:%M").to_string()).unwrap_or_default()
}

fn history(d: &Data, v: &Loaded) -> HistoryView {
    let all = ALL;
    let best = d
        .tests
        .iter()
        .filter(|t| t.grp == 0)
        .fold(None, |b: Option<&Test>, t| if b.is_none_or(|b| t.down > b.down) { Some(t) } else { b });
    HistoryView {
        overline: format!("{} tests", d.tests.iter().filter(|t| t.exit != all).count()),
        tested: best.is_some(),
        best: best.map(|t| mbps(t.down)).unwrap_or_default(),
        sub: best.map(|t| format!("{} · {} · download", v.name(&t.exit), when(t.at))).unwrap_or_default(),
        // A combined run is one row with its exits listed under it; their own rows aren't repeated.
        rows: d
            .tests
            .iter()
            .filter(|t| t.grp == 0 || t.exit == all)
            .map(|t| {
                let together = t.exit == all;
                HistoryRow {
                    all: together,
                    code: if together { "ALL".into() } else { v.code(&t.exit) },
                    hue: if together { INK_TEXT } else { v.hue(&t.exit) },
                    when: when(t.at),
                    down: mbps(t.down),
                    up: mbps(t.up),
                    ping: if t.idle > 0 { t.idle.to_string() } else { "—".into() },
                    line: if together {
                        format!("{} exits together", t.n)
                    } else {
                        [t.via.clone(), if t.server.is_empty() { v.name(&t.exit) } else { t.server.clone() }]
                            .into_iter()
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(" · ")
                    },
                    members: if together {
                        d.tests
                            .iter()
                            .filter(|m| m.grp == t.grp && m.exit != all)
                            .map(|m| Member {
                                code: v.code(&m.exit),
                                hue: v.hue(&m.exit),
                                name: v.name(&m.exit),
                                down: mbps(m.down),
                                up: mbps(m.up),
                                ping: m.idle.to_string(),
                            })
                            .collect()
                    } else {
                        vec![]
                    },
                }
            })
            .collect(),
    }
}

// ---- the speed test --------------------------------------------------------------------------------------------------

/// An exit to test, as its chip: a route's id or a node's, its look, and whether it's the one picked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Choice {
    pub id: String,
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub on: bool,
}

/// One of the speed test's figure cards: its title, its figure ("" for none yet) and unit; `active` while measured.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedCard {
    pub title: String,
    pub value: String,
    pub unit: String,
    pub active: bool,
}

/// The dial while a test measures: the reading in Mbps, what screen readers hear, how far the 20 seconds are, and the
/// line under the bar ("1/2 · Download").
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Gauge {
    pub mbps: f32,
    pub label: String,
    pub upload: bool,
    pub progress: f32,
    pub status: String,
}

/// The GO button: its word, size, colour and what screen readers hear; `working` shows the loading indicator in its
/// place, `bloom` once a test succeeded.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GoButton {
    pub text: String,
    pub size: i32,
    pub hue: i32,
    pub label: String,
    pub working: bool,
    pub bloom: bool,
}

/// Where a test runs: the M-Lab server's place (or that one is being found), then its machine and the provider and VPN
/// server the test goes through.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServerCard {
    pub place: String,
    pub line: String,
}

/// One exit's share of a combined run while it measures.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegBar {
    pub code: String,
    pub hue: i32,
    pub frac: f32,
    pub now: String,
    pub stopped: bool,
}

/// One exit of a finished combined run: the M-Lab server it used, or why it stopped, and its figures.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegResult {
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub line: String,
    pub failed: bool,
    pub down: String,
    pub up: String,
    pub ping: String,
}

/// One route before a combined run: ticked or not, then how finding its test server goes (`tone` 0 dim, 1 in the
/// accent, 2 found, with a check).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LegPick {
    pub id: String,
    pub code: String,
    pub hue: i32,
    pub name: String,
    pub sub: String,
    pub on: bool,
    pub state: String,
    pub tone: i32,
}

/// An exit that needs a decision before a combined run: why, and for one without a server at home, the choice between
/// the nearest server (`via`) and leaving it out (`out`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decision {
    pub exit: String,
    pub code: String,
    pub hue: i32,
    pub title: String,
    pub text: String,
    pub choice: bool,
    pub via: String,
    pub out: String,
    pub via_on: bool,
}

/// Every routed exit at once.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Together {
    pub cards: Vec<SpeedCard>,
    pub measuring: bool,
    pub gauge: Gauge,
    /// How many exits run, for the reading's line.
    pub exits: i32,
    pub bars: Vec<LegBar>,
    /// Done or failed: its error, the share of the download (done), each exit's results.
    pub finished: bool,
    pub error: String,
    pub done: bool,
    pub window: String,
    pub share: Vec<Part>,
    pub results: Vec<LegResult>,
    /// Before it: "Selected 2 of 3" or "Test servers · 1 of 3", in the case written; the routes, and the nodes that
    /// can't join.
    pub heading: String,
    pub working: bool,
    pub picks: Vec<LegPick>,
    pub nodes: Vec<Choice>,
    pub go: GoButton,
    pub note: String,
    /// What GO tests together: the ticked routes; it takes two.
    pub start: Vec<String>,
    /// The sheet before the measuring: what needs deciding, the data and tests it may use, and its Start.
    pub deciding: bool,
    pub decisions: Vec<Decision>,
    pub cost: String,
    pub yes: String,
    pub can_go: bool,
    /// The exits without a server at home that go via the nearest one ([`speed_test::go`]).
    pub nearest: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpeedView {
    pub overline: String,
    /// Not connected, or no exit to test.
    pub empty: bool,
    /// Two routes or more: the chip for all at once, its stripe of their colours, its words ("3 exits"), on or not.
    pub all_chip: bool,
    pub all_on: bool,
    pub all_hues: Vec<i32>,
    pub all_text: String,
    pub choices: Vec<Choice>,
    /// A test runs or waits for a decision: the chips are dim and don't change it.
    pub busy: bool,
    /// The exit tested: its id and name, and its colour for the dial and GO.
    pub exit: String,
    pub name: String,
    pub hue: i32,
    pub cards: Vec<SpeedCard>,
    pub measuring: bool,
    pub gauge: Gauge,
    pub error: String,
    /// M-Lab has no server in the exit's country: said, with a test through the nearest one.
    pub missing: String,
    pub go: GoButton,
    /// While a server is found or the ping measured: what is happening; "" otherwise.
    pub preparing: String,
    pub server_shown: bool,
    pub server: ServerCard,
    pub note: String,
    /// Testing a node moves the apps on the Tailscale route to it meanwhile: GO asks first.
    pub ask: bool,
    pub ask_title: String,
    pub ask_text: String,
    /// M-Lab's terms, the part with a figure in it.
    pub terms: String,
    pub together: Together,
}

/// A country's English name from its ISO code, as M-Lab's servers give it.
fn country_name(code: &str) -> String {
    catalog::name(code).map_or_else(|| code.to_string(), String::from)
}

/// "Milan, Italy": a server's city and country, the known ones.
fn place(city: &str, country: &str) -> String {
    [city.to_string(), country_name(country)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(", ")
}

fn card(title: &str, value: Option<String>, unit: impl Into<String>, active: bool) -> SpeedCard {
    SpeedCard { title: title.into(), value: value.unwrap_or_default(), unit: unit.into(), active }
}

fn speed(i: &Inputs, v: &Loaded) -> SpeedView {
    let t = &i.speed;
    let setup = i.setup;
    let running = i.running.unwrap_or(setup);
    let unknown = |id: &str| Ex { code: "?".into(), name: id.into(), via: String::new(), hue: INK_FAINT };
    // Routed exits by name, then the tailnet's other exit nodes (tested by switching Tailscale to them for the test).
    // Tests start by route id; the label is that of the route's current history.
    let mut options: Vec<(String, Ex)> = i
        .tags
        .keys()
        .filter(|id| *id != DIRECT)
        .map(|id| (id.clone(), v.ex(&stats::id_in(id, running)).cloned().unwrap_or_else(|| unknown(id))))
        .collect();
    options.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    options.extend(t.nodes.iter().map(|n| {
        (
            format!("{}{}", speed_test::NODE, n.ip),
            Ex { code: "TS".into(), name: n.name.clone(), via: "Tailscale".into(), hue: INK_TEXT },
        )
    }));
    // Every route at once once there are two, with apps or without (those connect for the run). Two routes by the same
    // name ("Fastest") are told apart by their provider.
    let mut routed: Vec<(String, Ex)> = setup
        .routes
        .iter()
        .map(|r| {
            let name = if setup.routes.iter().filter(|o| o.name() == r.name()).count() > 1 {
                format!("{} · {}", r.name(), r.source())
            } else {
                r.name()
            };
            (r.id.clone(), Ex { code: r.code(), name, via: r.source(), hue: r.hue })
        })
        .collect();
    routed.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    let chosen = t
        .chosen
        .map(String::from)
        .or_else(|| if t.all.is_some() { Some(ALL.into()) } else { options.first().map(|o| o.0.clone()) });
    let all_mode = routed.len() >= 2 && chosen.as_deref() == Some(ALL);
    let want = t.run.map(|r| r.exit.clone()).or(chosen);
    let picked = options.iter().find(|o| Some(&o.0) == want.as_ref()).or(options.first());
    let (exit, ex) = picked.map_or((String::new(), None), |(id, e)| (id.clone(), Some(e)));
    let name = ex.map(|e| e.name.clone()).unwrap_or_default();
    let node = exit.starts_with(speed_test::NODE);
    let busy = t.testing || t.all.is_some_and(|a| a.phase == Stage::Deciding);
    let server = if node { None } else { i.vpn.servers.get(&exit).map(|s| s.name.clone()) };
    let r = t.run;
    let stage = r.map(|r| r.phase);
    let measuring = matches!(stage, Some(Stage::Download | Stage::Upload));
    let (done, preparing) = (stage == Some(Stage::Done), stage == Some(Stage::Preparing));
    let upload = stage == Some(Stage::Upload);
    let found = r.and_then(|r| r.server.as_ref());
    let via = [ex.map(|e| e.via.clone()).filter(|v| !v.is_empty()), server.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    SpeedView {
        overline: if all_mode {
            "All exits · together".into()
        } else {
            [ex.map(|e| e.name.clone()), server.clone().or_else(|| ex.filter(|_| node).map(|e| e.via.clone()))]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" · ")
        },
        empty: i.vpn.phase != Phase::On || options.is_empty(),
        all_chip: routed.len() >= 2,
        all_on: all_mode,
        all_hues: routed.iter().map(|r| r.1.hue).collect(),
        all_text: format!("{} exits", routed.len()),
        choices: options
            .iter()
            .map(|(id, e)| Choice {
                id: id.clone(),
                code: e.code.clone(),
                hue: e.hue,
                name: e.name.clone(),
                on: *id == exit && !all_mode,
            })
            .collect(),
        busy,
        exit: exit.clone(),
        name: name.clone(),
        hue: ex.map_or(INK_ACCENT, |e| e.hue),
        cards: vec![
            // Ping, then the two speeds, as Ookla orders them: the median of five, then the range.
            card(
                "Ping",
                r.and_then(|r| r.ping).map(|p| p.median.to_string()),
                r.and_then(|r| r.ping).map_or_else(|| "ms".into(), |p| format!("ms · {}–{}", p.low, p.high)),
                false,
            ),
            card("Download", r.and_then(|r| r.down).map(mbps), "Mbps", stage == Some(Stage::Download)),
            card("Upload", r.and_then(|r| r.up).map(mbps), "Mbps", upload),
        ],
        measuring,
        gauge: r
            .filter(|_| measuring)
            .map(|r| {
                gauge(
                    r.now as f32 / 1e6,
                    format!("{} megabits per second, {}", mbps(r.now), if upload { "upload" } else { "download" }),
                    upload,
                    r.elapsed_ms,
                    String::new(),
                )
            })
            .unwrap_or_default(),
        error: r.and_then(|r| r.error.clone()).filter(|_| !measuring).unwrap_or_default(),
        missing: r
            .and_then(|r| r.missing.as_ref())
            .filter(|_| !measuring)
            .map(|c| format!("M-Lab has no test server in {c} yet, so this exit can't be tested in its own country."))
            .unwrap_or_default(),
        go: GoButton {
            text: if done { "AGAIN" } else { "GO" }.into(),
            size: if done { 150 } else { 200 },
            hue: ex.map_or(INK_ACCENT, |e| e.hue),
            label: format!("Start speed test through {name}"),
            working: preparing,
            bloom: done,
        },
        preparing: match (preparing, r) {
            (true, Some(r)) if node && r.server.is_none() => "Switching Tailscale".into(),
            (true, Some(r)) if r.server.is_some() => "Measuring ping".into(),
            (true, Some(_)) => "Finding a test server".into(),
            _ => String::new(),
        },
        server_shown: measuring || preparing || done,
        server: ServerCard {
            place: found.map_or_else(
                || format!("Finding one in {}…", ex.map_or("the exit's country", |e| e.name.as_str())),
                |s| place(&s.city, &s.country),
            ),
            line: [
                found.map(|s| s.machine.split('.').next().unwrap_or_default().to_string()),
                Some(via).filter(|v| !v.is_empty()).map(|v| format!("via {v}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · "),
        },
        note: if done {
            if setup.prefs.stats {
                "Test complete · saved with your statistics"
            } else {
                "Test complete · not saved: statistics are off"
            }
            .into()
        } else if node {
            format!(
                "Tailscale switches to {name} for the test, then back.{} Tested with M-Lab, about 20 seconds of real data.",
                if setup.ts_exit().is_some() { " Apps on your Tailscale route use it meanwhile." } else { "" }
            )
        } else {
            "Tested with M-Lab on a server in the exit's country, or a nearby one: ten seconds each way, real data."
                .into()
        },
        ask: node && (setup.ts_exit().is_some() || i.running.and_then(|s| s.ts_exit()).is_some()),
        ask_title: format!("Test through {name}?"),
        ask_text: format!(
            "For about 20 seconds, apps on your Tailscale route leave through {name} instead of their usual exit node. Test only through a node you trust with their traffic."
        ),
        terms: format!(
            "Also sent: the time, the app's name and version, and the exit's country when it's known. Nothing about your computer or accounts. Up to {} tests a day.",
            speed_test::PER_DAY
        ),
        together: together(i, v, &routed, &options),
    }
}

/// The dial's reading and the progress line under it; `status` follows the phase.
fn gauge(mbps: f32, label: String, upload: bool, elapsed_ms: i64, then: String) -> Gauge {
    Gauge {
        mbps,
        label,
        upload,
        progress: (elapsed_ms as f32 / (speed_test::MAX_SECONDS as f32 * 1000.0)).clamp(0.0, 1.0),
        status: format!("{}{then}", if upload { "2/2 · Upload" } else { "1/2 · Download" }),
    }
}

/// Every routed exit at once: tick the exits, GO finds a test server for each (no test data yet), a sheet asks about an
/// exit without one at home or a metered network, then all download together and all upload together.
fn together(i: &Inputs, v: &Loaded, exits: &[(String, Ex)], options: &[(String, Ex)]) -> Together {
    let t = &i.speed;
    let setup = i.setup;
    let running = i.running.unwrap_or(setup);
    let a = t.all;
    let picked: Vec<&String> = exits.iter().map(|e| &e.0).filter(|id| !t.unticked.contains(id)).collect();
    let stage = a.map(|a| a.phase);
    let measuring = matches!(stage, Some(Stage::Download | Stage::Upload));
    let working = matches!(stage, Some(Stage::Preparing | Stage::Deciding));
    let (done, failed) = (stage == Some(Stage::Done), stage == Some(Stage::Failed));
    let upload = stage == Some(Stage::Upload);
    let ex = |id: &str| exits.iter().find(|e| e.0 == id).map(|e| &e.1);
    let look = |id: &str| ex(id).map_or(("?".to_string(), INK_FAINT), |e| (e.code.clone(), e.hue));
    let legs = a.map_or(&[][..], |a| &a.legs[..]);
    let ran: Vec<&speed_test::Leg> = legs.iter().filter(|l| l.error.is_none()).collect();
    let (d, u) = (a.and_then(|a| a.down).map(total), a.and_then(|a| a.up).map(total));
    let active = |id: &str| setup.active_routes().iter().any(|r| r.id == id);
    // Data a run may use: each exit's best test this period both ways for ten seconds, else 500 Mbps each way.
    let gb = |ids: &[String]| {
        (ids.iter()
            .map(|id| v.tests.get(&stats::id_in(id, running)).map_or(1_000_000_000, |t| t.down + t.up))
            .sum::<i64>()
            * 10
            / 8) as f64
            / 1e9
    };
    let left = speed_test::PER_DAY - t.tests_today;
    let nearest: Vec<String> = legs
        .iter()
        .filter(|l| l.missing && l.usable() && !t.leave_out.contains(&l.exit))
        .map(|l| l.exit.clone())
        .collect();
    let going: Vec<String> = legs
        .iter()
        .filter(|l| l.usable() && (!l.missing || nearest.contains(&l.exit)))
        .map(|l| l.exit.clone())
        .collect();
    let country = |id: &str| {
        setup
            .route(Some(id))
            .and_then(|r| r.loc.country.clone())
            .or_else(|| ex(id).map(|e| e.name.clone()))
            .unwrap_or_else(|| "its country".into())
    };
    let scale = a.map_or(1, |a| a.now.max(1)) as f32;
    Together {
        cards: vec![
            card("Download", d.as_ref().map(|d| d.0.clone()), format!("{} total", d.as_ref().map_or("Gbps", |d| d.1.as_str())), stage == Some(Stage::Download)),
            card("Upload", u.as_ref().map(|u| u.0.clone()), format!("{} total", u.as_ref().map_or("Gbps", |u| u.1.as_str())), upload),
            card("Exits", Some(if a.is_none() { picked.len() } else { ran.len() }.to_string()), if done || failed { format!("of {} ran", exits.len()) } else { format!("of {}", exits.len()) }, false),
        ],
        measuring,
        gauge: a
            .filter(|_| measuring)
            .map(|a| {
                let (n, unit) = total(a.now);
                gauge(a.now as f32 / 1e6, format!("{n} {unit} together, {}", if upload { "upload" } else { "download" }), upload, a.elapsed_ms, format!(" · {} of {} running", ran.len(), legs.len()))
            })
            .unwrap_or_default(),
        exits: legs.len() as i32,
        // Each exit's plain linear share of the total now: what it adds, on a fast line or a slow one.
        bars: legs.iter().map(|l| LegBar { code: look(&l.exit).0, hue: look(&l.exit).1, frac: l.now as f32 / scale, now: mbps(l.now), stopped: l.error.is_some() }).collect(),
        finished: done || failed,
        error: a.and_then(|a| a.error.clone()).filter(|_| done || failed).unwrap_or_default(),
        done,
        window: format!("{} exits, same {} s", ran.len(), a.map_or(0, |a| a.window_ms / 1000)),
        share: ran.iter().map(|l| Part { value: l.down.unwrap_or(0).max(1) as f32, hue: look(&l.exit).1 }).collect(),
        results: legs
            .iter()
            .map(|l| LegResult {
                code: look(&l.exit).0,
                hue: look(&l.exit).1,
                name: ex(&l.exit).map_or_else(|| l.exit.clone(), |e| e.name.clone()),
                line: l.error.clone().unwrap_or_else(|| format!("M-Lab {}{}", l.server.as_ref().map_or("", |s| s.city.as_str()), if l.missing { " (nearest)" } else { "" })),
                failed: l.error.is_some(),
                down: l.down.map_or_else(|| "—".into(), mbps),
                up: l.up.map_or_else(|| "—".into(), mbps),
                ping: l.ping.map_or_else(|| "—".into(), |p| p.median.to_string()),
            })
            .collect(),
        heading: if working { format!("Test servers · {} of {}", legs.iter().filter(|l| l.server.is_some()).count(), legs.len()) } else { format!("Selected {} of {}", picked.len(), exits.len()) },
        working,
        picks: exits
            .iter()
            .map(|(id, e)| {
                let l = legs.iter().find(|l| l.exit == *id);
                let (state, tone) = match l {
                    _ if !working => (String::new(), 0),
                    None => ("Not ticked".into(), 0),
                    Some(l) if l.limited => ("Limited by M-Lab".into(), 1),
                    Some(l) if l.error.is_some() => ("Can't join".into(), 1),
                    Some(l) if l.missing => (l.server.as_ref().map_or_else(|| "None in its country".into(), |s| format!("Nearest: {}", s.city)), 1),
                    Some(Leg { server: Some(s), .. }) => (s.city.clone(), 2),
                    Some(_) => (if i.tags.contains_key(id) { "Finding…" } else { "Connecting…" }.into(), 0),
                };
                let server = i.vpn.servers.get(id).map(|s| s.name.clone()).or_else(|| (!active(id)).then(|| "connects for the test".into()));
                LegPick {
                    id: id.clone(),
                    code: e.code.clone(),
                    hue: e.hue,
                    name: e.name.clone(),
                    sub: [Some(e.via.clone()).filter(|v| !v.is_empty()), server].into_iter().flatten().collect::<Vec<_>>().join(" · "),
                    on: !t.unticked.contains(id),
                    state,
                    tone,
                }
            })
            .collect(),
        nodes: options.iter().filter(|o| o.0.starts_with(speed_test::NODE)).map(|(id, e)| Choice { id: id.clone(), code: e.code.clone(), hue: INK_FAINT, name: e.name.clone(), on: false }).collect(),
        go: if done || failed {
            GoButton { text: "AGAIN".into(), size: 150, hue: INK_TEXT, label: "Test all exits together again".into(), working: false, bloom: done }
        } else {
            GoButton { text: "GO".into(), size: 150, hue: INK_TEXT, label: format!("Test {} exits together", picked.len()), working, bloom: false }
        },
        note: if done {
            format!("Combined throughput on this computer. {}", if setup.prefs.stats { format!("Saved: each exit as a test marked \"with {} others\", and one History row.", ran.len().saturating_sub(1)) } else { "Not saved: statistics are off.".into() })
        } else if failed {
            String::new()
        } else if working {
            "No test data is sent yet. Nothing runs until every exit has a server or you decide.".into()
        } else if picked.len() < 2 {
            "Tick at least two exits.".into()
        } else {
            format!(
                "GO first finds a test server for every exit. Then all download together, then all upload together: ten seconds each.{}",
                if picked.iter().any(|id| !active(id)) { " Routes without apps connect just for the test, so the VPN restarts for a moment before and after." } else { "" }
            )
        },
        start: picked.iter().map(|id| id.to_string()).collect(),
        deciding: stage == Some(Stage::Deciding),
        decisions: legs
            .iter()
            .filter(|l| l.missing || !l.usable())
            .map(|l| {
                let name = ex(&l.exit).map_or_else(|| l.exit.clone(), |e| e.name.clone());
                let city = l.server.as_ref().map_or("", |s| s.city.as_str());
                Decision {
                    exit: l.exit.clone(),
                    code: look(&l.exit).0,
                    hue: look(&l.exit).1,
                    title: if l.limited {
                        "M-Lab is limiting this exit".into()
                    } else if l.error.is_some() {
                        format!("{name} can't join")
                    } else {
                        format!("No test server in {}", country(&l.exit))
                    },
                    text: match (&l.error, &l.server) {
                        _ if l.limited => format!("M-Lab allows a set number of tests from each internet address. {name} leaves through a server whose address other people share, and they have used up its tests for now. It's left out: try again later, or pick another server for this route in Routes."),
                        (Some(e), _) => format!("{e} It's left out of this run."),
                        (None, None) => format!("M-Lab has no server in {}, and none nearby answered. {name} is left out.", country(&l.exit)),
                        (None, Some(s)) => format!("M-Lab has no server in {}. The nearest is in {}, so {name}'s numbers would include the trip there.", country(&l.exit), place(&s.city, &s.country)),
                    },
                    choice: l.missing && l.usable(),
                    via: format!("Test {name} via {city}"),
                    out: format!("Leave {name} out"),
                    via_on: !t.leave_out.contains(&l.exit),
                }
            })
            .collect(),
        cost: format!(
            "{}Uses {} of about {left} tests left today, as counted on this computer. Leaving the page stops the test.",
            if a.is_some_and(|a| a.metered) { format!("On a metered connection: about {} GB in 20 seconds, from each exit's best test. ", fixed(gb(&going), 1)) } else { String::new() },
            going.len()
        ),
        yes: if going.len() < 2 {
            "Needs two exits".into()
        } else if going.len() as i32 > left {
            "Not enough tests left".into()
        } else {
            format!("Start {} together", going.len())
        },
        can_go: going.len() >= 2 && going.len() as i32 <= left,
        nearest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Location, WgPeer};
    use crate::ndt7::{Ping, Server};
    use crate::speed_test::Leg;

    const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";

    fn setup() -> Setup {
        let lab = WgPeer::new(
            "Home lab",
            KEY,
            vec!["10.8.0.2/32".into()],
            KEY,
            "203.0.113.7:51820",
            vec!["0.0.0.0/0".into()],
        );
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
                Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
            ],
            default_route: "nl".into(),
            prefs: crate::model::Prefs { stats: true, ..Default::default() },
            ..Setup::default()
        }
    }

    /// Wednesday 11 November 2026, 10:00.
    fn now() -> NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 11, 11).and_then(|d| d.and_hms_opt(10, 0, 0)).unwrap()
    }

    fn at(day: u32, h: u32, m: u32) -> i64 {
        start_ms(NaiveDate::from_ymd_opt(2026, 11, day).unwrap()) + (h as i64 * 60 + m as i64) * 60_000
    }

    fn id(s: &Setup, r: &str) -> String {
        stats::id_of(s.route(Some(r)).unwrap())
    }

    fn test(at: i64, exit: &str, down: i64, up: i64, grp: i64) -> Test {
        Test {
            at,
            exit: exit.into(),
            via: "Nord".into(),
            server: "nl1".into(),
            ip: String::new(),
            down,
            up,
            idle: 12,
            busy_down: 0,
            busy_up: 0,
            grp,
            n: 1,
        }
    }

    fn day(s: &Setup, d: u32, nl: i64, us: i64) -> (i64, IndexMap<String, Bytes>) {
        let e = epoch_day(NaiveDate::from_ymd_opt(2026, 11, d).unwrap());
        (e, [(id(s, "nl"), Bytes { up: 0, down: nl }), (id(s, "us"), Bytes { up: 0, down: us })].into_iter().collect())
    }

    struct Fixture {
        setup: Setup,
        data: Data,
        vpn: VpnState,
        tags: IndexMap<String, String>,
        live: Live,
        labels: IndexMap<String, String>,
    }

    fn fixture() -> Fixture {
        let setup = setup();
        let (nl, us) = (id(&setup, "nl"), id(&setup, "us"));
        let data = Data {
            days: [day(&setup, 9, 3_000_000_000, 1_000_000_000), day(&setup, 10, 1_000_000_000, 0)]
                .into_iter()
                .collect(),
            apps: vec![
                ("firefox".into(), nl.clone(), 2_500_000_000),
                ("app.unbraid".into(), nl.clone(), 1_500_000_000),
                ("firefox".into(), us.clone(), 600_000_000),
                ("?".into(), us.clone(), 400_000_000),
            ],
            tests: vec![
                test(at(10, 9, 0), &us, 300_000_000, 0, 0),
                test(at(9, 9, 0), &nl, 800_000_000, 90_000_000, 0),
                test(at(9, 8, 0), &nl, 950_000_000, 80_000_000, 5),
            ],
            spans: vec![
                (at(10, 8, 0), at(10, 12, 0), false),
                (at(10, 12, 0), at(10, 12, 30), true),
                (at(10, 12, 30), at(10, 14, 0), false),
            ],
            ..Data::default()
        };
        let vpn = VpnState { phase: Phase::On, ..VpnState::default() };
        let tags = [("nl".to_string(), "nl".to_string()), ("us".into(), "us".into())].into_iter().collect();
        let labels = [("firefox".to_string(), "Firefox".to_string())].into_iter().collect();
        Fixture { setup, data, vpn, tags, live: Live::default(), labels }
    }

    impl Fixture {
        fn view(&self, section: &str, flows_exit: Option<&str>, speed: SpeedInputs) -> StatsView {
            view(&Inputs {
                data: Some(&self.data),
                period: Period::Week,
                section,
                now: now(),
                setup: &self.setup,
                running: Some(&self.setup),
                vpn: &self.vpn,
                tags: &self.tags,
                live: &self.live,
                labels: &self.labels,
                has_data: true,
                flows_exit,
                flows_all: false,
                journal_day: None,
                speed,
            })
        }
    }

    #[test]
    fn figures_round_half_up_in_their_units() {
        assert_eq!(("4.4".to_string(), "GB".to_string()), bytes(4_350_000_000));
        assert_eq!("293 MB", bytes_text(292_500_000));
        assert_eq!("980 kB", bytes_text(980_400));
        assert_eq!("0 kB", bytes_text(0));
        assert_eq!(("94.2".to_string(), "Mbps".to_string()), rate(94_150_000));
        assert_eq!(("940".to_string(), "Mbps".to_string()), rate(940_900_000));
        // Small transfers never read as nothing.
        assert_eq!(("0.1".to_string(), "kbps".to_string()), rate(120));
        assert_eq!(("0".to_string(), "kbps".to_string()), rate(99));
        assert_eq!(("1.28".to_string(), "Gbps".to_string()), total(1_284_000_000));
        assert_eq!("3 h 20 m", hm(200 * 60_000));
        assert_eq!(vec![part("45", "m")], hm_parts(45 * 60_000 + 59_000));
    }

    #[test]
    fn scales_are_round() {
        assert_eq!(2.5, nice_ceil(2.17));
        assert_eq!(1.0, nice_ceil(0.0));
        assert_eq!(50.0, nice_ceil(41.0));
        assert_eq!(200.0, nice_ceil(200.1 * 0.9995));
        assert_eq!("2.5", scale_text(2.5));
        assert_eq!("200", scale_text(200.0));
        assert_eq!((1e9, "GB"), unit_for(1_000_000_000));
        assert_eq!((1e6, "MB"), unit_for(999_999_999));
    }

    #[test]
    fn periods_name_their_days() {
        let today = NaiveDate::from_ymd_opt(2026, 11, 11).unwrap();
        assert_eq!("TODAY · 11 NOV", range_label(Period::Day, today));
        assert_eq!("9–15 NOV", range_label(Period::Week, today));
        assert_eq!("1–30 NOV", range_label(Period::Month, today));
        // A week across two months says the second.
        assert_eq!("30–6 DEC", range_label(Period::Week, NaiveDate::from_ymd_opt(2026, 12, 2).unwrap()));
        assert_eq!(
            (NaiveDate::from_ymd_opt(2026, 12, 1).unwrap(), NaiveDate::from_ymd_opt(2026, 12, 31).unwrap()),
            range(Period::Month, NaiveDate::from_ymd_opt(2026, 12, 31).unwrap())
        );
    }

    #[test]
    fn back_goes_up_one_level() {
        assert_eq!("speed", back("history"));
        assert_eq!("live", back("speed"));
        assert_eq!("tunnels", back("tunnel:nl@0011223344"));
        assert_eq!("", back("tunnels"));
        assert_eq!("", back("usage"));
    }

    #[test]
    fn providers_name_who_carried_the_data() {
        let ex = |via: &str| Ex { code: "NL".into(), name: "x".into(), via: via.into(), hue: 0 };
        assert_eq!("NordVPN", provider_of("nl@1", Some(&ex("Nord"))));
        assert_eq!("Own servers", provider_of("lab@1", Some(&ex("WireGuard"))));
        assert_eq!("Home network", provider_of(stats::HOME, None));
        assert_eq!("Direct, no VPN", provider_of(DIRECT, None));
        assert_eq!("Other", provider_of("gone", None));
        assert_eq!("Unknown (older data)", provider_of("old", Some(&ex("Unknown (older data)"))));
    }

    #[test]
    fn the_hub_sums_the_period_by_exit_and_app() {
        let f = fixture();
        let v = f.view("", None, SpeedInputs::default());
        assert_eq!(part("5.0", "GB"), v.hub.usage);
        assert_eq!(
            vec!["Netherlands", "United States"],
            v.hub.legend.iter().map(|l| l.name.as_str()).collect::<Vec<_>>()
        );
        // An app's row takes the exit that carried most of it; unknown apps are "Other".
        assert_eq!(
            vec![("Firefox", "NL"), ("app.unbraid", "NL"), ("Other", "US")],
            v.hub.apps.iter().map(|a| (a.name.as_str(), a.code.as_str())).collect::<Vec<_>>()
        );
        assert_eq!("2 apps", v.hub.exits[0].apps);
        // Only solo tests count, and each exit's best: Netherlands' combined run reads higher but is left out.
        assert_eq!(
            ("800".to_string(), "best test · Netherlands".to_string()),
            (v.hub.best.clone(), v.hub.best_line.clone())
        );
        assert_eq!(2, v.selected, "Wednesday is the week's third day");
        assert_eq!("5 GB", v.scale);
    }

    #[test]
    fn flows_filter_by_exit_and_skip_direct() {
        let f = fixture();
        let us = id(&f.setup, "us");
        let v = f.view("flows", Some(&us), SpeedInputs::default());
        assert_eq!("3 apps into 2 exits · Direct traffic not shown", v.flows.sub);
        assert_eq!(vec!["Firefox", "Unknown app"], v.flows.rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>());
        assert_eq!(1.0, v.flows.rows[0].frac, "the list's first is the full meter");
        assert!(v.flows.lanes.iter().any(|l| l.selected && l.id == us));
        assert_eq!(
            vec![false, false, true],
            v.flows.pills.iter().map(|p| p.on).collect::<Vec<_>>(),
            "All, then the exits by data"
        );
        // The app's own traffic is named after it.
        let v = f.view("flows", None, SpeedInputs::default());
        assert_eq!("unbraid", v.flows.rows[1].name);
        // An exit with no data in the period filters nothing.
        assert_eq!(4, f.view("flows", Some("gone"), SpeedInputs::default()).flows.rows.len());
    }

    #[test]
    fn the_journal_counts_a_day_with_its_pause() {
        let f = fixture();
        let v = view(&Inputs {
            journal_day: Some(epoch_day(NaiveDate::from_ymd_opt(2026, 11, 10).unwrap())),
            ..inputs(&f)
        });
        assert_eq!("Tuesday 10 November", v.journal.date);
        assert_eq!(vec![part("5", "h"), part("30", "m")], v.journal.facts[0].parts);
        assert_eq!(vec![part("4", "h"), part("0", "m")], v.journal.facts[1].parts);
        assert_eq!("pauses · 30 m", v.journal.facts[2].label);
        assert!(v.journal.has_next && v.journal.has_prev);
        assert_eq!("1 of 7 days with at least 4 h connected", v.journal.sub);
        // Until a day is picked, the last with data: today. Tomorrow is not yet.
        let v = view(&inputs(&f));
        assert_eq!(epoch_day(NaiveDate::from_ymd_opt(2026, 11, 11).unwrap()) as i32, v.journal.day);
        assert!(!v.journal.has_next);
        assert_eq!(-1.0, v.journal.heat[v.journal.index as usize + 1]);
    }

    fn inputs(f: &Fixture) -> Inputs<'_> {
        Inputs {
            data: Some(&f.data),
            period: Period::Week,
            section: "journal",
            now: now(),
            setup: &f.setup,
            running: Some(&f.setup),
            vpn: &f.vpn,
            tags: &f.tags,
            live: &f.live,
            labels: &f.labels,
            has_data: true,
            flows_exit: None,
            flows_all: false,
            journal_day: None,
            speed: SpeedInputs::default(),
        }
    }

    #[test]
    fn tunnels_list_the_fastest_first_then_by_name() {
        let f = fixture();
        let v = f.view("tunnels", None, SpeedInputs::default());
        assert_eq!(
            vec!["Netherlands", "United States"],
            v.tunnels.rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>()
        );
        assert_eq!("↓800 ↑90.0", v.tunnels.rows[0].test);
        // A missing upload is a dash.
        assert_eq!("↓300 ↑—", v.tunnels.rows[1].test);
        assert_eq!("↓ download · ↑ 90.0 Mbps upload · Netherlands", v.tunnels.sub);
    }

    #[test]
    fn history_folds_a_combined_run_into_one_row() {
        let mut f = fixture();
        let (nl, us) = (id(&f.setup, "nl"), id(&f.setup, "us"));
        f.data.tests = vec![
            test(at(10, 21, 0), ALL, 900_000_000, 200_000_000, 7),
            test(at(10, 21, 0), &nl, 600_000_000, 100_000_000, 7),
            test(at(10, 21, 0), &us, 300_000_000, 0, 7),
            test(at(9, 9, 0), &nl, 500_000_000, 50_000_000, 0),
        ];
        let v = f.view("history", None, SpeedInputs::default());
        assert_eq!("3 tests", v.history.overline);
        assert_eq!(2, v.history.rows.len());
        assert_eq!(
            ("ALL", "2 exits together".to_string()),
            (v.history.rows[0].code.as_str(), format!("{} exits together", v.history.rows[0].members.len()))
        );
        assert_eq!("500", v.history.best, "the best download is a solo test's");
        assert_eq!("Nord · nl1", v.history.rows[1].line);
    }

    #[test]
    fn the_speed_test_offers_routed_exits_then_all_together() {
        let f = fixture();
        let v = f.view("speed", None, SpeedInputs::default());
        assert_eq!(
            vec!["Netherlands", "United States"],
            v.speed.choices.iter().map(|c| c.name.as_str()).collect::<Vec<_>>()
        );
        assert!(v.speed.choices[0].on && !v.speed.all_on, "the first exit until one is picked");
        assert_eq!(("GO", 200), (v.speed.go.text.as_str(), v.speed.go.size));
        assert_eq!("Finding one in Netherlands…", v.speed.server.place);
        // All together: every route, the one without apps connecting for the test.
        let v = f.view("speed", None, SpeedInputs { chosen: Some(ALL), ..SpeedInputs::default() });
        assert!(v.speed.all_on);
        assert_eq!("All exits · together", v.speed.overline);
        assert_eq!(vec!["lab", "nl", "us"], v.speed.together.start);
        assert_eq!("WireGuard · connects for the test", v.speed.together.picks[0].sub);
        let unticked = ["lab".to_string(), "us".to_string()];
        let v = f.view("speed", None, SpeedInputs { chosen: Some(ALL), unticked: &unticked, ..SpeedInputs::default() });
        assert_eq!("Tick at least two exits.", v.speed.together.note);
        assert_eq!("Selected 1 of 3", v.speed.together.heading);
    }

    #[test]
    fn before_together_an_exit_without_a_server_at_home_is_asked_about() {
        let f = fixture();
        let server = |city: &str| Some(Server { city: city.into(), country: "DE".into(), ..Server::default() });
        let all = All {
            id: 1,
            legs: vec![
                Leg { server: server("Amsterdam"), ..Leg::new("nl") },
                Leg {
                    server: server("Frankfurt"),
                    missing: true,
                    ping: Some(Ping { median: 20, low: 18, high: 25 }),
                    ..Leg::new("lab")
                },
                Leg { error: Some("The route isn't connected.".into()), ..Leg::new("us") },
            ],
            metered: true,
            phase: Stage::Deciding,
            now: 0,
            down: None,
            up: None,
            elapsed_ms: 0,
            window_ms: 0,
            error: None,
        };
        let v = f.view("speed", None, SpeedInputs { all: Some(&all), tests_today: 37, ..SpeedInputs::default() });
        let t = &v.speed.together;
        assert!(t.deciding && v.speed.busy);
        assert_eq!(vec!["lab"], t.nearest);
        assert_eq!(
            vec!["No test server in Home lab", "United States can't join"],
            t.decisions.iter().map(|d| d.title.as_str()).collect::<Vec<_>>()
        );
        assert_eq!("The route isn't connected. It's left out of this run.", t.decisions[1].text);
        assert!(t.decisions[0].choice && !t.decisions[1].choice);
        // Netherlands' best test this week, and 1 Gbit/s for one never tested; 3 tests left of M-Lab's 40.
        assert!(t.cost.starts_with("On a metered connection: about 2.4 GB in 20 seconds"), "{}", t.cost);
        assert!(t.cost.contains("Uses 2 of about 3 tests left today"), "{}", t.cost);
        assert_eq!(("Start 2 together", true), (t.yes.as_str(), t.can_go));
        // Left out, it doesn't go: one exit can't run together.
        let out = ["lab".to_string()];
        let v = f.view(
            "speed",
            None,
            SpeedInputs { all: Some(&all), tests_today: 37, leave_out: &out, ..SpeedInputs::default() },
        );
        assert_eq!(("Needs two exits", false), (v.speed.together.yes.as_str(), v.speed.together.can_go));
        let v = f.view("speed", None, SpeedInputs { all: Some(&all), tests_today: 39, ..SpeedInputs::default() });
        assert_eq!("Not enough tests left", v.speed.together.yes);
    }
}
