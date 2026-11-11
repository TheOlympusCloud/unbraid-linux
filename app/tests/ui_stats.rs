//! Renders Stats headless beside the sidebar, as the window shows it, with the data of the approved screenshots: a week
//! of traffic through three Nord exits, seen on Wednesday 11 November at 00:31. The hub in both themes and at the
//! smallest window, then each section. Shots go to `target/screenshots/stats-*.png`.

mod common;

use chrono::{Local, NaiveDate, NaiveDateTime, TimeZone};
use common::{headless, render, shots_dir};
use indexmap::IndexMap;
use slint::platform::WindowEvent;
use slint::{ComponentHandle, ModelRc, Rgb8Pixel, SharedString, VecModel};
use unbraid::model::{Location, Prefs, Route, Server, Setup, WgPeer};
use unbraid::ndt7::{self, Ping};
use unbraid::speed_test::{self, All, Leg, Phase as Stage, Run};
use unbraid::stats::{self, Bytes, Live, Test};
use unbraid::ui::stats::{self as logic, Data, Inputs, Period, SpeedInputs};
use unbraid::vpn::{Phase as VpnPhase, VpnState};

slint::slint! {
    import { Sidebar, ProfileChip } from "../ui/shell.slint";
    import { StatsScreen, StatsPage } from "../ui/stats.slint";
    import { Ink } from "../ui/theme.slint";
    import { Motion } from "../ui/motion.slint";
    export { StatsPage, Ink, Motion }
    export { NumPart, Part, Legend, Share, SpeedBar, AppBar, ExitBar, HubView, UsageView, LiveRow, LiveView, Named, Segment, Lane, Pill, FlowRow, FlowsView, Fact, JournalView, TunnelRow, TunnelsView, ServerRow, TunnelView, Member, HistoryRow, HistoryView, OffView, ChartPart, ChartSeries, DaySpan, MonthMark } from "../ui/stats.slint";
    export { Choice, SpeedCard, Gauge, GoButton, ServerCard, LegBar, LegResult, LegPick, Decision, Together, SpeedView } from "../ui/stats.slint";

    // The window as it will be: the sidebar, then the page.
    export component Shot inherits Window {
        in property <bool> wide: true;
        in property <[ProfileChip]> chips: [{ name: "Work" }, { name: "Home" }];
        background: Ink.ground;
        HorizontalLayout {
            Sidebar {
                wide: root.wide;
                current: 2;
                version: "2.8.2";
                profiles: root.chips;
            }
            StatsScreen { }
        }
    }
}

const KEY: &str = "5p4RkybdRU5uaDi90eu4KZPTFif0lKCg4Qp6t1c4F30=";
const HOUR: i64 = 3_600_000;

fn s(x: &str) -> SharedString {
    x.into()
}

fn list<T: Clone + 'static>(v: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(v))
}

fn strings(v: &[String]) -> ModelRc<SharedString> {
    list(v.iter().map(|x| s(x)).collect())
}

fn num(p: &logic::NumPart) -> NumPart {
    NumPart { value: s(&p.value), unit: s(&p.unit) }
}

fn nums(v: &[logic::NumPart]) -> ModelRc<NumPart> {
    list(v.iter().map(num).collect())
}

fn share(x: &logic::Share) -> Share {
    Share { name: s(&x.name), value: s(&x.value), pct: s(&x.pct), frac: x.frac }
}

fn part(p: &logic::Part) -> Part {
    Part { value: p.value, hue: p.hue }
}

/// A chart's parts in their colours: the page's ink for each hue, in the theme shown.
fn columns(page: &StatsPage, v: &[Vec<logic::Part>]) -> ModelRc<ModelRc<ChartPart>> {
    list(
        v.iter()
            .map(|c| list(c.iter().map(|p| ChartPart { value: p.value, color: page.invoke_ink(p.hue) }).collect()))
            .collect(),
    )
}

fn go_button(g: &logic::GoButton) -> GoButton {
    GoButton { text: s(&g.text), size: g.size, hue: g.hue, label: s(&g.label), working: g.working, bloom: g.bloom }
}

fn gauge(g: &logic::Gauge) -> Gauge {
    Gauge { mbps: g.mbps, label: s(&g.label), upload: g.upload, progress: g.progress, status: s(&g.status) }
}

fn cards(v: &[logic::SpeedCard]) -> ModelRc<SpeedCard> {
    list(
        v.iter()
            .map(|c| SpeedCard { title: s(&c.title), value: s(&c.value), unit: s(&c.unit), active: c.active })
            .collect(),
    )
}

fn choices(v: &[logic::Choice]) -> ModelRc<Choice> {
    list(v.iter().map(|c| Choice { id: s(&c.id), code: s(&c.code), hue: c.hue, name: s(&c.name), on: c.on }).collect())
}

fn speed_view(v: &logic::SpeedView) -> SpeedView {
    let t = &v.together;
    SpeedView {
        overline: s(&v.overline),
        empty: v.empty,
        all_chip: v.all_chip,
        all_on: v.all_on,
        all_hues: list(v.all_hues.clone()),
        all_text: s(&v.all_text),
        choices: choices(&v.choices),
        busy: v.busy,
        exit: s(&v.exit),
        name: s(&v.name),
        hue: v.hue,
        cards: cards(&v.cards),
        measuring: v.measuring,
        gauge: gauge(&v.gauge),
        error: s(&v.error),
        missing: s(&v.missing),
        go: go_button(&v.go),
        preparing: s(&v.preparing),
        server_shown: v.server_shown,
        server: ServerCard { place: s(&v.server.place), line: s(&v.server.line) },
        note: s(&v.note),
        ask: v.ask,
        ask_title: s(&v.ask_title),
        ask_text: s(&v.ask_text),
        terms: s(&v.terms),
        together: Together {
            cards: cards(&t.cards),
            measuring: t.measuring,
            gauge: gauge(&t.gauge),
            exits: t.exits,
            bars: list(
                t.bars
                    .iter()
                    .map(|b| LegBar { code: s(&b.code), hue: b.hue, frac: b.frac, now: s(&b.now), stopped: b.stopped })
                    .collect(),
            ),
            finished: t.finished,
            error: s(&t.error),
            done: t.done,
            window: s(&t.window),
            share: list(t.share.iter().map(part).collect()),
            results: list(
                t.results
                    .iter()
                    .map(|r| LegResult {
                        code: s(&r.code),
                        hue: r.hue,
                        name: s(&r.name),
                        line: s(&r.line),
                        failed: r.failed,
                        down: s(&r.down),
                        up: s(&r.up),
                        ping: s(&r.ping),
                    })
                    .collect(),
            ),
            heading: s(&t.heading),
            working: t.working,
            picks: list(
                t.picks
                    .iter()
                    .map(|k| LegPick {
                        id: s(&k.id),
                        code: s(&k.code),
                        hue: k.hue,
                        name: s(&k.name),
                        sub: s(&k.sub),
                        on: k.on,
                        state: s(&k.state),
                        tone: k.tone,
                    })
                    .collect(),
            ),
            nodes: choices(&t.nodes),
            go: go_button(&t.go),
            note: s(&t.note),
            start: strings(&t.start),
            deciding: t.deciding,
            decisions: list(
                t.decisions
                    .iter()
                    .map(|d| Decision {
                        exit: s(&d.exit),
                        code: s(&d.code),
                        hue: d.hue,
                        title: s(&d.title),
                        text: s(&d.text),
                        choice: d.choice,
                        via: s(&d.via),
                        out: s(&d.out),
                        via_on: d.via_on,
                    })
                    .collect(),
            ),
            cost: s(&t.cost),
            yes: s(&t.yes),
            can_go: t.can_go,
            nearest: strings(&t.nearest),
        },
    }
}

/// The view on the Page global, as the window will set it.
fn show(shot: &Shot, v: &logic::StatsView) {
    let page = StatsPage::get(shot);
    page.set_recording(v.recording);
    page.set_off(OffView {
        overline: s(&v.off.overline),
        title: s(&v.off.title),
        text: s(&v.off.text),
        button: s(&v.off.button),
        saved: v.off.saved,
    });
    page.set_loaded(v.loaded);
    page.set_period(v.period);
    page.set_section(s(&v.section));
    page.set_back(s(&v.back));
    page.set_range(s(&v.range));
    page.set_labels(strings(&v.labels));
    page.set_cap(v.cap);
    page.set_scale(s(&v.scale));
    page.set_selected(v.selected);
    page.set_empty(v.empty);
    page.set_weekdays(strings(&v.weekdays));
    let h = &v.hub;
    page.set_hub(HubView {
        overline: s(&h.overline),
        usage: num(&h.usage),
        usage_line: s(&h.usage_line),
        providers: list(h.providers.iter().map(share).collect()),
        live: h.live,
        live_now: num(&h.live_now),
        spark: list(h.spark.clone()),
        week: nums(&h.week),
        week_hours: list(h.week_hours.clone()),
        today: h.today,
        tested: h.tested,
        best: s(&h.best),
        best_line: s(&h.best_line),
        fastest: list(h.fastest.iter().map(|b| SpeedBar { code: s(&b.code), hue: b.hue, frac: b.frac }).collect()),
        legend: list(h.legend.iter().map(|l| Legend { name: s(&l.name), hue: l.hue }).collect()),
        columns: columns(&page, &h.columns),
        summary: s(&h.summary),
        apps: list(
            h.apps
                .iter()
                .map(|a| AppBar { name: s(&a.name), code: s(&a.code), hue: a.hue, frac: a.frac, bytes: s(&a.bytes) })
                .collect(),
        ),
        exits: list(
            h.exits
                .iter()
                .map(|e| ExitBar {
                    code: s(&e.code),
                    hue: e.hue,
                    name: s(&e.name),
                    apps: s(&e.apps),
                    bytes: s(&e.bytes),
                })
                .collect(),
        ),
    });
    let u = &v.usage;
    page.set_usage(UsageView {
        over: s(&u.over),
        value: num(&u.value),
        sub: s(&u.sub),
        trailing: s(&u.trailing),
        columns: columns(&page, &u.columns),
        summary: s(&u.summary),
        label: s(&u.label),
        providers: list(u.providers.iter().map(share).collect()),
    });
    let l = &v.live;
    page.set_live(LiveView {
        overline: s(&l.overline),
        empty: s(&l.empty),
        now: num(&l.now),
        sub: s(&l.sub),
        series: list(
            l.series
                .iter()
                .map(|x| ChartSeries { values: list(x.values.clone()), color: page.invoke_ink(x.hue) })
                .collect(),
        ),
        cap: l.cap,
        summary: s(&l.summary),
        rows: list(
            l.rows
                .iter()
                .map(|r| LiveRow { code: s(&r.code), hue: r.hue, name: s(&r.name), via: s(&r.via), now: num(&r.now) })
                .collect(),
        ),
    });
    let f = &v.flows;
    page.set_flows(FlowsView {
        sub: s(&f.sub),
        empty: f.empty,
        share: list(f.share.iter().map(part).collect()),
        lanes: list(
            f.lanes
                .iter()
                .map(|l| Lane {
                    id: s(&l.id),
                    code: s(&l.code),
                    hue: l.hue,
                    name: s(&l.name),
                    apps: s(&l.apps),
                    bytes: s(&l.bytes),
                    pct: s(&l.pct),
                    frac: l.frac,
                    segments: list(l.segments.iter().map(|g| Segment { weight: g.weight, alpha: g.alpha }).collect()),
                    names: list(l.names.iter().map(|n| Named { name: s(&n.name), bytes: s(&n.bytes) }).collect()),
                    rest: s(&l.rest),
                    selected: l.selected,
                })
                .collect(),
        ),
        pills: list(
            f.pills
                .iter()
                .map(|p| Pill { id: s(&p.id), code: s(&p.code), hue: p.hue, text: s(&p.text), on: p.on })
                .collect(),
        ),
        rows: list(
            f.rows
                .iter()
                .map(|r| FlowRow {
                    pkg: s(&r.pkg),
                    letter: s(&r.letter),
                    name: s(&r.name),
                    code: s(&r.code),
                    hue: r.hue,
                    bytes: s(&r.bytes),
                    frac: r.frac,
                })
                .collect(),
        ),
        more: s(&f.more),
    });
    let j = &v.journal;
    page.set_journal(JournalView {
        week: nums(&j.week),
        sub: s(&j.sub),
        heat: list(j.heat.clone()),
        months: list(j.months.iter().map(|m| MonthMark { week: m.week, name: s(&m.name) }).collect()),
        index: j.index,
        day: j.day,
        date: s(&j.date),
        has_prev: j.has_prev,
        has_next: j.has_next,
        spans: list(j.spans.iter().map(|x| DaySpan { from: x.from, to: x.to, paused: x.paused }).collect()),
        summary: s(&j.summary),
        facts: list(j.facts.iter().map(|x| Fact { parts: nums(&x.parts), label: s(&x.label) }).collect()),
    });
    let t = &v.tunnels;
    page.set_tunnels(TunnelsView {
        tested: t.tested,
        best: s(&t.best),
        sub: s(&t.sub),
        rows: list(
            t.rows
                .iter()
                .map(|r| TunnelRow {
                    id: s(&r.id),
                    code: s(&r.code),
                    hue: r.hue,
                    name: s(&r.name),
                    via: s(&r.via),
                    tested: r.tested,
                    test: s(&r.test),
                    frac: r.frac,
                })
                .collect(),
        ),
    });
    let t = &v.tunnel;
    page.set_tunnel(TunnelView {
        id: s(&t.id),
        overline: s(&t.overline),
        title: s(&t.title),
        hue: t.hue,
        tested: t.tested,
        best: s(&t.best),
        sub: s(&t.sub),
        servers: list(t.servers.iter().map(|x| ServerRow { name: s(&x.name), pct: s(&x.pct), frac: x.frac }).collect()),
    });
    page.set_speed(speed_view(&v.speed));
    page.set_mlab_consent(true);
    let x = &v.history;
    page.set_history(HistoryView {
        overline: s(&x.overline),
        tested: x.tested,
        best: s(&x.best),
        sub: s(&x.sub),
        rows: list(
            x.rows
                .iter()
                .map(|r| HistoryRow {
                    all: r.all,
                    code: s(&r.code),
                    hue: r.hue,
                    when: s(&r.when),
                    down: s(&r.down),
                    up: s(&r.up),
                    ping: s(&r.ping),
                    line: s(&r.line),
                    members: list(
                        r.members
                            .iter()
                            .map(|m| Member {
                                code: s(&m.code),
                                hue: m.hue,
                                name: s(&m.name),
                                down: s(&m.down),
                                up: s(&m.up),
                                ping: s(&m.ping),
                            })
                            .collect(),
                    ),
                })
                .collect(),
        ),
    });
}

/// The set-up app of the approved screenshots, recording statistics.
fn set_up() -> Setup {
    let lab =
        WgPeer::new("Home lab", KEY, vec!["10.8.0.2/32".into()], KEY, "203.0.113.7:51820", vec!["0.0.0.0/0".into()]);
    Setup {
        routes: vec![
            Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
            Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
            Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
            Route { wg: Some(lab), hue: 3, ..Route::new("lab", Location::default()) },
        ],
        default_route: "nl".into(),
        prefs: Prefs { stats: true, ..Prefs::default() },
        ..Setup::default()
    }
}

/// When the approved screenshots were taken: Wednesday 11 November, 00:31.
fn now() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(2026, 11, 11).and_then(|d| d.and_hms_opt(0, 31, 0)).expect("a date")
}

/// What the stats file held for the approved screenshots: each of the last 168 hours, six apps through three exits,
/// lighter at night; as the window reads it for `period`.
fn week_of_traffic(s: &Setup, period: Period) -> Data {
    let now_ms = Local.from_local_datetime(&now()).earliest().expect("a local time").timestamp_millis();
    let exit = |id: &str| stats::id_of(s.route(Some(id)).expect("a route"));
    let apps = [
        ("firefox", "us", 3e6, 60e6),
        ("spotify", "it", 1e6, 24e6),
        ("chromium", "nl", 2e6, 38e6),
        ("thunderbird", "us", 1e6, 6e6),
        ("discord", "it", 2e6, 9e6),
        ("signal-desktop", "nl", 1e6, 3e6),
    ];
    let (a, b) = logic::range(period, now().date());
    let (from, to) = (logic::epoch_day(a), logic::epoch_day(b));
    let mut d = Data::default();
    let mut by_app: IndexMap<(String, String), i64> = IndexMap::new();
    for h in 0..24 * 7 {
        let at = now_ms - h * HOUR;
        let night = if (1..=6).contains(&((at / HOUR) % 24)) { 0.1 } else { 1.0 };
        let w = 0.4 + 0.6 * (h as f64 / 4.0).sin().powi(2) * night;
        let day = stats::day_of(at);
        if day < from || day > to {
            continue;
        }
        for (app, route, up, down) in apps {
            let bytes = Bytes { up: (up * w) as i64, down: (down * w) as i64 };
            let e = d.days.entry(day).or_default().entry(exit(route)).or_default();
            e.up += bytes.up;
            e.down += bytes.down;
            if period == Period::Day {
                let e = d.hours.entry(stats::hour_of(at) - day * 24).or_default().entry(exit(route)).or_default();
                e.up += bytes.up;
                e.down += bytes.down;
            }
            *by_app.entry((app.to_string(), exit(route))).or_default() += bytes.total();
        }
    }
    d.apps = by_app.into_iter().map(|((app, exit), b)| (app, exit, b)).collect();
    d.apps.sort_by_key(|a| std::cmp::Reverse(a.2));
    d
}

/// The installed apps' names, as listed.
fn labels() -> IndexMap<String, String> {
    [
        ("firefox", "Firefox"),
        ("spotify", "Spotify"),
        ("chromium", "Chromium"),
        ("thunderbird", "Thunderbird"),
        ("signal-desktop", "Signal"),
        ("discord", "Discord"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// The page as the window shows it for `section`, with `data`.
fn stats_view(s: &Setup, data: &Data, period: Period, section: &str) -> logic::StatsView {
    World {
        setup: s.clone(),
        data: data.clone(),
        vpn: VpnState::default(),
        tags: IndexMap::new(),
        live: Live::default(),
    }
    .view(period, section, None)
}

/// What the page reads besides the stats file, for one picture of the app.
struct World {
    setup: Setup,
    data: Data,
    vpn: VpnState,
    tags: IndexMap<String, String>,
    live: Live,
}

impl World {
    fn view(&self, period: Period, section: &str, journal_day: Option<i64>) -> logic::StatsView {
        self.view_with(period, section, journal_day, SpeedInputs::default())
    }

    fn view_with(
        &self,
        period: Period,
        section: &str,
        journal_day: Option<i64>,
        speed: SpeedInputs,
    ) -> logic::StatsView {
        let on = self.vpn.phase == VpnPhase::On;
        logic::view(&Inputs {
            data: Some(&self.data),
            period,
            section,
            now: now(),
            setup: &self.setup,
            running: on.then_some(&self.setup),
            vpn: &self.vpn,
            tags: &self.tags,
            live: &self.live,
            labels: &labels(),
            has_data: true,
            flows_exit: None,
            flows_all: false,
            journal_day,
            speed,
        })
    }
}

/// Local time `h:m` on day `d` of November 2026, or `d` days before 1 November when negative, in epoch ms.
fn ms(d: i64, h: u32, m: u32) -> i64 {
    let day = NaiveDate::from_ymd_opt(2026, 11, 1).expect("a date") + chrono::TimeDelta::days(d - 1);
    Local
        .from_local_datetime(&day.and_hms_opt(h, m, 0).expect("a time"))
        .earliest()
        .expect("a local time")
        .timestamp_millis()
}

/// A speed test; `run` is its combined run's start and size ((0, 1) alone).
fn test(at: i64, exit: &str, server: &str, down: f64, up: f64, ping: i32, run: (i64, i32)) -> Test {
    let (grp, n) = run;
    Test {
        at,
        exit: exit.into(),
        via: "Nord".into(),
        server: server.into(),
        ip: String::new(),
        down: (down * 1e6) as i64,
        up: (up * 1e6) as i64,
        idle: ping,
        busy_down: 0,
        busy_up: 0,
        grp,
        n,
    }
}

/// The same week, connected: three tunnels with their servers, a minute of live samples, speed tests (one a combined
/// run), and the connected days of the last weeks.
fn connected() -> World {
    let setup = set_up();
    let mut data = week_of_traffic(&setup, Period::Week);
    let id = |r: &str| stats::id_of(setup.route(Some(r)).expect("a route"));
    let (nl, us, it) = (id("nl"), id("us"), id("it"));
    let together = ms(10, 21, 0);
    data.tests = vec![
        test(together + 30_000, &nl, "nl1256", 301.2, 92.4, 16, (together, 3)),
        test(together + 30_000, &us, "us8412", 188.6, 31.0, 97, (together, 3)),
        test(together + 30_000, &it, "it204", 104.9, 29.7, 41, (together, 3)),
        test(together + 30_000, "all", "", 594.7, 153.1, 0, (together, 3)),
        test(ms(10, 17, 3), &it, "it204", 128.4, 37.9, 38, (0, 1)),
        test(ms(10, 10, 12), &nl, "nl1256", 412.3, 88.1, 14, (0, 1)),
        test(ms(9, 19, 40), &us, "us8412", 236.8, 41.2, 96, (0, 1)),
    ];
    // Most days of the last weeks, and Tuesday in full: a morning, a pause at noon, the afternoon and the evening.
    data.spans = (2..80)
        .filter(|k| k % 7 != 3)
        .map(|k| (ms(11 - k, 8, 30), ms(11 - k, 9 + (k * 5 % 9) as u32, 10), false))
        .collect();
    data.spans.extend([
        (ms(10, 8, 10), ms(10, 12, 0), false),
        (ms(10, 12, 0), ms(10, 12, 25), true),
        (ms(10, 12, 25), ms(10, 18, 40), false),
        (ms(10, 20, 0), ms(10, 23, 15), false),
        (ms(11, 0, 5), ms(11, 0, 31), false),
    ]);
    data.spans.sort();
    data.servers = vec![("nl1256".into(), 820_000_000), ("nl1190".into(), 310_000_000), ("nl977".into(), 95_000_000)];
    let server = |name: &str, city: &str| Server {
        name: name.into(),
        host: format!("{name}.nordvpn.com"),
        ip: String::new(),
        public_key: String::new(),
        load: 9,
        city: city.into(),
        country: String::new(),
    };
    let vpn = VpnState {
        phase: VpnPhase::On,
        since: ms(11, 0, 5),
        servers: [
            ("nl".to_string(), server("nl1256", "Amsterdam")),
            ("us".into(), server("us8412", "New York")),
            ("it".into(), server("it204", "Milan")),
        ]
        .into_iter()
        .collect(),
        ..VpnState::default()
    };
    let wave = |base: f32, swing: f32, phase: f32| {
        (0..60).map(|i| (base + swing * ((i as f32 + phase) / 6.0).sin()).max(0.0) * 1e6).collect::<Vec<f32>>()
    };
    let live = Live {
        down: [
            (nl.clone(), wave(18.0, 7.0, 0.0)),
            (us.clone(), wave(7.5, 3.0, 9.0)),
            (it.clone(), wave(2.4, 1.2, 20.0)),
        ]
        .into_iter()
        .collect(),
        down_now: 0,
        up_now: 1_240_000,
    };
    let live = Live { down_now: live.down.values().map(|s| s[59] as i64).sum(), ..live };
    let tags = ["nl", "us", "it"].iter().map(|r| (r.to_string(), r.to_string())).collect();
    World { setup, data, vpn, tags, live }
}

fn shot_of(v: &logic::StatsView, light: bool, wide: bool) -> Shot {
    let shot = Shot::new().expect("create the window");
    Ink::get(&shot).set_light(light);
    shot.set_wide(wide);
    show(&shot, v);
    shot
}

fn at(pixels: &[Rgb8Pixel], width: u32, x: u32, y: u32) -> [u8; 3] {
    let p = pixels[(y * width + x) as usize];
    [p.r, p.g, p.b]
}

const GROUND: [u8; 3] = [0x0f, 0x12, 0x14];
const SURFACE: [u8; 3] = [0x17, 0x1b, 0x1e];
const SURFACE_TOP: [u8; 3] = [0x23, 0x2a, 0x2e];
const ACCENT_CONTAINER: [u8; 3] = [0x3a, 0x2a, 0x1f];

/// The hub, as approved: dark and light at the default size, and at the smallest window with the sidebar a rail.
#[test]
fn hub_as_approved() {
    headless();
    let dir = shots_dir();
    let s = set_up();
    let data = week_of_traffic(&s, Period::Week);
    let v = stats_view(&s, &data, Period::Week, "");
    assert_eq!("9–15 NOV", v.hub.overline);
    assert_eq!(
        vec!["United States", "Netherlands", "Italy"],
        v.hub.exits.iter().map(|e| e.name.as_str()).collect::<Vec<_>>()
    );
    for (light, file) in [(false, "stats-dark.png"), (true, "stats-light.png")] {
        let shot = shot_of(&v, light, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        if light {
            assert_eq!([0xf5, 0xf2, 0xee], at(&px, 1280, 640, 296), "{file}: the light ground");
            continue;
        }
        assert_eq!(GROUND, at(&px, 1280, 640, 296), "{file}: the ground between tiles and chart");
        assert_eq!(SURFACE, at(&px, 1280, 640, 260), "{file}: the Live tile");
        assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 980, 60), "{file}: the period on, Week");
        assert_eq!(SURFACE, at(&px, 1280, 1000, 500), "{file}: the chart's card");
    }
    let shot = shot_of(&v, false, false);
    render(&shot, 880, 600, &dir.join("stats-small.png"));
}

/// Usage, from its tile: the week's bars, neutral, and the providers' shares.
#[test]
fn usage_as_approved() {
    headless();
    let s = set_up();
    let data = week_of_traffic(&s, Period::Week);
    let v = stats_view(&s, &data, Period::Week, "usage");
    assert_eq!("By provider · share of the week", v.usage.label);
    let shot = shot_of(&v, false, true);
    let px = render(&shot, 1280, 800, &shots_dir().join("stats-usage.png"));
    assert_eq!(SURFACE_TOP, at(&px, 1280, 700, 300), "the hero card");
    assert_eq!(ACCENT_CONTAINER, at(&px, 1280, 760, 165), "the period on, Week");
}

/// Each section of the connected week, as its tile or link opens it.
#[test]
fn sections() {
    headless();
    let dir = shots_dir();
    let w = connected();
    let nl = stats::id_of(w.setup.route(Some("nl")).expect("a route"));
    let tuesday = logic::epoch_day(NaiveDate::from_ymd_opt(2026, 11, 10).expect("a date"));
    let tunnel = format!("tunnel:{nl}");
    for (section, file, day) in [
        ("", "stats-connected.png", None),
        ("live", "stats-live.png", None),
        ("flows", "stats-flows.png", None),
        ("journal", "stats-journal.png", Some(tuesday)),
        ("tunnels", "stats-tunnels.png", None),
        (tunnel.as_str(), "stats-tunnel.png", None),
        ("history", "stats-history.png", None),
    ] {
        let v = w.view(Period::Week, section, day);
        let shot = shot_of(&v, false, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        if !section.is_empty() {
            assert_eq!(GROUND, at(&px, 1280, 1200, 400), "{file}: the ground beside the reading width");
        }
        if section == "live" {
            assert_eq!("Now · 3 exits", v.live.overline);
            assert_eq!(SURFACE_TOP, at(&px, 1280, 700, 230), "{file}: the hero card");
        }
        if section == "journal" {
            assert_eq!("Tuesday 10 November", v.journal.date);
            assert_eq!(
                vec!["13 h 20 m", "6 h 15 m"],
                v.journal
                    .facts
                    .iter()
                    .take(2)
                    .map(|f| f.parts.iter().map(|p| format!("{} {}", p.value, p.unit)).collect::<Vec<_>>().join(" "))
                    .collect::<Vec<_>>()
            );
            assert_eq!("pauses · 25 m", v.journal.facts[2].label);
        }
        if section == "history" {
            assert_eq!("6 tests", v.history.overline);
            assert_eq!(3, v.history.rows[0].members.len(), "the combined run lists its exits");
        }
    }
}

/// Recording off with statistics kept: the page that offers them, and its consent sheet over the whole window.
#[test]
fn off_and_consent() {
    headless();
    let dir = shots_dir();
    let mut s = set_up();
    s.prefs.stats = false;
    let data = week_of_traffic(&s, Period::Week);
    let v = stats_view(&s, &data, Period::Week, "");
    assert_eq!("Recording off · saved statistics", v.hub.overline);
    let shot = shot_of(&v, false, true);
    let px = render(&shot, 1280, 800, &dir.join("stats-off.png"));
    assert_eq!(SURFACE_TOP, at(&px, 1280, 300, 190), "the page's mark");
    // Turn back on asks first, in a sheet over the whole window; Esc closes it.
    click(&shot, 357.0, 444.0);
    let px = render(&shot, 1280, 800, &dir.join("stats-consent.png"));
    assert!(near(at(&px, 1280, 640, 780), SURFACE), "the sheet: {:?}", at(&px, 1280, 640, 780));
    shot.window().dispatch_event(WindowEvent::KeyPressed { text: slint::platform::Key::Escape.into() });
    shot.window().dispatch_event(WindowEvent::KeyReleased { text: slint::platform::Key::Escape.into() });
    let px = common::shoot(&shot, 1280, 800, std::time::Duration::from_secs(1));
    assert_eq!(GROUND, at(&px, 1280, 640, 780), "Esc closed the sheet");
}

fn click(shot: &Shot, x: f32, y: f32) {
    let position = slint::LogicalPosition::new(x, y);
    let button = slint::platform::PointerEventButton::Left;
    shot.window().dispatch_event(WindowEvent::PointerMoved { position });
    shot.window().dispatch_event(WindowEvent::PointerPressed { position, button });
    shot.window().dispatch_event(WindowEvent::PointerReleased { position, button });
}

/// An M-Lab server, as Locate names one.
fn mlab(city: &str, country: &str, machine: &str) -> ndt7::Server {
    ndt7::Server { machine: machine.into(), city: city.into(), country: country.into(), ..ndt7::Server::default() }
}

fn leg(
    exit: &str,
    server: Option<ndt7::Server>,
    missing: bool,
    now: f64,
    down: Option<f64>,
    up: Option<f64>,
    ping: Option<i32>,
) -> Leg {
    let mbits = |m: f64| (m * 1e6) as i64;
    Leg {
        server,
        missing,
        now: mbits(now),
        down: down.map(mbits),
        up: up.map(mbits),
        ping: ping.map(|median| Ping { median, low: median - 2, high: median + 5 }),
        ..Leg::new(exit)
    }
}

fn combined(phase: Stage, legs: Vec<Leg>) -> All {
    let now = legs.iter().map(|l| l.now).sum();
    All {
        id: 1,
        legs,
        metered: true,
        phase,
        now,
        down: None,
        up: None,
        elapsed_ms: 7_200,
        window_ms: 9_400,
        error: None,
    }
}

/// The speed test, connected: one exit's finished test and one measuring; then every route together, before, while
/// measuring and once done, and the sheet that asks about an exit without a test server in its country.
#[test]
fn speed() {
    headless();
    let dir = shots_dir();
    let w = connected();
    let ams = mlab("Amsterdam", "NL", "mlab1-ams09.mlab-oti.measurement-lab.org");
    let done = Run {
        phase: Stage::Done,
        down: Some(412_300_000),
        up: Some(88_100_000),
        ping: Some(Ping { median: 12, low: 10, high: 17 }),
        server: Some(ams.clone()),
        ..Run::new("nl")
    };
    let measuring =
        Run { phase: Stage::Download, now: 287_400_000, down: None, up: None, elapsed_ms: 6_400, ..done.clone() };
    let mut s = w.setup.clone();
    s.apps.insert("firefox".into(), "us".into());
    s.apps.insert("spotify".into(), "it".into());
    let w = World { setup: s, ..w };
    let fra = mlab("Frankfurt", "DE", "mlab2-fra05.mlab-oti.measurement-lab.org");
    let all_done = All {
        down: Some(1_284_000_000),
        up: Some(302_000_000),
        ..combined(
            Stage::Done,
            vec![
                leg("nl", Some(ams.clone()), false, 0.0, Some(611.0), Some(140.2), Some(13)),
                leg("us", Some(mlab("New York", "US", "mlab1-lga03")), false, 0.0, Some(402.6), Some(96.1), Some(91)),
                leg("it", Some(mlab("Milan", "IT", "mlab1-mil04")), false, 0.0, Some(270.4), Some(65.7), Some(37)),
                Leg {
                    error: Some("The route didn't connect.".into()),
                    ..leg("lab", None, false, 0.0, None, None, None)
                },
            ],
        )
    };
    let all_measuring = combined(
        Stage::Download,
        vec![
            leg("nl", Some(ams.clone()), false, 402.0, None, None, Some(13)),
            leg("us", Some(mlab("New York", "US", "mlab1-lga03")), false, 233.5, None, None, Some(91)),
            leg("it", Some(mlab("Milan", "IT", "mlab1-mil04")), false, 151.2, None, None, Some(37)),
        ],
    );
    let deciding = combined(
        Stage::Deciding,
        vec![
            leg("nl", Some(ams.clone()), false, 0.0, None, None, Some(13)),
            leg("us", Some(mlab("New York", "US", "mlab1-lga03")), false, 0.0, None, None, Some(91)),
            leg("lab", Some(fra), true, 0.0, None, None, Some(22)),
        ],
    );
    let cases: [(&str, SpeedInputs); 6] = [
        ("stats-speed.png", SpeedInputs { run: Some(&done), chosen: Some("nl"), ..SpeedInputs::default() }),
        (
            "stats-speed-measuring.png",
            SpeedInputs { run: Some(&measuring), chosen: Some("nl"), testing: true, ..SpeedInputs::default() },
        ),
        ("stats-speed-all.png", SpeedInputs { chosen: Some(speed_test::ALL), ..SpeedInputs::default() }),
        (
            "stats-speed-all-measuring.png",
            SpeedInputs { all: Some(&all_measuring), testing: true, ..SpeedInputs::default() },
        ),
        ("stats-speed-all-done.png", SpeedInputs { all: Some(&all_done), ..SpeedInputs::default() }),
        ("stats-speed-deciding.png", SpeedInputs { all: Some(&deciding), tests_today: 4, ..SpeedInputs::default() }),
    ];
    for (file, speed) in cases {
        let v = w.view_with(Period::Week, "speed", None, speed);
        assert!(!v.speed.empty, "{file}: connected, with exits to test");
        let shot = shot_of(&v, false, true);
        let px = render(&shot, 1280, 800, &dir.join(file));
        match file {
            "stats-speed.png" => {
                assert_eq!("Netherlands · nl1256", v.speed.overline);
                assert_eq!(("AGAIN", 150), (v.speed.go.text.as_str(), v.speed.go.size));
                assert_eq!("Amsterdam, Netherlands", v.speed.server.place);
                assert_eq!("mlab1-ams09 · via Nord nl1256", v.speed.server.line);
            }
            "stats-speed-measuring.png" => assert_eq!("1/2 · Download", v.speed.gauge.status),
            "stats-speed-all.png" => {
                assert_eq!("Selected 4 of 4", v.speed.together.heading);
                assert!(
                    v.speed.together.note.ends_with("restarts for a moment before and after."),
                    "the Home lab route has no apps"
                );
            }
            "stats-speed-all-done.png" => assert_eq!("3 exits, same 9 s", v.speed.together.window),
            "stats-speed-deciding.png" => {
                assert_eq!(
                    vec!["lab"],
                    v.speed.together.nearest,
                    "an exit without a server at home goes via the nearest one"
                );
                assert_eq!("Start 3 together", v.speed.together.yes);
                assert!(near(at(&px, 1280, 900, 460), SURFACE), "the sheet over the page");
            }
            _ => {}
        }
    }
}

/// Close to `want` within a few levels: antialiasing and rounding differ by a step or two.
fn near(got: [u8; 3], want: [u8; 3]) -> bool {
    got.iter().zip(want).all(|(g, w)| g.abs_diff(w) <= 3)
}
