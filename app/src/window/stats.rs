//! Stats: the hub, its sections and the speed test. The figures are read off the window's thread, again every 30 s.

use super::{
    AppBar, AppWindow, ChartPart, ChartSeries, DaySpan, Decision, ExitBar, Fact, FlowRow, FlowsView, Gauge, GoButton,
    HistoryRow, HistoryView, HubView, Ink, JournalView, Lane, LegBar, LegPick, LegResult, Legend, LiveRow, LiveView,
    Member, MonthMark, Named, NumPart, OffView, Part, Pill, Segment, ServerCard, ServerRow, Share, SpeedBar, SpeedCard,
    SpeedChoice, SpeedView, StatsPage, Together, TunnelRow, TunnelView, TunnelsView, UsageView, Win, list, post, text,
    with,
};
use crate::model::Setup;
use crate::ui::stats::{self as logic, Data, Period, SpeedInputs};
use crate::vpn::{self, VpnState};
use crate::{app, desktop, speed_test, stats};
use indexmap::{IndexMap, IndexSet};
use slint::{Global, ModelRc, SharedString};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Glue {
    period: Period,
    section: String,
    flows_exit: Option<String>,
    flows_all: bool,
    journal_day: Option<i64>,
    /// The speed test's exit, routes unticked for a combined run, and exits it leaves out.
    chosen: Option<String>,
    unticked: Vec<String>,
    leave_out: Vec<String>,
    data: Option<Data>,
    /// What the data was read for, and when.
    read_for: Option<(Period, String)>,
    read_at: Option<Instant>,
    every: Option<slint::Timer>,
    last: Option<logic::StatsView>,
    light: bool,
    seen: bool,
}

fn strings(v: &[String]) -> ModelRc<SharedString> {
    list(v.iter().map(|x| text(x)).collect())
}

fn num(p: &logic::NumPart) -> NumPart {
    NumPart { value: text(&p.value), unit: text(&p.unit) }
}

fn nums(v: &[logic::NumPart]) -> ModelRc<NumPart> {
    list(v.iter().map(num).collect())
}

fn share(x: &logic::Share) -> Share {
    Share { name: text(&x.name), value: text(&x.value), pct: text(&x.pct), frac: x.frac }
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
    GoButton {
        text: text(&g.text),
        size: g.size,
        hue: g.hue,
        label: text(&g.label),
        working: g.working,
        bloom: g.bloom,
    }
}

fn gauge(g: &logic::Gauge) -> Gauge {
    Gauge { mbps: g.mbps, label: text(&g.label), upload: g.upload, progress: g.progress, status: text(&g.status) }
}

fn cards(v: &[logic::SpeedCard]) -> ModelRc<SpeedCard> {
    list(
        v.iter()
            .map(|c| SpeedCard { title: text(&c.title), value: text(&c.value), unit: text(&c.unit), active: c.active })
            .collect(),
    )
}

fn choices(v: &[logic::Choice]) -> ModelRc<SpeedChoice> {
    list(
        v.iter()
            .map(|c| SpeedChoice { id: text(&c.id), code: text(&c.code), hue: c.hue, name: text(&c.name), on: c.on })
            .collect(),
    )
}

fn speed_view(v: &logic::SpeedView) -> SpeedView {
    let t = &v.together;
    SpeedView {
        overline: text(&v.overline),
        empty: v.empty,
        all_chip: v.all_chip,
        all_on: v.all_on,
        all_hues: list(v.all_hues.clone()),
        all_text: text(&v.all_text),
        choices: choices(&v.choices),
        busy: v.busy,
        exit: text(&v.exit),
        name: text(&v.name),
        hue: v.hue,
        cards: cards(&v.cards),
        measuring: v.measuring,
        gauge: gauge(&v.gauge),
        error: text(&v.error),
        missing: text(&v.missing),
        go: go_button(&v.go),
        preparing: text(&v.preparing),
        server_shown: v.server_shown,
        server: ServerCard { place: text(&v.server.place), line: text(&v.server.line) },
        note: text(&v.note),
        ask: v.ask,
        ask_title: text(&v.ask_title),
        ask_text: text(&v.ask_text),
        terms: text(&v.terms),
        together: Together {
            cards: cards(&t.cards),
            measuring: t.measuring,
            gauge: gauge(&t.gauge),
            exits: t.exits,
            bars: list(
                t.bars
                    .iter()
                    .map(|b| LegBar {
                        code: text(&b.code),
                        hue: b.hue,
                        frac: b.frac,
                        now: text(&b.now),
                        stopped: b.stopped,
                    })
                    .collect(),
            ),
            finished: t.finished,
            error: text(&t.error),
            done: t.done,
            window: text(&t.window),
            share: list(t.share.iter().map(part).collect()),
            results: list(
                t.results
                    .iter()
                    .map(|r| LegResult {
                        code: text(&r.code),
                        hue: r.hue,
                        name: text(&r.name),
                        line: text(&r.line),
                        failed: r.failed,
                        down: text(&r.down),
                        up: text(&r.up),
                        ping: text(&r.ping),
                    })
                    .collect(),
            ),
            heading: text(&t.heading),
            working: t.working,
            picks: list(
                t.picks
                    .iter()
                    .map(|k| LegPick {
                        id: text(&k.id),
                        code: text(&k.code),
                        hue: k.hue,
                        name: text(&k.name),
                        sub: text(&k.sub),
                        on: k.on,
                        state: text(&k.state),
                        tone: k.tone,
                    })
                    .collect(),
            ),
            nodes: choices(&t.nodes),
            go: go_button(&t.go),
            note: text(&t.note),
            start: strings(&t.start),
            deciding: t.deciding,
            decisions: list(
                t.decisions
                    .iter()
                    .map(|d| Decision {
                        exit: text(&d.exit),
                        code: text(&d.code),
                        hue: d.hue,
                        title: text(&d.title),
                        text: text(&d.text),
                        choice: d.choice,
                        via: text(&d.via),
                        out: text(&d.out),
                        via_on: d.via_on,
                    })
                    .collect(),
            ),
            cost: text(&t.cost),
            yes: text(&t.yes),
            can_go: t.can_go,
            nearest: strings(&t.nearest),
        },
    }
}

/// The view on the page; what didn't change since `old` stays as it is.
fn set(page: &StatsPage, v: &logic::StatsView, old: Option<&logic::StatsView>) {
    let changed = |f: &dyn Fn(&logic::StatsView) -> bool| old.is_none_or(|o| !f(o));
    page.set_recording(v.recording);
    page.set_off(OffView {
        overline: text(&v.off.overline),
        title: text(&v.off.title),
        text: text(&v.off.text),
        button: text(&v.off.button),
        saved: v.off.saved,
    });
    page.set_loaded(v.loaded);
    page.set_period(v.period);
    page.set_section(text(&v.section));
    page.set_back(text(&v.back));
    page.set_range(text(&v.range));
    if changed(&|o| o.labels == v.labels) {
        page.set_labels(strings(&v.labels));
    }
    page.set_cap(v.cap);
    page.set_scale(text(&v.scale));
    page.set_selected(v.selected);
    page.set_empty(v.empty);
    if changed(&|o| o.weekdays == v.weekdays) {
        page.set_weekdays(strings(&v.weekdays));
    }
    let h = &v.hub;
    if changed(&|o| o.hub == v.hub) {
        page.set_hub(HubView {
            overline: text(&h.overline),
            usage: num(&h.usage),
            usage_line: text(&h.usage_line),
            providers: list(h.providers.iter().map(share).collect()),
            live: h.live,
            live_now: num(&h.live_now),
            spark: list(h.spark.clone()),
            week: nums(&h.week),
            week_hours: list(h.week_hours.clone()),
            today: h.today,
            tested: h.tested,
            best: text(&h.best),
            best_line: text(&h.best_line),
            fastest: list(
                h.fastest.iter().map(|b| SpeedBar { code: text(&b.code), hue: b.hue, frac: b.frac }).collect(),
            ),
            legend: list(h.legend.iter().map(|l| Legend { name: text(&l.name), hue: l.hue }).collect()),
            columns: columns(page, &h.columns),
            summary: text(&h.summary),
            apps: list(
                h.apps
                    .iter()
                    .map(|a| AppBar {
                        name: text(&a.name),
                        code: text(&a.code),
                        hue: a.hue,
                        frac: a.frac,
                        bytes: text(&a.bytes),
                    })
                    .collect(),
            ),
            exits: list(
                h.exits
                    .iter()
                    .map(|e| ExitBar {
                        code: text(&e.code),
                        hue: e.hue,
                        name: text(&e.name),
                        apps: text(&e.apps),
                        bytes: text(&e.bytes),
                    })
                    .collect(),
            ),
        });
    }
    let u = &v.usage;
    if changed(&|o| o.usage == v.usage) {
        page.set_usage(UsageView {
            over: text(&u.over),
            value: num(&u.value),
            sub: text(&u.sub),
            trailing: text(&u.trailing),
            columns: columns(page, &u.columns),
            summary: text(&u.summary),
            label: text(&u.label),
            providers: list(u.providers.iter().map(share).collect()),
        });
    }
    let l = &v.live;
    if changed(&|o| o.live == v.live) {
        page.set_live(LiveView {
            overline: text(&l.overline),
            empty: text(&l.empty),
            now: num(&l.now),
            sub: text(&l.sub),
            series: list(
                l.series
                    .iter()
                    .map(|x| ChartSeries { values: list(x.values.clone()), color: page.invoke_ink(x.hue) })
                    .collect(),
            ),
            cap: l.cap,
            summary: text(&l.summary),
            rows: list(
                l.rows
                    .iter()
                    .map(|r| LiveRow {
                        code: text(&r.code),
                        hue: r.hue,
                        name: text(&r.name),
                        via: text(&r.via),
                        now: num(&r.now),
                    })
                    .collect(),
            ),
        });
    }
    let f = &v.flows;
    if changed(&|o| o.flows == v.flows) {
        page.set_flows(FlowsView {
            sub: text(&f.sub),
            empty: f.empty,
            share: list(f.share.iter().map(part).collect()),
            lanes: list(
                f.lanes
                    .iter()
                    .map(|l| Lane {
                        id: text(&l.id),
                        code: text(&l.code),
                        hue: l.hue,
                        name: text(&l.name),
                        apps: text(&l.apps),
                        bytes: text(&l.bytes),
                        pct: text(&l.pct),
                        frac: l.frac,
                        segments: list(
                            l.segments.iter().map(|g| Segment { weight: g.weight, alpha: g.alpha }).collect(),
                        ),
                        names: list(
                            l.names.iter().map(|n| Named { name: text(&n.name), bytes: text(&n.bytes) }).collect(),
                        ),
                        rest: text(&l.rest),
                        selected: l.selected,
                    })
                    .collect(),
            ),
            pills: list(
                f.pills
                    .iter()
                    .map(|p| Pill { id: text(&p.id), code: text(&p.code), hue: p.hue, text: text(&p.text), on: p.on })
                    .collect(),
            ),
            rows: list(
                f.rows
                    .iter()
                    .map(|r| FlowRow {
                        pkg: text(&r.pkg),
                        letter: text(&r.letter),
                        name: text(&r.name),
                        code: text(&r.code),
                        hue: r.hue,
                        bytes: text(&r.bytes),
                        frac: r.frac,
                    })
                    .collect(),
            ),
            more: text(&f.more),
        });
    }
    let j = &v.journal;
    if changed(&|o| o.journal == v.journal) {
        page.set_journal(JournalView {
            week: nums(&j.week),
            sub: text(&j.sub),
            heat: list(j.heat.clone()),
            months: list(j.months.iter().map(|m| MonthMark { week: m.week, name: text(&m.name) }).collect()),
            index: j.index,
            day: j.day,
            date: text(&j.date),
            has_prev: j.has_prev,
            has_next: j.has_next,
            spans: list(j.spans.iter().map(|x| DaySpan { from: x.from, to: x.to, paused: x.paused }).collect()),
            summary: text(&j.summary),
            facts: list(j.facts.iter().map(|x| Fact { parts: nums(&x.parts), label: text(&x.label) }).collect()),
        });
    }
    let t = &v.tunnels;
    if changed(&|o| o.tunnels == v.tunnels) {
        page.set_tunnels(TunnelsView {
            tested: t.tested,
            best: text(&t.best),
            sub: text(&t.sub),
            rows: list(
                t.rows
                    .iter()
                    .map(|r| TunnelRow {
                        id: text(&r.id),
                        code: text(&r.code),
                        hue: r.hue,
                        name: text(&r.name),
                        via: text(&r.via),
                        tested: r.tested,
                        test: text(&r.test),
                        frac: r.frac,
                    })
                    .collect(),
            ),
        });
    }
    let t = &v.tunnel;
    if changed(&|o| o.tunnel == v.tunnel) {
        page.set_tunnel(TunnelView {
            id: text(&t.id),
            overline: text(&t.overline),
            title: text(&t.title),
            hue: t.hue,
            tested: t.tested,
            best: text(&t.best),
            sub: text(&t.sub),
            servers: list(
                t.servers.iter().map(|x| ServerRow { name: text(&x.name), pct: text(&x.pct), frac: x.frac }).collect(),
            ),
        });
    }
    if changed(&|o| o.speed == v.speed) {
        page.set_speed(speed_view(&v.speed));
    }
    let x = &v.history;
    if changed(&|o| o.history == v.history) {
        page.set_history(HistoryView {
            overline: text(&x.overline),
            tested: x.tested,
            best: text(&x.best),
            sub: text(&x.sub),
            rows: list(
                x.rows
                    .iter()
                    .map(|r| HistoryRow {
                        all: r.all,
                        code: text(&r.code),
                        hue: r.hue,
                        when: text(&r.when),
                        down: text(&r.down),
                        up: text(&r.up),
                        ping: text(&r.ping),
                        line: text(&r.line),
                        members: list(
                            r.members
                                .iter()
                                .map(|m| Member {
                                    code: text(&m.code),
                                    hue: m.hue,
                                    name: text(&m.name),
                                    down: text(&m.down),
                                    up: text(&m.up),
                                    ping: text(&m.ping),
                                })
                                .collect(),
                        ),
                    })
                    .collect(),
            ),
        });
    }
}

/// `f` inside the app's runtime: the speed test starts its work on it.
fn rt<T>(f: impl FnOnce() -> T) -> T {
    let _inside = app::runtime().enter();
    f()
}

/// The page's own state changed: the page shows it at once.
fn page(f: impl FnOnce(&mut Glue)) {
    with(|win| {
        f(&mut win.stats.borrow_mut());
        win.refresh();
    });
}

pub(super) fn wire(w: &AppWindow) {
    let p = StatsPage::get(w);
    p.on_icon(|pkg| with(|win| win.icon(&pkg)).unwrap_or_default());
    p.on_go(|section| {
        page(|g| {
            // Leaving the speed test ends a test under way.
            if g.section == "speed" && section != "speed" {
                rt(|| {
                    speed_test::cancel();
                    speed_test::clear();
                });
            }
            g.section = section.into();
        })
    });
    p.on_pick_period(|i| page(|g| g.period = Period::ALL[i.clamp(0, 2) as usize]));
    p.on_filter_flows(|id| {
        page(|g| {
            g.flows_exit = Some(id.to_string()).filter(|i| !i.is_empty());
            g.flows_all = false;
        })
    });
    p.on_toggle_all_flows(|| page(|g| g.flows_all = !g.flows_all));
    p.on_pick_day(|day| page(|g| g.journal_day = Some(i64::from(day))));
    p.on_turn_on(|| {
        with(|win| win.ui.set_stats(true));
    });
    p.on_choose(|id| {
        page(|g| g.chosen = Some(id.into()));
        rt(speed_test::clear);
    });
    p.on_start_test(|exit, anywhere| {
        rt(|| speed_test::start(&exit, anywhere));
    });
    p.on_agree_mlab(|| {
        app::store().set_mlab_consent(true);
        super::poke();
    });
    p.on_start_all(|| {
        with(|win| {
            let start = win.stats.borrow().last.as_ref().map(|v| v.speed.together.start.clone()).unwrap_or_default();
            rt(|| speed_test::start_all(&start, vpn::live().metered()));
        });
    });
    p.on_tick(|id, on| {
        page(|g| {
            g.unticked.retain(|u| *u != id.as_str());
            if !on {
                g.unticked.push(id.into());
            }
        })
    });
    p.on_decide(|exit, via| {
        page(|g| {
            g.leave_out.retain(|x| *x != exit.as_str());
            if !via {
                g.leave_out.push(exit.into());
            }
        })
    });
    p.on_go_together(|| {
        with(|win| {
            let nearest: IndexSet<String> = win
                .stats
                .borrow()
                .last
                .as_ref()
                .map(|v| v.speed.together.nearest.iter().cloned().collect())
                .unwrap_or_default();
            rt(|| speed_test::go(nearest));
        });
    });
    p.on_cancel_test(|| rt(speed_test::cancel));
    p.on_privacy(|| desktop::open("https://www.measurementlab.net/privacy/"));
}

/// Stats again: back to the hub.
pub(super) fn reselected(win: &Win) {
    win.stats.borrow_mut().section.clear();
}

/// Stats left the screen: no more one-second samples, and a test under way ends.
pub(super) fn left(win: &Win) {
    stats::set_watching(false);
    let mut g = win.stats.borrow_mut();
    if g.section == "speed" {
        rt(|| {
            speed_test::cancel();
            speed_test::clear();
        });
    }
    // The page's own choices go with it; the figures read stay for the next time.
    let (data, read_for, read_at) = (g.data.take(), g.read_for.take(), g.read_at.take());
    *g = Glue { data, read_for, read_at, seen: true, ..Glue::default() };
}

pub(super) fn show(win: &Win, setup: &Setup, vpn: &VpnState) {
    // Peaks and the live chart need one-second samples: only while Stats is on screen.
    stats::set_watching(true);
    let now = chrono::Local::now().naive_local();
    read(win, now.date());
    let labels: IndexMap<String, String> =
        win.ui.apps.borrow().iter().map(|a| (a.pkg.clone(), a.label.clone())).collect();
    let live = stats::live().borrow().clone();
    let (run, all) = (speed_test::run().borrow().clone(), speed_test::all().borrow().clone());
    let nodes = speed_test::nodes();
    let running = vpn::live().running();
    let tags = vpn::live().tags();
    let mut g = win.stats.borrow_mut();
    if g.every.is_none() {
        let t = slint::Timer::default();
        t.start(slint::TimerMode::Repeated, Duration::from_secs(30), super::poke);
        g.every = Some(t);
    }
    let v = logic::view(&logic::Inputs {
        data: g.data.as_ref(),
        period: g.period,
        section: &g.section,
        now,
        setup,
        running: running.as_ref(),
        vpn,
        tags: &tags,
        live: &live,
        labels: &labels,
        has_data: stats::size() > 0,
        flows_exit: g.flows_exit.as_deref(),
        flows_all: g.flows_all,
        journal_day: g.journal_day,
        speed: SpeedInputs {
            run: run.as_ref(),
            all: all.as_ref(),
            nodes: &nodes,
            testing: speed_test::testing(),
            chosen: g.chosen.as_deref(),
            unticked: &g.unticked,
            leave_out: &g.leave_out,
            tests_today: app::store().tests_today(),
        },
    });
    let p = StatsPage::get(&win.w);
    // The charts' colours are the theme's: a new theme draws them again.
    let light = Ink::get(&win.w).get_light();
    if g.light != light {
        g.light = light;
        g.last = None;
    }
    p.set_reveal(!g.seen);
    p.set_mlab_consent(app::store().mlab_consent());
    set(&p, &v, g.last.as_ref());
    g.last = Some(v);
}

/// The period's figures, read off the window's thread when the period or the tunnel open changes, and every 30 s.
fn read(win: &Win, today: chrono::NaiveDate) {
    let mut g = win.stats.borrow_mut();
    let tunnel = g.section.strip_prefix("tunnel:").unwrap_or("").to_string();
    let key = (g.period, tunnel.clone());
    if g.read_for.as_ref() == Some(&key) && g.read_at.is_some_and(|at| at.elapsed() < Duration::from_secs(29)) {
        return;
    }
    g.read_for = Some(key);
    g.read_at = Some(Instant::now());
    let period = g.period;
    app::runtime().spawn_blocking(move || {
        let data = logic::read(period, today, Some(tunnel.as_str()).filter(|t| !t.is_empty()));
        post(move |win| {
            let mut g = win.stats.borrow_mut();
            if g.read_for.as_ref().is_some_and(|(p, t)| *p == period && t.as_str() == tunnel.as_str()) {
                g.data = data;
            }
        });
    });
}

/// Shows everything again on the next redraw.
pub(super) fn forget(win: &Win) {
    win.stats.borrow_mut().last = None;
}
