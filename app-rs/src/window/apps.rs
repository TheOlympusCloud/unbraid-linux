//! Apps: the table of installed apps with its detail panel, and the disclosures that come before it.

use super::{AlsoRow, AppDetail, AppRow, AppWindow, AppsPage, ColumnHead, ExitChip, RouteChoice, Win, list, post, text, with};
use crate::model::Setup;
use crate::ui::apps::{self as logic, AppsView, Sort, Table};
use crate::ui::stats::epoch_day;
use crate::{app, apps as installed, desktop, stats};
use slint::Global;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct Glue {
    table: Table,
    last: Option<AppsView>,
    /// Today's bytes per app while statistics are recorded, read again each minute.
    today: HashMap<String, i64>,
    read_at: Option<Instant>,
    minute: Option<slint::Timer>,
    /// The profile shown when the table was last shown: a new one starts the table afresh.
    viewing: Option<Option<String>>,
}

fn row(win: &Win, r: &logic::AppRow) -> AppRow {
    AppRow {
        key: text(&r.key),
        label: text(&r.label),
        letter: text(&r.letter),
        icon: win.icon(&r.key),
        kind: text(&r.kind),
        unset: text(&r.unset),
        code: text(&r.code),
        hue: r.hue,
        filled: r.filled,
        direct: r.direct,
        note: text(&r.note),
        today: text(&r.today),
    }
}

fn detail(win: &Win, d: &logic::AppDetail) -> AppDetail {
    AppDetail {
        key: text(&d.key),
        label: text(&d.label),
        letter: text(&d.letter),
        icon: if d.key.is_empty() { slint::Image::default() } else { win.icon(&d.key) },
        program: text(&d.program),
        copy: text(&d.copy),
        leader: text(&d.leader),
        leader_note: text(&d.leader_note),
        leader_menu: text(&d.leader_menu),
        show_leader: text(&d.show_leader),
        default_only: d.default_only,
        choices: list(
            d.choices
                .iter()
                .map(|c| RouteChoice { id: text(&c.id), name: text(&c.name), sub: text(&c.sub), menu: text(&c.menu), code: text(&c.code), hue: c.hue, direct: c.direct, on: c.on })
                .collect(),
        ),
        also: list(d.also.iter().map(|a| AlsoRow { key: text(&a.key), label: text(&a.label), letter: text(&a.letter), icon: win.icon(&a.key), note: text(&a.note) }).collect()),
        lookups: d.lookups,
        lookups_sub: text(&d.lookups_sub),
        lookups_on: d.lookups_on,
        own: d.own,
        today: text(&d.today),
    }
}

/// The table's own state changed: the page shows it at once.
fn table(f: impl FnOnce(&mut Table, &[logic::AppRow])) {
    with(|win| {
        {
            let mut g = win.apps.borrow_mut();
            let rows = g.last.as_ref().map(|v| v.rows.clone()).unwrap_or_default();
            f(&mut g.table, &rows);
        }
        win.refresh();
    });
}

pub(super) fn wire(w: &AppWindow) {
    let page = AppsPage::get(w);
    page.on_show_apps(|| {
        with(|win| {
            win.s.borrow_mut().sheet = 2;
            win.refresh();
        });
    });
    page.on_add_program(|| {
        with(|win| {
            let ui = win.ui.clone();
            app::runtime().spawn(async move {
                let Some(file) = tokio::task::spawn_blocking(|| super::pick_file("Choose a program", false)).await.ok().flatten() else { return };
                if let Some(key) = ui.add_program(file).await {
                    post(move |win| win.apps.borrow_mut().table.added(&key));
                }
            });
        });
    });
    page.on_back(|| {
        with(|win| win.ui.view(None));
    });
    page.on_use_profile(|| {
        with(|win| {
            let viewing = win.ui.viewing.borrow().clone();
            if let Some(name) = viewing {
                win.ui.use_profile(&name);
            }
        });
    });
    page.on_search(|q| table(|t, _| t.query = q.into()));
    page.on_filter(|id| table(|t, _| t.filter = Some(id.into())));
    page.on_filter_all(|| table(|t, _| t.filter = None));
    page.on_toggle_system(|| table(|t, _| t.system = !t.system));
    page.on_sort(|column| table(|t, _| t.sort_by(Sort::ALL[column.clamp(0, Sort::ALL.len() as i32 - 1) as usize])));
    page.on_select(|key| table(|t, _| t.selected = Some(key.into())));
    page.on_step(|by| table(|t, rows| t.step(rows, by)));
    page.on_assign(|key, route| {
        with(|win| win.ui.assign(&key, Some(&route)));
    });
    page.on_use_default(|key| {
        with(|win| win.ui.assign(&key, None));
    });
    page.on_new_route(|key| {
        with(|win| win.open_picker(&format!("app:{key}")));
    });
    page.on_copy_path(|path| desktop::copy(&path));
    page.on_filter_lookups(|key| {
        with(|win| win.ui.set_prefs(|p| logic::filter_lookups(p, &key)));
    });
}

/// Apps again: the selection and the filter go, or the list goes back to its top.
pub(super) fn reselected(win: &Win) {
    if win.apps.borrow_mut().table.reselected() {
        win.w.set_apps_top(win.w.get_apps_top() + 1);
    }
}

/// Apps left the screen: its search, filter, order and selection go with it.
pub(super) fn left(win: &Win) {
    let mut g = win.apps.borrow_mut();
    g.minute = None;
    g.last = None;
    g.table = Table::default();
    g.viewing = None;
}

pub(super) fn show(win: &Win, setup: &Setup) {
    let ui = &win.ui;
    read_today(win, setup.prefs.stats);
    let viewing = ui.viewing.borrow().clone();
    let shown = ui.shown();
    let apps = ui.apps.borrow().clone();
    let disclosed = *ui.disclosed.borrow();
    let mut g = win.apps.borrow_mut();
    if g.viewing.as_ref() != Some(&viewing) {
        if g.viewing.is_some() {
            g.table.viewed();
        }
        g.viewing = Some(viewing.clone());
    }
    let v = logic::view(&apps, &shown, viewing.as_deref(), disclosed, &g.today, &g.table, installed::program_of);
    let page = AppsPage::get(&win.w);
    let old = g.last.as_ref();
    page.set_counts(text(&v.counts));
    page.set_disclosed(v.disclosed);
    page.set_editing(text(&v.editing));
    page.set_editing_hint(text(&v.editing_hint));
    page.set_back_label(text(&v.back_label));
    page.set_use_label(text(&v.use_label));
    if page.get_query() != v.query.as_str() {
        page.set_query(text(&v.query));
    }
    page.set_all(v.all);
    if old.is_none_or(|o| o.chips != v.chips) {
        page.set_chips(list(v.chips.iter().map(|c| ExitChip { id: text(&c.id), label: text(&c.label), hue: c.hue, direct: c.direct, on: c.on }).collect()));
    }
    page.set_system(v.system);
    if old.is_none_or(|o| o.heads != v.heads) {
        page.set_heads(list(v.heads.iter().map(|h| ColumnHead { text: text(&h.text), label: text(&h.label), on: h.on }).collect()));
    }
    page.set_stats(v.stats);
    if old.is_none_or(|o| o.rows != v.rows) {
        page.set_rows(list(v.rows.iter().map(|r| row(win, r)).collect()));
    }
    page.set_selected(text(&v.selected));
    page.set_selected_index(v.selected_index);
    if old.is_none_or(|o| o.detail != v.detail) {
        page.set_detail(detail(win, &v.detail));
    }
    g.last = Some(v);
}

/// Today's data per app, while statistics are recorded: read off the window's thread, again each minute.
fn read_today(win: &Win, on: bool) {
    let mut g = win.apps.borrow_mut();
    if !on {
        g.today.clear();
        g.read_at = None;
        g.minute = None;
        return;
    }
    if g.minute.is_none() {
        let t = slint::Timer::default();
        t.start(slint::TimerMode::Repeated, Duration::from_secs(60), super::poke);
        g.minute = Some(t);
    }
    if g.read_at.is_some_and(|at| at.elapsed() < Duration::from_secs(60)) {
        return;
    }
    g.read_at = Some(Instant::now());
    app::runtime().spawn_blocking(|| {
        let d = epoch_day(chrono::Local::now().date_naive());
        let today = stats::read(move |w| w.apps(d, d)).unwrap_or_default().into_iter().fold(HashMap::new(), |mut m, (app, _, b)| {
            *m.entry(app).or_insert(0) += b;
            m
        });
        post(move |win| win.apps.borrow_mut().today = today);
    });
}

/// Shows everything again on the next redraw.
pub(super) fn forget(win: &Win) {
    win.apps.borrow_mut().last = None;
}
