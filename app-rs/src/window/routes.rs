//! Routes, the profiles page inside it, and the connection-limit sheet over any page.

use super::{
    APPS, Act, AppMark, AppWindow, ExitLine, ExitRow, HomeRow, LimitSheetPage, ProfileRow, ProfileSheetView, ProfilesPage, RouteAction, RouteCard,
    RoutesPage, Sheet, UseBarView, Win, list, phase, sync, text, with,
};
use crate::model::Setup;
use crate::ui::{limit_sheet, profiles as plogic, routes as logic};
use crate::vpn::{self, VpnState};
use crate::{providers, stats};
use slint::{Global, ModelRc};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Default)]
pub struct Glue {
    last: Option<logic::RoutesView>,
    profiles: Option<plogic::ProfilesView>,
    /// Routes was shown before in this process: its rows don't rise in again.
    seen: bool,
    /// Once a second while connected or paused: the connection's clock and a pause's ring.
    tick: Option<slint::Timer>,
    /// Exits are still being asked; what started the asking (connected, the engine's start, the active routes).
    asking: bool,
    asked_for: Option<(bool, i32, Vec<String>)>,
    asker: Option<tokio::task::JoinHandle<()>>,
    /// The exceptions and the exits, updated row by row: a new list would build its rows again, and they would rise in
    /// again.
    exceptions: std::rc::Rc<slint::VecModel<RouteCard>>,
    exits: std::rc::Rc<slint::VecModel<ExitRow>>,
}

fn action(a: &logic::RouteAction) -> RouteAction {
    let act = match a.act {
        logic::Act::ChangeLocation => Act::ChangeLocation,
        logic::Act::Rename => Act::Rename,
        logic::Act::MakeDefault => Act::MakeDefault,
        logic::Act::MakeDirectDefault => Act::MakeDirectDefault,
        logic::Act::AssignInApps => Act::AssignInApps,
        logic::Act::Remove => Act::Remove,
        logic::Act::Drop => Act::Drop,
        logic::Act::Pause => Act::Pause,
        logic::Act::Disconnect => Act::Disconnect,
    };
    RouteAction { act, text: text(&a.text), danger: a.danger, minutes: a.minutes }
}

fn sheet(s: &logic::Sheet) -> Sheet {
    Sheet { title: text(&s.title), lead: text(&s.lead), actions: list(s.actions.iter().map(action).collect()), note: text(&s.note) }
}

fn exit(e: &logic::ExitLine) -> ExitLine {
    ExitLine { text: text(&e.text), ip: e.ip, failed: e.failed }
}

fn card(c: &logic::RouteCard) -> RouteCard {
    RouteCard {
        id: text(&c.id),
        direct: c.direct,
        code: text(&c.code),
        hue: c.hue,
        name: text(&c.name),
        place: text(&c.place),
        server: text(&c.server),
        apps_label: text(&c.apps_label),
        no_apps: c.no_apps,
        apps: list(c.apps.iter().map(|a| AppMark { pkg: text(&a.pkg), letter: text(&a.letter) }).collect()),
        more: c.more,
        exit: exit(&c.exit),
        wide: c.wide,
        menu: list(c.menu.iter().map(action).collect()),
        sheet: sheet(&c.sheet),
    }
}

fn use_bar(b: &plogic::UseBarView) -> UseBarView {
    UseBarView { name: text(&b.name), title: text(&b.title), sub: text(&b.sub), back: text(&b.back), ready: b.ready }
}

fn profile_sheet(p: &plogic::ProfileSheetView) -> ProfileSheetView {
    ProfileSheetView {
        title: text(&p.title),
        sub: text(&p.sub),
        copy: text(&p.copy),
        name: text(&p.name),
        valid: text(&p.valid),
        taken: p.taken,
        hint: text(&p.hint),
        count: text(&p.count),
        keeps_default: text(&p.keeps_default),
        keeps_exceptions: list(p.keeps_exceptions.iter().map(|e| text(e)).collect()),
        save: text(&p.save),
    }
}

pub(super) fn wire(w: &AppWindow) {
    let page = RoutesPage::get(w);
    page.on_icon(|pkg| with(|win| win.icon(&pkg)).unwrap_or_default());
    page.on_connect(|| {
        with(Win::connect);
    });
    page.on_pause(|m| {
        with(|win| win.ui.pause(m));
    });
    page.on_disconnect(|| {
        with(|win| win.ui.disconnect());
    });
    page.on_new_route(|| {
        with(|win| win.open_picker(""));
    });
    page.on_choose_default(|| {
        with(|win| win.open_picker("default"));
    });
    page.on_change_location(|id| {
        with(|win| {
            let own = win.ui.own_route(&id);
            win.open_picker(&own);
        });
    });
    page.on_make_default(|id| {
        with(|win| win.ui.set_default(&id));
    });
    page.on_assign_in_apps(|| {
        with(|win| {
            win.set_tab(APPS);
            win.refresh();
        });
    });
    page.on_rename_route(|id, name| {
        with(|win| win.ui.rename_route(&id, &name));
    });
    page.on_remove_route(|id| {
        with(|win| win.ui.remove_route(&id));
    });
    page.on_drop_route(|id| {
        with(|win| win.ui.drop_route(&id));
    });
    page.on_retry_switch(|name| {
        with(|win| win.ui.use_profile(&name));
    });
    page.on_use_profile(|name| {
        with(|win| win.ui.use_profile(&name));
    });
    page.on_dismiss_refused(|| {
        vpn::profiles::refused().send_replace(None);
    });
    page.on_stop_viewing(|| {
        with(|win| win.ui.view(None));
    });
    page.on_tailscale_sign_in(|url| {
        with(|win| win.ts_login(&url));
    });

    let profiles = ProfilesPage::get(w);
    // Set at once: the sheet clips the name being typed to its 12 characters.
    profiles.on_sheet_changed(|editing, empty, name| {
        with(|win| {
            let s = win.ui.setup().borrow().clone();
            let v = plogic::sheet(&s, Some(editing.as_str()).filter(|e| !e.is_empty()), empty, &name);
            ProfilesPage::get(&win.w).set_sheet(profile_sheet(&v));
        });
    });
    profiles.on_new_profile(|name, empty| {
        with(|win| win.ui.new_profile(&name, empty));
    });
    profiles.on_rename_profile(|old, name| {
        with(|win| win.ui.rename_profile(&old, &name));
    });
    profiles.on_forget_profile(|name| {
        with(|win| win.ui.forget_profile(&name));
    });
    profiles.on_move_profile(|name, by| {
        with(|win| win.ui.move_profile(&name, by));
    });

    let limit = LimitSheetPage::get(w);
    limit.on_share_server(|| {
        with(|win| {
            if let Some(ask) = win.ui.limit_ask.send_replace(None)
                && let Some((_, share)) = &ask.share
            {
                share();
            }
        });
    });
    limit.on_apply(|| {
        with(|win| {
            if let Some(ask) = win.ui.limit_ask.send_replace(None) {
                (ask.apply)();
            }
        });
    });
    limit.on_dismiss(|| {
        with(|win| win.ui.limit_ask.send_replace(None));
    });
}

/// Routes again: out of the profiles page, or back to the top.
pub(super) fn reselected(win: &Win) {
    let p = ProfilesPage::get(&win.w);
    if p.get_managing() {
        p.set_managing(false);
    } else {
        win.w.set_routes_top(win.w.get_routes_top() + 1);
    }
}

/// Routes left the screen: the exits stop being asked, the clock stops.
pub(super) fn left(win: &Win) {
    let mut g = win.routes.borrow_mut();
    if let Some(a) = g.asker.take() {
        a.abort();
    }
    g.asked_for = None;
    g.tick = None;
    g.last = None;
    g.profiles = None;
    g.seen = true;
}

pub(super) fn show(win: &Win, setup: &Setup, vpn: &VpnState) {
    let ui = &win.ui;
    let now = chrono::Utc::now().timestamp_millis();
    let on = vpn.phase == vpn::Phase::On;
    ask_exits(win, setup, vpn);
    // Right after a sign-in a provider's new key may not reach all its servers for a minute: Routes says so.
    let setting_up: HashSet<String> = if on {
        let active = setup.active_routes();
        providers::setting_up(now).into_iter().filter(|p| active.iter().any(|r| !r.imported() && r.loc.provider == *p)).collect()
    } else {
        HashSet::new()
    };
    let apps: Vec<logic::App> = ui.apps.borrow().iter().map(|a| logic::App { pkg: a.pkg.clone(), label: a.label.clone(), group: a.group.clone() }).collect();
    let live = stats::live().borrow().clone();
    let viewing = ui.viewing.borrow().clone();
    let switching = vpn::profiles::switching().borrow().clone();
    let refused = vpn::profiles::refused().borrow().clone();
    let exits = ui.exits.borrow().clone();
    let asking = win.routes.borrow().asking;
    let v = logic::view(&logic::Inputs {
        setup,
        viewing: viewing.as_deref(),
        vpn,
        asked: *vpn::live().asked.borrow(),
        switching: switching.as_deref(),
        refused: refused.as_ref().map(|r| (r.to.as_str(), r.kept.as_deref())),
        apps: &apps,
        exits: &exits,
        asking,
        setting_up: &setting_up,
        live: setup.prefs.stats.then_some(&live),
        now,
    });
    let mut g = win.routes.borrow_mut();
    // The connection's clock and a pause's ring move every second.
    let ticking = matches!(vpn.phase, vpn::Phase::On | vpn::Phase::Paused);
    if ticking != g.tick.is_some() {
        g.tick = ticking.then(|| {
            let t = slint::Timer::default();
            t.start(slint::TimerMode::Repeated, Duration::from_secs(1), super::poke);
            t
        });
    }
    let page = RoutesPage::get(&win.w);
    page.set_reveal(!g.seen);
    let old = g.last.as_ref();
    page.set_overline(text(&v.overline));
    page.set_phase(phase(v.phase));
    page.set_switching(v.switching);
    page.set_status(text(&v.status));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_sub_bad(v.sub_bad);
    page.set_label(text(&v.label));
    page.set_power_menu(v.power_menu);
    page.set_paused_ring(v.paused_ring);
    page.set_paused_left(v.paused_left);
    page.set_speeds(v.speeds);
    page.set_down(text(&v.down));
    page.set_down_unit(text(&v.down_unit));
    page.set_up(text(&v.up));
    page.set_up_unit(text(&v.up_unit));
    page.set_refused(text(&v.refused));
    page.set_retry(text(&v.retry));
    page.set_use_bar(v.use_bar.as_ref().map(use_bar).unwrap_or_default());
    page.set_not_set(v.not_set);
    if old.is_none_or(|o| o.default_route != v.default_route) {
        page.set_default_route(card(&v.default_route));
    }
    if old.is_none_or(|o| o.exceptions != v.exceptions) {
        sync(&g.exceptions, v.exceptions.iter().map(card).collect());
        page.set_exceptions(ModelRc::from(g.exceptions.clone()));
    }
    page.set_all_default(v.all_default);
    page.set_nord_note(v.nord_note);
    page.set_lit(v.lit);
    if old.is_none_or(|o| o.exits != v.exits) {
        sync(&g.exits, v.exits.iter().map(|e| ExitRow { code: text(&e.code), hue: e.hue, name: text(&e.name), place: text(&e.place), speed: text(&e.speed), exit: exit(&e.exit) }).collect());
        page.set_exits(ModelRc::from(g.exits.clone()));
    }
    page.set_home(v.home.as_ref().map(|h| HomeRow { sub: text(&h.sub), login_url: text(&h.login_url), lit: h.lit }).unwrap_or_default());
    if old.is_none_or(|o| o.power != v.power) {
        page.set_power(sheet(&v.power));
    }
    g.last = Some(v);

    let pv = plogic::view(setup);
    if g.profiles.as_ref() != Some(&pv) {
        let p = ProfilesPage::get(&win.w);
        p.set_sub(text(&pv.sub));
        p.set_at_limit(pv.at_limit);
        p.set_full_note(text(&pv.full_note));
        p.set_profiles(list(
            pv.rows.iter().map(|r| ProfileRow { name: text(&r.name), in_use: r.in_use, summary: text(&r.summary), code: text(&r.code), hue: r.hue, direct: r.direct }).collect(),
        ));
        g.profiles = Some(pv);
    }
}

/// Each exit is asked once its tunnels are up after a connect or a restart (a new server restarts them), then again for
/// any that didn't answer yet: a tunnel can take some seconds to carry traffic. Only while Routes is on screen.
fn ask_exits(win: &Win, setup: &Setup, vpn: &VpnState) {
    let on = vpn.phase == vpn::Phase::On;
    let key = (on, vpn.engine, setup.active_routes().iter().map(|r| r.id.clone()).collect::<Vec<_>>());
    let mut g = win.routes.borrow_mut();
    if g.asked_for.as_ref() == Some(&key) {
        return;
    }
    g.asked_for = Some(key);
    if let Some(a) = g.asker.take() {
        a.abort();
    }
    g.asking = on && win.ui.exit_tries_left();
    if !on {
        return;
    }
    let ui = win.ui.clone();
    g.asker = Some(crate::app::runtime().spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        for wait in [10, 20, 40] {
            if ui.check_exits().await || !ui.exit_tries_left() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        if !ui.check_exits().await {
            super::post(|win| win.routes.borrow_mut().asking = false);
        }
    }));
}

/// The connection-limit sheet, over whichever page asked.
pub(super) fn show_limit(win: &Win) {
    let page = LimitSheetPage::get(&win.w);
    let ask = win.ui.limit_ask.borrow().clone();
    page.set_shown(ask.is_some());
    if let Some(a) = ask {
        let v = limit_sheet::view(&a.text, a.share.as_ref().map(|s| s.0.as_str()));
        page.set_text(text(&v.text));
        page.set_share(text(&v.share));
    }
}

/// Shows everything again on the next redraw.
pub(super) fn forget(win: &Win) {
    win.routes.borrow_mut().last = None;
}
