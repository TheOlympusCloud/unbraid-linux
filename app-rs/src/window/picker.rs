//! The location picker: a dialog over the page it was opened from, for a new route, the default route, a route's
//! location or a new route for one app.

use super::{sync, AppWindow, Blocking, Choice, Lead, PickKind, PickRow, PickerPage, SETTINGS, Win, post, text, with};
use crate::model::{DIRECT, Location, Setup};
use crate::model::Server;
use crate::ui::picker::{self as logic, Picks, Sheet};
use crate::vpn::VpnState;
use crate::app;
use indexmap::IndexSet;
use slint::{Global, ModelRc, VecModel};
use std::rc::Rc;

#[derive(Default)]
pub struct Glue {
    target: String,
    picks: Picks,
    last: Option<logic::PickerView>,
    /// The provider whose countries were asked for again.
    refreshed: Option<String>,
    /// The Nord server type's countries, once fetched, and the one being fetched.
    allowed: Option<(String, IndexSet<String>)>,
    narrowing: Option<String>,
    /// The servers of the place loaded, once loaded, and the one loading.
    servers: Option<(Location, Vec<Server>)>,
    loading: Option<Location>,
    rows: Rc<VecModel<PickRow>>,
    panel: Rc<VecModel<PickRow>>,
}


fn row(r: &logic::PickRow) -> PickRow {
    PickRow {
        kind: match r.kind {
            logic::PickKind::Place => PickKind::Place,
            logic::PickKind::Label => PickKind::Label,
            logic::PickKind::Title => PickKind::Title,
            logic::PickKind::All => PickKind::All,
            logic::PickKind::Note => PickKind::Note,
            logic::PickKind::Message => PickKind::Message,
            logic::PickKind::Device => PickKind::Device,
            logic::PickKind::Typed => PickKind::Typed,
            logic::PickKind::Server => PickKind::Server,
            logic::PickKind::Settings => PickKind::Settings,
        },
        key: text(&r.key),
        title: text(&r.title),
        sub: text(&r.sub),
        lead: match r.lead {
            logic::Lead::None => Lead::None,
            logic::Lead::Code => Lead::Code,
            logic::Lead::Fastest => Lead::Fastest,
            logic::Lead::Direct => Lead::Direct,
        },
        code: text(&r.code),
        on: r.on,
        online: r.online,
        star: r.star,
        starred: r.starred,
        more: r.more,
        action: text(&r.action),
        i: r.i,
        n: r.n,
        small: r.small,
    }
}

fn choices(c: &[logic::Choice]) -> ModelRc<Choice> {
    super::list(c.iter().map(|c| Choice { key: text(&c.key), label: text(&c.label), sub: text(&c.sub), on: c.on, enabled: c.enabled }).collect())
}

/// The picker opens for `target`: its own state starts afresh.
pub(super) fn opened(win: &Win, target: &str) {
    let s = win.ui.setup().borrow().clone();
    let accounts = win.ui.accounts().borrow().clone();
    let mut g = win.picker.borrow_mut();
    g.target = target.into();
    g.picks = Picks::open(&s, target, &accounts);
    g.last = None;
}

/// The picker's own state changed: it shows it at once.
fn page(f: impl FnOnce(&mut Glue)) {
    with(|win| {
        f(&mut win.picker.borrow_mut());
        win.refresh();
    });
}

/// The place behind a row's key, as the last view listed it.
fn place(win: &Win, key: &str) -> Option<Location> {
    win.picker.borrow().last.as_ref().and_then(|v| v.places.get(key).cloned())
}

pub(super) fn wire(w: &AppWindow) {
    let p = PickerPage::get(w);
    p.on_close(|| {
        with(Win::close_picker);
    });
    p.on_add_provider(|| {
        with(Win::add_provider);
    });
    p.on_settings(|| {
        with(|win| {
            win.set_tab(SETTINGS);
            win.refresh();
        });
    });
    p.on_tab(|mine| page(|g| g.picks.tab(mine)));
    p.on_choose_provider(|id| page(|g| g.picks.provider(&id)));
    p.on_choose_protocol(|key| {
        with(|win| {
            let s = win.ui.setup().borrow().clone();
            let to = {
                let mut g = win.picker.borrow_mut();
                let target = g.target.clone();
                g.picks.set_protocol(&s, &target, Some(key.as_str()).filter(|k| !k.is_empty()))
            };
            if let Some(l) = to {
                let target = win.picker.borrow().target.clone();
                win.ui.set_location(&target, &l);
            }
            win.refresh();
        });
    });
    p.on_search(|t| page(|g| g.picks.query = t.into()));
    p.on_choose(|key| {
        with(|win| {
            let Some(l) = place(win, &key).map(|l| logic::picked(&l)) else { return };
            let target = win.picker.borrow().target.clone();
            match target.as_str() {
                "" => {
                    win.ui.add_route(&l);
                }
                "default" => win.ui.choose_default(&l),
                t if t.starts_with("app:") => win.ui.add_route_for(&t["app:".len()..], &l),
                t => win.ui.set_location(t, &l),
            }
            win.close_picker();
        });
    });
    p.on_star(|key| {
        with(|win| {
            if let Some(l) = place(win, &key) {
                win.ui.toggle_favorite(&l);
            }
        });
    });
    p.on_direct(|| {
        with(|win| {
            win.ui.set_default(DIRECT);
            win.close_picker();
        });
    });
    p.on_toggle_all(|| page(|g| g.picks.all_open = !g.picks.all_open));
    p.on_open_country(|key| {
        with(|win| {
            if let Some(l) = place(win, &key) {
                win.picker.borrow_mut().picks.open_country(&l);
            }
            win.refresh();
        });
    });
    p.on_close_country(|| page(|g| g.picks.show(Sheet::None)));
    p.on_toggle_servers(|| page(|g| g.picks.servers_open = !g.picks.servers_open));
    p.on_retry(|provider| {
        with(|win| win.ui.refresh_countries(&provider));
    });
    p.on_ts_exit(|ip, name| {
        with(|win| {
            if let Some(r) = win.ui.ts_lock(&ip) {
                let s = win.ui.setup().borrow().clone();
                win.picker.borrow_mut().picks.ts_note = Some(logic::lock_note(&s, &r));
                win.refresh();
                return;
            }
            let target = win.picker.borrow().target.clone();
            win.ui.add_ts_exit(&target, &ip, Some(name.as_str()).filter(|n| !n.is_empty()));
            win.close_picker();
        });
    });
    p.on_use_server(|id| {
        with(|win| {
            let s = win.ui.setup().borrow().servers.iter().find(|s| s.id == id.as_str()).cloned();
            let target = win.picker.borrow().target.clone();
            if let Some(s) = s {
                let route = win.ui.use_server(&target, &s);
                if target == "default" {
                    win.ui.set_default(&route);
                }
            }
            win.close_picker();
        });
    });
    p.on_open_options(|| page(|g| g.picks.show(Sheet::Options)));
    p.on_close_options(|| page(|g| g.picks.show(Sheet::None)));
    p.on_group(|key| page(|g| g.picks.group = Some(key.to_string()).filter(|k| !k.is_empty())));
    p.on_protection(|on| {
        with(|win| {
            let target = win.picker.borrow().target.clone();
            win.ui.set_filter(&target, on);
        });
    });
}

pub(super) fn show(win: &Win, setup: &Setup, vpn: &VpnState) {
    let ui = &win.ui;
    let accounts = ui.accounts().borrow().clone();
    let catalogs = ui.countries.borrow().clone();
    let mut g = win.picker.borrow_mut();
    let v = {
        let allowed = g.allowed.as_ref().filter(|(group, _)| g.narrowing.as_deref() == Some(group.as_str())).map(|(_, a)| a);
        let servers = g.servers.as_ref().filter(|(l, _)| g.loading.as_ref() == Some(l)).map(|(_, s)| s.as_slice());
        logic::view(&logic::Inputs {
            setup,
            target: &g.target,
            picks: &g.picks,
            accounts: &accounts,
            catalogs: &catalogs,
            catalogs_read: *ui.catalogs_read.borrow(),
            nodes: &vpn.ts_exit_nodes,
            allowed,
            servers,
        })
    };
    // What the view asks the window to fetch: a provider's countries again, a server type's countries, a place's
    // servers.
    if v.refresh != g.refreshed {
        g.refreshed = v.refresh.clone();
        if let Some(p) = &v.refresh {
            ui.refresh_countries(p);
        }
    }
    if v.narrow != g.narrowing {
        g.narrowing = v.narrow.clone();
        if let Some(group) = v.narrow.clone() {
            let ui = ui.clone();
            app::runtime().spawn(async move {
                if let Some(allowed) = ui.nord_group_countries(&group).await {
                    post(move |win| win.picker.borrow_mut().allowed = Some((group, allowed)));
                }
            });
        }
    }
    if v.load != g.loading {
        g.loading = v.load.clone();
        if let Some(l) = v.load.clone() {
            let account = accounts.get(&l.provider).cloned();
            app::runtime().spawn_blocking(move || {
                let list = logic::servers(&l, account.as_deref());
                post(move |win| win.picker.borrow_mut().servers = Some((l, list)));
            });
        }
    }
    if g.last.as_ref() == Some(&v) {
        return;
    }
    let page = PickerPage::get(&win.w);
    let old = g.last.as_ref();
    page.set_overline(text(&v.overline));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_hue(v.hue);
    page.set_mine(v.mine);
    page.set_fields(v.fields);
    page.set_provider_id(text(&v.provider_id));
    page.set_provider(text(&v.provider));
    if old.is_none_or(|o| o.providers != v.providers) {
        page.set_providers(choices(&v.providers));
    }
    page.set_protocol(text(&v.protocol));
    if old.is_none_or(|o| o.protocols != v.protocols) {
        page.set_protocols(choices(&v.protocols));
    }
    if page.get_query() != v.query.as_str() {
        page.set_query(text(&v.query));
    }
    page.set_placeholder(text(&v.placeholder));
    sync(&g.rows, v.rows.iter().map(row).collect());
    page.set_rows(ModelRc::from(g.rows.clone()));
    page.set_options(text(&v.options));
    page.set_country(text(&v.country));
    sync(&g.panel, v.panel.iter().map(row).collect());
    page.set_panel(ModelRc::from(g.panel.clone()));
    page.set_hint(text(&v.hint));
    page.set_options_open(v.options_open);
    if old.is_none_or(|o| o.groups != v.groups) {
        page.set_groups(choices(&v.groups));
    }
    page.set_blocking(v.blocking.as_ref().map(|b| Blocking { title: text(&b.title), sub: text(&b.sub), on: b.on, enabled: b.enabled }).unwrap_or_default());
    g.last = Some(v);
}
