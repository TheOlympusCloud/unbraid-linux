//! Settings in two panes, its dialogs, and the prompts that import a server of the user's own.

use super::{
    AppWindow, ImportPrompt, ImporterPage, SettingsAct, SettingsDialog, SettingsEnd, SettingsGlyph, SettingsGroup, SettingsInput, SettingsLicence, SettingsPage,
    SettingsRow, SettingsSubject, SettingsTone, Win, list, post, text, with,
};
use crate::autostart::Autostart;
use crate::desktop_settings::{self as ds, Theme};
use crate::limits::LIMIT_OPT;
use crate::model::Setup;
use crate::providers::{self, Device, Opt};
use crate::ui::importer::{self, PromptView};
use crate::ui::settings::{self as logic, Act, End, Glyph};
use crate::ui::status::Tone;
use crate::vpn::VpnState;
use crate::{app, desktop, keyring, paths, stats};
use indexmap::IndexMap;
use slint::Global;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Default)]
pub struct Glue {
    /// The pages open, from the subject on the left to the one shown; empty = Providers & servers.
    stack: Vec<String>,
    last: Option<logic::SettingsView>,
    /// The open provider page's settings, device slot and plan, read off the window's thread, and for which provider.
    read_for: Option<String>,
    opts: Vec<Opt>,
    device: Option<Device>,
    plan: Option<String>,
    /// Starting at login, read when a page shows.
    login: Option<(bool, bool, bool)>,
    login_for: Option<Vec<String>>,
    /// The stats file's size, read when a page shows and again once a delete has had time to finish.
    stats_size: u64,
    /// Why the home tunnel's config couldn't be imported; why the last file picked couldn't be.
    wg_error: Option<String>,
    import_error: Option<String>,
    /// The Tailscale node check last ran for this page and Tailscale setting.
    checked: Option<(Vec<String>, bool)>,
    /// Every 5 s while a provider's new key is being set up.
    tick: Option<slint::Timer>,
    prompt: Option<PromptView>,
}

macro_rules! same {
    ($f:ident: $from:ident => $to:ident [$($v:ident),* $(,)?]) => {
        fn $f(x: $from) -> $to {
            match x {
                $($from::$v => $to::$v),*
            }
        }
    };
}
same!(act: Act => SettingsAct [None, Open, Pick, Url, Dialog, Advanced, Tailscale, TsLogin, Suffix, Lan, HomeConfig, Opt, Filter, FilterRoutes, FilterDirect, Outside, Through, Stats, Login, Connect, Minimised, CloseToTray, RememberWindow, Theme, Tour, AddProvider, ImportFile, Shadowsocks, SaveFilter, SignOutTailscale, TsServer, Subnets, DeleteStats, Limit, SignOut, RenameServer, RemoveServer]);
same!(end: End => SettingsEnd [None, Chevron, Dot, Toggle, Radio, External, Delete, Mark, Keys, Remove, Expand]);
same!(glyph: Glyph => SettingsGlyph [None, VpnKey, Hub, Home, Tunnel, Shield, Layers, Stats, Bolt, Info, File, Phone, Dns, Lan, Router, Power, Routes, Sliders]);
same!(tone: Tone => SettingsTone [Good, Warn, Bad, Idle]);

fn row(r: &logic::Row) -> SettingsRow {
    SettingsRow {
        act: act(r.act),
        arg: text(&r.arg),
        title: text(&r.title),
        sub: text(&r.sub),
        icon: glyph(r.icon),
        end: end(r.end),
        checked: r.checked,
        cta: r.cta,
        danger: r.danger,
        tone: tone(r.tone),
        value: text(&r.value),
        hue: r.hue,
        wordmark: r.wordmark,
    }
}

fn group(g: &logic::Group) -> SettingsGroup {
    SettingsGroup {
        label: text(&g.label),
        rows: list(g.rows.iter().map(row).collect()),
        advanced: g.advanced,
        open_sub: text(&g.open_sub),
        button: text(&g.button),
        error: text(&g.error),
        caption: text(&g.caption),
    }
}

fn dialog(d: &logic::Dialog) -> SettingsDialog {
    SettingsDialog {
        key: text(&d.key),
        sheet: d.sheet,
        title: text(&d.title),
        text: text(&d.text),
        inputs: list(d.inputs.iter().map(|i| SettingsInput { label: text(&i.label), placeholder: text(&i.placeholder), value: text(&i.value), secret: i.secret }).collect()),
        hint: text(&d.hint),
        error: text(&d.error),
        rows: list(d.rows.iter().map(row).collect()),
        confirm: row(&d.confirm),
        other: row(&d.other),
        stays: d.stays,
    }
}

/// The page's own state changed: Settings shows it at once.
fn page(f: impl FnOnce(&mut Glue)) {
    with(|win| {
        f(&mut win.settings.borrow_mut());
        win.refresh();
    });
}

/// A change to the setup, as the view model saves it.
fn edit(f: impl FnOnce(&Setup) -> Setup) {
    app::store().edit(f);
}

/// Starting at login changed: written, then read back as the page shows it.
fn login(on: bool, connect: Option<bool>, minimised: Option<bool>) {
    if let Err(e) = Autostart::user().set(on, connect, minimised) {
        crate::log::w("Unbraid", &format!("autostart: {e}"));
    }
    page(|g| g.login = None);
}

/// A config file picked for the importer ([`importer::Draft::file`]): read off the window's thread, then its prompt
/// opens, or the importer says why it can't.
pub(super) fn import_file(win: &Win, kind: &str, prefix: Option<&str>) {
    win.settings.borrow_mut().import_error = None;
    win.ui.import_draft.send_modify(|d| d.file(kind, prefix));
    app::runtime().spawn(async {
        let Some(file) = desktop::pick_file(importer::PICK_TITLE, false).await else { return };
        let Ok((read, name)) = tokio::task::spawn_blocking(move || (importer::read_capped(&file), importer::file_name(&file))).await else { return };
        post(move |win| {
            let mut error = None;
            win.ui.import_draft.send_modify(|d| error = d.picked(read.as_deref(), &name));
            win.settings.borrow_mut().import_error = error;
        });
    });
}

pub(super) fn wire(w: &AppWindow) {
    let p = SettingsPage::get(w);
    p.on_valid(|key, typed| logic::valid(&key, &typed));
    p.on_clean(|key, typed| logic::clean(&key, &typed).into());
    p.on_pick(|s| page(|g| g.stack = vec![s.into()]));
    p.on_open(|to| page(|g| g.stack.push(to.into())));
    p.on_go_back(|| {
        page(|g| {
            g.stack.pop();
        })
    });
    p.on_open_url(|u| desktop::open(&u));
    p.on_dismiss_notice(|| {
        with(|win| win.ui.notice.send_replace(None));
    });
    p.on_set_tailscale(|on| edit(|s| logic::set_tailscale(s, on)));
    p.on_ts_login(|u| {
        with(|win| win.ts_login(&u));
    });
    p.on_allow_suffix(|d, on| edit(|s| logic::allow_suffix(s, &d, on)));
    p.on_set_lan(|on| edit(|s| logic::set_lan(s, on)));
    p.on_pick_home_config(|| {
        app::runtime().spawn(async {
            let Some(file) = desktop::pick_file(logic::PICK_HOME_CONFIG, false).await else { return };
            let Ok(read) = tokio::task::spawn_blocking(move || importer::read_capped(&file)).await else { return };
            post(move |win| {
                let error = match read {
                    None => Some(importer::UNREADABLE.to_string()),
                    Some(text) => win.ui.import_home_wire_guard(&text),
                };
                win.settings.borrow_mut().wg_error = error;
            });
        });
    });
    p.on_remove_home_wg(|| edit(logic::remove_home_wg));
    p.on_set_opt(|provider, key, value| {
        with(|win| win.ui.set_opt(&provider, &key, &value));
        page(|g| g.read_for = None);
    });
    p.on_set_limit(|provider, t| {
        with(|win| win.ui.set_opt(&provider, LIMIT_OPT, &t));
    });
    p.on_set_filter(|id| edit(|s| logic::set_filter(s, Some(id.as_str()).filter(|i| !i.is_empty()))));
    p.on_save_filter(|id, value| edit(|s| logic::save_filter(s, &id, &value)));
    p.on_set_filter_routes(|on| edit(|s| logic::set_filter_routes(s, on)));
    p.on_set_filter_direct(|on| edit(|s| logic::set_filter_direct(s, on)));
    p.on_set_filter_direct_apps(|on| edit(|s| logic::set_filter_direct_apps(s, on)));
    p.on_set_stats(|on| {
        with(|win| win.ui.set_stats(on));
    });
    // Turn on asks first, in the Stats page's own sheet.
    p.on_stats_consent(|| {
        with(|win| {
            win.s.borrow_mut().stats_consent = true;
            win.refresh();
        });
    });
    p.on_delete_stats(|| {
        with(|win| win.ui.delete_stats());
        // Deleting runs on the stats thread: the size is read again once it has had time to finish.
        slint::Timer::single_shot(Duration::from_millis(800), || page(|g| g.stats_size = stats::size()));
    });
    p.on_set_login(|on| login(on, None, None));
    p.on_set_connect(|on| login(true, Some(on), None));
    p.on_set_minimised(|on| login(true, None, Some(on)));
    p.on_set_close_to_tray(ds::set_close_to_tray);
    p.on_set_remember_window(ds::set_remember_window);
    p.on_set_theme(|name| {
        let t = match name.as_str() {
            "Dark" => Theme::Dark,
            "Light" => Theme::Light,
            _ => Theme::System,
        };
        ds::set_theme(t);
        super::poke();
    });
    p.on_tour(|| {
        with(|win| super::start::tour_to(win, 0));
    });
    p.on_adding(|| page(|g| g.import_error = None));
    p.on_add_provider(|| {
        with(Win::add_provider);
    });
    p.on_import_file(|kind, prefix| {
        with(|win| import_file(win, &kind, Some(prefix.as_str()).filter(|p| !p.is_empty())));
    });
    p.on_import_shadowsocks(|| {
        with(|win| {
            win.settings.borrow_mut().import_error = None;
            win.ui.import_draft.send_modify(importer::Draft::shadowsocks);
        });
    });
    p.on_sign_out_tailscale(|| {
        with(|win| win.ui.sign_out_tailscale());
    });
    p.on_set_tailscale_server(|url, key| {
        with(|win| {
            let some = |s: &str| Some(s.trim().to_string()).filter(|s| !s.is_empty());
            win.ui.set_tailscale_server(some(&url), some(&key));
        });
    });
    p.on_set_subnets(|t| {
        app::store().edit(|s| logic::set_subnets(s, &t).unwrap_or_else(|| s.clone()));
    });
    p.on_sign_out(|provider| {
        with(|win| win.ui.sign_out(&provider));
    });
    p.on_rename_server(|id, name| {
        with(|win| win.ui.rename_server(&id, &name));
    });
    p.on_remove_server(|id| {
        with(|win| win.ui.remove_server(&id));
    });

    let imp = ImporterPage::get(w);
    imp.on_import(|| {
        with(|win| {
            let mut made = None;
            let mut secrets = vec![];
            win.ui.import_draft.send_modify(|d| {
                made = d.import();
                secrets = d.secrets();
            });
            let Some(server) = made else { return };
            let saving = win.ui.import_server(None, server);
            app::runtime().spawn(async move {
                if saving.await {
                    tokio::task::spawn_blocking(move || {
                        for s in secrets {
                            if desktop::clip_text().is_some_and(|c| c.trim() == s.trim()) {
                                desktop::clear_clip();
                            }
                        }
                    });
                }
            });
            win.ui.import_draft.send_modify(importer::Draft::clear);
            SettingsPage::get(&win.w).set_dialog("".into());
            // Imported from Add provider: it closes, as after a sign-in.
            win.s.borrow_mut().adding = false;
            win.refresh();
        });
    });
    imp.on_cancel(|| {
        with(|win| win.ui.import_draft.send_modify(importer::Draft::clear));
    });
    imp.on_edited(|name, user, pass, link| {
        with(|win| {
            win.ui.import_draft.send_modify(|d| d.edited(&name, &user, &pass, &link));
            // At once: the prompt's fields are typed in.
            show_importer(win);
        });
    });
}

/// Settings again: back to Providers & servers.
pub(super) fn reselected(win: &Win) {
    win.settings.borrow_mut().stack.clear();
}

pub(super) fn left(win: &Win) {
    let mut g = win.settings.borrow_mut();
    g.last = None;
    g.tick = None;
    g.login_for = None;
}

/// Opens Settings on its hub (Providers & servers), as the tour does.
pub(super) fn hub(win: &Win) {
    win.settings.borrow_mut().stack.clear();
}

pub(super) fn show(win: &Win, setup: &Setup, vpn: &VpnState) {
    let ui = &win.ui;
    let accounts = ui.accounts().borrow().clone();
    let now = chrono::Utc::now().timestamp_millis();
    let stack = logic::shown(&win.settings.borrow().stack, &accounts);
    let mut g = win.settings.borrow_mut();
    // A node left behind can be signed out of: checked again when the page or Tailscale changes.
    let checked = (stack.clone(), setup.home.tailscale);
    if g.checked.as_ref() != Some(&checked) {
        g.checked = Some(checked);
        ui.check_tailscale();
    }
    if g.login_for.as_ref() != Some(&stack) || g.login.is_none() {
        let a = Autostart::user();
        g.login = Some((a.enabled(), a.connects(), a.minimised()));
        g.stats_size = stats::size();
        g.login_for = Some(stack.clone());
    }
    read_provider(&mut g, stack.last().map(String::as_str), &accounts);
    let setting_up = providers::setting_up(now);
    // A key's setup minute ends while Providers & servers may stay open.
    let ticking = stack.last().is_none_or(|p| p == "providers") && !setting_up.is_empty();
    if ticking != g.tick.is_some() {
        g.tick = ticking.then(|| {
            let t = slint::Timer::default();
            t.start(slint::TimerMode::Repeated, Duration::from_secs(5), super::poke);
            t
        });
    }
    let fresh: HashSet<String> = accounts.keys().filter(|id| app::store().countries_fresh(id)).cloned().collect();
    let list_dates: IndexMap<String, i64> = app::store().catalog_dates.borrow().clone();
    let running = crate::vpn::live().running();
    let tags = crate::vpn::live().tags();
    let notice = ui.notice.borrow().clone();
    let data = paths::data().ok();
    let key_file = data.filter(|d| keyring::in_file(d)).map(|d| d.to_string_lossy().replacen(&*paths::home().to_string_lossy(), "~", 1));
    let v = logic::view(&logic::Inputs {
        setup,
        vpn,
        accounts: &accounts,
        stack: &stack,
        notice: notice.as_deref(),
        fresh: &fresh,
        list_dates: &list_dates,
        setting_up: &setting_up,
        running: running.as_ref(),
        tags: &tags,
        opts: &g.opts,
        device: g.device.as_ref(),
        plan: g.plan.as_deref(),
        ts_stored: *ui.ts_stored.borrow(),
        login: g.login.unwrap_or_default(),
        theme: *ds::theme().borrow(),
        close_to_tray: *ds::close_to_tray().borrow(),
        remember_window: *ds::remember_window().borrow(),
        stats_size: g.stats_size,
        key_file: key_file.as_deref(),
        wg_error: g.wg_error.as_deref(),
        now,
    });
    if g.last.as_ref() != Some(&v) {
        let p = SettingsPage::get(&win.w);
        let old = g.last.as_ref();
        p.set_version(text(&v.version));
        if old.is_none_or(|o| o.subjects != v.subjects) {
            p.set_subjects(list(v.subjects.iter().map(|s| SettingsSubject { key: text(&s.key), title: text(&s.title), icon: glyph(s.icon), group: text(&s.group) }).collect()));
        }
        p.set_subject(text(&v.subject));
        p.set_page(text(&v.page));
        p.set_over(text(&v.over));
        p.set_title(text(&v.title));
        p.set_back(v.back);
        p.set_provider(text(&v.provider));
        p.set_notice(text(&v.notice));
        if old.is_none_or(|o| o.groups != v.groups) {
            p.set_groups(list(v.groups.iter().map(group).collect()));
        }
        if old.is_none_or(|o| o.licences != v.licences) {
            p.set_licences(list(v.licences.iter().map(|l| SettingsLicence { title: text(&l.title), text: text(&l.text) }).collect()));
        }
        if old.is_none_or(|o| o.dialogs != v.dialogs) {
            p.set_dialogs(list(v.dialogs.iter().map(dialog).collect()));
        }
        g.last = Some(v);
    }
}

/// The open provider page's settings, device slot and plan: some come from the provider's server list, so they are
/// read off the window's thread.
fn read_provider(g: &mut Glue, page: Option<&str>, accounts: &IndexMap<String, String>) {
    let id = page.and_then(|p| p.strip_prefix("provider:")).filter(|id| accounts.contains_key(*id)).map(str::to_string);
    if g.read_for == id {
        return;
    }
    g.read_for = id.clone();
    (g.opts, g.device, g.plan) = (vec![], None, None);
    let Some(id) = id else { return };
    let (Some(p), Some(account)) = (providers::get(&id), accounts.get(&id).cloned()) else { return };
    app::runtime().spawn_blocking(move || {
        let opts = logic::provider_opts(p, &account);
        let (device, plan) = (p.device(&account), p.plan(&account));
        post(move |win| {
            let mut g = win.settings.borrow_mut();
            if g.read_for.as_deref() == Some(id.as_str()) {
                (g.opts, g.device, g.plan) = (opts, device, plan);
            }
        });
    });
}

/// The import prompts and the importer's last error, over whichever page opened them.
pub(super) fn show_importer(win: &Win) {
    let v = importer::prompt(&win.ui.import_draft.borrow());
    let mut g = win.settings.borrow_mut();
    let p = ImporterPage::get(&win.w);
    p.set_error(text(g.import_error.as_deref().unwrap_or("")));
    if g.prompt.as_ref() != Some(&v) {
        p.set_prompt(ImportPrompt {
            kind: text(&v.kind),
            title: text(&v.title),
            text: text(&v.text),
            confirm: text(&v.confirm),
            danger: v.danger,
            ready: v.ready,
            name: text(&v.name),
            warning: text(&v.warning),
            error: text(&v.error),
        });
        g.prompt = Some(v);
    }
}

/// The importer's last error, for the sign-in's list.
pub(super) fn import_error(win: &Win) -> Option<String> {
    win.settings.borrow().import_error.clone()
}
