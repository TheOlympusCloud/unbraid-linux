//! Signing in: the first run's card, or Add provider beside the sidebar.

use super::{sync, AppWindow, FormField, FormView, Other, OtherRow, ProviderRow, SignInPage, Win, list, text, with};
use crate::app;
use crate::desktop;
use crate::ui::sign_in::{self as logic, form_key};
use slint::{Global, ModelRc, VecModel};
use std::rc::Rc;

#[derive(Default)]
pub struct Glue {
    /// The provider whose form is open; none lists the providers.
    step: Option<String>,
    last: Option<logic::SignInView>,
    fields: Rc<VecModel<FormField>>,
}

/// A PNG as the provider sent it, for the page.
fn picture(png: &[u8]) -> slint::Image {
    image::load_from_memory(png)
        .map(|i| i.to_rgba8())
        .map(|rgba| slint::Image::from_rgba8(slint::SharedPixelBuffer::clone_from_slice(rgba.as_raw(), rgba.width(), rgba.height())))
        .unwrap_or_default()
}

fn field(x: &logic::FormField) -> FormField {
    FormField {
        key: text(&x.key),
        label: text(&x.label),
        value: text(&x.value),
        placeholder: text(&x.placeholder),
        secret: x.secret,
        qr: x.qr,
        file: x.file,
        file_note: text(&x.file_note),
        last: x.last,
        asked: x.asked,
    }
}

/// The sign-in's own state changed: it shows it at once.
fn page(f: impl FnOnce(&mut Glue)) {
    with(|win| {
        f(&mut win.sign_in.borrow_mut());
        win.refresh();
    });
}

/// What the view reads, as it stands now.
fn view(win: &Win, adding: bool) -> logic::SignInView {
    let ui = &win.ui;
    let accounts = ui.accounts().borrow().clone();
    let notice = ui.notice.borrow().clone();
    let forms = ui.forms.borrow().clone();
    let signing = ui.signing.borrow().clone();
    let import_error = super::settings::import_error(win);
    let step = win.sign_in.borrow().step.clone();
    logic::view(&logic::Inputs {
        adding,
        accounts: &accounts,
        notice: notice.as_deref(),
        import_error: import_error.as_deref(),
        step: step.as_deref(),
        form: &forms.form,
        signing: &signing,
        errors: &forms.errors,
        links: &forms.links,
        challenges: &forms.challenges,
    })
}

/// A file picked for field `key` of provider `id`'s form, `picture` for a QR code.
fn pick_for(win: &Win, id: &str, key: &str, picture: bool) {
    let (ui, id, key) = (win.ui.clone(), id.to_string(), key.to_string());
    app::runtime().spawn(async move {
        let title = if picture { "Choose a picture of the QR code" } else { "Choose the config file" };
        let file = desktop::pick_file(title, picture).await;
        if picture {
            ui.read_qr(file, form_key(&id, &key), id);
        } else if let Some(f) = file {
            ui.load_form_file(f, form_key(&id, &key), id);
        }
    });
}

pub(super) fn wire(w: &AppWindow) {
    let p = SignInPage::get(w);
    p.on_close(|| {
        with(|win| {
            win.s.borrow_mut().adding = false;
            win.refresh();
        });
    });
    p.on_dismiss_notice(|| {
        with(|win| win.ui.notice.send_replace(None));
    });
    p.on_pick(|id| page(|g| g.step = Some(id.into())));
    // Back, or Esc in the form: the provider's half-filled form is forgotten.
    p.on_back(|id| {
        with(|win| {
            win.ui.discard_form(&id);
            win.sign_in.borrow_mut().step = None;
            win.refresh();
        });
    });
    p.on_field_changed(|id, key, typed| {
        with(|win| {
            win.ui.forms.send_modify(|f| {
                f.form.insert(form_key(&id, &key), typed.into());
                // An edit clears the last error, unless it is the answer to the provider's question.
                if f.challenges.get(id.as_str()).is_none_or(|c| c.field.key != key.as_str()) {
                    f.errors.shift_remove(id.as_str());
                    f.links.shift_remove(id.as_str());
                    f.challenges.shift_remove(id.as_str());
                }
            });
            win.refresh();
        });
    });
    p.on_submit(|id| {
        with(|win| {
            let adding = win.s.borrow().adding;
            let ui = &win.ui;
            let (accounts, forms, signing) = (ui.accounts().borrow().clone(), ui.forms.borrow().clone(), ui.signing.borrow().clone());
            let answers = logic::submit(&logic::Inputs {
                adding,
                accounts: &accounts,
                notice: None,
                import_error: None,
                step: Some(id.as_str()),
                form: &forms.form,
                signing: &signing,
                errors: &forms.errors,
                links: &forms.links,
                challenges: &forms.challenges,
            });
            if let Some(a) = answers {
                ui.sign_in(&id, a);
            }
        });
    });
    p.on_scan_qr(|id, key| {
        with(|win| pick_for(win, &id, &key, true));
    });
    p.on_choose_file(|id, key| {
        with(|win| pick_for(win, &id, &key, false));
    });
    p.on_import_file(|| {
        with(|win| super::settings::import_file(win, "any", None));
    });
    p.on_shadowsocks(|| {
        with(|win| win.ui.import_draft.send_modify(crate::ui::importer::Draft::shadowsocks));
    });
    p.on_tailscale_only(|| {
        with(|win| win.ui.use_tailscale_only());
    });
    p.on_open_link(|url| desktop::open(&url));
}

pub(super) fn show(win: &Win, adding: bool) {
    let v = view(win, adding);
    // The sign-in landed: Add provider closes, and the form starts afresh next time.
    if v.form.done {
        win.sign_in.borrow_mut().step = None;
        if adding {
            win.s.borrow_mut().adding = false;
            super::poke();
        }
    }
    let mut g = win.sign_in.borrow_mut();
    if g.last.as_ref() == Some(&v) {
        return;
    }
    let page = SignInPage::get(&win.w);
    let old = g.last.as_ref();
    page.set_overline(text(&v.overline));
    page.set_title(text(&v.title));
    page.set_sub(text(&v.sub));
    page.set_closable(v.closable);
    page.set_notice(text(&v.notice));
    if old.is_none_or(|o| o.providers != v.providers) {
        page.set_providers(list(v.providers.iter().map(|p| ProviderRow { id: text(&p.id), name: text(&p.name), fields: text(&p.fields) }).collect()));
    }
    let other = |o: logic::Other| match o {
        logic::Other::File => Other::File,
        logic::Other::Shadowsocks => Other::Shadowsocks,
        logic::Other::Tailscale => Other::Tailscale,
    };
    if old.is_none_or(|o| o.others != v.others) {
        page.set_others(list(v.others.iter().map(|o| OtherRow { other: other(o.other), title: text(&o.title), sub: text(&o.sub) }).collect()));
    }
    page.set_import_error(text(&v.import_error));
    let f = &v.form;
    sync(&g.fields, f.fields.iter().map(field).collect());
    page.set_form(FormView {
        id: text(&f.id),
        name: text(&f.name),
        fields: ModelRc::from(g.fields.clone()),
        captcha: f.captcha.as_deref().map(picture).unwrap_or_default(),
        error: text(&f.error),
        question: f.question,
        link: text(&f.link),
        link_label: text(&f.link_label),
        help: text(&f.help),
        ready: f.ready,
        busy: f.busy,
        done: f.done,
    });
    g.last = Some(v);
}

