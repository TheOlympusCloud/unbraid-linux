//! The welcome and the terms, before anything else; the tour over the pages.

use super::{
    AppWindow, ProfileChip, ROUTES, SETTINGS, Strand, TourPage, WelcomePage, WelcomeStep, Win, list, text, with,
};
use crate::desktop;
use crate::ui::{settings, tour, welcome};
use slint::Global;

#[derive(Default)]
pub struct Glue {
    /// The sidebar's chips as last shown.
    pub chips: Vec<ProfileChip>,
    /// Notes the window's place once it stops changing.
    pub place_timer: Option<slint::Timer>,
    /// The welcome as shown: a new install's, or the terms alone.
    welcome: Option<bool>,
    tour: Option<tour::TourView>,
}

pub(super) fn wire(w: &AppWindow) {
    let p = WelcomePage::get(w);
    p.on_accept(|| {
        with(|win| {
            let fresh = win.s.borrow().fresh.unwrap_or(true);
            tour::accept_terms(fresh);
            win.refresh();
        });
    });
    p.on_open_terms(|| desktop::open(settings::TERMS_URL));
    p.on_open_privacy(|| desktop::open(settings::PRIVACY));

    let t = TourPage::get(w);
    t.on_back(|| {
        with(|win| {
            let step = win.s.borrow().tour.unwrap_or(0);
            tour_to(win, step.saturating_sub(1));
        });
    });
    t.on_next(|| {
        with(|win| {
            let step = win.s.borrow().tour.unwrap_or(0);
            if step + 1 >= tour::TourStop::ALL.len() { end(win) } else { tour_to(win, step + 1) }
        });
    });
    t.on_close(|| {
        with(end);
    });
}

/// The tour at stop `step`: what was open closes, and its page shows (Settings on its hub).
pub(super) fn tour_to(win: &Win, step: usize) {
    let tab = tour::TourStop::ALL[step.min(tour::TourStop::ALL.len() - 1)].tab();
    win.s.borrow_mut().tour = Some(step);
    if tab == SETTINGS && win.tab() != SETTINGS {
        super::settings::hub(win);
    }
    win.set_tab(tab);
    win.refresh();
}

/// The tour ends, seen: Routes shows.
fn end(win: &Win) {
    win.s.borrow_mut().tour = None;
    tour::tour_seen();
    win.set_tab(ROUTES);
    win.refresh();
}

pub(super) fn show_welcome(win: &Win) {
    // A new install gets the whole welcome; someone updating from before the terms only the terms.
    let fresh =
        *win.s.borrow_mut().fresh.get_or_insert_with(|| !*win.ui.signed_in.borrow() && !*win.ui.disclosed.borrow());
    let mut g = win.start.borrow_mut();
    if g.welcome == Some(fresh) {
        return;
    }
    g.welcome = Some(fresh);
    let v = welcome::view(fresh);
    let p = WelcomePage::get(&win.w);
    p.set_fresh(v.fresh);
    p.set_steps(list(
        v.steps
            .iter()
            .map(|s| WelcomeStep { overline: text(&s.overline), title: text(&s.title), lead: text(&s.lead) })
            .collect(),
    ));
    p.set_strands(list(
        v.strands.iter().map(|s| Strand { path: text(&s.path), colour: s.colour, front: s.front }).collect(),
    ));
}

pub(super) fn show_tour(win: &Win) {
    let Some(step) = win.s.borrow().tour else { return };
    let v = tour::view(step, *win.ui.disclosed.borrow());
    let mut g = win.start.borrow_mut();
    if g.tour.as_ref() == Some(&v) {
        return;
    }
    let p = TourPage::get(&win.w);
    p.set_overline(text(&v.overline));
    p.set_title(text(&v.title));
    p.set_body(text(&v.body));
    p.set_next_label(text(&v.next_label));
    p.set_has_back(v.has_back);
    p.set_round(v.round);
    p.set_step(v.step);
    p.set_stops(v.stops);
    g.tour = Some(v);
}
