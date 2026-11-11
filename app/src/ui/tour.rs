//! The tour of the app: eight stops, each a note beside the element it is about, on the page it is on. And the
//! first-run state the window keeps in `unbraid_ui.properties`: the terms, the VPN disclosure, the tour still to show
//! and the leak-proof reminder.

use crate::APP;
use crate::prefs::{Editor, SharedPreferences};
use std::sync::{LazyLock, Mutex, MutexGuard};

/// Raise when the terms change in a way people must accept again.
const TERMS: i32 = 1;
const DAY_MS: i64 = 86_400_000;

/// First-run state, as its preferences hold it; without them (no data folder) it lasts until the app quits.
#[derive(Default)]
struct Onboarding {
    prefs: Option<&'static SharedPreferences>,
    terms_ok: bool,
    vpn_ok: bool,
    tour_pending: bool,
    /// Leak-proof setup: 0 not offered yet, 1 snoozed (the Routes reminder comes back at `leak_until`), 3 never remind.
    leak: i32,
    leak_until: i64,
    snoozes: i32,
}

impl Onboarding {
    fn load(prefs: Option<&'static SharedPreferences>) -> Self {
        let Some(p) = prefs else { return Onboarding::default() };
        // Until 2.4 one dialog covered both the VPN and the app list: accepting it covered the VPN too. Settled once,
        // before the apps-only Agree can write the old key.
        if !p.contains("vpn_disclosure") {
            let accepted = p.get_boolean("disclosure_accepted", false);
            p.edit(|e| e.put_boolean("vpn_disclosure", accepted));
        }
        Onboarding {
            prefs,
            terms_ok: p.get_int("terms", 0) >= TERMS,
            vpn_ok: p.get_boolean("vpn_disclosure", false),
            tour_pending: p.get_boolean("tour_pending", false),
            leak: p.get_int("leak", 0),
            leak_until: p.get_long("leak_until", 0),
            snoozes: p.get_int("leak_snoozes", 0),
        }
    }

    fn edit(&self, f: impl FnOnce(&mut Editor)) {
        if let Some(p) = self.prefs {
            p.edit(f);
        }
    }

    fn accept_terms(&mut self, fresh: bool) {
        self.terms_ok = true;
        self.tour_pending = fresh;
        self.edit(|e| {
            e.put_int("terms", TERMS);
            e.put_boolean("tour_pending", fresh);
        });
    }

    fn accept_vpn(&mut self) {
        self.vpn_ok = true;
        self.edit(|e| e.put_boolean("vpn_disclosure", true));
    }

    fn tour_seen(&mut self) {
        self.tour_pending = false;
        self.edit(|e| e.put_boolean("tour_pending", false));
    }

    fn set_leak(&mut self, v: i32) {
        if self.leak != v {
            self.leak = v;
            self.edit(|e| e.put_int("leak", v));
        }
    }

    fn snooze_leak(&mut self, now: i64) {
        self.leak_until = now + [3, 7, 14][self.snoozes.clamp(0, 2) as usize] * DAY_MS;
        self.snoozes += 1;
        self.leak = 1;
        let (until, snoozes) = (self.leak_until, self.snoozes);
        self.edit(|e| {
            e.put_int("leak", 1);
            e.put_long("leak_until", until);
            e.put_int("leak_snoozes", snoozes);
        });
    }

    fn leak_due(&self, now: i64) -> bool {
        self.leak == 1 && now >= self.leak_until
    }
}

fn state() -> MutexGuard<'static, Onboarding> {
    static STATE: LazyLock<Mutex<Onboarding>> =
        LazyLock::new(|| Mutex::new(Onboarding::load(SharedPreferences::named("unbraid_ui").ok())));
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Reads the state. Call it at start, before anything can write the apps' own `disclosure_accepted`.
pub fn init() {
    drop(state());
}

pub fn terms_ok() -> bool {
    state().terms_ok
}

pub fn vpn_ok() -> bool {
    state().vpn_ok
}

/// A new install gets the tour once it is set up (signed in).
pub fn tour_pending() -> bool {
    state().tour_pending
}

pub fn leak() -> i32 {
    state().leak
}

pub fn leak_until() -> i64 {
    state().leak_until
}

/// `fresh`: a new install, which then gets the tour once it is set up.
pub fn accept_terms(fresh: bool) {
    state().accept_terms(fresh);
}

pub fn accept_vpn() {
    state().accept_vpn();
}

pub fn tour_seen() {
    state().tour_seen();
}

pub fn set_leak(v: i32) {
    state().set_leak(v);
}

/// Not now: back in 3 days, then a week, then every two weeks for good.
pub fn snooze_leak() {
    state().snooze_leak(now_ms());
}

pub fn leak_due() -> bool {
    state().leak_due(now_ms())
}

/// The window's pages, as the sidebar lists them.
const PAGES: [&str; 4] = ["Routes", "Apps", "Stats", "Settings"];

/// The tour's stops: each names its page and the concept its element marks, never a position on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TourStop {
    Power,
    DefaultRoute,
    AddRoute,
    AppsList,
    StatsIntro,
    Connections,
    LocalHome,
    About,
}

impl TourStop {
    pub const ALL: [TourStop; 8] = [
        TourStop::Power,
        TourStop::DefaultRoute,
        TourStop::AddRoute,
        TourStop::AppsList,
        TourStop::StatsIntro,
        TourStop::Connections,
        TourStop::LocalHome,
        TourStop::About,
    ];

    /// The page it is on, as an index into the sidebar's pages: Routes, Apps, Stats, Settings.
    pub fn tab(self) -> usize {
        match self {
            TourStop::Power | TourStop::DefaultRoute | TourStop::AddRoute => 0,
            TourStop::AppsList => 1,
            TourStop::StatsIntro => 2,
            TourStop::Connections | TourStop::LocalHome | TourStop::About => 3,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            TourStop::Power => "Connect, pause, stop",
            TourStop::DefaultRoute => "The default exit",
            TourStop::AddRoute => "Add an exit",
            TourStop::AppsList => "Choose per app",
            TourStop::StatsIntro => "Your numbers, if you want them",
            TourStop::Connections => "Add connections",
            TourStop::LocalHome => "Home and local",
            TourStop::About => "You're set",
        }
    }

    pub fn body(self) -> String {
        match self {
            TourStop::Power => "Click to connect. Click again to pause or disconnect. Green is protected, orange paused, red off.".into(),
            TourStop::DefaultRoute => "Every app goes here unless you give it an exception. Click it to change the location.".into(),
            TourStop::AddRoute => "The + button adds a route: your provider's countries, or your own servers and Tailscale. It saves profiles too.".into(),
            TourStop::AppsList => "Click any app to pick its exit; Direct skips the VPN. Moved apps show on Routes as exceptions.".into(),
            TourStop::StatsIntro => "Data per app and exit, flows and speed tests. Off until you turn it on. Statistics stay on this computer; M-Lab publishes speed test results.".into(),
            TourStop::Connections => "Sign in to more providers, or import WireGuard, OpenVPN and Shadowsocks servers.".into(),
            TourStop::LocalHome => "Printers and casting stay reachable. Reach home through Tailscale or your router's WireGuard.".into(),
            TourStop::About => format!("The tray icon works without opening {APP}. Replay this tour here, in About & support."),
        }
    }
}

/// One stop's note.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TourView {
    /// "ROUTES · 1 / 8": its page, then where it is in the tour.
    pub overline: String,
    pub title: String,
    pub body: String,
    /// Next, or Done at the last stop.
    pub next_label: String,
    /// Back shows from the second stop on; there Esc goes back, on the first it closes the tour.
    pub has_back: bool,
    /// The spot is round, around the power button; elsewhere a rounded rectangle.
    pub round: bool,
    /// The stop's index, and how many there are, for the steps.
    pub step: i32,
    pub stops: i32,
}

/// The note at stop `step` (an index into [`TourStop::ALL`]); `apps_shown`: the installed apps are listed, so the
/// Apps stop has rows to point at.
pub fn view(step: usize, apps_shown: bool) -> TourView {
    let n = TourStop::ALL.len();
    let step = step.min(n - 1);
    let stop = TourStop::ALL[step];
    TourView {
        overline: format!("{} · {} / {n}", PAGES[stop.tab()].to_uppercase(), step + 1),
        title: stop.title().into(),
        body: if stop == TourStop::AppsList && !apps_shown {
            "Show my apps lists them here. Click any app to pick its exit; Direct skips the VPN.".into()
        } else {
            stop.body()
        },
        next_label: if step == n - 1 { "Done" } else { "Next" }.into(),
        has_back: step > 0,
        round: stop == TourStop::Power,
        step: step as i32,
        stops: n as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn prefs(dir: &Path, text: &str) -> &'static SharedPreferences {
        let file = dir.join("unbraid_ui.properties");
        std::fs::write(&file, text).unwrap();
        Box::leak(Box::new(SharedPreferences::new(file)))
    }

    fn reopen(dir: &Path) -> SharedPreferences {
        SharedPreferences::new(dir.join("unbraid_ui.properties"))
    }

    /// The earlier app's file reads as it wrote it: the terms, the tour still to show and a snoozed reminder.
    #[test]
    fn reads_what_the_earlier_app_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let p = prefs(
            dir.path(),
            "#Tue Nov 10 22:26:00 CET 2026\nleak=1\nleak_snoozes=2\nleak_until=1762800000000\nterms=1\ntour_pending=true\nvpn_disclosure=false\n",
        );
        let o = Onboarding::load(Some(p));
        assert!(o.terms_ok && o.tour_pending && !o.vpn_ok);
        assert_eq!((1, 1_762_800_000_000, 2), (o.leak, o.leak_until, o.snoozes));
        assert!(!o.leak_due(1_762_799_999_999) && o.leak_due(1_762_800_000_000));
        // Terms older than the current ones count as not accepted.
        assert!(!Onboarding::load(Some(prefs(dir.path(), "terms=0\n"))).terms_ok);
    }

    /// Accepting the old dialog covered the VPN: settled into the new key once, so the apps-only Agree that writes the
    /// old key later changes nothing for the VPN.
    #[test]
    fn the_old_disclosure_covers_the_vpn_once() {
        let dir = tempfile::tempdir().unwrap();
        let o = Onboarding::load(Some(prefs(dir.path(), "disclosure_accepted=true\n")));
        assert!(o.vpn_ok);
        assert!(reopen(dir.path()).get_boolean("vpn_disclosure", false), "settled in the file");

        let p = prefs(dir.path(), "");
        assert!(!Onboarding::load(Some(p)).vpn_ok);
        assert!(p.contains("vpn_disclosure"));
        p.edit(|e| e.put_boolean("disclosure_accepted", true));
        assert!(!Onboarding::load(Some(p)).vpn_ok, "the apps' Agree doesn't accept the VPN");
    }

    /// What each step accepts is written at once, and a new install has the tour waiting.
    #[test]
    fn accepting_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = Onboarding::load(Some(prefs(dir.path(), "")));
        assert!(!o.terms_ok && !o.tour_pending);
        o.accept_terms(true);
        o.accept_vpn();
        let again = Onboarding::load(Some(Box::leak(Box::new(reopen(dir.path())))));
        assert!(again.terms_ok && again.vpn_ok && again.tour_pending);
        assert_eq!(1, reopen(dir.path()).get_int("terms", 0));
        o.tour_seen();
        assert!(!o.tour_pending && !reopen(dir.path()).get_boolean("tour_pending", true));
        // Someone updating from before the terms accepts them without the tour.
        o.accept_terms(false);
        assert!(!reopen(dir.path()).get_boolean("tour_pending", true));
        // Without a data folder it still holds until the app quits.
        let mut lone = Onboarding::load(None);
        lone.accept_terms(true);
        assert!(lone.terms_ok && lone.tour_pending);
    }

    /// Not now: back in 3 days, then 7, then every 14.
    #[test]
    fn snoozes_lengthen() {
        let dir = tempfile::tempdir().unwrap();
        let mut o = Onboarding::load(Some(prefs(dir.path(), "")));
        let mut waits = Vec::new();
        for _ in 0..4 {
            o.snooze_leak(1000);
            waits.push((o.leak_until - 1000) / DAY_MS);
        }
        assert_eq!(vec![3, 7, 14, 14], waits);
        assert!(!o.leak_due(1000) && o.leak_due(1000 + 14 * DAY_MS));
        let file = reopen(dir.path());
        assert_eq!(
            (1, 4, 1000 + 14 * DAY_MS),
            (file.get_int("leak", 0), file.get_int("leak_snoozes", 0), file.get_long("leak_until", 0))
        );
        o.set_leak(3);
        assert!(!o.leak_due(i64::MAX));
        assert_eq!(3, reopen(dir.path()).get_int("leak", 0));
    }

    /// Each note names its page and place; Back from the second stop, Done at the last, the round spot on Power.
    #[test]
    fn notes() {
        let first = view(0, true);
        assert_eq!(
            ("ROUTES · 1 / 8", "Connect, pause, stop", "Next"),
            (first.overline.as_str(), first.title.as_str(), first.next_label.as_str())
        );
        assert!(first.round && !first.has_back);
        let last = view(7, true);
        assert_eq!(("SETTINGS · 8 / 8", "Done"), (last.overline.as_str(), last.next_label.as_str()));
        assert_eq!(
            "The tray icon works without opening unbraid. Replay this tour here, in About & support.",
            last.body
        );
        assert!(last.has_back && !last.round && last.stops == 8);
        assert_eq!(last, view(99, true));
        assert_eq!("APPS · 4 / 8", view(3, true).overline);
        assert_eq!(
            "Show my apps lists them here. Click any app to pick its exit; Direct skips the VPN.",
            view(3, false).body
        );
        assert_eq!(TourStop::AppsList.body(), view(3, true).body);
        let pages: Vec<_> = TourStop::ALL.iter().map(|s| s.tab()).collect();
        assert_eq!(vec![0, 0, 0, 1, 2, 3, 3, 3], pages);
    }
}
