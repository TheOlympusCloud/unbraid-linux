//! Profiles: saved setups to switch between, on Routes. The Profiles page lists them to rename, delete and reorder; a
//! sheet names a new one or edits one; a bar under Routes' header offers Use for one shown but not in use.

use crate::model::{DIRECT, MAX_PROFILES, PROFILE_NAME, Profile, Route, Setup, graphemes, take_graphemes};
use indexmap::{IndexMap, IndexSet};

/// What a profile keeps, in words: "Netherlands · 3 exceptions".
pub fn summary(s: &Setup, p: &Profile) -> String {
    if !p.ready() {
        return "Empty · no default route yet".into();
    }
    let n = p.apps.values().collect::<IndexSet<_>>().len();
    let exceptions = match n {
        0 => "no exceptions".to_string(),
        1 => "1 exception".to_string(),
        n => format!("{n} exceptions"),
    };
    format!("{} · {exceptions}", s.route(Some(&p.default_route)).map_or_else(|| "Direct".into(), Route::name))
}

/// Under Routes' header while a profile is shown but not in use: what is in use, Back to it (Close with none), and Use,
/// the one thing that switches. An empty profile can't be used until it has a default route (`ready`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UseBarView {
    pub name: String,
    pub title: String,
    pub sub: String,
    pub back: String,
    pub ready: bool,
}

pub fn use_bar(name: &str, in_use: Option<&str>, ready: bool) -> UseBarView {
    UseBarView {
        name: name.into(),
        title: format!("{name} · not in use"),
        sub: match in_use {
            _ if !ready => "Choose a default route to use it".into(),
            Some(p) => format!("{p} is in use"),
            None => "No profile is in use".into(),
        },
        back: if in_use.is_some() { "Back" } else { "Close" }.into(),
        ready,
    }
}

/// A saved profile on the Profiles page: its default route's mark, its name, whether it is in use, and its summary.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfileRow {
    pub name: String,
    pub in_use: bool,
    pub summary: String,
    pub code: String,
    pub hue: i32,
    /// Its default route is Direct, or not set yet.
    pub direct: bool,
}

/// The Profiles page.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfilesView {
    /// "2 of 20 · drag to reorder".
    pub sub: String,
    /// As many profiles as there can be: Add profile greys, and the reason sits beside it (`full_note`); Routes says
    /// it too when a new one is refused.
    pub at_limit: bool,
    pub full_note: String,
    pub rows: Vec<ProfileRow>,
}

pub fn view(s: &Setup) -> ProfilesView {
    let saved = s.saved();
    ProfilesView {
        sub: format!("{} of {MAX_PROFILES} · drag to reorder", saved.len()),
        at_limit: saved.len() >= MAX_PROFILES,
        full_note: format!("{MAX_PROFILES} profiles is the most. Delete one to add another."),
        rows: saved
            .iter()
            .map(|p| {
                let route = s.route(Some(&p.default_route));
                ProfileRow {
                    name: p.name.clone(),
                    in_use: s.profile.as_ref() == Some(&p.name),
                    summary: summary(s, p),
                    code: route.map(Route::code).unwrap_or_default(),
                    hue: route.map_or(0, |r| r.hue),
                    direct: route.is_none(),
                }
            })
            .collect(),
    }
}

/// The sheet for a new profile (`editing` none) or one being edited: a name of at most [`PROFILE_NAME`] characters
/// people see, what it keeps, and, when editing, Delete.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProfileSheetView {
    pub title: String,
    pub sub: String,
    /// A new profile's first choice: a copy of the one in use, or the current setup with none in use.
    pub copy: String,
    /// The name as typed, cut to [`PROFILE_NAME`] characters people see.
    pub name: String,
    /// The name Save saves; empty while the name can't be saved (Save greys).
    pub valid: String,
    /// The name is another profile's: the hint says so in the bad ink.
    pub taken: bool,
    pub hint: String,
    /// "3/12".
    pub count: String,
    /// What it keeps: the default route, then the exceptions (three, then "+N more"), or "None".
    pub keeps_default: String,
    pub keeps_exceptions: Vec<String>,
    pub save: String,
}

/// The profile sheet as it stands: for profile `editing` (none = new; `empty` = a new one starts empty), with `typed`.
pub fn sheet(s: &Setup, editing: Option<&str>, empty: bool, typed: &str) -> ProfileSheetView {
    let name = take_graphemes(typed, PROFILE_NAME);
    let valid = s.profile_name(&name, editing);
    let taken = !name.trim().is_empty() && valid.is_none() && graphemes(name.trim()) <= PROFILE_NAME;
    // New: the current setup (saved and in use when none is), a copy of the one in use, or empty.
    let shown = s.saved().into_iter().find(|p| Some(p.name.as_str()) == editing).unwrap_or_else(|| if empty { Profile::new("", "") } else { Profile { apps: s.apps.clone(), ..Profile::new("", &s.default_route) } });
    let mut by_route: IndexMap<&str, usize> = IndexMap::new();
    for route in shown.apps.values() {
        *by_route.entry(route.as_str()).or_default() += 1;
    }
    let ex: Vec<String> = by_route
        .iter()
        .map(|(id, n)| format!("{} · {}", if *id == DIRECT { "Direct".into() } else { s.route(Some(id)).map_or_else(|| id.to_string(), Route::name) }, if *n == 1 { "1 app".into() } else { format!("{n} apps") }))
        .collect();
    let mut keeps_exceptions: Vec<String> = if ex.is_empty() { vec!["None".into()] } else { ex.iter().take(3).cloned().collect() };
    if ex.len() > 3 {
        keeps_exceptions.push(format!("+{} more", ex.len() - 3));
    }
    ProfileSheetView {
        title: match () {
            _ if editing.is_some() => "Edit profile",
            _ if s.profile.is_none() && !empty => "Save this setup",
            _ => "New profile",
        }
        .into(),
        sub: match &s.profile {
            _ if editing.is_some() => "Rename it, or delete it".into(),
            _ if empty => "Empty, not in use until you click Use".into(),
            None => "Saves this setup so you can switch back in one click".into(),
            Some(p) => format!("A copy of {p}, not in use until you click Use"),
        },
        copy: s.profile.as_ref().map_or_else(|| "Current setup".into(), |p| format!("Copy of {p}")),
        count: format!("{}/{PROFILE_NAME}", graphemes(&name)),
        name,
        valid: valid.unwrap_or_default(),
        taken,
        hint: if taken { "You already have a profile with this name".into() } else { format!("Up to {PROFILE_NAME} characters") },
        keeps_default: if !shown.ready() { "Not set".into() } else { s.route(Some(&shown.default_route)).map_or_else(|| "Direct".into(), Route::name) },
        keeps_exceptions,
        save: if editing.is_none() { "Save profile" } else { "Save" }.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Location;

    fn base() -> Setup {
        Setup {
            routes: vec![
                Route::new("nl", Location::country("nord", 153, "NL", "Netherlands")),
                Route { hue: 1, ..Route::new("us", Location::country("nord", 228, "US", "United States")) },
                Route { hue: 2, ..Route::new("it", Location::country("nord", 106, "IT", "Italy")) },
            ],
            default_route: "nl".into(),
            apps: [("firefox", "us"), ("thunderbird", "us"), ("spotify", "it"), ("code", DIRECT)].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Setup::default()
        }
    }

    /// A profile in words: its default route and how many routes its exceptions use; an empty one says so.
    #[test]
    fn summaries() {
        let s = base();
        assert_eq!("Netherlands · 3 exceptions", summary(&s, &Profile { apps: s.apps.clone(), ..Profile::new("Home", "nl") }));
        assert_eq!("Italy · 1 exception", summary(&s, &Profile::with_apps("Work", "it", &[("a", "us"), ("b", "us")])));
        assert_eq!("Direct · no exceptions", summary(&s, &Profile::new("Trip", DIRECT)));
        assert_eq!("Empty · no default route yet", summary(&s, &Profile::new("New", "")));
    }

    /// The use bar names what is in use, offers Back to it (Close with none), and Use once the profile has a default.
    #[test]
    fn use_bars() {
        assert_eq!(UseBarView { name: "Trip".into(), title: "Trip · not in use".into(), sub: "Home is in use".into(), back: "Back".into(), ready: true }, use_bar("Trip", Some("Home"), true));
        assert_eq!(("No profile is in use", "Close"), (use_bar("Trip", None, true).sub.as_str(), use_bar("Trip", None, true).back.as_str()));
        assert_eq!("Choose a default route to use it", use_bar("Trip", Some("Home"), false).sub);
    }

    /// The Profiles page: how many of how many, each with its mark, summary and the one in use.
    #[test]
    fn page() {
        let s = base().save_as("Home").add("Trip", true);
        let v = view(&s);
        assert_eq!(("2 of 20 · drag to reorder", false, "20 profiles is the most. Delete one to add another."), (v.sub.as_str(), v.at_limit, v.full_note.as_str()));
        assert_eq!(ProfileRow { name: "Home".into(), in_use: true, summary: "Netherlands · 3 exceptions".into(), code: "NL".into(), hue: 0, direct: false }, v.rows[0]);
        assert!(v.rows[1].direct && !v.rows[1].in_use);
        let mut full = base();
        for n in 0..MAX_PROFILES {
            full = full.add(&format!("P{n}"), true);
        }
        assert!(view(&full).at_limit);
    }

    /// The sheet's words follow what it does: saving the setup, copying the one in use, empty, or editing.
    #[test]
    fn sheet_words() {
        let s = base();
        let first = sheet(&s, None, false, "");
        assert_eq!(("Save this setup", "Saves this setup so you can switch back in one click", "Current setup", "Save profile"), (first.title.as_str(), first.sub.as_str(), first.copy.as_str(), first.save.as_str()));
        assert_eq!(("Netherlands", vec!["United States · 2 apps".to_string(), "Italy · 1 app".into(), "Direct · 1 app".into()]), (first.keeps_default.as_str(), first.keeps_exceptions.clone()));
        let s = s.save_as("Home");
        let copy = sheet(&s, None, false, "");
        assert_eq!(("New profile", "A copy of Home, not in use until you click Use", "Copy of Home"), (copy.title.as_str(), copy.sub.as_str(), copy.copy.as_str()));
        let empty = sheet(&s, None, true, "");
        assert_eq!(("New profile", "Empty, not in use until you click Use", "Not set", vec!["None".to_string()]), (empty.title.as_str(), empty.sub.as_str(), empty.keeps_default.as_str(), empty.keeps_exceptions));
        let edit = sheet(&s, Some("Home"), false, "Home");
        assert_eq!(("Edit profile", "Rename it, or delete it", "Save", "Home"), (edit.title.as_str(), edit.sub.as_str(), edit.save.as_str(), edit.valid.as_str()));
    }

    /// A name: at most twelve characters people see, as typed; one another profile has (in any case) is said to be taken.
    #[test]
    fn names() {
        let s = base().save_as("Home");
        let taken = sheet(&s, None, false, "home ");
        assert_eq!((true, "", "You already have a profile with this name", "5/12"), (taken.taken, taken.valid.as_str(), taken.hint.as_str(), taken.count.as_str()));
        let ok = sheet(&s, None, false, " Travel ");
        assert_eq!((false, "Travel", "Up to 12 characters"), (ok.taken, ok.valid.as_str(), ok.hint.as_str()));
        let long = sheet(&s, None, false, "A very long profile name");
        assert_eq!(("A very long ", "12/12"), (long.name.as_str(), long.count.as_str()));
        assert_eq!("🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱🇳🇱", sheet(&s, None, false, &"🇳🇱".repeat(13)).name);
        let blank = sheet(&s, None, false, "   ");
        assert_eq!((false, ""), (blank.taken, blank.valid.as_str()));
        // Editing keeps its own name; four routes' exceptions show three and how many more.
        assert_eq!("Home", sheet(&s, Some("Home"), false, "Home").valid);
        let mut many = base();
        many.routes.push(Route::new("de", Location::country("nord", 81, "DE", "Germany")));
        many.apps.insert("chromium".into(), "de".into());
        assert_eq!(vec!["United States · 2 apps", "Italy · 1 app", "Direct · 1 app", "+1 more"], sheet(&many, None, false, "").keeps_exceptions);
    }
}
