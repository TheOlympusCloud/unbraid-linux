//! How a provider stands, in Settings: a colour, always with words.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Idle,
}

/// Older than this, a provider's only server list turns its status amber.
pub const OLD_LIST_MS: i64 = 60 * 86_400_000;

/// A provider's status from what the app already knows (no extra calls): `refused` its account, its key still
/// `setting_up`, its routes `blocked` for a passing reason, a route `dropping` (its warning), its only list published
/// long ago (`old_list`, that date), its saved server list over a day old (not `list_fresh`), its routes `connected`.
#[allow(clippy::too_many_arguments)]
pub fn provider_status(name: &str, used: bool, refused: bool, setting_up: bool, blocked: bool, list_fresh: bool, connected: bool, dropping: Option<&str>, old_list: Option<&str>) -> (Tone, String) {
    match () {
        _ if refused => (Tone::Bad, format!("{name} refused this computer. Sign in again")),
        _ if !used => (Tone::Idle, "Not used".into()),
        _ if setting_up => (Tone::Warn, "Setting up your key".into()),
        _ if blocked => (Tone::Warn, "Can't reach its servers right now".into()),
        _ if dropping.is_some() => (Tone::Warn, dropping.unwrap_or_default().into()),
        _ if old_list.is_some() => (Tone::Warn, format!("Its server list is from {} and may be out of date", old_list.unwrap_or_default())),
        _ if !list_fresh => (Tone::Warn, "Using an older server list".into()),
        _ if connected => (Tone::Good, "Connected".into()),
        _ => (Tone::Good, "Server list up to date".into()),
    }
}

/// A catalogue's publication date ([`crate::catalog::set_published`], epoch seconds), e.g. "6 Aug 2026".
pub fn published_on(epoch_seconds: i64) -> String {
    chrono::DateTime::from_timestamp(epoch_seconds, 0).map_or_else(|| "an unknown date".into(), |t| t.format("%-d %b %Y").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(used: bool, refused: bool, setting_up: bool, blocked: bool, fresh: bool, connected: bool) -> Tone {
        provider_status("IVPN", used, refused, setting_up, blocked, fresh, connected, None, None).0
    }

    /// The most pressing reason wins: the user must act, then a passing issue, then good news; unused is grey.
    #[test]
    fn most_pressing_first() {
        assert_eq!(Tone::Bad, tone(true, true, true, true, false, false));
        assert_eq!(Tone::Bad, tone(false, true, false, false, true, false));
        assert_eq!(Tone::Idle, tone(false, false, false, false, false, false));
        assert_eq!(Tone::Warn, tone(true, false, true, false, true, true));
        assert_eq!(Tone::Warn, tone(true, false, false, true, true, false));
        assert_eq!(Tone::Warn, tone(true, false, false, false, false, true));
        assert_eq!(Tone::Good, tone(true, false, false, false, true, true));
        assert_eq!(Tone::Good, tone(true, false, false, false, true, false));
        assert_eq!("Setting up your key", provider_status("IVPN", true, false, true, false, true, true, None, None).1);
    }

    /// A route that keeps dropping is a passing issue: below a refusal or blocked routes, above an old list.
    #[test]
    fn dropping_warns() {
        let d = "Netherlands keeps dropping. Proton VPN Free may be over its connection limit.";
        assert_eq!((Tone::Warn, d.to_string()), provider_status("Proton VPN Free", true, false, false, false, false, true, Some(d), None));
        assert_eq!(Tone::Bad, provider_status("Proton VPN Free", true, true, false, false, true, true, Some(d), None).0);
        assert_eq!(Tone::Good, provider_status("Proton VPN Free", true, false, false, false, true, true, None, None).0);
    }

    /// A provider's only server list published long ago warns, after a dropping route, with its date.
    #[test]
    fn old_list_warns() {
        assert_eq!(
            (Tone::Warn, "Its server list is from 6 Aug 2026 and may be out of date".to_string()),
            provider_status("Proton VPN Free", true, false, false, false, true, true, None, Some("6 Aug 2026"))
        );
        assert_eq!("6 Aug 2026", published_on(1785990858));
        assert_eq!("an unknown date", published_on(i64::MAX));
    }
}
