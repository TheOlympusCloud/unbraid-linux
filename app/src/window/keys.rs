//! The window's keyboard shortcuts, as the shortcuts list (Ctrl+/) shows them.

use slint::platform::Key;

/// What a shortcut asks the window for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ask {
    /// A page, as an index into the sidebar's pages: Routes, Apps, Stats, Settings.
    Page(usize),
    /// Apps, with the focus in its search.
    Search,
    NewRoute,
    Shortcuts,
    /// Connect, or disconnect when connected.
    Connect,
    /// Pause 15 minutes, or resume a pause.
    Pause,
    Close,
    Quit,
}

/// What `key` (as the window gets it: the character, or one of Slint's [`Key`] codes) asks for with these modifiers;
/// none for a key the window leaves to what has the focus. Esc is never the window's: it closes the innermost open
/// thing, a dialog before the page behind it.
pub fn keys(key: &str, ctrl: bool, shift: bool, alt: bool) -> Option<Ask> {
    let mut chars = key.chars();
    let (Some(c), None) = (chars.next(), chars.next()) else { return None };
    if c == char::from(Key::F1) {
        return Some(Ask::Shortcuts);
    }
    if !ctrl || alt {
        return None;
    }
    let c = c.to_ascii_lowercase();
    if shift {
        return match c {
            'c' => Some(Ask::Connect),
            'p' => Some(Ask::Pause),
            _ => None,
        };
    }
    Some(match c {
        '1' => Ask::Page(0),
        '2' => Ask::Page(1),
        '3' => Ask::Page(2),
        ',' => Ask::Page(3),
        'f' => Ask::Search,
        'n' => Ask::NewRoute,
        'w' => Ask::Close,
        'q' => Ask::Quit,
        '/' => Ask::Shortcuts,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc() -> String {
        char::from(Key::Escape).into()
    }

    /// Every shortcut in the list reaches what it names; other keys, Esc and Alt combinations stay with the focus.
    #[test]
    fn the_shortcuts_list_is_what_the_keys_do() {
        assert_eq!(Some(Ask::Page(1)), keys("2", true, false, false));
        assert_eq!(Some(Ask::Page(3)), keys(",", true, false, false));
        assert_eq!(Some(Ask::Search), keys("f", true, false, false));
        assert_eq!(Some(Ask::Shortcuts), keys("/", true, false, false));
        assert_eq!(Some(Ask::Shortcuts), keys(&String::from(char::from(Key::F1)), false, false, false));
        assert_eq!(Some(Ask::NewRoute), keys("n", true, false, false));
        // Shift's capital, as the desktop sends it.
        assert_eq!(Some(Ask::Connect), keys("C", true, true, false));
        assert_eq!(Some(Ask::Pause), keys("p", true, true, false));
        assert_eq!(Some(Ask::Quit), keys("q", true, false, false));
        assert_eq!(Some(Ask::Close), keys("w", true, false, false));
        assert_eq!(None, keys(&esc(), false, false, false));
        assert_eq!(None, keys("z", true, false, false));
        assert_eq!(None, keys("2", false, false, false));
        assert_eq!(None, keys("2", true, false, true));
        assert_eq!(None, keys("n", true, true, false));
    }
}
