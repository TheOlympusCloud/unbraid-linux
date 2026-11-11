//! Starting at login, through the XDG autostart folder.

use crate::error::Result;
use crate::{apps, paths};
use std::fs;
use std::path::PathBuf;

/// Starting and connecting at login (an XDG autostart entry), as Android's Always-on VPN starts the app at boot. It
/// connects once the user has logged in, as Android does after the first unlock.
pub struct Autostart {
    file: PathBuf,
}

impl Autostart {
    /// The user's entry, in $XDG_CONFIG_HOME/autostart.
    pub fn user() -> Self {
        let config = paths::env("XDG_CONFIG_HOME").map_or_else(|| paths::home().join(".config"), PathBuf::from);
        Autostart { file: config.join("autostart/unbraid.desktop") }
    }

    pub fn enabled(&self) -> bool {
        self.file.is_file()
            && fs::read_to_string(&self.file).is_ok_and(|text| {
                let e = apps::parse(&text);
                e.get("Hidden").map(String::as_str) != Some("true") && e.get("X-GNOME-Autostart-enabled").map(String::as_str) != Some("false")
            })
    }

    fn exec(&self) -> Option<String> {
        apps::parse(&fs::read_to_string(&self.file).ok()?).remove("Exec")
    }

    /// Started at login, it connects (as it always did before these were choices).
    pub fn connects(&self) -> bool {
        self.exec().is_none_or(|e| e.contains("--connect"))
    }

    /// Started at login, it stays in the tray, without a window.
    pub fn minimised(&self) -> bool {
        self.exec().is_none_or(|e| e.contains("--background"))
    }

    /// Turns it on or off; a choice left out (none) stays as it is.
    pub fn set(&self, on: bool, connect: Option<bool>, minimised: Option<bool>) -> Result<()> {
        let connect = connect.unwrap_or_else(|| self.connects());
        let minimised = minimised.unwrap_or_else(|| self.minimised());
        if !on {
            let _ = fs::remove_file(&self.file);
            return Ok(());
        }
        if let Some(dir) = self.file.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let exec = format!("unbraid{}{}", if minimised { " --background" } else { "" }, if connect { " --connect" } else { "" });
        fs::write(&self.file, format!("[Desktop Entry]\nType=Application\nName=unbraid\nComment=Starts unbraid at login\nExec={exec}\nIcon=unbraid\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Starting at login, with or without connecting and with or without the window; a change keeps the other choice.
    #[test]
    fn autostart_choices() {
        let tmp = tempfile::tempdir().unwrap();
        let a = Autostart { file: tmp.path().join("autostart/unbraid.desktop") };
        a.set(false, None, None).unwrap();
        a.set(true, Some(false), Some(true)).unwrap();
        assert!(a.enabled() && !a.connects() && a.minimised());
        a.set(true, Some(true), Some(false)).unwrap();
        assert!(a.connects() && !a.minimised());
        a.set(true, None, Some(true)).unwrap();
        assert!(a.connects() && a.minimised());
        a.set(false, None, None).unwrap();
        assert!(!a.enabled());
    }
}
