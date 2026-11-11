//! Settings: what its rows say.

use crate::APP;

/// The Tailscale row while Tailscale is off.
const IDLE: &str = "Reach your tailnet from every app";

/// The Tailscale row's line: off, waiting for the connection, or what the tailnet says of itself.
pub fn tailscale_sub(enabled: bool, connected: bool, state: Option<&str>) -> String {
    match state {
        _ if !enabled => IDLE.into(),
        _ if !connected => format!("Connects with {APP}"),
        Some("NeedsLogin") => "Sign-in needed".into(),
        Some("NeedsMachineAuth") => "Waiting for approval in the Tailscale admin console".into(),
        Some("InUseOtherUser") => "In use by another user on this device".into(),
        None | Some("" | "Starting" | "NoState") => "Starting".into(),
        Some("Running") => "Connected".into(),
        Some("Stopped") => "Stopped".into(),
        _ => IDLE.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tailscale's states read as what they are; no status yet while connected is starting, not idle.
    #[test]
    fn tailscale_status_text() {
        assert_eq!("Starting", tailscale_sub(true, true, None));
        assert_eq!("Starting", tailscale_sub(true, true, Some("")));
        assert_eq!("In use by another user on this device", tailscale_sub(true, true, Some("InUseOtherUser")));
        assert_eq!("Sign-in needed", tailscale_sub(true, true, Some("NeedsLogin")));
        assert_eq!("Connected", tailscale_sub(true, true, Some("Running")));
        assert_eq!("Connects with unbraid", tailscale_sub(true, false, None));
    }
}
