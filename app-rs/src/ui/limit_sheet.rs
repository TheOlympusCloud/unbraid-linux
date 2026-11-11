//! Asked before a route change goes over a provider's connection limit: nothing changes until the user answers.

/// The question: what the change would do ([`crate::limits::warning`]), and, when one of that provider's routes is
/// already on a server, the offer to put both routes on it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LimitSheetView {
    pub text: String,
    /// "Use nl1234 for both routes"; empty without a server to share.
    pub share: String,
}

/// The sheet for the change `text` describes; `server` is the one both routes could share.
pub fn view(text: &str, server: Option<&str>) -> LimitSheetView {
    LimitSheetView { text: text.into(), share: server.map(|s| format!("Use {s} for both routes")).unwrap_or_default() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The warning as written, and the offer only with a server to share.
    #[test]
    fn question_and_offer() {
        let text = crate::limits::warning("NordVPN", 10, "connection", 11);
        assert_eq!(LimitSheetView { text: text.clone(), share: "Use nl1256 for both routes".into() }, view(&text, Some("nl1256")));
        assert_eq!("", view(&text, None).share);
    }
}
