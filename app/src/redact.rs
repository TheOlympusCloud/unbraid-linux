//! Failures with messages meant for people, and keys and passwords kept out of them.
//!
//! Engine and library errors can quote the configuration they choked on, private keys included. Nothing from them
//! reaches the log or the screen without passing through here.

use crate::error::Error;
use regex::Regex;
use std::sync::LazyLock;

// The value: a quoted string (spaces and all) or, unquoted, up to the next blank. Quoted values may contain escaped
// quotes. Blanks are the ASCII ones only, so a value runs on through any other space character.
static SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(private_?key|pre_?shared_?key|auth_?key|password|secret|token)["']?[[:space:]]*[:=][[:space:]]*("(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|[^[:space:]]*)"#).unwrap()
});
static BLOB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_-]{40,}={0,2}").unwrap());
/// The longest a cleaned text gets, in UTF-16 units.
const MAX: usize = 160;

pub fn clean(s: &str) -> String {
    let s = SECRET.replace_all(s, "[hidden]");
    let s = BLOB.replace_all(&s, "[hidden]").replace('\n', " ");
    let mut units = 0;
    s.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= MAX
        })
        .collect()
}

/// What to tell the user: our own messages (cleaned), else a fixed text for the failure class.
pub fn message(e: &(dyn std::error::Error + 'static), fallback: &str) -> String {
    let own = || {
        let m = clean(&e.to_string());
        if m.trim().is_empty() { fallback.into() } else { m }
    };
    match e.downcast_ref::<Error>() {
        Some(Error::Auth { .. } | Error::Fail(_) | Error::NoLongerOffered(_)) => own(),
        None if e.is::<serde_json::Error>() => fallback.into(),
        Some(Error::Invalid(_) | Error::State(_)) => own(),
        Some(Error::Challenge(_) | Error::Status { .. } | Error::Io(_)) => {
            "Couldn't reach the server. Check the connection.".into()
        }
        None if e.is::<std::io::Error>() => "Couldn't reach the server. Check the connection.".into(),
        None => fallback.into(),
    }
}

/// One safe line for the log.
pub fn log(e: &(dyn std::error::Error + 'static)) -> String {
    let kind = match e.downcast_ref::<Error>() {
        Some(Error::Auth { .. }) => "Auth",
        Some(Error::Challenge(_)) => "Challenge",
        Some(Error::NoLongerOffered(_)) => "NoLongerOffered",
        Some(Error::Fail(_)) => "Fail",
        Some(Error::Status { .. }) => "Status",
        Some(Error::Io(_)) => "Io",
        Some(Error::Invalid(_)) => "Invalid",
        Some(Error::State(_)) => "State",
        None => "Error",
    };
    format!("{kind}: {}", clean(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tMTI=";

    #[test]
    fn keys_and_config_fragments_are_removed() {
        let raw = format!(
            "decode config: {{\"type\":\"wireguard\",\"private_key\":\"{KEY}\",\"peers\":[{{\"public_key\":\"{KEY}\"}}]}} password=hunter2"
        );
        let out = clean(&raw);
        assert!(!out.contains(KEY));
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("private_key\":\"a"));
        assert!(out.starts_with("decode config"));
    }

    #[test]
    fn quoted_secrets_go_whole() {
        let out = clean("auth failed: password=\"alpha beta gamma\" for user x");
        assert!(!out.contains("beta"));
        assert!(!out.contains("gamma"));
        assert!(out.ends_with("for user x"));
    }

    #[test]
    fn escaped_quotes_dont_end_the_secret() {
        let out = clean("bad: password=\"alpha\\\"bravo\\\\charlie\" ok");
        assert!(!out.contains("bravo"));
        assert!(!out.contains("charlie"));
        assert!(out.ends_with(" ok"));
    }

    #[test]
    fn long_blobs_go_but_ordinary_words_stay() {
        assert_eq!("[hidden]", clean(&"a".repeat(40)));
        assert_eq!("Sign in to Mullvad for Sweden", clean("Sign in to Mullvad for Sweden"));
    }

    #[test]
    fn output_is_short_and_single_line() {
        let out = clean(&format!("line one\nline two {}", "word ".repeat(100)));
        assert!(out.encode_utf16().count() <= 160);
        assert!(!out.contains('\n'));
    }

    #[test]
    fn message_chooses_a_fixed_text_for_unknown_classes() {
        assert_eq!("Sign in to Nord", message(&Error::Auth { message: "Sign in to Nord".into(), url: None }, "x"));
        assert_eq!(
            "Netherlands: de1 is unreachable",
            message(&Error::Fail("Netherlands: de1 is unreachable".into()), "x")
        );
        assert_eq!(
            "Invalid WireGuard key for Sweden",
            message(&Error::Invalid("Invalid WireGuard key for Sweden".into()), "x")
        );
        let parse = <serde_json::Error as serde::de::Error>::custom(format!(
            "Unexpected JSON token near \"private_key\":\"{KEY}\""
        ));
        assert_eq!("fallback", message(&parse, "fallback"));
        let other: Box<dyn std::error::Error + Send + Sync> = format!("private_key={KEY}").into();
        assert_eq!("fallback", message(&*other, "fallback"));
        assert_eq!(
            "Couldn't reach the server. Check the connection.",
            message(&Error::Io(format!("GET https://x/?token={KEY}")), "fallback")
        );
    }
}
