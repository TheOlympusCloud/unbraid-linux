//! What can go wrong, as the earlier app's exceptions said it: the kind decides what the window shows.

use crate::providers::Field;
use indexmap::IndexMap;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    /// Credentials were refused; the user must sign in again. `url`: where the user can fix it (a device list, say).
    #[error("{message}")]
    Auth { message: String, url: Option<String> },
    /// A sign-in needs one more answer (a two-factor code, a captcha's characters), asked with `field`; the same sign-in
    /// is then sent again with it and the hidden `keep` values.
    #[error("{message}")]
    Challenge { message: String, field: Field, image: Option<Vec<u8>>, keep: IndexMap<String, String> },
    /// The provider's list was read and no longer has a pinned server: final, so no older copy of it is used instead.
    #[error("{0} is no longer offered. Pick another server")]
    NoLongerOffered(String),
    /// A failure with a message meant for the user ([`crate::redact`] keeps secrets out of it).
    #[error("{0}")]
    Fail(String),
    /// An HTTP answer other than 2xx.
    #[error("HTTP {code}")]
    Status { code: u16 },
    /// The network or a file: couldn't reach, read or write.
    #[error("{0}")]
    Io(String),
    /// Input that can't be used (Kotlin's IllegalArgumentException).
    #[error("{0}")]
    Invalid(String),
    /// A state that doesn't allow it (Kotlin's IllegalStateException).
    #[error("{0}")]
    State(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
