//! [`ApiError`]: what every method returns on failure. `kind` is the machine-readable part (the daemon maps it
//! to JSON-RPC `data.kind`); `message` is for people and is sanitised and bounded like every other string.
//!
//! | kind               | serialised         | meaning                                                             |
//! |--------------------|--------------------|---------------------------------------------------------------------|
//! | `NotFound`         | `not_found`        | a well-formed id names no installed app                             |
//! | `InvalidArgument`  | `invalid_argument` | the caller's argument is malformed (an id that is not an `AppId`)   |
//! | `Unavailable`      | `unavailable`      | the request is fine but the host cannot answer: no data directory,  |
//! |                    |                    | unreadable/corrupt app metadata, an invalid, oversized, symlinked   |
//! |                    |                    | or unreadable `permissions.toml` (never a silent default)           |
//! | `ReadOnly`         | `read_only`        | a write method on a daemon started without `--write`                |
//! | `ConsentMismatch`  | `consent_mismatch` | `deps.install`: the plan changed since it was shown, or a consent   |
//! |                    |                    | item is not exactly a consent-gated package of it                   |
//! | `Busy`             | `busy`             | the daemon already runs its maximum of jobs                         |
//! | `AppBusy`          | `app_busy`         | a job for this app is still live                                    |
//! | `Unknown`          | (any other string) | deserialisation fallback for a newer daemon's kind; never produced here |
//! | `Internal`         | `internal`         | a bug: reserved for the daemon's catch-all (panic, serialisation)   |
//!
//! `ApiError` and `ErrorKind` are `#[non_exhaustive]`: downstream crates build an error with [`ApiError::new`]
//! (kind + message, message cleaned) and match `ErrorKind` with a wildcard arm; nothing else is needed.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorKind {
    NotFound,
    InvalidArgument,
    Unavailable,
    Internal,
    ReadOnly,
    ConsentMismatch,
    Busy,
    AppBusy,
    /// A kind this client does not know (a newer daemon's): deserialisation never fails on it.
    #[serde(other)]
    Unknown,
}

impl ErrorKind {
    /// Every kind this crate or the daemon produces (all but [`ErrorKind::Unknown`]), for documentation checks.
    pub const ALL: &'static [ErrorKind] = &[
        ErrorKind::NotFound,
        ErrorKind::InvalidArgument,
        ErrorKind::Unavailable,
        ErrorKind::Internal,
        ErrorKind::ReadOnly,
        ErrorKind::ConsentMismatch,
        ErrorKind::Busy,
        ErrorKind::AppBusy,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
#[error("{kind:?}: {message}")]
pub struct ApiError {
    pub kind: ErrorKind,
    pub message: String,
}

/// Longest message kept (error text can quote file content).
const MAX_MESSAGE: usize = 512;

impl ApiError {
    pub fn new(kind: ErrorKind, message: impl AsRef<str>) -> ApiError {
        ApiError {
            kind,
            message: rt_core::clean_text(message.as_ref(), MAX_MESSAGE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`ErrorKind::ALL`] lists every kind but `Unknown`: a new variant does not compile here until it is placed.
    #[test]
    fn all_lists_every_produced_kind() {
        let listed = |k: ErrorKind| match k {
            ErrorKind::NotFound
            | ErrorKind::InvalidArgument
            | ErrorKind::Unavailable
            | ErrorKind::Internal
            | ErrorKind::ReadOnly
            | ErrorKind::ConsentMismatch
            | ErrorKind::Busy
            | ErrorKind::AppBusy => true,
            ErrorKind::Unknown => false,
        };
        assert!(ErrorKind::ALL.iter().all(|k| listed(*k)));
        // Each listed variant once: 8 arms above say true.
        let mut names: Vec<String> = ErrorKind::ALL.iter().map(|k| format!("{k:?}")).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8);
        assert_eq!(ErrorKind::ALL.len(), 8);
    }
}
