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
//! | `Internal`         | `internal`         | a bug: reserved for the daemon's catch-all (panic, serialisation)   |
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    NotFound,
    InvalidArgument,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
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
