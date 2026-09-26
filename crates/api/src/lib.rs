//! The runtime as a typed, read-only API: what a front end (the `runtimed` daemon, a GUI) may ask, and the
//! sanitised, serialisable answers. No method changes anything on disk and none starts a process.
//!
//! Everything read from an app's directory is untrusted, so every free-text field in [`types`] is cleaned at the
//! boundary (control and format characters removed, length bounded) and ids are validated `AppId`s. Failures are
//! an [`ApiError`] whose [`ErrorKind`] is stable (see [`error`]).
pub mod compat;
pub mod error;
pub mod host;
pub mod runtime;
pub mod types;

pub use error::{ApiError, ErrorKind};
pub use runtime::Runtime;
pub use types::*;

/// The version of this API (semver): bumped when a method or a wire type changes.
pub const API_VERSION: &str = "0.1.0";
/// The wire protocol the daemon speaks over its socket.
pub const PROTOCOL: &str = "jsonrpc-2.0-ndjson";
