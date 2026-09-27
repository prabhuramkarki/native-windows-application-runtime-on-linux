//! The runtime as a typed API: what a front end (the `runtimed` daemon, a GUI) may ask, and the sanitised,
//! serialisable answers. No method changes anything on disk (a change is a [`jobs::JobSpec`]: the daemon runs the
//! `runtime` CLI with its validated argv); the only processes any method starts are the bounded host probes of
//! [`methods`] (`vulkaninfo`, bwrap's probe, the `systemd-run` scope probe, `wine --version`). [`host`] is the gathering code those methods share with the CLI (not a stable API).
//!
//! Everything read from an app's directory is untrusted, so every free-text field in [`types`] is cleaned at the
//! boundary (control and format characters removed, length bounded) and ids are validated `AppId`s. Failures are
//! an [`ApiError`] whose [`ErrorKind`] is stable (see [`error`]).
pub mod backends;
pub mod compat;
pub mod error;
pub mod host;
pub mod jobs;
pub mod methods;
pub mod runtime;
pub mod types;

pub use error::{ApiError, ErrorKind};
pub use runtime::Runtime;
pub use types::*;

/// The version of this API (semver): bumped when a method or a wire type changes.
pub const API_VERSION: &str = "0.2.1";
/// The wire protocol the daemon speaks over its socket.
pub const PROTOCOL: &str = "jsonrpc-2.0-ndjson";
