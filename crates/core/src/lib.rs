//! Core of the runtime: app ids, data directory resolution, Windows path handling and (in later tasks) the
//! environment store, install/run services and the compatibility-backend seam.
//!
//! Everything derived from a file or a user argument is untrusted. The types here are the validation boundary:
//! an [`AppId`] that exists is safe to use as a single path component.
pub mod backend;
pub mod dirs;
#[cfg(any(test, feature = "testing"))]
pub mod fake;
pub mod id;
pub mod launch;
pub mod meta;
pub mod proc;
pub mod store;
pub mod winpath;

pub use backend::{BackendError, CompatBackend, Detail, RunOpts, allowed_env};
pub use dirs::{DirsError, apps_dir, apps_dir_from, data_root, data_root_from};
#[cfg(any(test, feature = "testing"))]
pub use fake::{Call, FakeBackend};
pub use id::{AppId, IdError};
pub use launch::{Finished, LaunchError, Launcher, LogSink, Running};
pub use meta::{BackendInfo, MetaError, Metadata};
pub use proc::{HelperOutput, RunError};
pub use store::{AppEnv, ListEntry, Store, StoreError, StoreWarn, unique_id};
pub use winpath::{ResolveError, WinPath, WinPathError, join_new, resolve_under};
