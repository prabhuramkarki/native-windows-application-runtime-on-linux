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
pub mod install;
pub mod launch;
pub mod meta;
pub mod proc;
pub mod run;
pub mod store;
#[cfg(test)]
pub(crate) mod testutil;
pub(crate) mod text;
pub(crate) mod unzip;
pub mod winpath;

pub use backend::{BackendError, CompatBackend, Detail, RunOpts, allowed_env};
pub use dirs::{DirsError, apps_dir, apps_dir_from, data_root, data_root_from};
#[cfg(any(test, feature = "testing"))]
pub use fake::{Call, FakeBackend};
pub use id::{AppId, IdError};
pub use install::{InstallError, InstallOpts, InstallOutcome, install};
pub use launch::{Finished, LaunchError, Launcher, LogSink, Running};
pub use meta::{BackendInfo, MetaError, Metadata};
pub use proc::{HelperOutput, RunError};
pub use run::{RunAppError, RunOptions, RunOutcome, Started, TargetKind, classify, exit_code, run, start};
pub use store::{AppEnv, ListEntry, Store, StoreError, StoreWarn, unique_id};
pub use unzip::{NameError, ZipError};
pub use winpath::{ResolveError, WinPath, WinPathError, join_new, resolve_under};
