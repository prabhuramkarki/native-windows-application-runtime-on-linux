//! Core of the runtime: app ids, data directory resolution, Windows path handling and (in later tasks) the
//! environment store, install/run services and the compatibility-backend seam.
//!
//! Everything derived from a file or a user argument is untrusted. The types here are the validation boundary:
//! an [`AppId`] that exists is safe to use as a single path component.
pub mod dirs;
pub mod id;
pub mod meta;
pub mod store;
pub mod winpath;

pub use dirs::{DirsError, apps_dir, apps_dir_from, data_root, data_root_from};
pub use id::{AppId, IdError};
pub use meta::{BackendInfo, MetaError, Metadata};
pub use store::{AppEnv, ListEntry, Store, StoreError, StoreWarn, unique_id};
pub use winpath::{ResolveError, WinPath, WinPathError, join_new, resolve_under};
