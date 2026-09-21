//! Core of the runtime: app ids, data directory resolution and (in later tasks) the environment store,
//! install/run services and the compatibility-backend seam.
//!
//! Everything derived from a file or a user argument is untrusted. The types here are the validation boundary:
//! an [`AppId`] that exists is safe to use as a single path component.
pub mod dirs;
pub mod id;

pub use dirs::{DirsError, apps_dir, apps_dir_from, data_root, data_root_from};
pub use id::{AppId, IdError};
