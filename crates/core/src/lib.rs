//! Core of the runtime: app ids, data directory resolution, Windows path handling and (in later tasks) the
//! environment store, install/run services and the compatibility-backend seam.
//!
//! Everything derived from a file or a user argument is untrusted. The types here are the validation boundary:
//! an [`AppId`] that exists is safe to use as a single path component.
pub mod backend;
pub mod cache;
pub mod dirs;
pub mod display;
pub mod doctor;
#[cfg(any(test, feature = "testing"))]
pub mod fake;
pub mod graphics;
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
pub mod unzip;
pub mod winpath;

pub use backend::{
    BACKEND_API_VERSION, BackendError, Capabilities, CompatBackend, Detail, RunOpts, Unsupported, allowed_env,
};
pub use cache::Cached;
pub use dirs::{DirsError, apps_dir, apps_dir_from, data_root, data_root_from};
pub use display::{DRIVERS_KEY, GraphicsDriver, driver_from_value};
#[cfg(any(test, feature = "testing"))]
pub use fake::{Call, FAKE_CAPABILITIES, FakeBackend};
pub use graphics::{
    HostVulkan, VulkanDevice, VulkanVerdict, host_verdict, judge, parse_vulkaninfo_summary, probe_host,
};
pub use id::{AppId, IdError};
pub use install::{INPUT_CAP, Input, InstallError, InstallOpts, InstallOutcome, install, read_input};
pub use launch::{Finished, LaunchError, Launcher, LogSink, Running, Sandbox};
pub use meta::{
    BackendInfo, ConsentRecord, DOTNET_PACKAGE_ID, DependencyRecord, InstallerMeta, MAX_DEPENDENCIES, MAX_FIELD_LEN,
    MAX_NAME_LEN, MAX_REQUESTED_DEPENDENCIES, MIN_SCHEMA_VERSION, MetaError, Metadata, PackageMeta,
    REQUESTABLE_PERMISSIONS, SCHEMA_VERSION,
};
/// The PE model the backend contract speaks ([`Capabilities`]), for backends that do not depend on it directly.
pub use pe;
pub use proc::{HelperOutput, RunError};
pub use run::{
    ResolvedProgram, RunAppError, RunOptions, RunOutcome, Started, Target, TargetKind, classify, exit_code,
    find_target, resolve_program, run, start,
};
pub use store::{AppEnv, ListEntry, Store, StoreError, StoreWarn, unique_id};
pub use text::{clean as clean_text, is_format};
pub use unzip::{NameError, ZipError};
pub use winpath::{ResolveError, WinPath, WinPathError, join_new, resolve_under};
