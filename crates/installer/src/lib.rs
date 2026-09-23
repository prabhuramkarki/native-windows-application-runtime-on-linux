//! Installer-family detection and the silent-flag matrix (Phase 3 Task 1).
//!
//! Pure logic only: no file I/O, no subprocess spawning. [`plan`] decides which flags a caller
//! should pass to run an installer, silent or not; it never runs anything itself.

mod discover;
mod family;
mod lnk;
mod msi;
mod pipeline;
mod reg;
mod sandbox;
mod snapshot;
mod uninstall;

pub use discover::{Candidate, RankResult, rank};
pub use family::{InstallerFamily, PlanError, Program, RunPlan, SilentFlags, plan, silent_flags};
pub use lnk::{LnkError, ShellLink};
pub use msi::{MsiError, MsiInfo};
pub use pipeline::{
    INPUT_CAP, InstallOutcome, InstallerError, InstallerOpts, install_via_installer, looks_like_installer,
};
pub use reg::{RegError, RegKey, RegValue, WineReg};
pub use sandbox::{InstallerSandbox, RO_BINDS, SandboxOpts, find_bwrap, find_bwrap_on_path};
pub use snapshot::{InstallDiff, Snapshot, UninstallEntry};
pub use uninstall::{UninstallOutcome, uninstall};
