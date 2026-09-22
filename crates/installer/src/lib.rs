//! Installer-family detection and the silent-flag matrix (Phase 3 Task 1).
//!
//! Pure logic only: no file I/O, no subprocess spawning. [`plan`] decides which flags a caller
//! should pass to run an installer, silent or not; it never runs anything itself.

mod family;

pub use family::{InstallerFamily, PlanError, Program, RunPlan, SilentFlags, plan, silent_flags};
