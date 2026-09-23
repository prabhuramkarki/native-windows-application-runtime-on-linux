//! `.desktop` generation, icon extraction, and MIME/file-association for Phase 3's installed apps.
//!
//! [`icon`] extracts a PE's own icon as PNG bytes (Task 3). [`entry`] turns that, plus an app's `Metadata`, into
//! a real `~/.local/share/applications/runtime-<id>.desktop` launcher and its hicolor icon files, and can remove
//! them again (Task 7). [`mime`] registers `runtime` as a handler for `.exe`/`.msi` files, so a file manager's
//! "Open With"/double-click can hand a Windows installer straight to `runtime install` (Task 7).
//!
//! **Scope boundary (binding, Task 7's own ruling).** `.desktop` generation is wired ONLY into
//! `installer::pipeline`'s `.msi`/`.exe` installer path (Phase 3 Task 6, `crates/installer/src/pipeline.rs`).
//! Phase 2's plain portable-exe/zip `rt_core::install` path predates this plan and is deliberately left
//! untouched: installing a portable `.exe` or a `.zip` today does not create a `.desktop` entry. This is a
//! known, documented gap, not an oversight — extending it to Phase 2 installs is out of this task's scope.
pub mod entry;
pub mod icon;
pub mod mime;
pub(crate) mod xdg;

#[cfg(test)]
pub(crate) mod testutil;
