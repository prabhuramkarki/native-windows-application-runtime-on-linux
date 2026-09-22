//! `.desktop` generation, icon extraction, and MIME/file-association for Phase 3's installed apps.
//!
//! Only [`icon`] exists yet (Task 3); `entry` (`.desktop` file generation) and `mime` (`.exe`/`.msi`
//! association) are later tasks in the same plan.
pub mod icon;
