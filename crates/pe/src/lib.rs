//! Header-based analysis of Windows binaries. Never trusts file extensions.
mod analyze;
mod detect;
mod icon;
mod installer;
mod model;
mod version;

pub use analyze::analyze;
pub use detect::{FileKind, detect};
pub use icon::{GroupIconEntry, find_group_icon, icon_bytes};
pub use model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a PE file")]
    NotPe,
    #[error("malformed PE: {0}")]
    Malformed(String),
}
