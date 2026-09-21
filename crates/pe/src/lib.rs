//! Header-based analysis of Windows binaries. Never trusts file extensions.
mod detect;
mod model;

pub use detect::{FileKind, detect};
pub use model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a PE file")]
    NotPe,
    #[error("malformed PE: {0}")]
    Malformed(String),
}
