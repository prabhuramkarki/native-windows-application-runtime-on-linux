//! The `.wrun` v1 package format: one zip file holding a strict TOML manifest (`wrun.toml`, the first entry) and a
//! `payload/` tree, with the size and sha256 of every payload file in the manifest.
//!
//! **A `.wrun` is hostile input.** It is read only through the hardened zip planner ([`rt_core::unzip`], the
//! production [`Limits`] of `install`) plus the package rules below, and nothing is written before the whole
//! container and manifest are validated:
//!
//! * the first central-directory entry is the file `wrun.toml` (at most 64 KiB); every other entry is below
//!   `payload/`; `wrun.sig` is reserved for signed packages and refused in v1 ([`PackageError::Signed`]);
//! * names are UTF-8, use `/` only (no `\`) and are canonical (no `.` components, no empty ones); every other name
//!   rule is `unzip`'s;
//! * entries `unzip` would skip (symlink, device, FIFO, socket) are refused, not skipped;
//! * the manifest's `[[files]]` equals exactly the set of payload files with their declared sizes, and each file's
//!   bytes are hashed while streaming ([`Package::verify`], [`Package::unpack`], [`Package::extract_one`]).
//!
//! The **package digest** is the sha256 of the raw `wrun.toml` bytes: it covers every file hash, and it is what a
//! future signature will sign. v1 packages are unsigned: their origin is not verified.
//!
//! Every string taken from a package reaches an error message only through [`rt_core::clean_text`], bounded.
mod manifest;
mod read;
mod write;

pub use manifest::{
    Entry, FORMAT, FileRef, MAX_DEPENDENCIES, MAX_ICON_BYTES, MAX_MANIFEST_BYTES, Manifest, Requests, parse_manifest,
};
pub use read::{Package, open};
pub use rt_core::unzip::Limits;
pub use write::pack;

use std::io;

/// The name of the manifest entry.
pub const MANIFEST_NAME: &str = "wrun.toml";
/// Reserved for the signature of a future format revision; refused in v1.
pub const SIGNATURE_NAME: &str = "wrun.sig";
/// Every payload path starts with this.
pub const PAYLOAD_PREFIX: &str = "payload/";

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("{0}")]
    Zip(#[from] rt_core::ZipError),
    #[error("invalid wrun.toml: {0}")]
    Manifest(String),
    #[error("not a valid .wrun package: {0}")]
    Layout(String),
    #[error("payload file {path} does not match the manifest (size or sha256): the package was modified or damaged")]
    Integrity { path: String },
    #[error("this package is signed (wrun.sig): signed packages need a newer runtime")]
    Signed,
    #[error("cannot {what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

/// An untrusted string for an error message: cleaned, bounded, quoted.
pub(crate) fn shown(s: &str) -> String {
    format!("\"{}\"", rt_core::clean_text(s, 120))
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// Lowercase hex, as the manifest writes digests.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)] as char, HEX[usize::from(b & 15)] as char])
        .collect()
}

#[cfg(test)]
mod tests;
