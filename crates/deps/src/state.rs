//! Per-app dependency state: which packages the runtime installed for an app, and the consent it recorded.
//!
//! The only source of truth is [`Metadata::dependencies`]. These helpers read and edit that list and nothing
//! else: installed state is never inferred from files in the prefix (a file there may come from the app, its
//! installer or the user, and proves nothing about which verified package version put it there). Callers persist
//! changes with [`Metadata::write_atomic`], which validates them.

use crate::resolve::{InstalledRef, InstalledSet};
use rt_core::{ConsentRecord, DependencyRecord, MAX_DEPENDENCIES, Metadata, SCHEMA_VERSION};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    #[error("an app may record at most {MAX_DEPENDENCIES} dependencies")]
    TooMany,
}

/// The recorded packages as the resolver's [`InstalledSet`] (id, version, sha256), in the recorded order.
pub fn installed_set(md: &Metadata) -> InstalledSet {
    InstalledSet(
        md.dependencies
            .iter()
            .map(|d| InstalledRef {
                id: d.id.clone(),
                version: d.version.clone(),
                sha256: d.sha256.clone(),
            })
            .collect(),
    )
}

/// Records `rec`, replacing any entry with the same id, and keeps the list sorted by id. Marks `md` as the current
/// schema, so an older binary that ignores `dependencies` refuses the file instead of silently dropping them.
/// Fails, leaving `md` unchanged, if a new id would exceed [`MAX_DEPENDENCIES`].
pub fn record(md: &mut Metadata, rec: DependencyRecord) -> Result<(), StateError> {
    if let Some(existing) = md.dependencies.iter_mut().find(|d| d.id == rec.id) {
        *existing = rec;
    } else if md.dependencies.len() >= MAX_DEPENDENCIES {
        return Err(StateError::TooMany);
    } else {
        md.dependencies.push(rec);
    }
    // Also sorts a hand-edited, unsorted list; at most `MAX_DEPENDENCIES` entries, so cheap.
    md.dependencies.sort_by(|a, b| a.id.cmp(&b.id));
    md.schema_version = SCHEMA_VERSION;
    Ok(())
}

/// Removes the record for `id`. Returns whether there was one.
pub fn forget(md: &mut Metadata, id: &str) -> bool {
    let before = md.dependencies.len();
    md.dependencies.retain(|d| d.id != id);
    md.dependencies.len() != before
}

/// The consent recorded for `id` at exactly `version` (consent is per package and per version, spec §4). `None`
/// if the package is not recorded, was recorded at a different version, or was recorded without consent.
///
/// Caller obligation (Task 7): a `Some` is not enough to skip the prompt. The caller must ALSO compare
/// `licence_text_sha256` with the hash of the licence text it is about to show; consent to different licence text
/// is not consent.
pub fn consent_of<'a>(md: &'a Metadata, id: &str, version: &str) -> Option<&'a ConsentRecord> {
    md.dependencies
        .iter()
        .find(|d| d.id == id && d.version == version)?
        .consent
        .as_ref()
}

#[cfg(test)]
mod tests;
