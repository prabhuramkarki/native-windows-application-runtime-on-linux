//! Minimal RT_GROUP_ICON (type 14) / RT_ICON (type 3) resource access.
//!
//! `rt_desktop::icon` (Phase 3) needs to find a PE's icon-group directory and read its member
//! RT_ICON entries by id; nothing in `analyze.rs`/`model.rs` exposed that (the only existing
//! resource consumer, `version.rs`, reads RT_VERSION), so this is a small, self-contained addition
//! rather than a change to either.
//!
//! Bytes are untrusted (the PE is a hostile installer's own `.exe`). Two things carry over from
//! `analyze.rs`'s hazards (see `docs/THIRD_PARTY.md`'s `pelite` row): the same 8-byte alignment
//! copy pelite needs before it may be handed a buffer, and the same `res_rva % 4` guard before
//! calling `resources()` (a misaligned resource directory RVA makes pelite dereference a
//! misaligned reference, UB caught as SIGABRT in debug builds). Past that guard, the directory
//! walk (`Resources::root`/`get_dir`/`first_dir`/`first_data`) and `GroupResource::new` are
//! pelite's own bounds-checked code: every offset is checked against the section length before
//! use and every count is validated against the bytes actually available (see `group.rs` in the
//! vendored source), unlike the version-info TLV walker `version.rs` had to replace. So this
//! module does not need its own hand-rolled structure reader the way `version.rs` did — it is a
//! thin, reviewed wrapper around pelite's existing group/icon API, not a new parser.
//!
//! Nothing here decodes pixel data: `icon_bytes` returns the raw RT_ICON resource bytes (a DIB or
//! a PNG stream) exactly as stored; decoding and bounding pixel dimensions is `rt_desktop::icon`'s
//! job, on data it must treat as hostile regardless of where it came from.
use crate::analyze::{Aligned, check_layout};
use crate::{Error, FileKind, detect};
use pelite::PeFile;
use pelite::resources::{FindError, Name, Resources};

/// One RT_ICON member named by an RT_GROUP_ICON directory: which RT_ICON resource id it points at,
/// and the declared size/depth used to pick the best match for a requested pixel size. Per the ICO
/// format, a declared width or height of 0 means 256 (the largest size ICO can express in one
/// byte), so both are normalised to `256` here rather than handed on as a misleading `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupIconEntry {
    pub id: u16,
    pub width: u16,
    pub height: u16,
    pub bit_count: u16,
}

/// Reads the first RT_GROUP_ICON resource's entry list. `Ok(None)`: the image has no icon resource
/// at all (RT_GROUP_ICON absent, or no resource directory whatsoever) — a normal, common case, not
/// an error. `Err`: the bytes are not a readable PE, or the resource directory itself is corrupt.
///
/// Only the first group is read (real executables built by one linker invocation carry exactly
/// one `IDI_ICON1`-style group; a multi-icon-group image, rare and not something `windres`
/// produces, would need a name/id to disambiguate that nothing here has a use for yet).
pub fn find_group_icon(bytes: &[u8]) -> Result<Option<Vec<GroupIconEntry>>, Error> {
    with_resources(bytes, |res| -> Result<Option<Vec<GroupIconEntry>>, Error> {
        let dir = match res
            .root()
            .map_err(FindError::Pe)
            .and_then(|r| r.get_dir(Name::GROUP_ICON))
        {
            Ok(d) => d,
            Err(FindError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Malformed(format!("group icon directory: {e}"))),
        };
        let group_dir = match dir.first_dir() {
            Ok(d) => d,
            Err(FindError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Malformed(format!("group icon directory: {e}"))),
        };
        let data = match group_dir.first_data() {
            Ok(d) => d,
            Err(FindError::NotFound) => return Ok(None),
            Err(e) => return Err(Error::Malformed(format!("group icon directory: {e}"))),
        };
        let raw = data
            .bytes()
            .map_err(|e| Error::Malformed(format!("group icon data: {e}")))?;
        let group = pelite::resources::group::GroupResource::new(res, raw)
            .map_err(|e| Error::Malformed(format!("group icon header: {e}")))?;
        let norm = |v: u8| if v == 0 { 256 } else { u16::from(v) };
        Ok(Some(
            group
                .entries()
                .iter()
                .map(|e| GroupIconEntry {
                    id: e.nId,
                    width: norm(e.bWidth),
                    height: norm(e.bHeight),
                    bit_count: e.wBitCount,
                })
                .collect(),
        ))
    })?
    .unwrap_or(Ok(None))
}

/// Reads the raw RT_ICON resource bytes for one member id of a group icon (an ICO "image" entry:
/// either an uncompressed DIB or, commonly for a 256x256 entry, a raw PNG stream — `rt_desktop`
/// tells them apart by magic bytes). `Ok(None)`: no RT_ICON with that id (also covers "no resource
/// directory at all"). Bounded by the resource directory's own declared sizes only; the caller is
/// responsible for bounding whatever it decodes from the returned bytes.
pub fn icon_bytes(bytes: &[u8], id: u16) -> Result<Option<Vec<u8>>, Error> {
    with_resources(bytes, |res| -> Result<Option<Vec<u8>>, Error> {
        let found = res
            .root()
            .map_err(FindError::Pe)
            .and_then(|r| r.get_dir(Name::Id(u32::from(pelite::image::RT_ICON))))
            .and_then(|d| d.get_dir(Name::Id(u32::from(id))))
            .and_then(|d| d.first_data())
            .and_then(|d| d.bytes().map_err(FindError::Pe));
        match found {
            Ok(b) => Ok(Some(b.to_vec())),
            Err(FindError::NotFound) => Ok(None),
            Err(e) => Err(Error::Malformed(format!("icon data (id {id}): {e}"))),
        }
    })?
    .unwrap_or(Ok(None))
}

/// Aligns `bytes` if needed, opens it as a PE, checks the same layout hazards `analyze()` does,
/// and hands the resource directory to `f` — all within this call, so the aligned copy (when one
/// is needed) stays alive for exactly as long as `f` borrows from it. `Ok(None)`: the image has no
/// resource directory at all. `Err`: not a readable PE, or the resource directory RVA/header is
/// corrupt.
fn with_resources<R>(bytes: &[u8], f: impl FnOnce(Resources<'_>) -> R) -> Result<Option<R>, Error> {
    if detect(bytes) != FileKind::Pe {
        return Err(Error::NotPe);
    }
    let copy;
    let bytes = if bytes.as_ptr().align_offset(8) == 0 {
        bytes
    } else {
        copy = Aligned::new(bytes);
        copy.bytes()
    };
    let file = PeFile::from_bytes(bytes).map_err(|e| Error::Malformed(e.to_string()))?;
    check_layout(&file)?;
    // Index 2 = IMAGE_DIRECTORY_ENTRY_RESOURCE, same constant as analyze.rs's DIR_RESOURCE.
    let res_rva = file.data_directory().get(2).map_or(0, |d| d.VirtualAddress);
    if res_rva == 0 {
        return Ok(None);
    }
    if res_rva % 4 != 0 {
        return Err(Error::Malformed(format!(
            "resources: directory RVA {res_rva:#x} is not 4-byte aligned"
        )));
    }
    match file.resources() {
        Ok(res) => Ok(Some(f(res))),
        Err(pelite::Error::Null) => Ok(None),
        Err(e) => Err(Error::Malformed(format!("resources: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_a_pe_is_an_error() {
        assert!(matches!(find_group_icon(b"not a pe"), Err(Error::NotPe)));
        assert!(matches!(icon_bytes(b"not a pe", 1), Err(Error::NotPe)));
    }

    #[test]
    fn truncated_pe_never_panics() {
        // A truncated MZ/PE stub: `detect` may say Pe or not depending on how much of the header
        // survives; either way this must return cleanly.
        for n in 0..64 {
            let mut b = vec![0u8; n];
            if n >= 2 {
                b[0..2].copy_from_slice(b"MZ");
            }
            let _ = find_group_icon(&b);
            let _ = icon_bytes(&b, 1);
        }
    }
}
