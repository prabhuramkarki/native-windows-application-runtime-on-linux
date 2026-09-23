//! A bounded, panic-free `[MS-SHLLINK]` "Shell Link" (`.lnk`) reader.
//!
//! **Third-party crate spike (Task 3, Part A).** Tried `lnk 0.6.4` first (the most-downloaded
//! parse+write crate, per the plan): a 10 000-iteration xorshift byte-flip/truncate fuzz of a
//! hand-built minimal valid `.lnk` (fixed 76-byte header + `RelativePath`/`WorkingDir`/
//! `IconLocation` StringData, no `LinkInfo`) made `lnk::ShellLink::open` panic on 103 of 10 000
//! mutations: `attempt to multiply with overflow` in `strings/sized_string.rs`, a debug-mode
//! arithmetic-overflow panic reached by mutating a StringData length field. Also tried `parselnk
//! 0.1.1`: no fuzzing was even needed — its `header.rs` reads the `HotKey` field with
//! `cursor.read_u8().unwrap()` twice, so any file truncated at that point panics outright. Both
//! are the exact class of hazard `pe::version` was written to replace (see its module doc): a
//! structured reader written for well-formed files that turns a hostile or truncated one into a
//! panic. Given that, and that only three fields are needed here — `RELATIVE_PATH`,
//! `ICON_LOCATION` (path + the header's `IconIndex`), `WORKING_DIR` — all read straight from the
//! fixed header plus a handful of length-prefixed StringData records, a hand-rolled, bounded
//! reader is both safer and less code than adopting and then hardening a third-party crate. No
//! `.lnk` crate is a dependency of this project; nothing added to `docs/THIRD_PARTY.md`.
//!
//! **What is read.** The fixed 76-byte `ShellLinkHeader` (signature, `LinkCLSID`, `LinkFlags`,
//! `IconIndex`); `LinkInfo`, if present, is skipped by its own declared size (never interpreted:
//! it exists only to resolve a target that is not found where the link says it is, which is out
//! of scope here). `LinkTargetIDList`, if present, is skipped by its declared size for the
//! purposes of locating the next structure, but — since real Wine-created shortcuts turn out to
//! encode their target *only* here, with `RELATIVE_PATH` StringData absent — its `SHITEMID` item
//! sequence is also walked as a fallback: when `RELATIVE_PATH` is absent (or present but
//! unparseable), a best-effort absolute path is reconstructed from the list's drive/folder/file
//! items (see [`id_list_path`]) and fed through [`WinPath::parse`] exactly like the StringData
//! fields. `RELATIVE_PATH` StringData, when present and parseable, always wins; this is purely a
//! fallback for when it is not. No other shell-namespace item shapes (e.g. CLSID-rooted special
//! folders) are resolved — those are skipped as unrecognized, not walked into. Then whichever of
//! the `NAME_STRING` / `RELATIVE_PATH` / `WORKING_DIR` / `COMMAND_LINE_ARGUMENTS` /
//! `ICON_LOCATION` StringData records `LinkFlags` says are present, in that fixed order, keeping
//! only the three this module exposes. `ExtraData` (anything after the last StringData) is never
//! read.
//!
//! **Bounds.** Every size taken from the file is checked before use (`checked_add`, `.get(..)`,
//! never raw indexing) — a malformed or hostile size ends the parse with `Err`, never a panic and
//! never a read past the buffer. Most of the parse is a fixed sequence of "read one bounded
//! thing, check it fits, move on" steps, each touching the file at most once. The one exception
//! is [`id_list_path`]'s walk over `LinkTargetIDList`'s items, whose count is attacker-controlled
//! — but each iteration consumes at least 2 bytes of the already-validated, finite `[start, end)`
//! region `skip_id_list` computes (a zero or negative advance is rejected, not looped on), so the
//! loop is bounded by that region's length and never reads past `end`; a malformed *individual*
//! item is skipped or ends the walk early, never the whole `ShellLink::parse` call.
//!
//! **Paths inside a `.lnk` are Windows paths, parsed through [`rt_core::WinPath`]** (Phase 2's
//! validated type; no second path type is invented here). `RELATIVE_PATH` in particular is
//! usually a genuinely *relative* string (`.\Target.exe`), which `WinPath::parse` — an absolute
//! `X:\...`-only type — rejects; that is expected, not a bug: an unparseable embedded path just
//! leaves that one field `None`, with a note in [`ShellLink::warnings`], never aborting the whole
//! parse over one bad or merely-relative field.
use rt_core::WinPath;

/// `ShellLinkHeader` is always exactly this many bytes ([MS-SHLLINK] 2.1).
const HEADER_LEN: usize = 76;
const HEADER_SIGNATURE: u32 = 0x0000_004C;
/// `LinkCLSID`: always `{00021401-0000-0000-C000-000000000046}`, byte-for-byte, in every real
/// `.lnk` file ([MS-SHLLINK] 2.1).
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

const HAS_LINK_TARGET_ID_LIST: u32 = 0x1;
const HAS_LINK_INFO: u32 = 0x2;
const HAS_NAME: u32 = 0x4;
const HAS_RELATIVE_PATH: u32 = 0x8;
const HAS_WORKING_DIR: u32 = 0x10;
const HAS_ARGUMENTS: u32 = 0x20;
const HAS_ICON_LOCATION: u32 = 0x40;
const IS_UNICODE: u32 = 0x80;

/// The subset of a parsed `.lnk` this project needs. See the module doc for exactly what is (and
/// is not) read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShellLink {
    /// The `RELATIVE_PATH` StringData, if present AND it parsed as a [`WinPath`] (see the module
    /// doc: a genuinely relative string is common and expected here, and leaves this `None`).
    /// When `RELATIVE_PATH` is absent or unparseable, falls back to a best-effort absolute path
    /// reconstructed from `LinkTargetIDList`'s items, if that IDList is present and yields one
    /// (see [`id_list_path`]) — the common case for real Wine-created shortcuts.
    pub relative_path: Option<WinPath>,
    /// The `ICON_LOCATION` StringData path, paired with the header's `IconIndex`. `None` when
    /// `ICON_LOCATION` is absent or its path did not parse as a [`WinPath`]; the index alone,
    /// without a usable path, is not reported (there is nothing to look the icon up in).
    pub icon_location: Option<(WinPath, i32)>,
    /// The `WORKING_DIR` StringData, if present and parseable.
    pub working_dir: Option<WinPath>,
    /// One entry per field that was present in the file but unusable: an embedded path that did
    /// not parse as a [`WinPath`] (the corresponding field above is `None`). Never aborts the
    /// parse — one bad field, not a whole failure. Empty when every present field parsed cleanly.
    pub warnings: Vec<String>,
}

/// Why [`ShellLink::parse`] refused a whole file outright. Reaching `Err` here means the file's
/// own bookkeeping (a size, an offset) is inconsistent enough that continuing would mean reading
/// past the buffer or losing track of where the next field starts — never a panic, always a
/// clean refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LnkError {
    #[error("too short for a ShellLinkHeader ({len} bytes, need at least {HEADER_LEN})")]
    Truncated { len: usize },
    #[error("bad HeaderSize/signature: not a .lnk file")]
    BadSignature,
    #[error("bad LinkCLSID: not a .lnk file")]
    BadClsid,
    #[error("{0}")]
    Malformed(String),
}

impl ShellLink {
    /// Parses a `.lnk` file. Never panics on any byte sequence (see the module doc for the fuzz
    /// evidence backing that claim). `Err`: the file is not a `.lnk` at all, or a size/offset
    /// inside it is inconsistent enough that the rest of the file cannot be located reliably.
    pub fn parse(bytes: &[u8]) -> Result<ShellLink, LnkError> {
        if bytes.len() < HEADER_LEN {
            return Err(LnkError::Truncated { len: bytes.len() });
        }
        let header = &bytes[..HEADER_LEN];
        if u32_at(header, 0) != Some(HEADER_SIGNATURE) {
            return Err(LnkError::BadSignature);
        }
        if header[4..20] != LINK_CLSID {
            return Err(LnkError::BadClsid);
        }
        let flags = u32_at(header, 20).ok_or(LnkError::BadSignature)?;
        let icon_index = i32_at(header, 56).ok_or(LnkError::BadSignature)?;
        let unicode = flags & IS_UNICODE != 0;

        let mut pos = HEADER_LEN;
        // The item region within LinkTargetIDList, if present: `[start, end)`, content only (the
        // 2-byte IDListSize field itself excluded). Captured here, walked later as a fallback —
        // see the module doc and `id_list_path`.
        let mut id_list_region: Option<(usize, usize)> = None;
        if flags & HAS_LINK_TARGET_ID_LIST != 0 {
            let content_start = pos + 2;
            pos = skip_id_list(bytes, pos)?;
            id_list_region = Some((content_start, pos));
        }
        if flags & HAS_LINK_INFO != 0 {
            pos = skip_link_info(bytes, pos)?;
        }

        let mut warnings = Vec::new();
        let take = |flag: u32, field: &'static str, pos: &mut usize| -> Result<Option<String>, LnkError> {
            if flags & flag == 0 {
                return Ok(None);
            }
            let (s, next) = read_string_data(bytes, *pos, unicode, field)?;
            *pos = next;
            Ok(Some(s))
        };

        take(HAS_NAME, "Name", &mut pos)?; // read and discarded: not one of the three fields needed
        let relative_path_str = take(HAS_RELATIVE_PATH, "RelativePath", &mut pos)?;
        let working_dir_str = take(HAS_WORKING_DIR, "WorkingDir", &mut pos)?;
        take(HAS_ARGUMENTS, "Arguments", &mut pos)?;
        let icon_location_str = take(HAS_ICON_LOCATION, "IconLocation", &mut pos)?;
        // ExtraData, if any, starts at `pos`; never read (see module doc).

        let mut parse_field = |s: Option<String>, field: &str| -> Option<WinPath> {
            let s = s?;
            match WinPath::parse(&s) {
                Ok(p) => Some(p),
                Err(e) => {
                    warnings.push(format!("{field}: not a usable Windows path: {e}"));
                    None
                }
            }
        };
        let mut relative_path = parse_field(relative_path_str, "RelativePath");
        let working_dir = parse_field(working_dir_str, "WorkingDir");
        let icon_location = parse_field(icon_location_str, "IconLocation").map(|p| (p, icon_index));

        // Fallback: RELATIVE_PATH absent (or present but unparseable) is exactly the case real
        // Wine-created shortcuts hit — their target lives only in LinkTargetIDList. Never
        // overrides a RELATIVE_PATH that already parsed.
        if relative_path.is_none()
            && let Some((start, end)) = id_list_region
            && let Some(assembled) = id_list_path(bytes, start, end)
        {
            match WinPath::parse(&assembled) {
                Ok(p) => relative_path = Some(p),
                Err(e) => {
                    warnings.push(format!("LinkTargetIDList: recovered path not usable: {e}"));
                }
            }
        }

        Ok(ShellLink {
            relative_path,
            icon_location,
            working_dir,
            warnings,
        })
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn i32_at(b: &[u8], at: usize) -> Option<i32> {
    u32_at(b, at).map(|v| v as i32)
}

/// Skips a `LinkTargetIDList` at `bytes[pos..]` (a 2-byte `IDListSize` followed by that many
/// bytes; contents never interpreted) and returns the offset right after it.
fn skip_id_list(bytes: &[u8], pos: usize) -> Result<usize, LnkError> {
    let size =
        usize::from(u16_at(bytes, pos).ok_or_else(|| LnkError::Malformed("truncated LinkTargetIDList size".into()))?);
    let end = pos
        .checked_add(2)
        .and_then(|p| p.checked_add(size))
        .ok_or_else(|| LnkError::Malformed("LinkTargetIDList size overflow".into()))?;
    if end > bytes.len() {
        return Err(LnkError::Malformed(
            "LinkTargetIDList runs past the end of the file".into(),
        ));
    }
    Ok(end)
}

/// Walks a `LinkTargetIDList`'s `SHITEMID` item sequence at `bytes[pos..end]` (`pos`/`end` from
/// `skip_id_list`: `end` is already validated `<= bytes.len()`) and reconstructs a best-effort
/// absolute Windows path string, or `None` if nothing usable was found (no drive item, or the
/// list was empty). Each item is `cbSize: u16` (itself included in the count) then `cbSize - 2`
/// bytes, terminated by `cbSize == 0`; this walker never reads outside `[pos, end)`.
///
/// Only three item shapes are recognized (see the module doc for why nothing else is): a
/// CLSID-rooted item (`0x1F`/`0x2F`, e.g. "My Computer") is a known, fixed, ignorable prefix; a
/// drive item (type byte `0x20..=0x2E`) holds a null-terminated ANSI drive path like `C:\\`; a
/// folder/file item (type byte `0x30..=0x3F`) holds a fixed 12-byte header then a null-terminated
/// ANSI short (8.3) name, optionally followed (after padding to an even item-relative offset) by
/// an extension block whose long UTF-16LE name is preferred when present and non-empty. Anything
/// else, or any item whose bytes do not fit the shape being attempted, is skipped: one bad or
/// unrecognized item narrows the result, it never aborts the walk (and never aborts
/// [`ShellLink::parse`] — see its caller).
fn id_list_path(bytes: &[u8], mut pos: usize, end: usize) -> Option<String> {
    let mut drive: Option<String> = None;
    let mut segments: Vec<String> = Vec::new();
    while pos < end {
        let cbsize = usize::from(u16_at(bytes, pos)?);
        if cbsize < 2 {
            break; // 0 is the list terminator; anything else below 2 can't even cover itself
        }
        let item_end = match pos.checked_add(cbsize) {
            Some(e) if e <= end => e,
            _ => break, // declared size overflows or runs past the validated region: stop here
        };
        let content_start = pos + 2; // safe: cbsize >= 2, so item_end >= content_start
        if content_start < item_end
            && let Some(&type_byte) = bytes.get(content_start)
        {
            match type_byte {
                0x1F | 0x2F => {} // CLSID-rooted item ("My Computer" etc.): not a path segment
                0x20..=0x2E => {
                    if let Some(s) = read_drive_item(bytes, content_start, item_end) {
                        drive = Some(s);
                    }
                }
                0x30..=0x3F => {
                    if let Some(s) = read_file_entry_name(bytes, content_start, item_end)
                        && !s.is_empty()
                    {
                        segments.push(s);
                    }
                }
                _ => {} // unrecognized shape: not a general shell-namespace resolver, skip it
            }
        }
        pos = item_end;
    }
    let mut path = drive?;
    if !path.ends_with('\\') {
        path.push('\\');
    }
    path.push_str(&segments.join("\\"));
    Some(path)
}

/// Reads a drive item's path (e.g. `C:\\`): a null-terminated ANSI string starting right after
/// the type byte, bounded within `[content_start, item_end)`.
fn read_drive_item(bytes: &[u8], content_start: usize, item_end: usize) -> Option<String> {
    let str_start = content_start.checked_add(1)?;
    let raw = bytes.get(str_start..item_end)?; // `.get` on a backwards range is `None`, never a panic
    let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let s = std::str::from_utf8(&raw[..nul]).ok()?;
    (!s.is_empty()).then_some(s.to_owned())
}

/// Reads a folder/file item's name: the fixed 12-byte header (type byte already consumed by the
/// caller; reserved byte, 4-byte file size, 4-byte date, 2-byte attributes — none of which this
/// project needs), then a null-terminated ANSI short (8.3) name, then — if an extension block
/// with a usable long name follows — that long name instead. Bounded within
/// `[content_start, item_end)`. `None` if even the short name is not recoverable.
fn read_file_entry_name(bytes: &[u8], content_start: usize, item_end: usize) -> Option<String> {
    let name_start = content_start.checked_add(12)?;
    let short_region = bytes.get(name_start..item_end)?; // `.get` on a backwards range is `None`, never a panic
    let nul_rel = short_region.iter().position(|&b| b == 0)?;
    let short_name = std::str::from_utf8(&short_region[..nul_rel]).ok().map(str::to_owned);

    let mut ext_pos = name_start.checked_add(nul_rel)?.checked_add(1)?;
    if !ext_pos.checked_sub(content_start)?.is_multiple_of(2) {
        ext_pos = ext_pos.checked_add(1)?;
    }
    if let Some(long_name) = read_long_name(bytes, ext_pos, item_end) {
        return Some(long_name);
    }
    short_name
}

/// Reads a folder/file item's extension block's long (non-8.3) name, if present: a 2-byte
/// `ExtensionSize` (itself included in the count), then a fixed 18-byte sub-header (version,
/// signature, timestamps — not needed here), then a null-terminated UTF-16LE name. Bounded within
/// `[ext_pos, item_end)`. `None` on any shape mismatch or truncation — the caller falls back to
/// the short name.
fn read_long_name(bytes: &[u8], ext_pos: usize, item_end: usize) -> Option<String> {
    let ext_size = usize::from(u16_at(bytes, ext_pos)?);
    if ext_size < 20 {
        return None; // too small to hold its own 18-byte sub-header past the size field
    }
    let ext_end = ext_pos.checked_add(ext_size)?;
    if ext_end > item_end {
        return None;
    }
    let name_start = ext_pos.checked_add(20)?;
    let region = bytes.get(name_start..ext_end)?;
    let mut i = 0;
    let nul_at = loop {
        if i + 1 >= region.len() {
            return None; // no UTF-16 NUL terminator found within the extension block
        }
        if region[i] == 0 && region[i + 1] == 0 {
            break i;
        }
        i += 2;
    };
    let units: Vec<u16> = region[..nul_at]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let s = String::from_utf16_lossy(&units);
    (!s.is_empty()).then_some(s)
}

/// Skips a `LinkInfo` structure at `bytes[pos..]` (a 4-byte `LinkInfoSize`, itself included in
/// that count, covering the whole structure; contents never interpreted) and returns the offset
/// right after it.
fn skip_link_info(bytes: &[u8], pos: usize) -> Result<usize, LnkError> {
    let size =
        usize::try_from(u32_at(bytes, pos).ok_or_else(|| LnkError::Malformed("truncated LinkInfo size".into()))?)
            .map_err(|_| LnkError::Malformed("LinkInfo size does not fit usize".into()))?;
    if size < 4 {
        return Err(LnkError::Malformed(format!(
            "LinkInfo size {size} is smaller than its own size field"
        )));
    }
    let end = pos
        .checked_add(size)
        .ok_or_else(|| LnkError::Malformed("LinkInfo size overflow".into()))?;
    if end > bytes.len() {
        return Err(LnkError::Malformed("LinkInfo runs past the end of the file".into()));
    }
    Ok(end)
}

/// Reads one `StringData` record (a 2-byte character count, `CountCharacters`, followed by that
/// many UTF-16LE units when `unicode`, else that many single-byte code-page bytes decoded lossily
/// as UTF-8 — an approximation for the rare non-Unicode case, acceptable here since the result
/// only ever feeds `WinPath::parse`, which rejects anything that is not a plausible path anyway).
/// Returns the decoded string and the offset right after it. `CountCharacters` is a `u16`, so the
/// decoded byte length is bounded (at most 131 070 bytes) with no separate cap needed.
fn read_string_data(bytes: &[u8], pos: usize, unicode: bool, field: &'static str) -> Result<(String, usize), LnkError> {
    let count =
        usize::from(u16_at(bytes, pos).ok_or_else(|| LnkError::Malformed(format!("{field}: truncated length")))?);
    let data_start = pos
        .checked_add(2)
        .ok_or_else(|| LnkError::Malformed(format!("{field}: offset overflow")))?;
    let byte_len = if unicode { count.checked_mul(2) } else { Some(count) }
        .ok_or_else(|| LnkError::Malformed(format!("{field}: length overflow")))?;
    let end = data_start
        .checked_add(byte_len)
        .ok_or_else(|| LnkError::Malformed(format!("{field}: length overflow")))?;
    let raw = bytes
        .get(data_start..end)
        .ok_or_else(|| LnkError::Malformed(format!("{field}: runs past the end of the file")))?;
    let s = if unicode {
        let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    // [MS-SHLLINK] says CountCharacters excludes any terminator and none should be present, but a
    // real shortcut written by Wine (see the `hello.lnk` fixture) includes one trailing NUL inside
    // the count anyway. Trimmed here rather than left in, or every downstream `WinPath::parse`
    // would have to special-case a trailing NUL itself.
    Ok((s.trim_end_matches('\0').to_owned(), end))
}

#[cfg(test)]
mod tests;
