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
//! `IconIndex`); `LinkTargetIDList` and `LinkInfo`, if present, are skipped by their own declared
//! size (never interpreted: both exist only to resolve a target that is not found where the link
//! says it is, which is out of scope here); then whichever of the `NAME_STRING` /
//! `RELATIVE_PATH` / `WORKING_DIR` / `COMMAND_LINE_ARGUMENTS` / `ICON_LOCATION` StringData
//! records `LinkFlags` says are present, in that fixed order, keeping only the three this module
//! exposes. `ExtraData` (anything after the last StringData) is never read.
//!
//! **Bounds.** Every size taken from the file is checked before use (`checked_add`, `.get(..)`,
//! never raw indexing) — a malformed or hostile size ends the parse with `Err`, never a panic and
//! never a read past the buffer. There is no loop whose iteration count is attacker-controlled
//! (unlike `pe::version`'s TLV tree), so there is nothing here that needs its own iteration
//! budget: the whole parse is a fixed sequence of "read one bounded thing, check it fits, move
//! on" steps, each touching the file at most once.
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
        if flags & HAS_LINK_TARGET_ID_LIST != 0 {
            pos = skip_id_list(bytes, pos)?;
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
        let relative_path = parse_field(relative_path_str, "RelativePath");
        let working_dir = parse_field(working_dir_str, "WorkingDir");
        let icon_location = parse_field(icon_location_str, "IconLocation").map(|p| (p, icon_index));

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
