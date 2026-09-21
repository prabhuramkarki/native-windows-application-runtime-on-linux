//! Hostile-input zip handling for `install`: a read-only PLAN of the whole archive, then extraction of exactly that
//! plan.
//!
//! **Nothing in an archive is trusted**: names, sizes, modes, counts. The flow is
//!
//! 1. [`open`] first runs [`prevalidate`]: a STRICT check of the end record and of the whole central directory,
//!    done by this module before the `zip` crate sees the file. It requires exactly one end-of-central-directory
//!    signature in the last 64 KiB, a comment that ends at the end of the file, disk numbers 0, equal entry counts
//!    for this disk and in total, at most [`Limits::max_entries`] entries, a directory of at most [`MAX_CD_BYTES`]
//!    that ends exactly where the end record (or zip64 record) starts, a valid zip64 record and locator whenever
//!    the crate would go zip64 (count, size or offset field saturated), and a central directory that walks: exactly
//!    `count` headers, sane name lengths, bytes consumed equal to the stated size. Anything else is a
//!    [`Layout`] error. So every number the crate later uses to size its allocations (its `Vec::with_capacity`
//!    takes the entry count) has been checked against the file and bounded by us first.
//!    The crate could still, in principle, fail on OUR record for its own reasons (a malformed extra field) and
//!    then walk back to an earlier `PK\5\6` hidden in file data (say a stored nested zip). That is made
//!    unreachable: the crate reads through `Guarded`, which shows zeros for every byte before the central
//!    directory until `ZipArchive::new` has returned, and the directory, its zip64 extensible data and the tail
//!    window are scanned for stray signatures by [`prevalidate`]. Afterwards the crate's entry count, archive
//!    offset and directory start must equal ours. Limits: archives must start at byte 0 (no self-extracting
//!    prefix), zip64 records must be adjacent to the locator, the directory must directly precede the end record.
//!    Then the plan is built from the central directory alone (no entry data is read):
//!    * every name is parsed with [`WinPath::parse`] as `C:\<name>` after stripping ONE trailing separator (a
//!      directory marker). `\` is a separator (Windows semantics; a Linux name with a backslash becomes a nested
//!      path). `..`, absolute, drive, UNC, `\\?\`, `:` (alternate streams), NUL/control characters, reserved device
//!      names (`con.txt`), trailing dot/space, over-deep (> 128) and empty/`.` names are all errors. `.`
//!      components are dropped, so `a/./b` is `a/b`.
//!    * names are compared case-insensitively: two entries that differ only by case (files or directories) are a
//!      [`ZipError::CaseCollision`], the same canonical name twice is [`ZipError::Duplicate`], a file that is also
//!      a directory prefix (`a` and `a/b`) is [`ZipError::TypeConflict`]. The `zip` crate silently keeps the LAST of
//!      two identical raw names, so the count in the end record is compared with the number of distinct names.
//!    * only regular files and directories are extracted. Entries whose Unix mode says symlink, device, FIFO or
//!      socket are skipped and counted (one warning by the caller); permission bits are never used.
//!    * encrypted and non-stored/deflate entries are errors; declared sizes are capped per entry and in total,
//!      and a declared-size to compressed-size ratio above [`Limits::max_ratio`] (for entries over
//!      [`Limits::ratio_floor`]) is a bomb. A central directory that DECLARES huge sizes is therefore refused
//!      before anything is created.
//! 2. [`extract`] creates the planned directories (`0755`, never an existing one) and files (`0644`, `create_new`,
//!    never setuid/exec, never through a symlink) below a directory the caller has just made, streaming through a
//!    fixed 64 KiB buffer. An entry that yields more than its declared size is an error at the first excess chunk
//!    (nothing past the declared size is written), and the bytes actually written are counted against
//!    [`Limits::max_total_bytes`] while streaming. Entries read into memory for analysis go through
//!    `read_capped`, which is `take(declared + 1)`. Declared sizes are never trusted for allocation.
//!
//! **Not covered:** `create_new` + planned names stop everything the archive itself can do, but a process that
//! can write into the destination while it is being extracted could swap a directory for a symlink. `install`
//! only extracts when no Wine process is running in the prefix (`CompatBackend::prepare` stops the server before
//! returning), and Phase 5's sandbox is the real boundary.
use crate::text::{clean, quote};
use crate::winpath::{WinPath, WinPathError};
use std::collections::HashMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use zip::{CompressionMethod, ZipArchive};

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

/// Every cap of the zip path. `Limits::default()` holds the production values; tests lower them.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Most entries in the archive.
    pub max_entries: usize,
    /// Most directories the extraction would create (explicit and implied).
    pub max_dirs: usize,
    /// Most bytes extracted in total: checked on the declared sizes and again on the bytes actually written.
    pub max_total_bytes: u64,
    /// Largest declared size of one entry.
    pub max_entry_bytes: u64,
    /// The ratio guard only applies to entries declaring more than this many bytes.
    pub ratio_floor: u64,
    /// Highest accepted declared-size / compressed-size ratio.
    pub max_ratio: u64,
    /// Largest entry read into memory to be analysed as a candidate program.
    pub max_candidate_bytes: u64,
    /// Most candidate programs analysed (more means the caller must say which one).
    pub max_candidates: usize,
    /// Most bytes read into memory for analysis in total.
    pub max_analysis_bytes: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_entries: 20_000,
            max_dirs: 20_000,
            max_total_bytes: 4 * GIB,
            max_entry_bytes: 4 * GIB,
            ratio_floor: MIB,
            max_ratio: 1000,
            max_candidate_bytes: 512 * MIB,
            max_candidates: 64,
            max_analysis_bytes: 4 * GIB,
        }
    }
}

/// Why an entry name was refused. Carries no untrusted text (the caller quotes the name).
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("the name is empty")]
    Empty,
    #[error("the name is the archive root")]
    Root,
    #[error("{0}")]
    Path(WinPathError),
}

/// Why the end record or the central directory of an archive is refused before the `zip` crate sees it. Carries no
/// untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Layout {
    #[error("ambiguous end record: more than one end-of-central-directory signature in the last 64 KiB")]
    AmbiguousEnd,
    #[error("the end record does not end at the end of the file (trailing data, or a comment length that lies)")]
    EndNotAtEof,
    #[error("multi-disk archives are not supported")]
    MultiDisk,
    #[error("the end record states different entry counts for this disk and in total")]
    CountMismatch,
    #[error("the central directory is larger than 64 MiB")]
    DirectoryTooLarge,
    #[error("the central directory lies outside the archive")]
    DirectoryOutOfBounds,
    #[error("the central directory is not directly followed by the end record")]
    DirectoryGap,
    #[error("the zip64 end record or its locator is missing or inconsistent")]
    Zip64,
    #[error("a zip64 locator is present but the end record does not point to it: ambiguous")]
    StrayZip64Locator,
    #[error("unsupported archive layout: data before the first entry, or a damaged central directory start")]
    PrependedData,
    #[error("inconsistent central directory (entry headers do not add up to the stated size and count)")]
    InconsistentDirectory,
    #[error("entry names are too long (over 4096 bytes each or 16 MiB together)")]
    NamesTooLong,
}

/// What [`prevalidate`] established about an archive, all bounded and consistent with the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirInfo {
    pub entries: u64,
    pub cd_offset: u64,
    pub cd_size: u64,
}

/// Error texts embed entry names only through `text::quote` (escaped, at most 125 characters each).
#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("not a usable zip archive: {0}")]
    Format(String),
    #[error("unusable zip archive: {0}")]
    Layout(#[from] Layout),
    #[error("the archive has more than {max} entries")]
    TooManyEntries { max: usize },
    #[error("the archive would create more than {max} directories")]
    TooManyDirs { max: usize },
    #[error(
        "the archive lists {declared} entries but only {distinct} distinct names (duplicate entry names are refused)"
    )]
    DuplicateNames { declared: u64, distinct: usize },
    #[error("entry {name} has an unacceptable name: {why}")]
    BadName { name: String, why: NameError },
    #[error("entries {a} and {b} differ only by letter case (Windows would treat them as one name)")]
    CaseCollision { a: String, b: String },
    #[error("entry {name} appears twice")]
    Duplicate { name: String },
    #[error("entries {a} and {b} disagree on whether the name is a file or a directory")]
    TypeConflict { a: String, b: String },
    #[error("entry {name} is encrypted (encrypted archives are not supported)")]
    Encrypted { name: String },
    #[error("entry {name} uses an unsupported compression method (only stored and deflate)")]
    Unsupported { name: String },
    #[error("entry {name} declares {size} bytes, more than the {max} byte limit per entry")]
    EntryTooLarge { name: String, size: u64, max: u64 },
    #[error("the archive declares more than {max} bytes in total")]
    TotalTooLarge { max: u64 },
    #[error(
        "entry {name} looks like a zip bomb (declares {size} bytes from {compressed} compressed: more than {max}:1)"
    )]
    Ratio {
        name: String,
        size: u64,
        compressed: u64,
        max: u64,
    },
    #[error("entry {name} holds more data than it declares")]
    LiesAboutSize { name: String },
    #[error("entry {name} holds less data than it declares")]
    ShortEntry { name: String },
    #[error("more than {max} bytes were extracted")]
    ExtractedTooMuch { max: u64 },
    #[error("cannot analyse more than {max} bytes of candidate programs")]
    AnalysisBudget { max: u64 },
    #[error("cannot extract {name}: {source}")]
    Io {
        name: String,
        #[source]
        source: io::Error,
    },
}

fn format_err(e: &zip::result::ZipError) -> ZipError {
    // The crate's messages are static or numeric; still clip them.
    ZipError::Format(clean(&e.to_string(), 200))
}

/// Parses an entry name into validated components (`C:\` is prepended so [`WinPath`] does the work, see the module
/// docs). Exactly one trailing separator is stripped first (it marks a directory).
pub fn entry_path(name: &str) -> Result<Vec<String>, NameError> {
    let stripped = name.strip_suffix(['/', '\\']).unwrap_or(name);
    if stripped.is_empty() {
        return Err(NameError::Empty);
    }
    let path = WinPath::parse(&format!("C:\\{stripped}")).map_err(NameError::Path)?;
    if path.components().is_empty() {
        return Err(NameError::Root);
    }
    Ok(path.components().to_vec())
}

#[derive(Debug, Clone)]
pub struct PlannedFile {
    /// Index in the archive.
    pub index: usize,
    /// Validated components below the extraction directory.
    pub path: Vec<String>,
    /// Declared uncompressed size.
    pub size: u64,
}

#[derive(Debug)]
pub struct Plan {
    /// Regular files, in archive order.
    pub files: Vec<PlannedFile>,
    /// Every directory to create (explicit and implied), parents before children.
    pub dirs: Vec<Vec<String>>,
    /// Entries skipped because they are not regular files or directories.
    pub skipped: usize,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Kind {
    File,
    Dir,
}

struct Seen {
    /// The canonical spelling (components joined with `\`).
    exact: String,
    kind: Kind,
    /// Named by an entry (rather than only implied by a longer name).
    explicit: bool,
}

const MODE_TYPE_MASK: u32 = 0o170_000;
const MODE_REG: u32 = 0o100_000;
const MODE_DIR: u32 = 0o040_000;

fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Largest central directory accepted, in bytes.
pub const MAX_CD_BYTES: u64 = 64 << 20;
/// Longest entry name accepted in the central directory, in bytes, and the most all names may total.
const MAX_NAME_BYTES: usize = 4096;
const MAX_NAMES_TOTAL: usize = 16 << 20;
/// The end record is searched in this many bytes at the end of the file (a 22 byte record plus a 65535 byte comment).
const TAIL_WINDOW: u64 = 22 + 65_535;
/// Most bytes of zip64 "extensible data" between the zip64 end record and its locator.
const MAX_ZIP64_EXTENSIBLE: u64 = 64 * 1024;
const SIG_EOCD: &[u8; 4] = b"PK\x05\x06";
const SIG_ZIP64_EOCD: &[u8; 4] = b"PK\x06\x06";
const SIG_ZIP64_LOCATOR: &[u8; 4] = b"PK\x06\x07";
const SIG_CENTRAL: &[u8; 4] = b"PK\x01\x02";

fn read_at<R: Read + Seek>(r: &mut R, at: u64, len: usize) -> Result<Vec<u8>, ZipError> {
    let io_err = |e: io::Error| ZipError::Format(clean(&e.to_string(), 200));
    let mut buf = vec![0u8; len];
    r.seek(SeekFrom::Start(at)).map_err(io_err)?;
    r.read_exact(&mut buf).map_err(io_err)?;
    Ok(buf)
}

fn le16(b: &[u8], at: usize) -> u64 {
    u64::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn le32(b: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

fn has_end_signature(bytes: &[u8]) -> bool {
    bytes.windows(4).any(|w| w == SIG_EOCD)
}

/// Strictly validates an archive of `len` bytes BEFORE the `zip` crate is allowed to look at it, and returns the
/// numbers the crate will later rely on, all bounded. The crate parses the whole central directory with a
/// `Vec::with_capacity(count)` taken from whichever end record it settles on, so it must never be handed an
/// archive whose count, sizes or record choice we have not checked ourselves.
///
/// * The end-of-central-directory record is found in the last 22 + 65535 bytes, must be the ONLY signature there,
///   and its comment must end exactly at the end of the file. (The crate walks back over every `PK\5\6` and falls
///   back to an earlier one when a candidate fails its own checks; see [`open`] for how that is made unreachable.)
/// * disk numbers are 0, entries on this disk equal the total, the total is at most `max_entries`, the directory
///   is at most [`MAX_CD_BYTES`] and ends exactly where the end record (or the zip64 end record) begins.
/// * The crate goes zip64 when the count is `0xFFFF` OR the directory size OR offset is `0xFFFFFFFF`: then the
///   zip64 locator must sit directly before the end record and a valid zip64 record must sit directly before the
///   locator, and the same rules apply to its 64-bit values. A locator without such a sentinel is ambiguous.
/// * The central directory is walked: exactly `count` headers starting with `PK\1\2`, names of at most 4096 bytes
///   (16 MiB together), the variable-length fields staying inside the directory, and the bytes consumed equal to
///   the stated size. Data before the first entry (self-extracting archives, prepended junk) makes the first
///   signature miss and is refused: this reader supports archives that start at byte 0.
pub fn prevalidate<R: Read + Seek>(r: &mut R, len: u64, limits: &Limits) -> Result<DirInfo, ZipError> {
    let no_end = || ZipError::Format("no end of central directory record (not a zip archive)".to_owned());
    if len < 22 {
        return Err(no_end());
    }
    let window = len.min(TAIL_WINDOW);
    let window_start = len - window;
    let tail = read_at(r, window_start, window as usize)?;
    let mut sigs = tail
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == SIG_EOCD)
        .map(|(i, _)| i);
    let at = sigs.next().ok_or_else(no_end)?;
    if sigs.next().is_some() {
        return Err(Layout::AmbiguousEnd.into());
    }
    let eocd_pos = window_start + at as u64;
    if at + 22 > tail.len() || eocd_pos + 22 + le16(&tail, at + 20) != len {
        return Err(Layout::EndNotAtEof.into());
    }
    let rec = &tail[at..at + 22];
    if le16(rec, 4) != 0 || le16(rec, 6) != 0 {
        return Err(Layout::MultiDisk.into());
    }
    if le16(rec, 8) != le16(rec, 10) {
        return Err(Layout::CountMismatch.into());
    }
    let (count32, size32, offset32) = (le16(rec, 10), le32(rec, 12), le32(rec, 16));
    let zip64 = count32 == 0xFFFF || size32 == 0xFFFF_FFFF || offset32 == 0xFFFF_FFFF;
    let locator_at = eocd_pos.checked_sub(20);
    let locator = match locator_at {
        Some(p) => Some(read_at(r, p, 20)?),
        None => None,
    };
    let has_locator = locator.as_ref().is_some_and(|l| &l[..4] == SIG_ZIP64_LOCATOR);
    // Where the directory must end (the start of whatever follows it) and what is scanned for stray signatures.
    let (entries, cd_size, cd_offset, dir_end, mut scan): (u64, u64, u64, u64, Vec<u8>) = if !zip64 {
        if has_locator {
            return Err(Layout::StrayZip64Locator.into());
        }
        (count32, size32, offset32, eocd_pos, Vec::new())
    } else {
        let (Some(locator), Some(locator_pos)) = (locator.filter(|_| has_locator), locator_at) else {
            return Err(Layout::Zip64.into());
        };
        if le32(&locator, 4) != 0 || le32(&locator, 16) > 1 {
            return Err(Layout::MultiDisk.into());
        }
        let z64_pos = le64(&locator, 8);
        if z64_pos.checked_add(56).is_none_or(|end| end > locator_pos) {
            return Err(Layout::Zip64.into());
        }
        let head = read_at(r, z64_pos, 56)?;
        let size = le64(&head, 4);
        // The record and its extensible data end exactly where the locator begins.
        if &head[..4] != SIG_ZIP64_EOCD
            || size < 44
            || size - 44 > MAX_ZIP64_EXTENSIBLE
            || z64_pos.checked_add(12).and_then(|p| p.checked_add(size)) != Some(locator_pos)
        {
            return Err(Layout::Zip64.into());
        }
        if le32(&head, 16) != 0 || le32(&head, 20) != 0 {
            return Err(Layout::MultiDisk.into());
        }
        if le64(&head, 24) != le64(&head, 32) {
            return Err(Layout::CountMismatch.into());
        }
        let sector = read_at(r, z64_pos + 56, (size - 44) as usize)?;
        (le64(&head, 32), le64(&head, 40), le64(&head, 48), z64_pos, sector)
    };
    if entries > limits.max_entries as u64 {
        return Err(ZipError::TooManyEntries {
            max: limits.max_entries,
        });
    }
    if cd_size > MAX_CD_BYTES {
        return Err(Layout::DirectoryTooLarge.into());
    }
    if cd_offset.checked_add(cd_size).is_none_or(|end| end > dir_end) {
        return Err(Layout::DirectoryOutOfBounds.into());
    }
    let cd = read_at(r, cd_offset, cd_size as usize)?;
    let mut pos = 0usize;
    let mut names_total = 0usize;
    for i in 0..entries {
        if pos + 46 > cd.len() || &cd[pos..pos + 4] != SIG_CENTRAL {
            return Err(if i == 0 {
                Layout::PrependedData
            } else {
                Layout::InconsistentDirectory
            }
            .into());
        }
        let (name, extra, comment) = (
            le16(&cd, pos + 28) as usize,
            le16(&cd, pos + 30) as usize,
            le16(&cd, pos + 32) as usize,
        );
        names_total += name;
        if name > MAX_NAME_BYTES || names_total > MAX_NAMES_TOTAL {
            return Err(Layout::NamesTooLong.into());
        }
        pos += 46 + name + extra + comment;
    }
    if pos != cd.len() {
        return Err(Layout::InconsistentDirectory.into());
    }
    if cd_offset + cd_size != dir_end {
        return Err(Layout::DirectoryGap.into());
    }
    // No other end record may hide in anything the crate may read after the directory starts: not in the
    // directory (names, extra fields, comments), not in the zip64 extensible data.
    scan.extend_from_slice(&cd);
    if has_end_signature(&scan) {
        return Err(Layout::AmbiguousEnd.into());
    }
    Ok(DirInfo {
        entries,
        cd_offset,
        cd_size,
    })
}

/// The reader the `zip` crate parses the directory through. While `masked` is set every byte BEFORE the central
/// directory reads as zero, so the crate's backward search for end records can only ever find the one we
/// validated (any other `PK\5\6` in the file data is invisible). It is switched off once `ZipArchive::new`
/// returns: entry data is read unmodified.
pub struct Guarded {
    file: File,
    below: u64,
    pos: u64,
    masked: Arc<AtomicBool>,
}

impl Guarded {
    /// `pos` starts at the file's real cursor (not at 0), so the mask is right even if the reader is used before
    /// its first seek. `prevalidate` reads through a shared `&File`, so the cursor is not necessarily at 0.
    fn new(mut file: File, below: u64, masked: Arc<AtomicBool>) -> io::Result<Guarded> {
        let pos = file.stream_position()?;
        Ok(Guarded {
            file,
            below,
            pos,
            masked,
        })
    }
}

impl Read for Guarded {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(buf)?;
        if self.masked.load(Ordering::Relaxed) && self.pos < self.below {
            let zeros = usize::try_from(self.below - self.pos).unwrap_or(usize::MAX).min(n);
            buf[..zeros].fill(0);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Guarded {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        self.pos = self.file.seek(from)?;
        Ok(self.pos)
    }
}

/// The archive type of this module.
pub type Archive = ZipArchive<Guarded>;

/// Opens the archive and plans it (see the module docs). Reads no entry data.
///
/// The `zip` crate only ever sees an archive that [`prevalidate`] accepted, through a reader that hides every
/// other end-record signature (`Guarded`), so it cannot settle on a different record than the validated one; as
/// defence in depth the count, the offset and the directory start it ends up with must equal ours, and the number
/// of distinct names must equal the stated count (the crate keeps only the LAST of two identical raw names).
pub fn open(file: File, limits: &Limits) -> Result<(Archive, Plan), ZipError> {
    let len = file
        .metadata()
        .map_err(|e| ZipError::Format(clean(&e.to_string(), 200)))?
        .len();
    let info = prevalidate(&mut &file, len, limits)?;
    let masked = Arc::new(AtomicBool::new(true));
    let guarded =
        Guarded::new(file, info.cd_offset, masked.clone()).map_err(|e| ZipError::Format(clean(&e.to_string(), 200)))?;
    let parsed = ZipArchive::new(guarded);
    masked.store(false, Ordering::Relaxed);
    let mut archive = parsed.map_err(|e| format_err(&e))?;
    if info.entries != archive.len() as u64 {
        return Err(ZipError::DuplicateNames {
            declared: info.entries,
            distinct: archive.len(),
        });
    }
    if archive.offset() != 0 || archive.central_directory_start() != info.cd_offset {
        return Err(Layout::InconsistentDirectory.into());
    }
    let plan = plan(&mut archive, limits)?;
    Ok((archive, plan))
}

fn register(
    names: &mut HashMap<String, Seen>,
    folded: &str,
    exact: &str,
    kind: Kind,
    explicit: bool,
) -> Result<bool, ZipError> {
    match names.get_mut(folded) {
        None => {
            names.insert(
                folded.to_owned(),
                Seen {
                    exact: exact.to_owned(),
                    kind,
                    explicit,
                },
            );
            Ok(true)
        }
        Some(seen) => {
            if seen.exact != exact {
                return Err(ZipError::CaseCollision {
                    a: quote(&seen.exact),
                    b: quote(exact),
                });
            }
            if seen.kind != kind {
                return Err(ZipError::TypeConflict {
                    a: quote(&seen.exact),
                    b: quote(exact),
                });
            }
            if explicit && seen.explicit {
                return Err(ZipError::Duplicate { name: quote(exact) });
            }
            seen.explicit |= explicit;
            Ok(false)
        }
    }
}

fn plan(archive: &mut Archive, limits: &Limits) -> Result<Plan, ZipError> {
    let mut names: HashMap<String, Seen> = HashMap::new();
    let mut files = Vec::new();
    let mut skipped = 0usize;
    let mut total = 0u64;
    let mut dirs = 0usize;
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).map_err(|e| format_err(&e))?;
        let raw_name = entry.name();
        let shown = quote(raw_name);
        let path = entry_path(raw_name).map_err(|why| ZipError::BadName {
            name: shown.clone(),
            why,
        })?;
        if entry.encrypted() {
            return Err(ZipError::Encrypted { name: shown });
        }
        if !matches!(
            entry.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(ZipError::Unsupported { name: shown });
        }
        let mode_type = entry.unix_mode().map_or(0, |m| m & MODE_TYPE_MASK);
        if mode_type != 0 && mode_type != MODE_REG && mode_type != MODE_DIR {
            skipped += 1;
            continue;
        }
        let is_dir = mode_type == MODE_DIR || raw_name.ends_with(['/', '\\']);
        let kind = if is_dir { Kind::Dir } else { Kind::File };
        let (size, compressed) = (entry.size(), entry.compressed_size());
        if kind == Kind::File {
            if size > limits.max_entry_bytes {
                return Err(ZipError::EntryTooLarge {
                    name: shown,
                    size,
                    max: limits.max_entry_bytes,
                });
            }
            total = total.saturating_add(size);
            if total > limits.max_total_bytes {
                return Err(ZipError::TotalTooLarge {
                    max: limits.max_total_bytes,
                });
            }
            if size > limits.ratio_floor && size / compressed.max(1) > limits.max_ratio {
                return Err(ZipError::Ratio {
                    name: shown,
                    size,
                    compressed,
                    max: limits.max_ratio,
                });
            }
        }
        // Register every prefix as a directory, then the entry itself.
        let (mut exact, mut folded) = (String::new(), String::new());
        for (i, component) in path.iter().enumerate() {
            if i > 0 {
                exact.push('\\');
                folded.push('\\');
            }
            exact.push_str(component);
            folded.push_str(&fold(component));
            let last = i + 1 == path.len();
            let k = if last { kind } else { Kind::Dir };
            if register(&mut names, &folded, &exact, k, last)? && k == Kind::Dir {
                dirs += 1;
                if dirs > limits.max_dirs {
                    return Err(ZipError::TooManyDirs { max: limits.max_dirs });
                }
            }
        }
        if kind == Kind::File {
            files.push(PlannedFile { index, path, size });
        }
    }
    let mut dir_list: Vec<Vec<String>> = names
        .values()
        .filter(|s| s.kind == Kind::Dir)
        .map(|s| s.exact.split('\\').map(str::to_owned).collect())
        .collect();
    dir_list.sort();
    Ok(Plan {
        files,
        dirs: dir_list,
        skipped,
    })
}

fn join(dest: &Path, components: &[String]) -> Result<PathBuf, io::Error> {
    let mut p = dest.to_path_buf();
    for c in components {
        // Re-checked here so containment does not rest on the planner alone.
        if c.is_empty() || c == "." || c == ".." || c.contains(['/', '\\', '\0']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe path component"));
        }
        p.push(c);
    }
    Ok(p)
}

/// Extracts the plan below `dest` (which must exist and be a directory the caller just made). Returns the number
/// of bytes written. Nothing already present is overwritten: every file is created with `create_new`.
pub fn extract(archive: &mut Archive, plan: &Plan, dest: &Path, limits: &Limits) -> Result<u64, ZipError> {
    let io_err = |name: &[String], source| ZipError::Io {
        name: quote(&name.join("\\")),
        source,
    };
    for dir in &plan.dirs {
        let path = join(dest, dir).map_err(|e| io_err(dir, e))?;
        // Not recursive: parents come first in the plan, and an existing directory is an error.
        DirBuilder::new()
            .mode(0o755)
            .create(&path)
            .map_err(|e| io_err(dir, e))?;
    }
    let mut total = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    for f in &plan.files {
        let path = join(dest, &f.path).map_err(|e| io_err(&f.path, e))?;
        let shown = || quote(&f.path.join("\\"));
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .map_err(|e| io_err(&f.path, e))?;
        let mut entry = archive.by_index(f.index).map_err(|e| format_err(&e))?;
        let mut written = 0u64;
        loop {
            let n = entry.read(&mut buf).map_err(|e| io_err(&f.path, e))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > f.size {
                return Err(ZipError::LiesAboutSize { name: shown() });
            }
            if total + n as u64 > limits.max_total_bytes {
                return Err(ZipError::ExtractedTooMuch {
                    max: limits.max_total_bytes,
                });
            }
            total += n as u64;
            io::Write::write_all(&mut out, &buf[..n]).map_err(|e| io_err(&f.path, e))?;
        }
        if written != f.size {
            return Err(ZipError::ShortEntry { name: shown() });
        }
    }
    Ok(total)
}

/// Reads `src` to its end, handing out at most `size + 1` bytes: memory is bounded by the DECLARED size whatever
/// the entry really holds (one byte more than declared is how the caller notices a lie).
fn read_capped(src: impl Read, size: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(usize::try_from(size.min(64 * MIB)).unwrap_or(0));
    src.take(size + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Reads one entry into memory for analysis. `declared` is the (already capped) declared size; reading stops one
/// byte past it. `budget` is what is left of [`Limits::max_analysis_bytes`].
pub fn read_entry(
    archive: &mut Archive,
    file: &PlannedFile,
    budget: &mut u64,
    limits: &Limits,
) -> Result<Vec<u8>, ZipError> {
    if file.size > *budget {
        return Err(ZipError::AnalysisBudget {
            max: limits.max_analysis_bytes,
        });
    }
    *budget -= file.size;
    let shown = || quote(&file.path.join("\\"));
    let entry = archive.by_index(file.index).map_err(|e| format_err(&e))?;
    let bytes = read_capped(entry, file.size).map_err(|source| ZipError::Io { name: shown(), source })?;
    match (bytes.len() as u64).cmp(&file.size) {
        std::cmp::Ordering::Greater => Err(ZipError::LiesAboutSize { name: shown() }),
        std::cmp::Ordering::Less => Err(ZipError::ShortEntry { name: shown() }),
        std::cmp::Ordering::Equal => Ok(bytes),
    }
}

#[cfg(test)]
mod tests;
