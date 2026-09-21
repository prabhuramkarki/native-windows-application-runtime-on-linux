//! Hostile-input zip handling for `install`: a read-only PLAN of the whole archive, then extraction of exactly that
//! plan.
//!
//! **Nothing in an archive is trusted**: names, sizes, modes, counts. The flow is
//!
//! 1. [`open`] reads the end-of-central-directory record itself (entry count, zip64 aware) and refuses more than
//!    [`Limits::max_entries`] entries BEFORE the `zip` crate parses the central directory, then builds the plan
//!    from the central directory alone (no entry data is read):
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
use crate::text::quote;
use crate::winpath::{WinPath, WinPathError};
use std::collections::HashMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
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

/// Error texts embed entry names only through [`quote`] (escaped, at most 125 characters each).
#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("not a usable zip archive: {0}")]
    Format(String),
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
    let mut m = e.to_string();
    m.truncate(200);
    ZipError::Format(m)
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

/// The entry count of the archive as the end record states it, read from the last 64 KiB of the file (zip64 aware).
fn declared_entries(file: &File) -> Result<u64, ZipError> {
    let bad = |what: &str| ZipError::Format(what.to_owned());
    let io_err = |e: io::Error| ZipError::Format(e.to_string());
    let mut f = file;
    let len = f.seek(SeekFrom::End(0)).map_err(io_err)?;
    let n = len.min(22 + 65_535);
    let mut tail = vec![0u8; n as usize];
    f.seek(SeekFrom::Start(len - n)).map_err(io_err)?;
    f.read_exact(&mut tail).map_err(io_err)?;
    let sig = b"PK\x05\x06";
    let pos = tail
        .windows(4)
        .rposition(|w| w == sig)
        .filter(|&p| p + 22 <= tail.len())
        .ok_or_else(|| bad("no end of central directory record (not a zip archive)"))?;
    let total = u64::from(u16::from_le_bytes([tail[pos + 10], tail[pos + 11]]));
    if total != 0xFFFF {
        return Ok(total);
    }
    // zip64: the locator sits right before the end record and points at the zip64 end record.
    let loc = pos.checked_sub(20).ok_or_else(|| bad("zip64 locator missing"))?;
    if &tail[loc..loc + 4] != b"PK\x06\x07" {
        return Err(bad("zip64 locator missing"));
    }
    let off = u64::from_le_bytes(tail[loc + 8..loc + 16].try_into().unwrap_or_default());
    let mut rec = [0u8; 56];
    f.seek(SeekFrom::Start(off)).map_err(io_err)?;
    f.read_exact(&mut rec).map_err(io_err)?;
    if &rec[..4] != b"PK\x06\x06" {
        return Err(bad("zip64 end of central directory record missing"));
    }
    Ok(u64::from_le_bytes(rec[32..40].try_into().unwrap_or_default()))
}

/// Opens the archive and plans it (see the module docs). Reads no entry data.
pub fn open(file: File, limits: &Limits) -> Result<(ZipArchive<File>, Plan), ZipError> {
    let declared = declared_entries(&file)?;
    if declared > limits.max_entries as u64 {
        return Err(ZipError::TooManyEntries {
            max: limits.max_entries,
        });
    }
    let mut archive = ZipArchive::new(file).map_err(|e| format_err(&e))?;
    // `declared <= max_entries` here, so equality also bounds `archive.len()`.
    if declared != archive.len() as u64 {
        return Err(ZipError::DuplicateNames {
            declared,
            distinct: archive.len(),
        });
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

fn plan(archive: &mut ZipArchive<File>, limits: &Limits) -> Result<Plan, ZipError> {
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
pub fn extract(archive: &mut ZipArchive<File>, plan: &Plan, dest: &Path, limits: &Limits) -> Result<u64, ZipError> {
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
    archive: &mut ZipArchive<File>,
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
