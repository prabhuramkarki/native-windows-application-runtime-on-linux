//! Windows-style paths and their containment-safe mapping onto a host directory (a Wine prefix's `drive_c`).
//!
//! **This module is a security boundary.** Its inputs are untrusted (zip entry names, `metadata.executable`) and its
//! outputs decide where files are read and created on the host. The rules:
//!
//! * [`WinPath::parse`] accepts only `X:\a\b` / `X:/a/b`. Everything else is an error, never "normalised": relative
//!   and drive-relative paths (`C:foo`, `C:`), UNC, `\\?\`, `\\.\`, `\??\` (including Wine's `\\?\unix\` host
//!   escape), empty components (`a\\b`, trailing separators), `..`, control characters and NUL, `< > : " | ? *`
//!   (`:` is reported as an alternate data stream), components ending in a space or `.`, and reserved device names
//!   (`CON PRN AUX NUL COM0-9 LPT0-9 COM¹²³ LPT¹²³ CONIN$ CONOUT$`, any case, with or without an extension). `.`
//!   components are dropped. The fields are private: an existing `WinPath` is always valid.
//! * Caps are checked before any scanning: total length (bytes, which is never smaller than the UTF-16 unit count
//!   Windows limits) in O(1), then per component (bytes, so it also fits Linux `NAME_MAX`) and component count.
//! * [`resolve_under`] / [`join_new`] map `C:` onto a root directory by looking every component up in the *real*
//!   directory listing (exact name first, else a unique case-insensitive match, ambiguity is an error) and stat-ing
//!   the match with `symlink_metadata`. A symlink at any component, including the last, is refused, so nothing
//!   can be reached through a link and the result is `root` plus real, single-segment names. A listing is capped at
//!   [`MAX_DIR_ENTRIES`] entries.
//!
//! Name comparison is `str::to_lowercase` on both sides (locale-independent, full Unicode lowercase mapping). There
//! is no Unicode normalisation (NFC and NFD spellings are different names) and no NTFS `$UpCase` table; 8.3 short
//! names (`PROGRA~1`) are literal names on Linux and are never expanded; fullwidth look-alikes of `.` `\` `/` are
//! ordinary characters. Format characters such as bidi overrides are not rejected, so a name can be
//! misleading when displayed: print untrusted names through the CLI's `safe()`. Reserved-name matching folds only
//! ASCII case.
//!
//! **What this does not do.**
//! * TOCTOU: the checks and the caller's later `open`/`create` are separate system calls. A process that can
//!   write inside the root (another user of the prefix, or the Windows program itself) can swap a component for a
//!   symlink between them. Without `openat2(RESOLVE_NO_SYMLINKS)` (not used: no libc dependency) this cannot be
//!   closed here. Callers must treat the returned path as a hint: open the final component with `O_NOFOLLOW` /
//!   `create_new`, and only resolve while no Windows process is running in the prefix. Phase 5's sandbox is the
//!   real boundary.
//! * Only `root` itself is checked for being a symlink. Its ancestors are the runtime's own layout and trusted, and
//!   hard links and bind mounts inside the root are not detected.
//! * Nothing is ever created, modified or deleted by this module.
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Longest accepted path, in bytes (Windows' 32_767 UTF-16 unit limit; bytes are never fewer than units).
pub const MAX_TOTAL_LEN: usize = 32_767;
/// Longest accepted component, in bytes (Windows allows 255 UTF-16 units, Linux `NAME_MAX` is 255 bytes).
pub const MAX_COMPONENT_LEN: usize = 255;
/// Most components (after dropping `.`) in one path.
pub const MAX_COMPONENTS: usize = 128;
/// Most directory entries examined while looking up one component; a bigger directory is an error.
pub const MAX_DIR_ENTRIES: usize = 100_000;

/// Why a string is not an acceptable Windows path. Carries no untrusted text, only single offending characters
/// (which are `Debug`-escaped in messages).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WinPathError {
    #[error("path is empty")]
    Empty,
    #[error("path is too long ({len} bytes, max {MAX_TOTAL_LEN})")]
    TooLong { len: usize },
    #[error("path has no drive letter (relative or rooted paths are not accepted)")]
    NoDrive,
    #[error("drive-relative paths (`C:` or `C:name`) are not accepted")]
    DriveRelative,
    #[error("UNC paths are not accepted")]
    Unc,
    #[error("device and NT namespace paths (`\\\\?\\`, `\\\\.\\`, `\\??\\`) are not accepted")]
    DevicePath,
    #[error("path has more than {MAX_COMPONENTS} components")]
    TooManyComponents,
    #[error("path has an empty component (doubled or trailing separator)")]
    EmptyComponent,
    #[error("`..` components are not accepted")]
    ParentDir,
    #[error("path component is longer than {MAX_COMPONENT_LEN} bytes")]
    ComponentTooLong,
    #[error("path contains control character {0:?}")]
    ControlChar(char),
    #[error("path contains illegal character {0:?}")]
    IllegalChar(char),
    #[error("alternate data streams (`:` in a name) are not accepted")]
    AlternateStream,
    #[error("path component ends with a space or a dot")]
    TrailingDotOrSpace,
    #[error("path component is a reserved device name")]
    ReservedName,
}

/// A validated absolute Windows path: an uppercase drive letter and zero or more validated components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WinPath {
    drive: char,
    components: Vec<String>,
}

fn is_sep(b: u8) -> bool {
    b == b'\\' || b == b'/'
}

/// True for names Windows treats as devices, in any directory, with any extension (`con.txt`, `NUL.tar.gz`).
fn is_reserved(component: &str) -> bool {
    // The device name is the text before the first dot, ignoring spaces just before that dot.
    let stem = component.split('.').next().unwrap_or_default().trim_end_matches(' ');
    if ["con", "prn", "aux", "nul", "conin$", "conout$"]
        .iter()
        .any(|n| stem.eq_ignore_ascii_case(n))
    {
        return true;
    }
    // `get` is None when byte 3 is not a char boundary or the stem is short.
    let Some(head) = stem.get(..3) else {
        return false;
    };
    if !(head.eq_ignore_ascii_case("com") || head.eq_ignore_ascii_case("lpt")) {
        return false;
    }
    let mut tail = stem[3..].chars();
    matches!(
        (tail.next(), tail.next()),
        (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
    )
}

/// Validates one non-`.` component (see the module docs for the rules).
fn check_component(c: &str) -> Result<(), WinPathError> {
    if c.is_empty() {
        return Err(WinPathError::EmptyComponent);
    }
    if c == ".." {
        return Err(WinPathError::ParentDir);
    }
    if c.len() > MAX_COMPONENT_LEN {
        return Err(WinPathError::ComponentTooLong);
    }
    for ch in c.chars() {
        match ch {
            ':' => return Err(WinPathError::AlternateStream),
            '<' | '>' | '"' | '|' | '?' | '*' => return Err(WinPathError::IllegalChar(ch)),
            _ if ch.is_control() => return Err(WinPathError::ControlChar(ch)),
            _ => {}
        }
    }
    if c.ends_with([' ', '.']) {
        return Err(WinPathError::TrailingDotOrSpace);
    }
    if is_reserved(c) {
        return Err(WinPathError::ReservedName);
    }
    Ok(())
}

impl WinPath {
    /// Parses `C:\dir\file.exe` or `C:/dir/file.exe` (either separator, mixed allowed, drive letter of any case).
    /// See the module docs for everything that is rejected. `C:\` (no components) is the drive root.
    pub fn parse(s: &str) -> Result<WinPath, WinPathError> {
        // O(1) length cap first: a hostile 1 GiB string is never scanned.
        if s.len() > MAX_TOTAL_LEN {
            return Err(WinPathError::TooLong { len: s.len() });
        }
        let b = s.as_bytes();
        let Some(&first) = b.first() else {
            return Err(WinPathError::Empty);
        };
        if is_sep(first) {
            // `\\?\`, `\\.\`, `\??\` (also with `/`), then UNC, else rooted-without-drive.
            let ends_prefix = |i: usize| b.get(i).is_none_or(|&c| is_sep(c));
            if b.get(1).is_some_and(|&c| is_sep(c)) {
                if matches!(b.get(2), Some(b'?' | b'.')) && ends_prefix(3) {
                    return Err(WinPathError::DevicePath);
                }
                return Err(WinPathError::Unc);
            }
            if b.get(1) == Some(&b'?') && b.get(2) == Some(&b'?') && ends_prefix(3) {
                return Err(WinPathError::DevicePath);
            }
            return Err(WinPathError::NoDrive);
        }
        if !(first.is_ascii_alphabetic() && b.get(1) == Some(&b':')) {
            return Err(WinPathError::NoDrive);
        }
        // Bytes 0 and 1 are ASCII, so slicing at 2 and 3 is on char boundaries.
        let rest = &s[2..];
        if !rest.as_bytes().first().is_some_and(|&c| is_sep(c)) {
            return Err(WinPathError::DriveRelative);
        }
        let rest = &rest[1..];
        let mut components = Vec::new();
        if !rest.is_empty() {
            for c in rest.split(['\\', '/']) {
                if c == "." {
                    continue;
                }
                check_component(c)?;
                if components.len() == MAX_COMPONENTS {
                    return Err(WinPathError::TooManyComponents);
                }
                components.push(c.to_owned());
            }
        }
        Ok(WinPath {
            drive: first.to_ascii_uppercase() as char,
            components,
        })
    }

    /// The drive letter, uppercase `A`..=`Z`.
    pub fn drive(&self) -> char {
        self.drive
    }

    /// The validated components, without the drive; empty for the drive root.
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

impl fmt::Display for WinPath {
    /// The canonical form: uppercase drive, `\` separators, no `.`, no trailing separator (`C:\` for the root).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.drive)?;
        if self.components.is_empty() {
            return f.write_str("\\");
        }
        for c in &self.components {
            write!(f, "\\{c}")?;
        }
        Ok(())
    }
}

/// Why a [`WinPath`] could not be mapped onto the host. Carries no untrusted text.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("drive is not mapped (only C: exists in a prefix)")]
    UnmappedDrive,
    #[error("the drive root is a symbolic link")]
    RootIsSymlink,
    #[error("the drive root is not a directory")]
    RootNotDirectory,
    #[error("path component is not a plain file name")]
    InvalidComponent,
    #[error("path does not exist")]
    NotFound,
    #[error("path goes through a symbolic link")]
    Symlink,
    #[error("a path component is not a directory")]
    NotADirectory,
    #[error("path names a special file (not a regular file or directory)")]
    SpecialFile,
    #[error("more than one directory entry matches this name ignoring case")]
    Ambiguous,
    #[error("directory has more than {max} entries")]
    TooManyEntries { max: usize },
    #[error("i/o error while resolving path: {0}")]
    Io(#[from] io::Error),
}

/// A component that is safe to append to a host path: one plain segment. `WinPath` already guarantees this; it
/// is re-checked here so containment does not depend on an invariant held elsewhere.
fn is_plain_name(c: &str) -> bool {
    !c.is_empty() && c != "." && c != ".." && !c.contains(['/', '\\', '\0'])
}

fn fold(s: &str) -> String {
    s.to_lowercase()
}

/// Finds the entry of `dir` named `want`: the exact name, else the only case-insensitive match. Entries whose names
/// are not UTF-8 can never equal a `&str` and are skipped (but count towards the cap).
fn find_entry(dir: &Path, want: &str, max_entries: usize) -> Result<Option<OsString>, ResolveError> {
    let folded = fold(want);
    let mut exact = None;
    let mut similar: Option<OsString> = None;
    let mut ambiguous = false;
    for (n, entry) in fs::read_dir(dir)?.enumerate() {
        if n >= max_entries {
            return Err(ResolveError::TooManyEntries { max: max_entries });
        }
        let name = entry?.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if s == want {
            exact = Some(name);
        } else if fold(s) == folded {
            ambiguous = similar.is_some();
            similar.get_or_insert(name);
        }
    }
    // Exact wins (Wine resolves the same way); only the case-insensitive fallback can be ambiguous.
    match (exact, similar, ambiguous) {
        (Some(name), _, _) => Ok(Some(name)),
        (None, Some(_), true) => Err(ResolveError::Ambiguous),
        (None, similar, _) => Ok(similar),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Every component must exist.
    Existing,
    /// Components may be missing from the first missing one onwards.
    Create,
}

fn walk(root: &Path, p: &WinPath, mode: Mode, max_entries: usize) -> Result<PathBuf, ResolveError> {
    if p.drive != 'C' {
        return Err(ResolveError::UnmappedDrive);
    }
    if !p.components.iter().all(|c| is_plain_name(c)) {
        return Err(ResolveError::InvalidComponent);
    }
    let root_type = fs::symlink_metadata(root)?.file_type();
    if root_type.is_symlink() {
        return Err(ResolveError::RootIsSymlink);
    }
    if !root_type.is_dir() {
        return Err(ResolveError::RootNotDirectory);
    }
    let mut cur = root.to_path_buf();
    let mut missing = false;
    for (i, comp) in p.components.iter().enumerate() {
        if missing {
            cur.push(comp);
            continue;
        }
        let Some(real) = find_entry(&cur, comp, max_entries)? else {
            if mode == Mode::Existing {
                return Err(ResolveError::NotFound);
            }
            missing = true;
            cur.push(comp);
            continue;
        };
        cur.push(real);
        let file_type = fs::symlink_metadata(&cur)?.file_type();
        if file_type.is_symlink() {
            return Err(ResolveError::Symlink);
        }
        if i + 1 < p.components.len() {
            if !file_type.is_dir() {
                return Err(ResolveError::NotADirectory);
            }
        } else if !(file_type.is_file() || file_type.is_dir()) {
            return Err(ResolveError::SpecialFile);
        }
    }
    Ok(cur)
}

/// Maps `p` (drive `C:`) onto the EXISTING file or directory under `root`, matching every component against the
/// real listing (see the module docs). Refuses symlinks anywhere, including at the last component and in `root`
/// itself. The returned path is `root` joined with the real on-disk names. A missing component is
/// [`ResolveError::NotFound`]; callers decide what that means. Read-only; subject to the TOCTOU limit in the
/// module docs.
pub fn resolve_under(root: &Path, p: &WinPath) -> Result<PathBuf, ResolveError> {
    walk(root, p, Mode::Existing, MAX_DIR_ENTRIES)
}

/// Maps `p` (drive `C:`) onto a destination under `root` for creating a file. Existing components are matched
/// like [`resolve_under`] (so `c:\program files\x` reuses `Program Files`) and may not be symlinks; from the first
/// missing component on, the validated text is used verbatim. Creates nothing. The caller must still create files
/// without following links (`create_new`) because of the TOCTOU limit in the module docs.
pub fn join_new(root: &Path, p: &WinPath) -> Result<PathBuf, ResolveError> {
    walk(root, p, Mode::Create, MAX_DIR_ENTRIES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Component;

    fn ok(s: &str) -> WinPath {
        WinPath::parse(s)
            .unwrap_or_else(|e| panic!("{:?} should be accepted: {e}", s.chars().take(60).collect::<String>()))
    }

    fn check_rejects(cases: Vec<(String, WinPathError)>) {
        for (input, want) in cases {
            let shown: String = input.chars().take(40).collect();
            assert_eq!(WinPath::parse(&input), Err(want), "input {shown:?}");
        }
    }

    fn cases(list: &[(&str, WinPathError)]) -> Vec<(String, WinPathError)> {
        list.iter().map(|(s, e)| ((*s).to_owned(), e.clone())).collect()
    }

    // ---------------------------------------------------------------- parse: accepted forms

    #[test]
    fn parse_accepts_and_canonicalises() {
        let mixed = "C:\\a/b\\c/d";
        let table: Vec<(&str, &str)> = vec![
            ("C:\\dir\\file.exe", "C:\\dir\\file.exe"),
            ("C:/dir/file.exe", "C:\\dir\\file.exe"),
            ("c:\\dir", "C:\\dir"),
            ("c:/dir", "C:\\dir"),
            (mixed, "C:\\a\\b\\c\\d"),
            ("C:\\", "C:\\"),
            ("C:/", "C:\\"),
            ("C:\\.", "C:\\"),
            ("C:\\.\\a\\.\\b\\.", "C:\\a\\b"),
            ("Z:\\x", "Z:\\x"),
            ("a:\\x", "A:\\x"),
            (
                "C:\\Program Files (x86)\\My App\\app.exe",
                "C:\\Program Files (x86)\\My App\\app.exe",
            ),
            ("C:\\a b.txt", "C:\\a b.txt"),
            ("C:\\ lead", "C:\\ lead"),
            ("C:\\.hidden", "C:\\.hidden"),
            ("C:\\a..b", "C:\\a..b"),
            ("C:\\file.tar.gz", "C:\\file.tar.gz"),
            ("C:\\PROGRA~1\\APP~1.EXE", "C:\\PROGRA~1\\APP~1.EXE"),
            (
                "C:\\\u{e9}\\\u{65e5}\u{672c}\u{8a9e}",
                "C:\\\u{e9}\\\u{65e5}\u{672c}\u{8a9e}",
            ),
            (
                "C:\\a$b\\a,b;c=d\\[x]\\'q'\\a%2fb\\a~",
                "C:\\a$b\\a,b;c=d\\[x]\\'q'\\a%2fb\\a~",
            ),
            // Look-alikes of reserved names and separators that are NOT reserved.
            (
                "C:\\console\\comm\\com10\\lpt\\nulls.txt\\aux2\\con-x\\xcon",
                "C:\\console\\comm\\com10\\lpt\\nulls.txt\\aux2\\con-x\\xcon",
            ),
            ("C:\\\u{ff23}\u{ff2f}\u{ff2e}", "C:\\\u{ff23}\u{ff2f}\u{ff2e}"), // fullwidth CON
            ("C:\\\u{ff0e}\u{ff0e}", "C:\\\u{ff0e}\u{ff0e}"),                 // fullwidth ".."
            ("C:\\a\u{ff3c}b", "C:\\a\u{ff3c}b"),                             // fullwidth backslash
            ("C:\\com\u{b9}\u{b9}", "C:\\com\u{b9}\u{b9}"),
        ];
        for (input, canonical) in table {
            assert_eq!(ok(input).to_string(), canonical, "input {input:?}");
        }
    }

    #[test]
    fn parse_exposes_uppercase_drive_and_components() {
        let p = ok("c:/Dir/.\\File.EXE");
        assert_eq!(p.drive(), 'C');
        assert_eq!(p.components(), ["Dir".to_owned(), "File.EXE".to_owned()]);
        assert_eq!(ok("d:\\").drive(), 'D');
        assert!(ok("C:\\").components().is_empty());
    }

    // ---------------------------------------------------------------- parse: rejections

    #[test]
    fn rejects_empty_and_relative_and_rooted_paths() {
        check_rejects(cases(&[
            ("", WinPathError::Empty),
            (" ", WinPathError::NoDrive),
            ("dir\\file.exe", WinPathError::NoDrive),
            ("file.exe", WinPathError::NoDrive),
            (".\\a", WinPathError::NoDrive),
            ("..\\a", WinPathError::NoDrive),
            ("\\dir", WinPathError::NoDrive),
            ("/dir", WinPathError::NoDrive),
            ("/etc/passwd", WinPathError::NoDrive),
            ("\\", WinPathError::NoDrive),
            ("/", WinPathError::NoDrive),
            ("1:\\a", WinPathError::NoDrive),
            ("\u{e9}:\\a", WinPathError::NoDrive),
            ("CC:\\a", WinPathError::NoDrive),
            (":\\a", WinPathError::NoDrive),
            ("\\?\\C:\\a", WinPathError::NoDrive),
        ]));
    }

    #[test]
    fn rejects_drive_relative_paths() {
        check_rejects(cases(&[
            ("C:", WinPathError::DriveRelative),
            ("c:", WinPathError::DriveRelative),
            ("C:foo", WinPathError::DriveRelative),
            ("C:foo\\bar", WinPathError::DriveRelative),
            ("c:..\\x", WinPathError::DriveRelative),
            ("C:.", WinPathError::DriveRelative),
            ("C:\u{e9}", WinPathError::DriveRelative),
        ]));
    }

    #[test]
    fn rejects_unc_paths() {
        check_rejects(cases(&[
            ("\\\\server\\share", WinPathError::Unc),
            ("//server/share", WinPathError::Unc),
            ("\\/server\\share", WinPathError::Unc),
            ("/\\server/share", WinPathError::Unc),
            ("\\\\server", WinPathError::Unc),
            ("\\\\", WinPathError::Unc),
            ("\\\\.foo\\x", WinPathError::Unc),
            ("\\\\?x\\y", WinPathError::Unc),
        ]));
    }

    #[test]
    fn rejects_device_and_nt_namespace_paths_including_wine_unix_escape() {
        check_rejects(cases(&[
            ("\\\\?\\C:\\x", WinPathError::DevicePath),
            ("\\\\.\\C:\\x", WinPathError::DevicePath),
            ("\\??\\C:\\x", WinPathError::DevicePath),
            ("\\\\?\\unix\\etc\\passwd", WinPathError::DevicePath),
            ("\\\\?\\UNC\\srv\\share", WinPathError::DevicePath),
            ("//?/C:/x", WinPathError::DevicePath),
            ("\\\\.\\pipe\\x", WinPathError::DevicePath),
            ("\\\\?", WinPathError::DevicePath),
            ("\\\\.", WinPathError::DevicePath),
            ("/??/C:/x", WinPathError::DevicePath),
            ("\\??", WinPathError::DevicePath),
            // The same forms hidden after a drive are empty components, never a device path.
            ("C:\\\\?\\unix\\etc", WinPathError::EmptyComponent),
            ("C:\\??\\x", WinPathError::IllegalChar('?')),
        ]));
    }

    #[test]
    fn rejects_parent_dir_components() {
        // `..` is refused outright, never normalised, wherever it appears.
        check_rejects(cases(&[
            ("C:\\..", WinPathError::ParentDir),
            ("C:\\a\\..\\b", WinPathError::ParentDir),
            ("C:\\a\\..", WinPathError::ParentDir),
            ("C:/../x", WinPathError::ParentDir),
            ("C:\\..\\..\\Windows", WinPathError::ParentDir),
            ("C:\\a/../../b", WinPathError::ParentDir),
            ("C:\\.\\..\\x", WinPathError::ParentDir),
            ("C:\\a\\.\\..\\..", WinPathError::ParentDir),
        ]));
        // Dot lookalikes that are not `..` are ordinary names or other errors, never traversal.
        check_rejects(cases(&[
            ("C:\\...", WinPathError::TrailingDotOrSpace),
            ("C:\\.. ", WinPathError::TrailingDotOrSpace),
            ("C:\\ ..", WinPathError::TrailingDotOrSpace),
            ("C:\\..\\", WinPathError::ParentDir),
            ("C:\\..:x", WinPathError::AlternateStream),
        ]));
    }

    #[test]
    fn rejects_empty_components_and_trailing_separators() {
        check_rejects(cases(&[
            ("C:\\a\\\\b", WinPathError::EmptyComponent),
            ("C:\\\\a", WinPathError::EmptyComponent),
            ("C:\\a\\", WinPathError::EmptyComponent),
            ("C:/a//b", WinPathError::EmptyComponent),
            ("C:\\a/", WinPathError::EmptyComponent),
            ("C:\\\\", WinPathError::EmptyComponent),
            ("C:\\.\\", WinPathError::EmptyComponent),
            ("C://", WinPathError::EmptyComponent),
            ("C:\\a\\/b", WinPathError::EmptyComponent),
        ]));
    }

    #[test]
    fn rejects_nul_and_control_characters() {
        check_rejects(cases(&[
            ("C:\\a\0b", WinPathError::ControlChar('\0')),
            ("C:\\\0", WinPathError::ControlChar('\0')),
            ("C:\\a\nb", WinPathError::ControlChar('\n')),
            ("C:\\a\rb", WinPathError::ControlChar('\r')),
            ("C:\\a\tb", WinPathError::ControlChar('\t')),
            ("C:\\a\x1bb", WinPathError::ControlChar('\x1b')),
            ("C:\\a\x01", WinPathError::ControlChar('\x01')),
            ("C:\\a\x7fb", WinPathError::ControlChar('\x7f')),
            ("C:\\a\u{85}b", WinPathError::ControlChar('\u{85}')),
            ("C:\\a\u{9f}", WinPathError::ControlChar('\u{9f}')),
            ("C:\\ok\\a\0", WinPathError::ControlChar('\0')),
        ]));
    }

    #[test]
    fn rejects_wildcard_and_illegal_characters() {
        check_rejects(cases(&[
            ("C:\\a<b", WinPathError::IllegalChar('<')),
            ("C:\\a>b", WinPathError::IllegalChar('>')),
            ("C:\\a\"b", WinPathError::IllegalChar('"')),
            ("C:\\a|b", WinPathError::IllegalChar('|')),
            ("C:\\a?b", WinPathError::IllegalChar('?')),
            ("C:\\a*b", WinPathError::IllegalChar('*')),
            ("C:\\*.exe", WinPathError::IllegalChar('*')),
            ("C:\\dir\\?", WinPathError::IllegalChar('?')),
        ]));
    }

    #[test]
    fn rejects_alternate_data_streams() {
        check_rejects(cases(&[
            ("C:\\a.txt:stream", WinPathError::AlternateStream),
            ("C:\\::$DATA", WinPathError::AlternateStream),
            ("C:\\a:b", WinPathError::AlternateStream),
            ("C:\\a.txt::$DATA", WinPathError::AlternateStream),
            ("C:\\dir:$I30:$INDEX_ALLOCATION", WinPathError::AlternateStream),
            ("C:\\:", WinPathError::AlternateStream),
            ("C:\\C:\\x", WinPathError::AlternateStream),
            ("C:\\a\\b.txt:", WinPathError::AlternateStream),
        ]));
    }

    #[test]
    fn rejects_trailing_dots_and_spaces() {
        check_rejects(cases(&[
            ("C:\\a.", WinPathError::TrailingDotOrSpace),
            ("C:\\a ", WinPathError::TrailingDotOrSpace),
            ("C:\\a...", WinPathError::TrailingDotOrSpace),
            ("C:\\...", WinPathError::TrailingDotOrSpace),
            ("C:\\a. ", WinPathError::TrailingDotOrSpace),
            ("C:\\a .", WinPathError::TrailingDotOrSpace),
            ("C:\\ ", WinPathError::TrailingDotOrSpace),
            ("C:\\. ", WinPathError::TrailingDotOrSpace),
            ("C:\\dir.\\x", WinPathError::TrailingDotOrSpace),
            ("C:\\dir \\x", WinPathError::TrailingDotOrSpace),
            ("C:\\con.", WinPathError::TrailingDotOrSpace),
        ]));
    }

    #[test]
    fn rejects_reserved_device_names() {
        let mut list: Vec<String> = Vec::new();
        for name in [
            "con", "CON", "Con", "cOn", "prn", "PRN", "aux", "AUX", "nul", "NUL", "Nul",
        ] {
            list.push(format!("C:\\{name}"));
            list.push(format!("C:\\{name}.txt"));
            list.push(format!("C:\\dir\\{name}.tar.gz"));
            list.push(format!("C:\\{name}\\file"));
        }
        for n in 0..=9 {
            for base in ["com", "COM", "Com", "lpt", "LPT", "Lpt"] {
                list.push(format!("C:\\{base}{n}"));
                list.push(format!("C:\\{base}{n}.log"));
            }
        }
        for sup in ['\u{b9}', '\u{b2}', '\u{b3}'] {
            list.push(format!("C:\\COM{sup}"));
            list.push(format!("C:\\lpt{sup}.txt"));
        }
        for extra in [
            "conin$",
            "CONIN$",
            "conout$",
            "CONOUT$.x",
            "con .txt",
            "nul  .txt",
            "aux.a.b.c",
        ] {
            list.push(format!("C:\\{extra}"));
        }
        for input in list {
            assert_eq!(
                WinPath::parse(&input),
                Err(WinPathError::ReservedName),
                "input {input:?}"
            );
        }
    }

    #[test]
    fn component_length_cap_is_exact_and_counts_bytes() {
        assert!(WinPath::parse(&format!("C:\\{}", "a".repeat(255))).is_ok());
        assert_eq!(
            WinPath::parse(&format!("C:\\{}", "a".repeat(256))),
            Err(WinPathError::ComponentTooLong)
        );
        // 127 x 2-byte chars = 254 bytes fits; 128 = 256 bytes does not (Linux NAME_MAX counts bytes).
        assert!(WinPath::parse(&format!("C:\\{}", "\u{e9}".repeat(127))).is_ok());
        assert_eq!(
            WinPath::parse(&format!("C:\\{}", "\u{e9}".repeat(128))),
            Err(WinPathError::ComponentTooLong)
        );
        // Also in a middle component.
        assert_eq!(
            WinPath::parse(&format!("C:\\ok\\{}\\ok", "a".repeat(300))),
            Err(WinPathError::ComponentTooLong)
        );
    }

    #[test]
    fn component_count_cap_is_exact_and_ignores_dot_components() {
        let comps = |n: usize| vec!["a"; n].join("\\");
        assert_eq!(ok(&format!("C:\\{}", comps(128))).components().len(), 128);
        assert_eq!(
            WinPath::parse(&format!("C:\\{}", comps(129))),
            Err(WinPathError::TooManyComponents)
        );
        // `.` components are dropped before counting.
        let dotted = [".", "a"].repeat(64).join("\\") + &"\\.".repeat(300);
        assert_eq!(ok(&format!("C:\\{dotted}")).components().len(), 64);
        let dotted = [".", "a"].repeat(128).join("\\");
        assert_eq!(ok(&format!("C:\\{dotted}")).components().len(), 128);
    }

    #[test]
    fn total_length_cap_is_checked_first_and_is_exact() {
        // 127 components of 255 bytes plus one of 252: exactly 32_767 bytes, every other cap satisfied.
        let build = |last: usize| {
            let mut s = String::from("C:");
            for _ in 0..127 {
                s.push('\\');
                s.push_str(&"a".repeat(255));
            }
            s.push('\\');
            s.push_str(&"b".repeat(last));
            s
        };
        let at_cap = build(252);
        assert_eq!(at_cap.len(), MAX_TOTAL_LEN);
        assert_eq!(ok(&at_cap).components().len(), 128);
        // One byte more: TooLong, even though the component count and lengths would be the next complaint.
        let over = build(253);
        assert_eq!(
            WinPath::parse(&over),
            Err(WinPathError::TooLong { len: MAX_TOTAL_LEN + 1 })
        );
        // Rejected as too long before anything else looks at the content: these would otherwise fail differently.
        let many = format!("C:\\{}", "a\\".repeat(20_000));
        assert_eq!(WinPath::parse(&many), Err(WinPathError::TooLong { len: many.len() }));
        let nul = format!("C:\\{}", "\0".repeat(MAX_TOTAL_LEN));
        assert_eq!(WinPath::parse(&nul), Err(WinPathError::TooLong { len: nul.len() }));
        let huge = format!("C:\\{}", "a".repeat(4 * 1024 * 1024));
        assert_eq!(WinPath::parse(&huge), Err(WinPathError::TooLong { len: huge.len() }));
        let unc = "\\".repeat(MAX_TOTAL_LEN + 1);
        assert!(matches!(WinPath::parse(&unc), Err(WinPathError::TooLong { .. })));
    }

    #[test]
    fn display_is_canonical_and_round_trips() {
        for s in [
            "c:/a/./b",
            "C:\\a\\b",
            "C:\\",
            "z:\\Program Files\\App.exe",
            "C:\\\u{e9}\\\u{65e5}",
        ] {
            let p = ok(s);
            let shown = p.to_string();
            assert!(shown.starts_with(p.drive()));
            assert_eq!(ok(&shown), p, "round trip of {s:?}");
            assert_eq!(ok(&shown).to_string(), shown);
        }
        assert_eq!(ok("c:/a/./b").to_string(), "C:\\a\\b");
    }

    #[test]
    fn error_messages_do_not_echo_raw_control_characters() {
        for input in [
            "C:\\a\0b",
            "C:\\a\x1b[31mb",
            "C:\\a\u{85}",
            "C:\\a\u{202e}\0",
            "C:\\a\rb",
        ] {
            let msg = WinPath::parse(input).unwrap_err().to_string();
            assert!(!msg.chars().any(char::is_control), "raw control char in {msg:?}");
        }
    }

    // ---------------------------------------------------------------- filesystem fixtures

    struct Fx {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        root: PathBuf,
        outside: PathBuf,
    }

    impl Fx {
        /// `base/drive_c` (the root under test, empty) and `base/outside` (holds `secret.txt` and `sub/`).
        fn new() -> Fx {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().to_path_buf();
            let root = base.join("drive_c");
            let outside = base.join("outside");
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(outside.join("sub")).unwrap();
            fs::write(outside.join("secret.txt"), "secret").unwrap();
            Fx {
                _tmp: tmp,
                base,
                root,
                outside,
            }
        }

        fn file(&self, rel: &str) {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "x").unwrap();
        }

        fn dir(&self, rel: &str) {
            fs::create_dir_all(self.root.join(rel)).unwrap();
        }

        fn link(&self, rel: &str, target: &Path) {
            let path = self.root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            symlink(target, path).unwrap();
        }

        fn resolve(&self, s: &str) -> Result<PathBuf, ResolveError> {
            resolve_under(&self.root, &ok(s))
        }

        fn join(&self, s: &str) -> Result<PathBuf, ResolveError> {
            join_new(&self.root, &ok(s))
        }
    }

    /// Every entry under `base` with its kind (symlinks not followed), to prove nothing was created or changed.
    fn snapshot(base: &Path) -> BTreeSet<String> {
        fn go(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let md = fs::symlink_metadata(&path).unwrap();
                let kind = if md.file_type().is_symlink() {
                    format!("link->{}", fs::read_link(&path).unwrap().display())
                } else if md.is_dir() {
                    "dir".to_owned()
                } else {
                    format!("file:{}", md.len())
                };
                out.insert(format!("{} {kind}", path.strip_prefix(base).unwrap().display()));
                if md.is_dir() {
                    go(&path, base, out);
                }
            }
        }
        let mut out = BTreeSet::new();
        go(base, base, &mut out);
        out
    }

    // ---------------------------------------------------------------- resolve_under

    #[test]
    fn resolve_finds_exact_and_case_insensitive_matches_and_returns_real_names() {
        let fx = Fx::new();
        fx.file("Program Files/app.exe");
        let want = fx.root.join("Program Files").join("app.exe");
        assert_eq!(fx.resolve("C:\\Program Files\\app.exe").unwrap(), want);
        assert_eq!(fx.resolve("c:\\program files\\App.EXE").unwrap(), want);
        assert_eq!(fx.resolve("C:/PROGRAM FILES/APP.EXE").unwrap(), want);
        assert_eq!(fx.resolve("C:\\Program Files\\.\\app.exe").unwrap(), want);
        assert_eq!(fx.resolve("C:\\Program Files").unwrap(), fx.root.join("Program Files"));
    }

    #[test]
    fn resolve_of_the_drive_root_is_the_root() {
        let fx = Fx::new();
        assert_eq!(fx.resolve("C:\\").unwrap(), fx.root);
        assert_eq!(fx.join("C:\\").unwrap(), fx.root);
    }

    #[test]
    fn resolve_case_folding_is_unicode_lowercase_on_both_sides() {
        let fx = Fx::new();
        fx.file("\u{dc}n\u{ef}.txt");
        assert_eq!(
            fx.resolve("C:\\\u{fc}N\u{cf}.TXT").unwrap(),
            fx.root.join("\u{dc}n\u{ef}.txt")
        );
        // No normalisation: the decomposed spelling is a different name.
        assert!(matches!(
            fx.resolve("C:\\U\u{308}n\u{ef}.txt"),
            Err(ResolveError::NotFound)
        ));
    }

    #[test]
    fn resolve_missing_components_are_not_found() {
        let fx = Fx::new();
        fx.file("dir/a.txt");
        assert!(matches!(fx.resolve("C:\\dir\\b.txt"), Err(ResolveError::NotFound)));
        assert!(matches!(fx.resolve("C:\\nodir\\b.txt"), Err(ResolveError::NotFound)));
        assert!(matches!(fx.resolve("C:\\nothing"), Err(ResolveError::NotFound)));
    }

    #[test]
    fn short_names_and_lookalike_dots_are_literal_names_never_expanded() {
        let fx = Fx::new();
        fx.file("Program Files/app.exe");
        assert!(matches!(
            fx.resolve("C:\\PROGRA~1\\app.exe"),
            Err(ResolveError::NotFound)
        ));
        // Fullwidth dots are two ordinary characters, not `..`: nothing matches, and a destination stays inside.
        assert!(matches!(
            fx.resolve("C:\\\u{ff0e}\u{ff0e}\\x"),
            Err(ResolveError::NotFound)
        ));
        let dest = fx.join("C:\\\u{ff0e}\u{ff0e}\\x").unwrap();
        assert_eq!(dest, fx.root.join("\u{ff0e}\u{ff0e}").join("x"));
        assert!(dest.components().all(|c| c != Component::ParentDir));
    }

    #[test]
    fn unmapped_drives_are_refused_before_touching_the_filesystem() {
        let nowhere = Path::new("/nonexistent/for/sure/drive_c");
        for s in ["D:\\x", "Z:\\", "a:\\x"] {
            assert!(matches!(
                resolve_under(nowhere, &ok(s)),
                Err(ResolveError::UnmappedDrive)
            ));
            assert!(matches!(join_new(nowhere, &ok(s)), Err(ResolveError::UnmappedDrive)));
        }
    }

    #[test]
    fn ambiguous_case_variants_are_an_error() {
        let fx = Fx::new();
        fx.file("ci/A.txt");
        fx.file("ci/a.txt");
        fx.file("Dir/x");
        fx.file("dir/y");
        // Two entries differ only by case and the request matches neither exactly: refuse to guess.
        assert!(matches!(fx.resolve("C:\\ci\\A.TXT"), Err(ResolveError::Ambiguous)));
        assert!(matches!(fx.join("C:\\ci\\A.TXT"), Err(ResolveError::Ambiguous)));
        assert!(matches!(fx.resolve("C:\\DIR\\x"), Err(ResolveError::Ambiguous)));
        assert!(matches!(fx.join("C:\\DIR\\new"), Err(ResolveError::Ambiguous)));
        // An exact spelling is unambiguous (same as Wine): it resolves to exactly that entry.
        assert_eq!(fx.resolve("C:\\ci\\A.txt").unwrap(), fx.root.join("ci").join("A.txt"));
        assert_eq!(fx.resolve("C:\\ci\\a.txt").unwrap(), fx.root.join("ci").join("a.txt"));
        assert_eq!(fx.resolve("C:\\Dir\\x").unwrap(), fx.root.join("Dir").join("x"));
    }

    #[test]
    fn ambiguity_uses_the_same_folding_for_every_entry() {
        // U+212A KELVIN SIGN lowercases to `k`: it collides with `k.txt` and `K.txt` under to_lowercase.
        let fx = Fx::new();
        fx.file("\u{212a}.txt");
        fx.file("k.txt");
        assert!(matches!(fx.resolve("C:\\K.TXT"), Err(ResolveError::Ambiguous)));
        assert_eq!(fx.resolve("C:\\k.txt").unwrap(), fx.root.join("k.txt"));
    }

    #[test]
    fn non_utf8_entries_are_ignored_not_fatal() {
        use std::os::unix::ffi::OsStrExt;
        let fx = Fx::new();
        fx.file("good.txt");
        fs::write(fx.root.join(std::ffi::OsStr::from_bytes(b"bad\xff.txt")), "x").unwrap();
        assert_eq!(fx.resolve("C:\\GOOD.txt").unwrap(), fx.root.join("good.txt"));
        assert!(matches!(fx.resolve("C:\\bad.txt"), Err(ResolveError::NotFound)));
        assert_eq!(fx.join("C:\\new.txt").unwrap(), fx.root.join("new.txt"));
    }

    #[test]
    fn resolve_refuses_symlink_components_everywhere() {
        let fx = Fx::new();
        fx.file("real/inner.txt");
        fx.link("out", &fx.outside); // directory link pointing outside the root
        fx.link("Nested/deep/out2", &fx.outside);
        fx.link("outfile", &fx.outside.join("secret.txt")); // file link pointing outside
        fx.link("in", Path::new("real")); // relative link that stays inside the root
        fx.link("inabs", &fx.root.join("real")); // absolute link that stays inside the root
        fx.link("dangling", Path::new("nowhere"));
        fx.link("loop", Path::new("loop"));
        for s in [
            "C:\\out",             // last component is a link
            "C:\\out\\secret.txt", // link in the middle
            "C:\\OUT\\secret.txt", // matched case-insensitively, still a link
            "C:\\out\\sub",        // through the link to a directory
            "C:\\Nested\\deep\\out2\\secret.txt",
            "C:\\outfile",
            "C:\\in\\inner.txt", // inside links are refused too
            "C:\\in",
            "C:\\inabs\\inner.txt",
            "C:\\dangling",
            "C:\\loop",
            "C:\\loop\\x",
        ] {
            assert!(
                matches!(fx.resolve(s), Err(ResolveError::Symlink)),
                "{s} must be refused as a symlink, got {:?}",
                fx.resolve(s)
            );
        }
        // The real target is fine, so the refusal is about the link.
        assert!(fx.resolve("C:\\real\\inner.txt").is_ok());
    }

    #[test]
    fn root_that_is_a_symlink_is_refused() {
        let fx = Fx::new();
        let link_root = fx.base.join("link_root");
        symlink(&fx.outside, &link_root).unwrap();
        for s in ["C:\\", "C:\\secret.txt", "C:\\sub"] {
            assert!(matches!(
                resolve_under(&link_root, &ok(s)),
                Err(ResolveError::RootIsSymlink)
            ));
            assert!(matches!(join_new(&link_root, &ok(s)), Err(ResolveError::RootIsSymlink)));
        }
    }

    #[test]
    fn root_must_exist_and_be_a_directory() {
        let fx = Fx::new();
        let missing = fx.base.join("missing");
        assert!(matches!(
            resolve_under(&missing, &ok("C:\\x")),
            Err(ResolveError::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
        let file_root = fx.outside.join("secret.txt");
        assert!(matches!(
            resolve_under(&file_root, &ok("C:\\x")),
            Err(ResolveError::RootNotDirectory)
        ));
        assert!(matches!(
            join_new(&file_root, &ok("C:\\x")),
            Err(ResolveError::RootNotDirectory)
        ));
    }

    #[test]
    fn resolve_through_a_file_is_not_a_directory() {
        let fx = Fx::new();
        fx.file("file.txt");
        assert!(matches!(
            fx.resolve("C:\\file.txt\\x"),
            Err(ResolveError::NotADirectory)
        ));
        assert!(matches!(fx.join("C:\\file.txt\\x"), Err(ResolveError::NotADirectory)));
    }

    #[test]
    fn resolve_refuses_special_files() {
        let fx = Fx::new();
        let _listener = std::os::unix::net::UnixListener::bind(fx.root.join("sock")).unwrap();
        assert!(matches!(fx.resolve("C:\\sock"), Err(ResolveError::SpecialFile)));
        assert!(matches!(fx.join("C:\\sock"), Err(ResolveError::SpecialFile)));
        assert!(matches!(fx.resolve("C:\\sock\\x"), Err(ResolveError::NotADirectory)));
    }

    #[test]
    fn resolve_refuses_hand_built_paths_that_could_escape() {
        // A WinPath can only come from `parse`, but containment must not rest on that invariant alone: build
        // invalid ones directly (possible only inside this module) and require both entry points to refuse.
        let fx = Fx::new();
        fx.dir("a");
        for bad in ["..", ".", "", "a/b", "/etc", "a\\b", "x\0y", "../outside"] {
            let p = WinPath {
                drive: 'C',
                components: vec![bad.to_owned()],
            };
            assert!(
                matches!(resolve_under(&fx.root, &p), Err(ResolveError::InvalidComponent)),
                "resolve_under accepted component {bad:?}"
            );
            assert!(
                matches!(join_new(&fx.root, &p), Err(ResolveError::InvalidComponent)),
                "join_new accepted component {bad:?}"
            );
            // Also after valid components, and when the parent does not exist (missing tail is verbatim).
            let p = WinPath {
                drive: 'C',
                components: vec!["a".to_owned(), bad.to_owned()],
            };
            assert!(matches!(join_new(&fx.root, &p), Err(ResolveError::InvalidComponent)));
            let p = WinPath {
                drive: 'C',
                components: vec!["nope".to_owned(), bad.to_owned()],
            };
            assert!(matches!(join_new(&fx.root, &p), Err(ResolveError::InvalidComponent)));
        }
    }

    #[test]
    fn resolve_result_is_inside_the_root_and_already_real() {
        let fx = Fx::new();
        fx.file("Program Files/App/app.exe");
        let got = fx.resolve("c:\\PROGRAM FILES\\app\\APP.EXE").unwrap();
        assert!(got.starts_with(&fx.root));
        let canon_root = fs::canonicalize(&fx.root).unwrap();
        assert_eq!(
            fs::canonicalize(&got).unwrap(),
            canon_root.join("Program Files/App/app.exe")
        );
    }

    #[test]
    fn directory_entry_cap_is_enforced() {
        assert_eq!(MAX_DIR_ENTRIES, 100_000);
        let fx = Fx::new();
        for i in 0..5 {
            fx.file(&format!("big/f{i}"));
        }
        let p = ok("C:\\big\\f0");
        // Exactly at the cap is fine, one entry over is an error (the cap is a parameter only for testing).
        assert!(walk(&fx.root, &p, Mode::Existing, 5).is_ok());
        assert!(matches!(
            walk(&fx.root, &p, Mode::Existing, 4),
            Err(ResolveError::TooManyEntries { max: 4 })
        ));
        assert!(matches!(
            walk(&fx.root, &p, Mode::Create, 4),
            Err(ResolveError::TooManyEntries { max: 4 })
        ));
        // A miss in a big directory hits the cap too (it does not scan on and report NotFound).
        let miss = ok("C:\\big\\zzz");
        assert!(matches!(
            walk(&fx.root, &miss, Mode::Existing, 3),
            Err(ResolveError::TooManyEntries { max: 3 })
        ));
    }

    #[test]
    fn directory_entry_cap_holds_at_the_real_limit() {
        // Through the public API with the real cap: exactly MAX_DIR_ENTRIES entries is fine, one more is an error.
        let fx = Fx::new();
        let dir = fx.root.join("huge");
        fs::create_dir(&dir).unwrap();
        for i in 0..MAX_DIR_ENTRIES {
            fs::write(dir.join(format!("f{i}")), "").unwrap();
        }
        assert!(fx.resolve("C:\\huge\\f5").is_ok());
        fs::write(dir.join("one_more"), "").unwrap();
        assert!(matches!(
            fx.resolve("C:\\huge\\f5"),
            Err(ResolveError::TooManyEntries { max: MAX_DIR_ENTRIES })
        ));
        assert!(matches!(
            fx.join("C:\\huge\\new"),
            Err(ResolveError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn unreadable_directories_report_io_errors() {
        let fx = Fx::new();
        fx.file("locked/x");
        let locked = fx.root.join("locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = fs::read_dir(&locked).is_ok(); // running as root
        let got = fx.resolve("C:\\locked\\x");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        if !readable_anyway {
            assert!(
                matches!(&got, Err(ResolveError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied),
                "got {got:?}"
            );
        }
    }

    // ---------------------------------------------------------------- join_new

    #[test]
    fn join_new_allows_missing_components_and_creates_nothing() {
        let fx = Fx::new();
        let before = snapshot(&fx.base);
        assert_eq!(
            fx.join("C:\\a\\B\\c.txt").unwrap(),
            fx.root.join("a").join("B").join("c.txt")
        );
        assert_eq!(snapshot(&fx.base), before, "join_new must not create anything");
    }

    #[test]
    fn join_new_reuses_existing_components_case_insensitively_then_uses_text_verbatim() {
        let fx = Fx::new();
        fx.dir("Program Files");
        let before = snapshot(&fx.base);
        assert_eq!(
            fx.join("c:\\PROGRAM files\\New Dir\\X.EXE").unwrap(),
            fx.root.join("Program Files").join("New Dir").join("X.EXE")
        );
        assert_eq!(snapshot(&fx.base), before);
    }

    #[test]
    fn join_new_of_an_existing_file_returns_its_path() {
        let fx = Fx::new();
        fx.file("dir/App.exe");
        assert_eq!(
            fx.join("C:\\DIR\\app.exe").unwrap(),
            fx.root.join("dir").join("App.exe")
        );
    }

    #[test]
    fn join_new_refuses_to_pass_through_existing_symlinks() {
        let fx = Fx::new();
        fx.link("out", &fx.outside);
        fx.link("existing", &fx.outside.join("secret.txt"));
        fx.link("dangling", Path::new("nowhere/file"));
        fx.dir("real");
        fx.link("real/sub", &fx.outside.join("sub"));
        let before = snapshot(&fx.base);
        for s in [
            "C:\\out\\new.txt",           // parent is a link to outside
            "C:\\OUT\\deep\\er\\new.txt", // the missing tail must not hide the link
            "C:\\out",                    // destination itself is a link
            "C:\\existing",               // link to an outside file: creating would write through it
            "C:\\dangling",               // dangling link: creating would write through it
            "C:\\real\\sub\\x",
        ] {
            assert!(
                matches!(fx.join(s), Err(ResolveError::Symlink)),
                "{s} must be refused, got {:?}",
                fx.join(s)
            );
        }
        assert_eq!(
            snapshot(&fx.base),
            before,
            "nothing may be created, least of all outside the root"
        );
    }

    // ---------------------------------------------------------------- fuzz

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn pick<'a, T>(state: &mut u64, items: &'a [T]) -> &'a T {
        &items[(xorshift(state) % items.len() as u64) as usize]
    }

    /// Independent re-statement of the component rules, written differently from `check_component`.
    fn assert_component_is_valid(c: &str) {
        assert!(!c.is_empty() && c != "." && c != "..", "component {c:?}");
        assert!(c.len() <= 255, "component too long");
        assert!(
            !c.chars().any(|ch| ch.is_control() || "<>:\"|?*/\\".contains(ch)),
            "bad character in {c:?}"
        );
        assert!(!c.ends_with(' ') && !c.ends_with('.'), "trailing space/dot in {c:?}");
        let lower = c.to_lowercase();
        let stem = lower.split('.').next().unwrap().trim_end_matches(' ');
        let devices = ["con", "prn", "aux", "nul", "conin$", "conout$"];
        assert!(!devices.contains(&stem), "reserved name {c:?}");
        for prefix in ["com", "lpt"] {
            if let Some(n) = stem.strip_prefix(prefix) {
                assert!(
                    !(n.chars().count() == 1 && "0123456789\u{b9}\u{b2}\u{b3}".contains(n)),
                    "reserved name {c:?}"
                );
            }
        }
    }

    fn assert_parsed_is_valid(p: &WinPath) {
        assert!(p.drive().is_ascii_uppercase());
        assert!(p.components().len() <= 128);
        assert!(p.to_string().len() <= 32_767 + 128);
        for c in p.components() {
            assert_component_is_valid(c);
        }
        assert_eq!(
            WinPath::parse(&p.to_string()).as_ref(),
            Ok(p),
            "Display must round trip"
        );
    }

    #[test]
    fn fuzz_parse_and_resolve_never_panic_and_never_escape() {
        let fx = Fx::new();
        fx.file("dir/file.txt");
        fx.file("dir/sub/deep.txt");
        fx.file("Program Files/app.exe");
        fx.file("ci/A.txt");
        fx.file("ci/a.txt");
        fx.file("file.txt");
        fx.link("link", &fx.outside);
        fx.link("Inlink", Path::new("dir"));
        fx.link("loop", Path::new("loop"));
        fx.link("dangling", Path::new("nowhere"));
        fx.link("dir/up", Path::new(".."));
        fx.link("dir/abs", &fx.base);
        let canon_root = fs::canonicalize(&fx.root).unwrap();
        let before = snapshot(&fx.base);

        let alphabet: Vec<char> =
            "\\\\\\///::..\0?* <>\"|aAcCo nN~1$\u{e9}\u{65e5}\u{1f600}\u{212a}\u{202e}\u{1b}\u{b9}\u{ff0e}\n"
                .chars()
                .collect();
        let tokens = [
            "C:\\",
            "c:/",
            "\\",
            "/",
            "..",
            ".",
            "...",
            "dir",
            "DIR",
            "Dir",
            "sub",
            "deep.txt",
            "file.txt",
            "FILE.TXT",
            "Program Files",
            "PROGRAM FILES",
            "app.exe",
            "ci",
            "A.txt",
            "a.TXT",
            "link",
            "LINK",
            "inlink",
            "loop",
            "dangling",
            "up",
            "abs",
            "secret.txt",
            "outside",
            "new",
            "x.exe",
            "con",
            "aux.txt",
            "a:b",
            "~1",
            "..\\",
            "\\\\?\\",
            "COM1",
            "",
            " ",
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let (mut parsed, mut resolved, mut joined) = (0u32, 0u32, 0u32);
        for _ in 0..30_000 {
            let s: String = match xorshift(&mut state) % 3 {
                0 => {
                    let len = (xorshift(&mut state) % 40) as usize;
                    (0..len).map(|_| *pick(&mut state, &alphabet)).collect()
                }
                1 => {
                    let len = (xorshift(&mut state) % 12) as usize;
                    let body: String = (0..len).map(|_| *pick(&mut state, &alphabet)).collect();
                    format!("C:\\{body}")
                }
                _ => {
                    let count = (xorshift(&mut state) % 8) as usize;
                    let mut s = String::from(*pick(&mut state, &["C:\\", "c:/", "C:\\", "C:\\", "D:\\", ""]));
                    for _ in 0..count {
                        s.push_str(pick(&mut state, &tokens));
                        s.push(if xorshift(&mut state).is_multiple_of(2) {
                            '\\'
                        } else {
                            '/'
                        });
                    }
                    s.pop();
                    s
                }
            };
            let Ok(p) = WinPath::parse(&s) else { continue };
            parsed += 1;
            assert_parsed_is_valid(&p);

            match resolve_under(&fx.root, &p) {
                Ok(path) => {
                    resolved += 1;
                    assert!(path.starts_with(&fx.root), "{s:?} -> {path:?}");
                    assert!(path.components().all(|c| c != Component::ParentDir));
                    // Real and inside: canonicalising changes nothing but the (already real) root prefix.
                    let rel = path.strip_prefix(&fx.root).unwrap();
                    assert_eq!(fs::canonicalize(&path).unwrap(), canon_root.join(rel), "{s:?}");
                }
                Err(ResolveError::Io(e)) => panic!("unexpected i/o error for {s:?}: {e}"),
                Err(_) => {}
            }
            match join_new(&fx.root, &p) {
                Ok(path) => {
                    joined += 1;
                    assert!(path.starts_with(&fx.root), "{s:?} -> {path:?}");
                    assert!(path.components().all(|c| c != Component::ParentDir));
                    // The deepest existing ancestor must be a real path inside the root (no link on the way).
                    let existing = path.ancestors().find(|a| fs::symlink_metadata(a).is_ok()).unwrap();
                    let rel = existing.strip_prefix(&fx.root).unwrap();
                    assert_eq!(fs::canonicalize(existing).unwrap(), canon_root.join(rel), "{s:?}");
                }
                Err(ResolveError::Io(e)) => panic!("unexpected i/o error for {s:?}: {e}"),
                Err(_) => {}
            }
        }
        // The fuzz must actually exercise the filesystem paths, not just reject everything.
        assert!(parsed > 3_000, "only {parsed} inputs parsed");
        assert!(resolved > 300, "only {resolved} inputs resolved");
        assert!(joined > 1_000, "only {joined} inputs joined");
        assert_eq!(snapshot(&fx.base), before, "no operation may change the tree");
    }

    #[test]
    fn fuzz_parse_alone_with_hostile_alphabet() {
        let alphabet: Vec<char> = "\\/:.\0?* ~$aZ\u{e9}\u{1f600}\u{212a}\u{b9}\t\u{85}\u{ff3c}<>|\""
            .chars()
            .collect();
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..50_000 {
            let len = (xorshift(&mut state) % 60) as usize;
            let body: String = (0..len).map(|_| *pick(&mut state, &alphabet)).collect();
            let s = if xorshift(&mut state).is_multiple_of(2) {
                format!("C:\\{body}")
            } else {
                body
            };
            if let Ok(p) = WinPath::parse(&s) {
                assert_parsed_is_valid(&p);
            }
        }
    }
}
