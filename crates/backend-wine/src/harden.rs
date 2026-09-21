//! Prefix hardening: removes what Wine's default prefix exposes of the host.
//!
//! After `wineboot -u` a fresh prefix contains (measured on Wine 10.0): `dosdevices/z: -> /`,
//! `dosdevices/com1..com32 -> /dev/ttyS*`, and under `drive_c/users/<user>/` links (`Desktop`, `Documents`,
//! `Downloads`, `Music`, `Pictures`, `Videos`, `AppData/Roaming/Microsoft/Windows/Templates`) to the REAL home
//! directories. [`harden_prefix`] leaves exactly this state:
//!
//! * `dosdevices` holds only `c: -> ../drive_c`;
//! * no symlink under `drive_c` resolves outside `drive_c`: one to a directory (or one whose target cannot be
//!   examined) is replaced by an empty real directory; one to a file, a dangling one and one in a loop is removed.
//!   Links that stay inside `drive_c` are left alone.
//!
//! Nothing is ever followed. Every decision uses `lstat` (`DirEntry::file_type`, `symlink_metadata`); the only
//! calls that resolve a link are `fs::canonicalize`/`fs::metadata` on ONE link at a time to learn where it points,
//! and the walk never descends into a symlink. The whole tree is examined first and only then modified, so a cap
//! that trips (depth 12, 200 000 entries) leaves the prefix untouched, and the result does not depend on the order
//! in which `read_dir` lists the entries.
//!
//! **Not a boundary.** Wine recreates the `com*` links on every start (it does not recreate `z:`), and
//! `\\?\unix\...` NT paths still reach host files. This is defence in depth; the real boundary is Phase 5.
//! Run it with no Wine process in the prefix (`prepare` stops the server first): a same-uid process racing the
//! walk can swap entries between the check and the fix; that race is out of scope for Phase 2.
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Directory levels below `drive_c` that are examined. A directory this deep is refused: its children would
/// not be examined.
pub const MAX_DEPTH: usize = 12;
/// Directory entries examined below `drive_c`.
pub const MAX_ENTRIES: usize = 200_000;

#[derive(Debug, thiserror::Error)]
pub enum HardenError {
    #[error("the prefix path has a trailing separator or a `.`/`..` component; refusing (it could follow a symlink)")]
    NonCanonical,
    #[error("{what} is a symbolic link; refusing to harden through it")]
    Symlink { what: &'static str },
    #[error("{what} is missing or not a directory")]
    NotADirectory { what: &'static str },
    #[error("more than {max} directory levels below drive_c; refusing (not everything could be examined)")]
    TooDeep { max: usize },
    #[error("more than {max} entries below drive_c; refusing (not everything could be examined)")]
    TooManyEntries { max: usize },
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// What [`harden_prefix`] changed. All paths are relative to the prefix and sorted. An idempotent second run
/// reports nothing changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HardenReport {
    /// Entries removed from `dosdevices` (everything except `c:`).
    pub devices_removed: Vec<OsString>,
    /// `dosdevices/c:` was missing or wrong and was recreated as `../drive_c`.
    pub c_link_fixed: bool,
    /// Outward links to a directory (or of unknown target) replaced by an empty directory.
    pub links_replaced: Vec<PathBuf>,
    /// Outward links to a file, dangling links and link loops, removed.
    pub links_removed: Vec<PathBuf>,
    /// Links left alone because they resolve inside `drive_c`.
    pub inside_links_kept: usize,
}

impl HardenReport {
    pub fn changed(&self) -> bool {
        !self.devices_removed.is_empty()
            || self.c_link_fixed
            || !self.links_replaced.is_empty()
            || !self.links_removed.is_empty()
    }
}

/// Refuses a prefix that hardening (or Wine, which follows links) must not touch: a symlinked or non-canonical
/// `prefix`, or a symlinked / non-directory `drive_c` or `dosdevices` where one already exists. Missing parts are
/// fine (Wine creates them). `prepare` calls this BEFORE `wineboot`.
pub fn precheck(prefix: &Path) -> Result<(), HardenError> {
    check_spelling(prefix)?;
    if lstat_dir(prefix, "prefix")?.is_none() {
        return Ok(());
    }
    lstat_dir(&prefix.join("drive_c"), "drive_c")?;
    lstat_dir(&prefix.join("dosdevices"), "dosdevices")?;
    Ok(())
}

/// See the module docs.
pub fn harden_prefix(prefix: &Path) -> Result<HardenReport, HardenError> {
    harden_with_limits(prefix, MAX_DEPTH, MAX_ENTRIES)
}

pub(crate) fn harden_with_limits(
    prefix: &Path,
    max_depth: usize,
    max_entries: usize,
) -> Result<HardenReport, HardenError> {
    check_spelling(prefix)?;
    require_dir(prefix, "prefix")?;
    let drive_c = prefix.join("drive_c");
    require_dir(&drive_c, "drive_c")?;
    let dosdevices = prefix.join("dosdevices");
    // Resolved once: link targets are resolved too, so the comparison is between real paths.
    let real_drive_c = fs::canonicalize(&drive_c).map_err(|e| io_err(&drive_c, e))?;

    // 1. Examine everything. Nothing has been modified yet, so any error below leaves the prefix as it was.
    let devices = scan_dosdevices(&dosdevices, max_entries)?;
    let scan = scan_drive_c(&drive_c, &real_drive_c, max_depth, max_entries)?;

    // 2. Fix.
    let mut report = HardenReport {
        inside_links_kept: scan.inside_links,
        ..HardenReport::default()
    };
    apply_dosdevices(&dosdevices, devices, &mut report)?;
    for (path, fix) in scan.fixes {
        fs::remove_file(&path).map_err(|e| io_err(&path, e))?; // unlinks the link itself
        let relative = path.strip_prefix(prefix).unwrap_or(&path).to_path_buf();
        match fix {
            Fix::ReplaceWithDir => {
                fs::create_dir(&path).map_err(|e| io_err(&path, e))?;
                report.links_replaced.push(relative);
            }
            Fix::Remove => report.links_removed.push(relative),
        }
    }
    report.devices_removed.sort();
    report.links_replaced.sort();
    report.links_removed.sort();
    Ok(report)
}

fn io_err(path: &Path, source: io::Error) -> HardenError {
    HardenError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `symlink_metadata` on a path with a trailing `/` or `/.` follows a final symlink, and `..` can hide one:
/// such spellings are refused instead of normalised (the same rule as `Store::new`).
fn check_spelling(prefix: &Path) -> Result<(), HardenError> {
    let raw = prefix.as_os_str().as_encoded_bytes();
    let has_dots = prefix
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir));
    if raw.ends_with(b"/") || raw.ends_with(b"/.") || has_dots || prefix.file_name().is_none() {
        return Err(HardenError::NonCanonical);
    }
    Ok(())
}

/// `Ok(Some(()))` for a real directory, `Ok(None)` when missing, an error for a symlink or another type.
fn lstat_dir(path: &Path, what: &'static str) -> Result<Option<()>, HardenError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(HardenError::Symlink { what }),
        Ok(m) if m.file_type().is_dir() => Ok(Some(())),
        Ok(_) => Err(HardenError::NotADirectory { what }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path, e)),
    }
}

fn require_dir(path: &Path, what: &'static str) -> Result<(), HardenError> {
    lstat_dir(path, what)?.ok_or(HardenError::NotADirectory { what })
}

/// What to do with one outward link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fix {
    ReplaceWithDir,
    Remove,
}

struct Scan {
    fixes: Vec<(PathBuf, Fix)>,
    inside_links: usize,
}

/// `dosdevices` entries other than `c:` (names only), from a directory that is not a symlink. `None`: it is missing.
fn scan_dosdevices(dosdevices: &Path, max_entries: usize) -> Result<Option<Vec<OsString>>, HardenError> {
    if lstat_dir(dosdevices, "dosdevices")?.is_none() {
        return Ok(None);
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dosdevices).map_err(|e| io_err(dosdevices, e))? {
        if names.len() >= max_entries {
            return Err(HardenError::TooManyEntries { max: max_entries });
        }
        names.push(entry.map_err(|e| io_err(dosdevices, e))?.file_name());
    }
    Ok(Some(names))
}

/// Makes `dosdevices` hold exactly `c: -> ../drive_c`.
fn apply_dosdevices(
    dosdevices: &Path,
    names: Option<Vec<OsString>>,
    report: &mut HardenReport,
) -> Result<(), HardenError> {
    if names.is_none() {
        fs::create_dir(dosdevices).map_err(|e| io_err(dosdevices, e))?;
    }
    for name in names.unwrap_or_default() {
        let path = dosdevices.join(&name);
        if name == "c:" {
            if fs::read_link(&path).is_ok_and(|t| t == Path::new("../drive_c")) {
                continue;
            }
            report.c_link_fixed = true; // wrong target or not a link: replaced below
        } else {
            report.devices_removed.push(name);
        }
        remove_entry(&path)?;
    }
    let c = dosdevices.join("c:");
    if fs::symlink_metadata(&c).is_err() {
        std::os::unix::fs::symlink("../drive_c", &c).map_err(|e| io_err(&c, e))?;
        report.c_link_fixed = true;
    }
    Ok(())
}

/// Removes a link or file, or a real directory with everything in it; never follows a link.
fn remove_entry(path: &Path) -> Result<(), HardenError> {
    let is_real_dir = fs::symlink_metadata(path)
        .map_err(|e| io_err(path, e))?
        .file_type()
        .is_dir();
    let result = if is_real_dir {
        fs::remove_dir_all(path) // std's implementation does not follow symlinks
    } else {
        fs::remove_file(path)
    };
    result.map_err(|e| io_err(path, e))
}

/// Walks `drive_c` read-only (an explicit stack, never following a symlink) and classifies every symlink.
fn scan_drive_c(
    drive_c: &Path,
    real_drive_c: &Path,
    max_depth: usize,
    max_entries: usize,
) -> Result<Scan, HardenError> {
    let mut scan = Scan {
        fixes: Vec::new(),
        inside_links: 0,
    };
    let mut seen = 0usize;
    // (directory, depth of its entries)
    let mut stack = vec![(drive_c.to_path_buf(), 1usize)];
    while let Some((dir, depth)) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| io_err(&dir, e))? {
            let entry = entry.map_err(|e| io_err(&dir, e))?;
            seen += 1;
            if seen > max_entries {
                return Err(HardenError::TooManyEntries { max: max_entries });
            }
            let path = entry.path();
            let file_type = entry.file_type().map_err(|e| io_err(&path, e))?; // lstat semantics
            if file_type.is_symlink() {
                match classify(&path, real_drive_c) {
                    None => scan.inside_links += 1,
                    Some(fix) => scan.fixes.push((path, fix)),
                }
            } else if file_type.is_dir() {
                if depth >= max_depth {
                    return Err(HardenError::TooDeep { max: max_depth });
                }
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(scan)
}

/// `ELOOP`: too many levels of symbolic links.
const ELOOP: i32 = 40;

/// `None`: the link resolves inside `real_drive_c` (leave it). Otherwise what to do with it.
fn classify(link: &Path, real_drive_c: &Path) -> Option<Fix> {
    match fs::canonicalize(link) {
        Ok(real) if real.starts_with(real_drive_c) => None,
        Ok(_) => Some(match fs::metadata(link) {
            Ok(m) if !m.is_dir() => Fix::Remove,
            _ => Fix::ReplaceWithDir, // a directory, or a target that cannot be examined
        }),
        Err(e)
            if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
                || e.raw_os_error() == Some(ELOOP) =>
        {
            Some(Fix::Remove) // dangling or looping
        }
        Err(_) => Some(Fix::ReplaceWithDir), // e.g. permission denied: unknown target
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// Every entry below `root` (lstat; never follows), one line each, sorted: `dir/`, `file`, `link -> target`.
    fn listing(root: &Path) -> Vec<String> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let rel = e.path().strip_prefix(root).unwrap().display().to_string();
                let ft = fs::symlink_metadata(e.path()).unwrap().file_type();
                if ft.is_symlink() {
                    out.push(format!("{rel} -> {}", fs::read_link(e.path()).unwrap().display()));
                } else if ft.is_dir() {
                    out.push(format!("{rel}/"));
                    walk(&e.path(), root, out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn mkdirs(p: &Path) {
        fs::create_dir_all(p).unwrap();
    }

    struct Fx {
        _t: TempDir,
        root: PathBuf,
        prefix: PathBuf,
        outside: PathBuf,
    }

    impl Fx {
        fn drive_c(&self) -> PathBuf {
            self.prefix.join("drive_c")
        }
        fn user(&self) -> PathBuf {
            self.drive_c().join("users/u")
        }
    }

    /// A prefix as `wineboot` leaves it, plus hostile extras, next to an `outside` tree that must never change.
    fn fixture() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let outside = root.join("outside");
        mkdirs(&outside.join("Desktop"));
        mkdirs(&outside.join("sub/deep"));
        fs::write(outside.join("canary.txt"), b"canary").unwrap();
        fs::write(outside.join("file.txt"), b"file").unwrap();
        fs::write(outside.join("Desktop/secret.txt"), b"secret").unwrap();
        fs::write(outside.join("sub/deep/x"), b"x").unwrap();
        // A link INSIDE the outside tree that a link-following walk would treat as outward and "fix".
        symlink("/etc", outside.join("sub/evil")).unwrap();

        let prefix = root.join("prefix");
        let dd = prefix.join("dosdevices");
        mkdirs(&dd);
        symlink("../drive_c", dd.join("c:")).unwrap();
        symlink("/", dd.join("z:")).unwrap();
        symlink("/dev/ttyS0", dd.join("com1")).unwrap();
        symlink("/dev/lp0", dd.join("lpt1")).unwrap();

        let dc = prefix.join("drive_c");
        mkdirs(&dc.join("Program Files"));
        mkdirs(&dc.join("inside_dir"));
        fs::write(dc.join("inside_dir/note.txt"), b"n").unwrap();
        fs::write(dc.join("inside_file.txt"), b"i").unwrap();
        let u = dc.join("users/u");
        mkdirs(&u.join("AppData/Roaming/Microsoft/Windows"));
        symlink(outside.join("Desktop"), u.join("Desktop")).unwrap();
        symlink(&outside, u.join("Documents")).unwrap();
        symlink("../../inside_dir", u.join("Music")).unwrap(); // relative, inside
        symlink(dc.join("inside_file.txt"), u.join("Pictures")).unwrap(); // absolute, inside, a file
        symlink("/", u.join("Videos")).unwrap(); // named like a folder, points at the host root
        symlink(outside.join("file.txt"), u.join("file_link")).unwrap(); // outward file
        symlink("/nonexistent/xyz", u.join("dangling")).unwrap();
        symlink("loop_b", u.join("loop_a")).unwrap();
        symlink("loop_a", u.join("loop_b")).unwrap();
        symlink(".", u.join("self")).unwrap(); // inside, would loop forever if followed
        symlink("chain_b", u.join("chain_a")).unwrap(); // a -> b -> outside
        symlink(outside.join("Desktop"), u.join("chain_b")).unwrap();
        symlink("../../../../outside", u.join("rel_out")).unwrap(); // relative, outward
        symlink(
            outside.join("sub"),
            u.join("AppData/Roaming/Microsoft/Windows/Templates"),
        )
        .unwrap();
        fs::write(prefix.join("system.reg"), b"reg").unwrap();
        Fx {
            _t: t,
            root,
            prefix,
            outside,
        }
    }

    fn sorted(mut v: Vec<PathBuf>) -> Vec<PathBuf> {
        v.sort();
        v
    }

    fn rel(paths: &[&str]) -> Vec<PathBuf> {
        sorted(paths.iter().map(PathBuf::from).collect())
    }

    #[test]
    fn synthetic_prefix_ends_in_the_exact_hardened_state() {
        let fx = fixture();
        let report = harden_prefix(&fx.prefix).unwrap();

        let u = "drive_c/users/u";
        let mut expected: Vec<String> = [
            "dosdevices/",
            "dosdevices/c: -> ../drive_c",
            "drive_c/",
            "drive_c/Program Files/",
            "drive_c/inside_dir/",
            "drive_c/inside_dir/note.txt",
            "drive_c/inside_file.txt",
            "drive_c/users/",
            "system.reg",
        ]
        .map(String::from)
        .into();
        for d in [
            "",
            "/AppData",
            "/AppData/Roaming",
            "/AppData/Roaming/Microsoft",
            "/AppData/Roaming/Microsoft/Windows",
        ] {
            expected.push(format!("{u}{d}/"));
        }
        for d in ["Desktop", "Documents", "Videos", "chain_a", "chain_b", "rel_out"] {
            expected.push(format!("{u}/{d}/"));
        }
        expected.push(format!("{u}/AppData/Roaming/Microsoft/Windows/Templates/"));
        expected.push(format!("{u}/Music -> ../../inside_dir"));
        expected.push(format!("{u}/Pictures -> {}/inside_file.txt", fx.drive_c().display()));
        expected.push(format!("{u}/self -> ."));
        expected.sort();
        assert_eq!(listing(&fx.prefix), expected);

        assert_eq!(
            report
                .devices_removed
                .iter()
                .map(|o| o.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["com1", "lpt1", "z:"]
        );
        assert!(!report.c_link_fixed);
        assert_eq!(
            report.links_replaced,
            rel(&[
                "drive_c/users/u/AppData/Roaming/Microsoft/Windows/Templates",
                "drive_c/users/u/Desktop",
                "drive_c/users/u/Documents",
                "drive_c/users/u/Videos",
                "drive_c/users/u/chain_a",
                "drive_c/users/u/chain_b",
                "drive_c/users/u/rel_out",
            ])
        );
        assert_eq!(
            report.links_removed,
            rel(&[
                "drive_c/users/u/dangling",
                "drive_c/users/u/file_link",
                "drive_c/users/u/loop_a",
                "drive_c/users/u/loop_b",
            ])
        );
        assert_eq!(report.inside_links_kept, 3);
        assert!(report.changed());
    }

    #[test]
    fn the_outside_tree_is_never_touched_or_followed() {
        let fx = fixture();
        let before = listing(&fx.outside);
        assert!(before.contains(&"sub/evil -> /etc".to_string()));
        harden_prefix(&fx.prefix).unwrap();
        assert_eq!(listing(&fx.outside), before, "something below the outside tree changed");
        assert_eq!(fs::read(fx.outside.join("canary.txt")).unwrap(), b"canary");
        assert_eq!(fs::read(fx.outside.join("file.txt")).unwrap(), b"file");
        assert_eq!(fs::read(fx.outside.join("Desktop/secret.txt")).unwrap(), b"secret");
        assert_eq!(fs::read_link(fx.outside.join("sub/evil")).unwrap(), Path::new("/etc"));
        // Only `outside` and `prefix` exist under the root.
        let mut top: Vec<_> = fs::read_dir(&fx.root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        top.sort();
        assert_eq!(top, [OsString::from("outside"), OsString::from("prefix")]);
    }

    #[test]
    fn dosdevices_ends_with_only_c_pointing_at_drive_c() {
        let fx = fixture();
        harden_prefix(&fx.prefix).unwrap();
        let dd = fx.prefix.join("dosdevices");
        let names: Vec<_> = fs::read_dir(&dd).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, [OsString::from("c:")]);
        assert_eq!(fs::read_link(dd.join("c:")).unwrap(), Path::new("../drive_c"));
        // A real directory inside dosdevices is removed too, and nothing it holds is followed.
        let fx = fixture();
        let dd = fx.prefix.join("dosdevices");
        mkdirs(&dd.join("d:/sub"));
        symlink(&fx.outside, dd.join("d:/sub/out")).unwrap();
        fs::write(dd.join("e:"), b"file").unwrap();
        let before = listing(&fx.outside);
        harden_prefix(&fx.prefix).unwrap();
        assert_eq!(fs::read_dir(&dd).unwrap().count(), 1);
        assert_eq!(listing(&fx.outside), before);
    }

    #[test]
    fn a_wrong_or_missing_c_link_is_repaired() {
        for setup in ["missing", "to-root", "real-dir", "dangling-dosdevices"] {
            let fx = fixture();
            let dd = fx.prefix.join("dosdevices");
            match setup {
                "missing" => fs::remove_file(dd.join("c:")).unwrap(),
                "to-root" => {
                    fs::remove_file(dd.join("c:")).unwrap();
                    symlink("/", dd.join("c:")).unwrap();
                }
                "real-dir" => {
                    fs::remove_file(dd.join("c:")).unwrap();
                    mkdirs(&dd.join("c:/x"));
                }
                _ => fs::remove_dir_all(&dd).unwrap(), // dosdevices missing altogether
            }
            let report = harden_prefix(&fx.prefix).unwrap();
            assert!(report.c_link_fixed, "{setup}");
            assert_eq!(
                fs::read_link(dd.join("c:")).unwrap(),
                Path::new("../drive_c"),
                "{setup}"
            );
            assert_eq!(fs::read_dir(&dd).unwrap().count(), 1, "{setup}");
        }
    }

    #[test]
    fn outward_links_become_empty_directories_at_any_depth_up_to_the_cap() {
        let fx = fixture();
        // The depth-6 Templates link of the spike, and one at the deepest examined level (12).
        let mut deep = fx.drive_c();
        for i in 0..11 {
            deep = deep.join(format!("d{i}"));
        }
        mkdirs(&deep);
        symlink(&fx.outside, deep.join("link")).unwrap();
        harden_prefix(&fx.prefix).unwrap();
        for p in [
            fx.user().join("AppData/Roaming/Microsoft/Windows/Templates"),
            deep.join("link"),
            fx.user().join("Desktop"),
        ] {
            let m = fs::symlink_metadata(&p).unwrap();
            assert!(m.file_type().is_dir() && !m.file_type().is_symlink(), "{}", p.display());
            assert_eq!(fs::read_dir(&p).unwrap().count(), 0, "{} must be empty", p.display());
        }
    }

    #[test]
    fn links_to_files_dangling_links_and_loops_are_removed() {
        let fx = fixture();
        harden_prefix(&fx.prefix).unwrap();
        for n in ["file_link", "dangling", "loop_a", "loop_b"] {
            assert!(fs::symlink_metadata(fx.user().join(n)).is_err(), "{n} must be gone");
        }
    }

    #[test]
    fn inside_links_are_kept_and_never_followed() {
        let fx = fixture();
        // A link into a directory that itself holds an outward link: that link is fixed once, at its real
        // location, and the walk terminates despite `self -> .`.
        symlink("inside_dir", fx.drive_c().join("alias")).unwrap();
        symlink(&fx.outside, fx.drive_c().join("inside_dir/out")).unwrap();
        let report = harden_prefix(&fx.prefix).unwrap();
        assert_eq!(
            fs::read_link(fx.drive_c().join("alias")).unwrap(),
            Path::new("inside_dir")
        );
        assert_eq!(fs::read_link(fx.user().join("self")).unwrap(), Path::new("."));
        assert_eq!(
            fs::read_link(fx.user().join("Music")).unwrap(),
            Path::new("../../inside_dir")
        );
        assert!(
            fs::symlink_metadata(fx.drive_c().join("inside_dir/out"))
                .unwrap()
                .is_dir()
        );
        assert_eq!(
            report.links_replaced.iter().filter(|p| p.ends_with("out")).count(),
            1,
            "{:?}",
            report.links_replaced
        );
        assert_eq!(report.inside_links_kept, 4);
    }

    #[test]
    fn hardening_is_idempotent() {
        let fx = fixture();
        harden_prefix(&fx.prefix).unwrap();
        let once = listing(&fx.prefix);
        let second = harden_prefix(&fx.prefix).unwrap();
        assert_eq!(listing(&fx.prefix), once);
        assert!(!second.changed(), "{second:?}");
        assert_eq!(second.inside_links_kept, 3);
    }

    #[test]
    fn refuses_a_symlinked_prefix_and_touches_nothing() {
        let fx = fixture();
        let link = fx.root.join("prefix-link");
        symlink(&fx.prefix, &link).unwrap();
        let before = listing(&fx.prefix);
        let e = harden_prefix(&link).unwrap_err();
        assert!(matches!(e, HardenError::Symlink { what: "prefix" }), "{e:?}");
        assert_eq!(listing(&fx.prefix), before);
    }

    #[test]
    fn refuses_a_symlinked_drive_c_and_touches_nothing() {
        let fx = fixture();
        // drive_c -> a directory that is full of outward links; nothing there may be changed.
        let real = fx.root.join("elsewhere");
        fs::rename(fx.drive_c(), &real).unwrap();
        symlink(&real, fx.drive_c()).unwrap();
        let before = (listing(&real), listing(&fx.prefix));
        let e = harden_prefix(&fx.prefix).unwrap_err();
        assert!(matches!(e, HardenError::Symlink { what: "drive_c" }), "{e:?}");
        assert_eq!((listing(&real), listing(&fx.prefix)), before);
    }

    #[test]
    fn refuses_a_symlinked_dosdevices_and_deletes_nothing_through_it() {
        let fx = fixture();
        let real = fx.root.join("devices");
        fs::rename(fx.prefix.join("dosdevices"), &real).unwrap();
        symlink(&real, fx.prefix.join("dosdevices")).unwrap();
        let before = listing(&real);
        let e = harden_prefix(&fx.prefix).unwrap_err();
        assert!(matches!(e, HardenError::Symlink { what: "dosdevices" }), "{e:?}");
        assert_eq!(listing(&real), before);
    }

    #[test]
    fn refuses_a_prefix_spelled_so_that_lstat_would_follow_a_link() {
        let fx = fixture();
        let link = fx.root.join("prefix-link");
        symlink(&fx.prefix, &link).unwrap();
        for spelling in [
            format!("{}/", link.display()),
            format!("{}/.", link.display()),
            format!("{}/../prefix-link", fx.prefix.display()),
        ] {
            let e = harden_prefix(Path::new(&spelling)).unwrap_err();
            assert!(matches!(e, HardenError::NonCanonical), "{spelling}: {e:?}");
        }
    }

    #[test]
    fn a_missing_prefix_or_drive_c_is_an_error() {
        let t = tempfile::tempdir().unwrap();
        assert!(matches!(
            harden_prefix(&t.path().join("nope")).unwrap_err(),
            HardenError::NotADirectory { what: "prefix" }
        ));
        mkdirs(&t.path().join("p"));
        assert!(matches!(
            harden_prefix(&t.path().join("p")).unwrap_err(),
            HardenError::NotADirectory { what: "drive_c" }
        ));
        fs::write(t.path().join("p/drive_c"), b"").unwrap();
        assert!(matches!(
            harden_prefix(&t.path().join("p")).unwrap_err(),
            HardenError::NotADirectory { what: "drive_c" }
        ));
    }

    #[test]
    fn the_documented_caps() {
        assert_eq!((MAX_DEPTH, MAX_ENTRIES), (12, 200_000));
    }

    #[test]
    fn a_directory_at_the_depth_cap_is_refused_and_nothing_is_changed() {
        let fx = fixture();
        let mut deep = fx.drive_c();
        for i in 0..12 {
            deep = deep.join(format!("d{i}"));
        }
        mkdirs(&deep);
        let before = listing(&fx.prefix);
        let e = harden_prefix(&fx.prefix).unwrap_err();
        assert!(matches!(e, HardenError::TooDeep { max: 12 }), "{e:?}");
        assert_eq!(
            listing(&fx.prefix),
            before,
            "a tripped cap must leave the prefix as it was"
        );
    }

    #[test]
    fn the_entry_cap_is_enforced_before_anything_is_changed() {
        let fx = fixture();
        let many = fx.drive_c().join("many");
        mkdirs(&many);
        for i in 0..100 {
            fs::write(many.join(format!("f{i}")), b"").unwrap();
        }
        let before = listing(&fx.prefix);
        let e = harden_with_limits(&fx.prefix, MAX_DEPTH, 50).unwrap_err();
        assert!(matches!(e, HardenError::TooManyEntries { max: 50 }), "{e:?}");
        assert_eq!(listing(&fx.prefix), before);
        // With room for everything it works.
        harden_with_limits(&fx.prefix, MAX_DEPTH, 10_000).unwrap();
    }

    #[test]
    fn the_entry_cap_covers_dosdevices_too() {
        let t = tempfile::tempdir().unwrap();
        let prefix = t.path().join("prefix");
        mkdirs(&prefix.join("drive_c"));
        mkdirs(&prefix.join("dosdevices"));
        for i in 0..10 {
            symlink("/dev/null", prefix.join(format!("dosdevices/com{i}"))).unwrap();
        }
        let e = harden_with_limits(&prefix, MAX_DEPTH, 5).unwrap_err();
        assert!(matches!(e, HardenError::TooManyEntries { max: 5 }), "{e:?}");
        assert_eq!(
            fs::read_dir(prefix.join("dosdevices")).unwrap().count(),
            10,
            "nothing removed"
        );
        harden_with_limits(&prefix, MAX_DEPTH, 50).unwrap();
    }

    #[test]
    fn a_wide_and_deep_hostile_tree_is_walked_within_the_caps() {
        // 3 levels x 20 dirs = 8 000 dirs + a link loop in each: finishes, and is bounded by the entry cap.
        let fx = fixture();
        for a in 0..20 {
            for b in 0..20 {
                let d = fx.drive_c().join(format!("w{a}/x{b}"));
                mkdirs(&d);
                symlink("..", d.join("up")).unwrap();
            }
        }
        let r = harden_prefix(&fx.prefix).unwrap();
        assert!(r.inside_links_kept >= 400);
        let e = harden_with_limits(&fx.prefix, MAX_DEPTH, 300).unwrap_err();
        assert!(matches!(e, HardenError::TooManyEntries { .. }));
    }

    #[test]
    fn precheck_accepts_missing_parts_and_refuses_links() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("prefix");
        precheck(&p).unwrap(); // nothing there yet
        mkdirs(&p);
        precheck(&p).unwrap(); // prefix only
        mkdirs(&p.join("drive_c"));
        mkdirs(&p.join("dosdevices"));
        precheck(&p).unwrap();

        let fx = fixture();
        precheck(&fx.prefix).unwrap();
        let link = fx.root.join("l");
        symlink(&fx.prefix, &link).unwrap();
        assert!(matches!(
            precheck(&link).unwrap_err(),
            HardenError::Symlink { what: "prefix" }
        ));
        assert!(matches!(
            precheck(Path::new("/tmp/")).unwrap_err(),
            HardenError::NonCanonical
        ));

        let real = fx.root.join("elsewhere");
        fs::rename(fx.drive_c(), &real).unwrap();
        symlink(&real, fx.drive_c()).unwrap();
        assert!(matches!(
            precheck(&fx.prefix).unwrap_err(),
            HardenError::Symlink { what: "drive_c" }
        ));
        fs::remove_file(fx.drive_c()).unwrap();
        mkdirs(&fx.drive_c());
        let dd = fx.root.join("dd");
        fs::rename(fx.prefix.join("dosdevices"), &dd).unwrap();
        symlink(&dd, fx.prefix.join("dosdevices")).unwrap();
        assert!(matches!(
            precheck(&fx.prefix).unwrap_err(),
            HardenError::Symlink { what: "dosdevices" }
        ));
        // A prefix that is a file is refused too.
        fs::write(fx.root.join("file"), b"").unwrap();
        assert!(matches!(
            precheck(&fx.root.join("file")).unwrap_err(),
            HardenError::NotADirectory { .. }
        ));
    }
}
