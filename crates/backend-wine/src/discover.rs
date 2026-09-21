//! Locating the system Wine: the `wine` binary, `wineserver` and the built-in DLL directories.
//!
//! Everything is injected (`env`, `is_file`, `is_dir`) so the search order is unit-testable without a Wine
//! installation; [`is_executable_file`] and [`is_dir`] are the real filesystem checks.
//!
//! Order for `wine`: `$RUNTIME_WINE` (absolute; a bad value is an ERROR, never a silent fallback to another
//! Wine), then `wine64`, then `wine` on `$PATH`. For `wineserver` (it is usually NOT on `PATH`): `$RUNTIME_WINESERVER`
//! (absolute, same rule), `wineserver` on `PATH`, then a fixed list of well-known locations. `PATH` entries that
//! are empty or relative are skipped (an empty entry means "the current directory": a planted `wine` there must
//! never be picked up). An empty override variable counts as unset.
//!
//! The candidates are trusted system locations: a symlink to the real binary (`/usr/bin/wine` ->
//! `/etc/alternatives/wine`) is normal and followed (`fs::metadata`). This is not the untrusted-input check that
//! `winpath`/`harden` do.
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const ENV_WINE: &str = "RUNTIME_WINE";
pub const ENV_WINESERVER: &str = "RUNTIME_WINESERVER";

/// Where `wineserver` lives when it is not on `PATH`, in order.
pub const WINESERVER_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/wine/wineserver",
    "/usr/lib64/wine/wineserver",
    "/usr/lib/wine/wineserver",
    "/opt/wine-stable/bin/wineserver",
    "/opt/wine-staging/bin/wineserver",
    "/opt/wine-devel/bin/wineserver",
];

/// What was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub wine: PathBuf,
    pub wineserver: PathBuf,
    /// `<dir of wineserver>/x86_64-windows` and `/i386-windows`, those that exist.
    pub dll_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscoverError {
    /// `value` is the (lossy, cut to 200 chars) text of the variable.
    #[error("{var} must be an absolute path, but is {value:?}")]
    NotAbsolute { var: &'static str, value: String },
    #[error("{var} points to {path:?}, which is not an executable file")]
    NotExecutable { var: &'static str, path: PathBuf },
    #[error(
        "Wine was not found (looked at ${ENV_WINE}, then `wine64` and `wine` on PATH); install it, e.g. `sudo apt install wine`, or set ${ENV_WINE} to an absolute path"
    )]
    WineNotFound,
    #[error(
        "wineserver was not found (looked at ${ENV_WINESERVER}, PATH and the usual Wine directories); install the full Wine package, e.g. `sudo apt install wine`, or set ${ENV_WINESERVER} to an absolute path"
    )]
    WineserverNotFound,
}

/// A regular file (after following symlinks) with an execute bit; `false` on any error, a symlink loop included.
pub fn is_executable_file(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// A directory (after following symlinks).
pub fn is_dir(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_dir())
}

/// Runs the search described in the module docs.
pub fn discover(
    env: &impl Fn(&str) -> Option<OsString>,
    is_file: &impl Fn(&Path) -> bool,
    is_dir: &impl Fn(&Path) -> bool,
) -> Result<Found, DiscoverError> {
    let path = env("PATH").unwrap_or_default();
    let wine = match override_var(env, ENV_WINE, is_file)? {
        Some(p) => p,
        None => ["wine64", "wine"]
            .iter()
            .find_map(|name| on_path(name, &path, is_file))
            .ok_or(DiscoverError::WineNotFound)?,
    };
    let wineserver = match override_var(env, ENV_WINESERVER, is_file)? {
        Some(p) => p,
        None => on_path("wineserver", &path, is_file)
            .or_else(|| WINESERVER_CANDIDATES.iter().map(PathBuf::from).find(|c| is_file(c)))
            .ok_or(DiscoverError::WineserverNotFound)?,
    };
    let dll_dirs = match wineserver.parent() {
        Some(dir) => ["x86_64-windows", "i386-windows"]
            .iter()
            .map(|d| dir.join(d))
            .filter(|d| is_dir(d))
            .collect(),
        None => Vec::new(),
    };
    Ok(Found {
        wine,
        wineserver,
        dll_dirs,
    })
}

/// `Ok(None)` when the variable is unset or empty; an error when it is set but not an absolute executable file.
fn override_var(
    env: &impl Fn(&str) -> Option<OsString>,
    var: &'static str,
    is_file: &impl Fn(&Path) -> bool,
) -> Result<Option<PathBuf>, DiscoverError> {
    let Some(value) = env(var).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        return Err(DiscoverError::NotAbsolute {
            var,
            value: value.to_string_lossy().chars().take(200).collect(),
        });
    }
    if !is_file(&path) {
        return Err(DiscoverError::NotExecutable { var, path });
    }
    Ok(Some(path))
}

/// The first `name` in an absolute `PATH` directory; empty and relative entries are skipped.
fn on_path(name: &str, path: &OsStr, is_file: &impl Fn(&Path) -> bool) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_file(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::os::unix::fs::symlink;

    /// A fake host: environment variables plus the set of files and directories that "exist".
    #[derive(Default)]
    struct Host {
        env: HashMap<&'static str, OsString>,
        files: HashSet<PathBuf>,
        dirs: HashSet<PathBuf>,
    }

    impl Host {
        fn var(mut self, k: &'static str, v: &str) -> Host {
            self.env.insert(k, v.into());
            self
        }
        fn file(mut self, p: &str) -> Host {
            self.files.insert(p.into());
            self
        }
        fn dir(mut self, p: &str) -> Host {
            self.dirs.insert(p.into());
            self
        }
        fn run(&self) -> Result<Found, DiscoverError> {
            discover(&|k| self.env.get(k).cloned(), &|p| self.files.contains(p), &|p| {
                self.dirs.contains(p)
            })
        }
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn a_typical_debian_layout() {
        let h = Host::default()
            .var("PATH", "/usr/local/bin:/usr/bin:/bin")
            .file("/usr/bin/wine")
            .file("/usr/bin/wine64")
            .file("/usr/lib/x86_64-linux-gnu/wine/wineserver")
            .dir("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows")
            .dir("/usr/lib/x86_64-linux-gnu/wine/i386-windows");
        assert_eq!(
            h.run().unwrap(),
            Found {
                wine: p("/usr/bin/wine64"),
                wineserver: p("/usr/lib/x86_64-linux-gnu/wine/wineserver"),
                dll_dirs: vec![
                    p("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows"),
                    p("/usr/lib/x86_64-linux-gnu/wine/i386-windows")
                ],
            }
        );
    }

    #[test]
    fn wine_search_order_override_then_wine64_then_wine() {
        let base = || Host::default().file("/usr/lib/wine/wineserver").var("PATH", "/a:/b");
        // wine64 anywhere on PATH beats `wine` in an earlier directory.
        let h = base().file("/a/wine").file("/b/wine64");
        assert_eq!(h.run().unwrap().wine, p("/b/wine64"));
        // `wine` is the fallback.
        let h = base().file("/a/wine");
        assert_eq!(h.run().unwrap().wine, p("/a/wine"));
        // The first directory wins for the same name.
        let h = base().file("/a/wine64").file("/b/wine64");
        assert_eq!(h.run().unwrap().wine, p("/a/wine64"));
        // The override beats everything.
        let h = base()
            .file("/a/wine64")
            .file("/opt/w/wine")
            .var("RUNTIME_WINE", "/opt/w/wine");
        assert_eq!(h.run().unwrap().wine, p("/opt/w/wine"));
    }

    #[test]
    fn wineserver_search_order_override_then_path_then_fixed_candidates() {
        let base = || Host::default().file("/usr/bin/wine").var("PATH", "/usr/bin:/srv/bin");
        // All fixed candidates, in the documented order: remove the winner each time.
        let mut h = base();
        for c in WINESERVER_CANDIDATES {
            h = h.file(c);
        }
        let mut expected: Vec<PathBuf> = WINESERVER_CANDIDATES.iter().map(PathBuf::from).collect();
        while let Some(first) = expected.first().cloned() {
            assert_eq!(h.run().unwrap().wineserver, first);
            h.files.remove(&first);
            expected.remove(0);
        }
        assert_eq!(h.run(), Err(DiscoverError::WineserverNotFound));
        // PATH beats the fixed list, the override beats PATH.
        let h = base().file("/usr/lib/wine/wineserver").file("/srv/bin/wineserver");
        assert_eq!(h.run().unwrap().wineserver, p("/srv/bin/wineserver"));
        let h = h.file("/opt/x/ws").var("RUNTIME_WINESERVER", "/opt/x/ws");
        assert_eq!(h.run().unwrap().wineserver, p("/opt/x/ws"));
    }

    #[test]
    fn the_fixed_candidate_list_is_the_documented_one() {
        assert_eq!(
            WINESERVER_CANDIDATES,
            [
                "/usr/lib/x86_64-linux-gnu/wine/wineserver",
                "/usr/lib64/wine/wineserver",
                "/usr/lib/wine/wineserver",
                "/opt/wine-stable/bin/wineserver",
                "/opt/wine-staging/bin/wineserver",
                "/opt/wine-devel/bin/wineserver",
            ]
        );
    }

    #[test]
    fn dll_dirs_are_the_existing_ones_next_to_wineserver() {
        let base = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/opt/wine-stable/bin/wineserver");
        assert_eq!(base.run().unwrap().dll_dirs, Vec::<PathBuf>::new());
        let h = base.dir("/opt/wine-stable/bin/i386-windows");
        assert_eq!(h.run().unwrap().dll_dirs, vec![p("/opt/wine-stable/bin/i386-windows")]);
        // A directory elsewhere does not count.
        let h = h.dir("/usr/lib/wine/x86_64-windows");
        assert_eq!(h.run().unwrap().dll_dirs, vec![p("/opt/wine-stable/bin/i386-windows")]);
    }

    #[test]
    fn relative_and_empty_path_entries_are_skipped() {
        // Would-be hits at relative locations must never be found; the absolute entry after them is.
        let h = Host::default()
            .var("PATH", ":.:bin:./bin:../x:/good")
            .file("wine64")
            .file("./wine64")
            .file("bin/wine64")
            .file("./bin/wine64")
            .file("../x/wine64")
            .file("/good/wine64")
            .file("/usr/lib/wine/wineserver");
        assert_eq!(h.run().unwrap().wine, p("/good/wine64"));
        // Only relative entries: nothing is found, and wineserver is not picked from them either.
        let h = Host::default()
            .var("PATH", ":.:bin")
            .file("wine64")
            .file("bin/wine64")
            .file("bin/wineserver")
            .file("wineserver")
            .file("/usr/lib/wine/wineserver");
        assert_eq!(h.run(), Err(DiscoverError::WineNotFound));
        let h = Host::default()
            .var("PATH", ":bin:.")
            .var("RUNTIME_WINE", "/usr/bin/wine")
            .file("/usr/bin/wine")
            .file("bin/wineserver")
            .file("wineserver");
        assert_eq!(h.run(), Err(DiscoverError::WineserverNotFound));
    }

    #[test]
    fn a_missing_path_variable_is_not_a_crash() {
        let h = Host::default().file("/usr/lib/wine/wineserver");
        assert_eq!(h.run(), Err(DiscoverError::WineNotFound));
    }

    #[test]
    fn non_absolute_overrides_are_rejected_not_ignored() {
        for bad in ["wine", "./wine", "../wine", "bin/wine", "~/wine", " /usr/bin/wine"] {
            let h = Host::default()
                .var("PATH", "/usr/bin")
                .file("/usr/bin/wine64")
                .file("/usr/bin/wineserver")
                .var("RUNTIME_WINE", bad);
            assert!(
                matches!(
                    h.run(),
                    Err(DiscoverError::NotAbsolute {
                        var: "RUNTIME_WINE",
                        ..
                    })
                ),
                "{bad}: {:?}",
                h.run()
            );
            let h = Host::default()
                .var("PATH", "/usr/bin")
                .file("/usr/bin/wine64")
                .file("/usr/bin/wineserver")
                .var("RUNTIME_WINESERVER", bad);
            assert!(
                matches!(
                    h.run(),
                    Err(DiscoverError::NotAbsolute {
                        var: "RUNTIME_WINESERVER",
                        ..
                    })
                ),
                "{bad}: {:?}",
                h.run()
            );
        }
    }

    #[test]
    fn an_override_that_is_not_an_executable_file_is_an_error() {
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine64")
            .file("/usr/bin/wineserver")
            .var("RUNTIME_WINE", "/nonexistent/wine");
        assert_eq!(
            h.run(),
            Err(DiscoverError::NotExecutable {
                var: "RUNTIME_WINE",
                path: p("/nonexistent/wine")
            })
        );
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine64")
            .var("RUNTIME_WINE", "/usr/bin/wine64")
            .var("RUNTIME_WINESERVER", "/nonexistent/ws");
        assert_eq!(
            h.run(),
            Err(DiscoverError::NotExecutable {
                var: "RUNTIME_WINESERVER",
                path: p("/nonexistent/ws")
            })
        );
    }

    #[test]
    fn an_empty_override_counts_as_unset() {
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine64")
            .file("/usr/bin/wineserver")
            .var("RUNTIME_WINE", "")
            .var("RUNTIME_WINESERVER", "");
        assert_eq!(h.run().unwrap().wine, p("/usr/bin/wine64"));
    }

    #[test]
    fn a_non_utf8_override_is_handled() {
        use std::os::unix::ffi::OsStringExt;
        let mut h = Host::default().var("PATH", "/usr/bin").file("/usr/bin/wineserver");
        h.env.insert("RUNTIME_WINE", OsString::from_vec(b"rel\xff".to_vec()));
        assert!(matches!(h.run(), Err(DiscoverError::NotAbsolute { .. })));
        let mut h = Host::default().var("PATH", "/usr/bin").file("/usr/bin/wineserver");
        h.env.insert("RUNTIME_WINE", OsString::from_vec(b"/x/\xff".to_vec()));
        assert!(matches!(h.run(), Err(DiscoverError::NotExecutable { .. })));
    }

    #[test]
    fn an_override_value_in_an_error_is_bounded() {
        let h = Host::default().var("RUNTIME_WINE", &"x".repeat(100_000));
        match h.run() {
            Err(DiscoverError::NotAbsolute { value, .. }) => assert!(value.chars().count() <= 200),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nothing_installed_gives_an_install_hint() {
        let h = Host::default().var("PATH", "/usr/bin:/bin");
        let e = h.run().unwrap_err();
        assert_eq!(e, DiscoverError::WineNotFound);
        assert!(e.to_string().contains("apt install wine"), "{e}");
        let h = h.file("/usr/bin/wine");
        let e = h.run().unwrap_err();
        assert_eq!(e, DiscoverError::WineserverNotFound);
        assert!(e.to_string().contains("apt install wine"), "{e}");
    }

    // ---- the real filesystem checks ----

    fn write(path: &Path, mode: u32) {
        fs::write(path, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn is_executable_file_on_a_real_filesystem() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        write(&d.join("exec"), 0o755);
        write(&d.join("plain"), 0o644);
        write(&d.join("group-exec"), 0o610);
        fs::create_dir(d.join("dir")).unwrap();
        fs::set_permissions(d.join("dir"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink(d.join("exec"), d.join("link-to-exec")).unwrap();
        symlink(d.join("plain"), d.join("link-to-plain")).unwrap();
        symlink(d.join("loop-b"), d.join("loop-a")).unwrap();
        symlink(d.join("loop-a"), d.join("loop-b")).unwrap();
        symlink(d.join("nowhere"), d.join("dangling")).unwrap();
        for (name, want) in [
            ("exec", true),
            ("group-exec", true),
            ("link-to-exec", true), // /usr/bin/wine is a symlink chain: following is normal
            ("plain", false),
            ("link-to-plain", false),
            ("dir", false),
            ("loop-a", false),
            ("dangling", false),
            ("missing", false),
        ] {
            assert_eq!(is_executable_file(&d.join(name)), want, "{name}");
        }
    }

    #[test]
    fn is_dir_on_a_real_filesystem() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("d")).unwrap();
        fs::write(t.path().join("f"), b"").unwrap();
        symlink(t.path().join("d"), t.path().join("l")).unwrap();
        assert!(is_dir(&t.path().join("d")));
        assert!(is_dir(&t.path().join("l")));
        assert!(!is_dir(&t.path().join("f")));
        assert!(!is_dir(&t.path().join("nope")));
    }
}
