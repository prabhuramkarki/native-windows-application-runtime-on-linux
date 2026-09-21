//! Locating the system Wine: the `wine` binary, `wineserver` and the built-in DLL directories.
//!
//! Everything is injected (`env`, `is_file`, `is_dir`) so the search order is unit-testable without a Wine
//! installation; [`is_executable_file`] and [`is_dir`] are the real filesystem checks.
//!
//! Order for `wine`: `$RUNTIME_WINE` (absolute; a bad value is an ERROR, never a silent fallback to another
//! Wine), then `wine64`, then `wine` on `$PATH`. For `wineserver` (it is usually NOT on `PATH`): `$RUNTIME_WINESERVER`
//! (absolute, same rule); when `$RUNTIME_WINE` is set, the `wineserver` next to it; `wineserver` on `PATH`; then a
//! fixed list of well-known locations (including `/usr/lib/wine/wineserver64`, the reported Ubuntu 24.04 name). `PATH` entries that
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
    // Reported layout of Ubuntu 24.04's Wine 9 packages (not verified on a real 24.04).
    "/usr/lib/wine/wineserver64",
    "/opt/wine-stable/bin/wineserver",
    "/opt/wine-staging/bin/wineserver",
    "/opt/wine-devel/bin/wineserver",
];

/// What was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub wine: PathBuf,
    pub wineserver: PathBuf,
    /// The built-in DLL directories that exist (see `find_dll_dirs`: next to the wineserver, next to its
    /// canonical location, `../lib/wine`, `../lib64/wine`). EMPTY means "could not be found": callers (`doctor`)
    /// must report "DLL availability not verified", not "DLL missing".
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

/// `fs::canonicalize`, `None` on any error.
pub fn canonicalize(p: &Path) -> Option<PathBuf> {
    fs::canonicalize(p).ok()
}

/// Runs the search described in the module docs. `canonicalize` resolves symlinks (`None`: cannot be resolved).
pub fn discover(
    env: &impl Fn(&str) -> Option<OsString>,
    is_file: &impl Fn(&Path) -> bool,
    is_dir: &impl Fn(&Path) -> bool,
    canonicalize: &impl Fn(&Path) -> Option<PathBuf>,
) -> Result<Found, DiscoverError> {
    let path = env("PATH").unwrap_or_default();
    let wine_override = override_var(env, ENV_WINE, is_file)?;
    let wine = match &wine_override {
        Some(p) => p.clone(),
        None => ["wine64", "wine"]
            .iter()
            .find_map(|name| on_path(name, &path, is_file))
            .ok_or(DiscoverError::WineNotFound)?,
    };
    let wineserver = match override_var(env, ENV_WINESERVER, is_file)? {
        Some(p) => p,
        None => wine_override
            .as_deref()
            .and_then(Path::parent)
            .map(|dir| dir.join("wineserver"))
            .filter(|sibling| is_file(sibling))
            .or_else(|| on_path("wineserver", &path, is_file))
            .or_else(|| WINESERVER_CANDIDATES.iter().map(PathBuf::from).find(|c| is_file(c)))
            .ok_or(DiscoverError::WineserverNotFound)?,
    };
    let dll_dirs = find_dll_dirs(&wineserver, is_dir, canonicalize);
    Ok(Found {
        wine,
        wineserver,
        dll_dirs,
    })
}

/// The built-in DLL directories that exist, for the wineserver path as given AND its canonical location (a
/// `/usr/bin/wineserver` symlink points into the real Wine directory). Per directory `D` (`<parent>` of the
/// wineserver): `D/{x86_64,i386}-windows`, then `D/../lib/wine/...` and `D/../lib64/wine/...` (the `/opt/wine-*`
/// layout). Deduplicated, in that order. Empty when nothing is found: that means "not verified", not "missing".
fn find_dll_dirs(
    wineserver: &Path,
    is_dir: &impl Fn(&Path) -> bool,
    canonicalize: &impl Fn(&Path) -> Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut bases: Vec<PathBuf> = Vec::new();
    let real = canonicalize(wineserver);
    for server in std::iter::once(wineserver).chain(real.as_deref()) {
        if let Some(dir) = server.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    let mut found: Vec<PathBuf> = Vec::new();
    for base in bases {
        let mut roots = vec![base.clone()];
        if let Some(up) = base.parent() {
            roots.push(up.join("lib/wine"));
            roots.push(up.join("lib64/wine"));
        }
        for root in roots {
            for arch in ["x86_64-windows", "i386-windows"] {
                let dir = root.join(arch);
                if is_dir(&dir) && !found.contains(&dir) {
                    found.push(dir);
                }
            }
        }
    }
    found
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
        /// What `canonicalize` returns for a path (a symlink, in the fake host); anything else: itself.
        canon: HashMap<PathBuf, PathBuf>,
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
        fn link(mut self, from: &str, to: &str) -> Host {
            self.canon.insert(from.into(), to.into());
            self
        }
        fn run(&self) -> Result<Found, DiscoverError> {
            discover(
                &|k| self.env.get(k).cloned(),
                &|p| self.files.contains(p),
                &|p| self.dirs.contains(p),
                &|p| Some(self.canon.get(p).cloned().unwrap_or_else(|| p.to_path_buf())),
            )
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
                "/usr/lib/wine/wineserver64",
                "/opt/wine-stable/bin/wineserver",
                "/opt/wine-staging/bin/wineserver",
                "/opt/wine-devel/bin/wineserver",
            ]
        );
    }

    #[test]
    fn the_ubuntu_noble_wineserver64_layout_is_found() {
        // Reported Wine 9 layout on Ubuntu 24.04: `wine64` on PATH, only `/usr/lib/wine/wineserver64`, no `wineserver` anywhere.
        let h = Host::default()
            .var("PATH", "/usr/local/bin:/usr/bin:/bin")
            .file("/usr/bin/wine64")
            .file("/usr/lib/wine/wineserver64")
            .dir("/usr/lib/wine/x86_64-windows");
        let found = h.run().unwrap();
        assert_eq!(found.wine, p("/usr/bin/wine64"));
        assert_eq!(found.wineserver, p("/usr/lib/wine/wineserver64"));
        assert_eq!(found.dll_dirs, vec![p("/usr/lib/wine/x86_64-windows")]);
        // A plain `wineserver` in the same directory still wins over the `64` name.
        let h = h.file("/usr/lib/wine/wineserver");
        assert_eq!(h.run().unwrap().wineserver, p("/usr/lib/wine/wineserver"));
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

    // ---- dll dirs: the wineserver path may be a symlink or live in an /opt layout ----

    #[test]
    fn dll_dirs_of_a_symlinked_wineserver_come_from_its_canonical_parent() {
        // Debian alternatives style: /usr/bin/wineserver -> the real one next to the DLL directories.
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/usr/bin/wineserver")
            .link("/usr/bin/wineserver", "/usr/lib/x86_64-linux-gnu/wine/wineserver")
            .dir("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows")
            .dir("/usr/lib/x86_64-linux-gnu/wine/i386-windows");
        let found = h.run().unwrap();
        assert_eq!(
            found.wineserver,
            p("/usr/bin/wineserver"),
            "the path as given is what runs"
        );
        assert_eq!(
            found.dll_dirs,
            vec![
                p("/usr/lib/x86_64-linux-gnu/wine/x86_64-windows"),
                p("/usr/lib/x86_64-linux-gnu/wine/i386-windows")
            ]
        );
    }

    #[test]
    fn dll_dirs_in_an_opt_layout_are_found_under_lib_wine() {
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/opt/wine-x/bin/wineserver")
            .var("RUNTIME_WINESERVER", "/opt/wine-x/bin/wineserver")
            .dir("/opt/wine-x/lib/wine/x86_64-windows")
            .dir("/opt/wine-x/lib/wine/i386-windows");
        assert_eq!(
            h.run().unwrap().dll_dirs,
            vec![
                p("/opt/wine-x/lib/wine/x86_64-windows"),
                p("/opt/wine-x/lib/wine/i386-windows")
            ]
        );
        // lib64 too.
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/opt/wine-y/bin/wineserver")
            .var("RUNTIME_WINESERVER", "/opt/wine-y/bin/wineserver")
            .dir("/opt/wine-y/lib64/wine/x86_64-windows");
        assert_eq!(
            h.run().unwrap().dll_dirs,
            vec![p("/opt/wine-y/lib64/wine/x86_64-windows")]
        );
    }

    #[test]
    fn dll_dir_candidates_are_tried_for_the_given_and_the_canonical_parent_and_deduplicated() {
        // /usr/local/bin/wineserver -> /opt/w/bin/wineserver: DLLs are only in the canonical layout, one of the
        // directories is next to the link as well (found via the given path), none is listed twice.
        let h = Host::default()
            .var("PATH", "/usr/local/bin:/usr/bin")
            .file("/usr/bin/wine")
            .file("/usr/local/bin/wineserver")
            .link("/usr/local/bin/wineserver", "/opt/w/bin/wineserver")
            .dir("/usr/local/lib/wine/i386-windows")
            .dir("/opt/w/lib/wine/x86_64-windows")
            .dir("/opt/w/lib/wine/i386-windows");
        assert_eq!(
            h.run().unwrap().dll_dirs,
            vec![
                p("/usr/local/lib/wine/i386-windows"),
                p("/opt/w/lib/wine/x86_64-windows"),
                p("/opt/w/lib/wine/i386-windows"),
            ]
        );
        // A canonical path equal to the given one adds nothing twice.
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/usr/lib/wine/wineserver")
            .dir("/usr/lib/wine/x86_64-windows");
        let h = h.var("RUNTIME_WINESERVER", "/usr/lib/wine/wineserver");
        assert_eq!(h.run().unwrap().dll_dirs, vec![p("/usr/lib/wine/x86_64-windows")]);
    }

    #[test]
    fn the_same_directory_reached_two_ways_is_listed_once() {
        // /usr/bin/wineserver -> /usr/lib/wine/wineserver: `/usr/lib/wine/x86_64-windows` is both
        // `<given dir>/../lib/wine/...` and `<canonical dir>/...`.
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/usr/bin/wineserver")
            .link("/usr/bin/wineserver", "/usr/lib/wine/wineserver")
            .dir("/usr/lib/wine/x86_64-windows");
        assert_eq!(h.run().unwrap().dll_dirs, vec![p("/usr/lib/wine/x86_64-windows")]);
    }

    #[test]
    fn no_dll_dir_found_is_an_empty_list_not_an_error() {
        // `doctor` must then say "DLL availability not verified", never "missing".
        let h = Host::default()
            .var("PATH", "/usr/bin")
            .file("/usr/bin/wine")
            .file("/usr/bin/wineserver")
            .dir("/somewhere/else/x86_64-windows");
        let found = h.run().unwrap();
        assert_eq!(found.dll_dirs, Vec::<PathBuf>::new());
    }

    #[test]
    fn a_real_symlinked_wineserver_in_a_tempdir() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let real = root.join("real/lib/wine");
        fs::create_dir_all(real.join("x86_64-windows")).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        write(&real.join("wineserver"), 0o755);
        write(&root.join("bin/wine64"), 0o755);
        symlink(real.join("wineserver"), root.join("bin/wineserver")).unwrap();
        let path = root.join("bin");
        let found = discover(
            &|k| (k == "PATH").then(|| path.clone().into_os_string()),
            &is_executable_file,
            &is_dir,
            &canonicalize,
        )
        .unwrap();
        assert_eq!(found.wineserver, root.join("bin/wineserver"));
        assert_eq!(found.dll_dirs, vec![real.join("x86_64-windows")]);
    }

    #[test]
    fn canonicalize_on_a_real_filesystem() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        fs::write(root.join("f"), b"").unwrap();
        symlink(root.join("f"), root.join("l")).unwrap();
        assert_eq!(canonicalize(&root.join("l")), Some(root.join("f")));
        assert_eq!(canonicalize(&root.join("missing")), None);
    }

    // ---- wineserver next to an overridden wine ----

    #[test]
    fn with_runtime_wine_set_the_wineserver_next_to_it_is_tried_first() {
        let base = || {
            Host::default()
                .var("PATH", "/usr/bin")
                .var("RUNTIME_WINE", "/opt/w/bin/wine")
                .file("/opt/w/bin/wine")
                .file("/usr/bin/wineserver")
                .file("/usr/lib/wine/wineserver")
        };
        // The sibling beats PATH and the fixed candidates ...
        let h = base().file("/opt/w/bin/wineserver");
        assert_eq!(h.run().unwrap().wineserver, p("/opt/w/bin/wineserver"));
        // ... but not RUNTIME_WINESERVER ...
        let h = h.var("RUNTIME_WINESERVER", "/usr/lib/wine/wineserver");
        assert_eq!(h.run().unwrap().wineserver, p("/usr/lib/wine/wineserver"));
        // ... and a missing sibling falls through to PATH.
        assert_eq!(base().run().unwrap().wineserver, p("/usr/bin/wineserver"));
    }

    #[test]
    fn the_sibling_rule_is_for_an_overridden_wine_only() {
        // wine64 comes from PATH (/b), wineserver exists in /a and /b: plain PATH order (/a) applies.
        let h = Host::default()
            .var("PATH", "/a:/b")
            .file("/b/wine64")
            .file("/a/wineserver")
            .file("/b/wineserver");
        assert_eq!(h.run().unwrap().wineserver, p("/a/wineserver"));
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
