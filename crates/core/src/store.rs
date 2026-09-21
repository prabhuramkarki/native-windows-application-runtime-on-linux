//! The per-app environment store: `<apps_dir>/<id>/...`.
//!
//! ```text
//! <apps_dir>/<id>/         mode 0700, created by `Store::create`
//!   metadata.json          written by `Store::write_metadata` (atomic)
//!   config cache logs runtime registry/   empty directories, created by `Store::create`
//!   prefix/                the compatibility backend's prefix (created later by the backend)
//!     drive_c/             what `resolve_under` maps `C:` onto
//! ```
//!
//! Every path under the store is `apps_dir.join(id)` for a validated [`AppId`] (one safe path component), never
//! text read from a file. Everything found on disk is untrusted: a directory entry may be a symlink, a file or
//! a directory with a hostile `metadata.json`; those become [`StoreWarn`]s, never panics.
//!
//! `Store::new` REJECTS (rather than normalises) an `apps_dir` that is relative or ends with a separator or a
//! `.`/`..` component: `symlink_metadata("link/")` follows the link, so such a spelling could turn a lstat check
//! into a follow. The apps dir itself is trusted configuration and may be a symlink.
use crate::id::MAX_LEN;
use crate::{AppId, IdError, MetaError, Metadata};
use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// `list` looks at no more than this many directory entries.
pub const MAX_LIST_ENTRIES: usize = 10_000;
/// Highest numeric suffix `unique_id` tries.
pub const MAX_UNIQUE_SUFFIX: u32 = 999;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("apps directory must be an absolute path")]
    RelativeRoot,
    #[error("apps directory must not end with a separator, `.` or `..`")]
    NonCanonicalRoot,
    #[error("app environment already exists")]
    AlreadyExists,
    #[error("app environment does not exist")]
    NotFound,
    #[error("app environment is a symbolic link or not a directory")]
    NotADirectory,
    #[error("path is not directly under the apps directory")]
    NotUnderApps,
    #[error("metadata id does not match the directory name")]
    IdMismatch,
    #[error("directory name is not a valid app id: {0}")]
    InvalidName(#[from] IdError),
    #[error("more than {max} entries in the apps directory; the rest were not examined")]
    TooManyEntries { max: usize },
    #[error("no free id up to suffix -{MAX_UNIQUE_SUFFIX}")]
    NoUniqueId,
    #[error("{0}")]
    Meta(#[from] MetaError),
    #[error("i/o error: {0}")]
    Io(#[source] std::io::Error),
}

/// One `list` entry that could not be turned into an app. `name` is the (lossily decoded, UNTRUSTED) directory
/// name and the error text may quote file content: sanitise both before printing.
#[derive(Debug)]
pub struct StoreWarn {
    pub name: String,
    pub error: StoreError,
}

impl std::fmt::Display for StoreWarn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.name, self.error)
    }
}

/// One row of [`Store::list`]: an app, or the reason an entry is not one.
pub type ListEntry = Result<(AppEnv, Metadata), StoreWarn>;

/// A validated handle on one app's directory. Obtained from [`Store::create`] or [`Store::get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEnv {
    id: AppId,
    root: PathBuf,
}

impl AppEnv {
    pub fn id(&self) -> &AppId {
        &self.id
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// The backend's prefix directory (`root/prefix`); it does not exist until the backend creates it.
    pub fn prefix(&self) -> PathBuf {
        self.root.join("prefix")
    }
    /// `prefix/drive_c`: the directory `resolve_under` maps `C:` onto.
    pub fn drive_c(&self) -> PathBuf {
        self.prefix().join("drive_c")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    pub fn metadata_path(&self) -> PathBuf {
        self.root.join("metadata.json")
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    apps_dir: PathBuf,
}

fn io_err(e: io::Error) -> StoreError {
    StoreError::Io(e)
}

/// Requires a real directory at `path`: a symlink (even to a directory) or any other type is refused.
fn require_real_dir(path: &Path) -> Result<(), StoreError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(StoreError::NotADirectory),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::NotFound),
        Err(e) => Err(io_err(e)),
    }
}

fn private_dir() -> DirBuilder {
    let mut b = DirBuilder::new();
    b.mode(0o700);
    b
}

impl Store {
    /// The apps directory must be absolute and in canonical form (see the module docs); it need not exist yet.
    pub fn new(apps_dir: impl Into<PathBuf>) -> Result<Store, StoreError> {
        let apps_dir = apps_dir.into();
        if !apps_dir.is_absolute() {
            return Err(StoreError::RelativeRoot);
        }
        let raw = apps_dir.as_os_str().as_bytes();
        // `file_name` is None for `/` and a trailing `..`; the byte checks catch a trailing `/` and `/.`, which
        // `Path` would silently drop.
        if raw.ends_with(b"/") || raw.ends_with(b"/.") || apps_dir.file_name().is_none() {
            return Err(StoreError::NonCanonicalRoot);
        }
        Ok(Store { apps_dir })
    }

    pub fn apps_dir(&self) -> &Path {
        &self.apps_dir
    }

    fn env_for(&self, id: &AppId) -> AppEnv {
        AppEnv {
            id: id.clone(),
            root: self.apps_dir.join(id.as_str()),
        }
    }

    /// Creates a new environment; fails if anything (of any type, including a symlink) exists at the target.
    /// A failure part-way leaves the partly built directory: `remove` cleans it up.
    pub fn create(&self, id: &AppId) -> Result<AppEnv, StoreError> {
        // The apps dir is trusted configuration: it may be missing (created here) or a symlink (followed).
        private_dir().recursive(true).create(&self.apps_dir).map_err(io_err)?;
        let env = self.env_for(id);
        // `mkdir` (not `create_dir_all`): an existing entry of any type, a symlink included, is an error and
        // is never followed.
        private_dir().create(env.root()).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => StoreError::AlreadyExists,
            _ => io_err(e),
        })?;
        for d in ["config", "cache", "logs", "runtime", "registry"] {
            private_dir().create(env.root().join(d)).map_err(io_err)?;
        }
        Ok(env)
    }

    /// The environment for `id`; it must exist and be a real directory (not a symlink).
    pub fn get(&self, id: &AppId) -> Result<AppEnv, StoreError> {
        let env = self.env_for(id);
        require_real_dir(env.root())?;
        Ok(env)
    }

    /// Reads and validates the app's `metadata.json`; its `id` must equal the directory's.
    pub fn read_metadata(&self, env: &AppEnv) -> Result<Metadata, StoreError> {
        let md = Metadata::read(&env.metadata_path())?;
        if md.id != env.id {
            return Err(StoreError::IdMismatch);
        }
        Ok(md)
    }

    /// Atomically writes the app's `metadata.json`; `md.id` must equal the directory's.
    pub fn write_metadata(&self, env: &AppEnv, md: &Metadata) -> Result<(), StoreError> {
        if md.id != env.id {
            return Err(StoreError::IdMismatch);
        }
        md.write_atomic(&env.metadata_path())?;
        Ok(())
    }

    /// Every app, sorted by directory name. Bad entries are reported in place; at most [`MAX_LIST_ENTRIES`]
    /// entries are examined, then a final `TooManyEntries` warning.
    pub fn list(&self) -> Vec<ListEntry> {
        self.list_limited(MAX_LIST_ENTRIES)
    }

    fn list_limited(&self, max: usize) -> Vec<ListEntry> {
        let warn = |name: &OsStr, error| StoreWarn {
            name: name.to_string_lossy().into_owned(),
            error,
        };
        let entries = match fs::read_dir(&self.apps_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => return vec![Err(warn(OsStr::new(""), io_err(e)))],
        };
        let mut rows: Vec<(OsString, ListEntry)> = Vec::new();
        let mut truncated = false;
        for entry in entries {
            if rows.len() >= max {
                truncated = true;
                break;
            }
            let row = match entry {
                Ok(entry) => {
                    let name = entry.file_name();
                    // Lossy: a non-UTF-8 name becomes U+FFFD, which is never a valid id character.
                    let loaded = AppId::parse(&name.to_string_lossy())
                        .map_err(StoreError::from)
                        .and_then(|id| {
                            let env = self.get(&id)?;
                            let md = self.read_metadata(&env)?;
                            Ok((env, md))
                        });
                    let result = loaded.map_err(|error| warn(&name, error));
                    (name, result)
                }
                Err(e) => (OsString::new(), Err(warn(OsStr::new(""), io_err(e)))),
            };
            rows.push(row);
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out: Vec<_> = rows.into_iter().map(|(_, r)| r).collect();
        if truncated {
            out.push(Err(warn(OsStr::new(""), StoreError::TooManyEntries { max })));
        }
        out
    }

    /// Deletes the app's whole directory. Refuses a symlink or non-directory at the app path.
    pub fn remove(&self, id: &AppId) -> Result<(), StoreError> {
        self.remove_app_dir(&self.env_for(id).root)
    }

    /// The deletion guard, on a path: it must be exactly `apps_dir/<one name>` and a real directory. Nothing is
    /// canonicalised. `remove_dir_all` removes a symlink inside the tree as a link, never its target.
    fn remove_app_dir(&self, dir: &Path) -> Result<(), StoreError> {
        // `apps/..` has parent `apps`, so a name is required too.
        if dir.parent() != Some(self.apps_dir.as_path()) || dir.file_name().is_none() {
            return Err(StoreError::NotUnderApps);
        }
        require_real_dir(dir)?;
        fs::remove_dir_all(dir).map_err(io_err)
    }
}

/// `base` if free, else `base-2`, `base-3`, ... up to `-999` (the base is cut so the result stays a valid id of
/// at most 64 bytes). Existing means any entry at all, including a dangling symlink.
pub fn unique_id(store: &Store, base: &AppId) -> Result<AppId, StoreError> {
    let taken = |id: &AppId| match fs::symlink_metadata(store.apps_dir.join(id.as_str())) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_err(e)),
    };
    if !taken(base)? {
        return Ok(base.clone());
    }
    for n in 2..=MAX_UNIQUE_SUFFIX {
        let suffix = format!("-{n}");
        // Ids are ASCII, so cutting at a byte index is on a char boundary. Trimming a trailing `.`/`-` left by the
        // cut avoids ids like `a--2`.
        let base = base.as_str();
        let head = base[..base.len().min(MAX_LEN - suffix.len())].trim_end_matches(['.', '-']);
        let candidate = AppId::parse(&format!("{head}{suffix}"))?;
        if !taken(&candidate)? {
            return Ok(candidate);
        }
    }
    Err(StoreError::NoUniqueId)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::{MAX_FILE_BYTES, sample};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn id(s: &str) -> AppId {
        AppId::parse(s).unwrap()
    }

    struct Fx {
        _tmp: tempfile::TempDir,
        base: PathBuf,
        apps: PathBuf,
        outside: PathBuf,
        store: Store,
    }

    impl Fx {
        /// `base/apps` (the store, empty) and `base/outside` (holds `canary.txt`).
        fn new() -> Fx {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().to_path_buf();
            let apps = base.join("apps");
            let outside = base.join("outside");
            fs::create_dir(&apps).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("canary.txt"), "canary").unwrap();
            let store = Store::new(&apps).unwrap();
            Fx {
                _tmp: tmp,
                base,
                apps,
                outside,
                store,
            }
        }

        /// A complete valid app.
        fn add(&self, name: &str) -> AppEnv {
            let env = self.store.create(&id(name)).unwrap();
            self.store.write_metadata(&env, &sample(name)).unwrap();
            env
        }

        fn assert_canary(&self) {
            assert_eq!(fs::read_to_string(self.outside.join("canary.txt")).unwrap(), "canary");
        }
    }

    /// `(kind, name)` per entry: `ok` or `warn`, in list order.
    fn shape(list: &[ListEntry]) -> Vec<(&'static str, String)> {
        list.iter()
            .map(|r| match r {
                Ok((env, md)) => {
                    assert_eq!(env.id(), &md.id);
                    ("ok", env.id().to_string())
                }
                Err(w) => ("warn", w.name.clone()),
            })
            .collect()
    }

    fn ok(name: &str) -> (&'static str, String) {
        ("ok", name.into())
    }
    fn warn(name: &str) -> (&'static str, String) {
        ("warn", name.into())
    }

    // ------------------------------------------------------------------------------- Store::new

    #[test]
    fn new_requires_an_absolute_root() {
        for p in ["", "apps", "./apps", "rel/apps", "../apps"] {
            assert!(matches!(Store::new(p), Err(StoreError::RelativeRoot)), "{p:?}");
        }
    }

    #[test]
    fn new_rejects_a_root_that_is_not_in_canonical_form() {
        for p in [
            "/tmp/apps/",
            "/tmp/apps//",
            "/",
            "/tmp/apps/.",
            "/tmp/apps/..",
            "/tmp/apps/./",
        ] {
            assert!(matches!(Store::new(p), Err(StoreError::NonCanonicalRoot)), "{p:?}");
        }
        Store::new("/tmp/apps").unwrap();
        Store::new("/tmp/a.b/apps").unwrap();
    }

    // -------------------------------------------------------------------- create / get / accessors

    #[test]
    fn create_get_list_remove_happy_path() {
        let fx = Fx::new();
        assert!(fx.store.list().is_empty());
        let env = fx.add("notepad");
        assert_eq!(env.id().as_str(), "notepad");
        assert_eq!(env.root(), fx.apps.join("notepad"));
        assert_eq!(env.prefix(), fx.apps.join("notepad/prefix"));
        assert_eq!(env.drive_c(), fx.apps.join("notepad/prefix/drive_c"));
        assert_eq!(env.logs_dir(), fx.apps.join("notepad/logs"));
        assert_eq!(env.metadata_path(), fx.apps.join("notepad/metadata.json"));
        assert_eq!(fx.store.get(&id("notepad")).unwrap(), env);
        assert_eq!(fx.store.read_metadata(&env).unwrap(), sample("notepad"));
        fx.add("alpha");
        assert_eq!(shape(&fx.store.list()), [ok("alpha"), ok("notepad")]);
        fx.store.remove(&id("notepad")).unwrap();
        assert!(!env.root().exists());
        assert!(matches!(fx.store.get(&id("notepad")), Err(StoreError::NotFound)));
        assert_eq!(shape(&fx.store.list()), [ok("alpha")]);
    }

    #[test]
    fn create_makes_the_documented_layout_with_private_modes() {
        let fx = Fx::new();
        let env = fx.store.create(&id("app")).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(env.root()), 0o700);
        for d in ["config", "cache", "logs", "runtime", "registry"] {
            let p = env.root().join(d);
            assert!(fs::symlink_metadata(&p).unwrap().is_dir(), "{d}");
            assert_eq!(fs::read_dir(&p).unwrap().count(), 0, "{d} not empty");
            assert_eq!(mode(&p), 0o700, "{d}");
        }
        assert!(!env.prefix().exists(), "the backend creates the prefix");
        assert!(!env.metadata_path().exists());
    }

    #[test]
    fn create_creates_a_missing_apps_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("a/b/apps")).unwrap();
        assert!(store.list().is_empty());
        store.create(&id("x")).unwrap();
        assert!(tmp.path().join("a/b/apps/x/logs").is_dir());
    }

    #[test]
    fn create_twice_errors_and_keeps_the_first() {
        let fx = Fx::new();
        let env = fx.add("app");
        assert!(matches!(fx.store.create(&id("app")), Err(StoreError::AlreadyExists)));
        assert_eq!(fx.store.read_metadata(&env).unwrap(), sample("app"));
    }

    #[test]
    fn create_over_a_symlink_or_file_errors_and_does_not_touch_the_target() {
        let fx = Fx::new();
        symlink(&fx.outside, fx.apps.join("linked")).unwrap();
        assert!(matches!(fx.store.create(&id("linked")), Err(StoreError::AlreadyExists)));
        assert_eq!(
            fs::read_dir(&fx.outside).unwrap().count(),
            1,
            "created inside the link target"
        );
        fx.assert_canary();
        symlink(fx.base.join("does-not-exist"), fx.apps.join("dangling")).unwrap();
        assert!(matches!(
            fx.store.create(&id("dangling")),
            Err(StoreError::AlreadyExists)
        ));
        assert!(!fx.base.join("does-not-exist").exists());
        fs::write(fx.apps.join("file"), "x").unwrap();
        assert!(matches!(fx.store.create(&id("file")), Err(StoreError::AlreadyExists)));
    }

    #[test]
    fn get_refuses_symlinks_and_files_and_reports_missing() {
        let fx = Fx::new();
        symlink(&fx.outside, fx.apps.join("linked")).unwrap();
        fs::write(fx.apps.join("file"), "x").unwrap();
        assert!(matches!(fx.store.get(&id("linked")), Err(StoreError::NotADirectory)));
        assert!(matches!(fx.store.get(&id("file")), Err(StoreError::NotADirectory)));
        assert!(matches!(fx.store.get(&id("missing")), Err(StoreError::NotFound)));
    }

    // ------------------------------------------------------------------------------------ metadata

    #[test]
    fn write_metadata_refuses_an_id_that_differs_from_the_directory() {
        let fx = Fx::new();
        let env = fx.store.create(&id("app")).unwrap();
        assert!(matches!(
            fx.store.write_metadata(&env, &sample("other")),
            Err(StoreError::IdMismatch)
        ));
        assert!(!env.metadata_path().exists());
    }

    #[test]
    fn write_metadata_validates_and_leaves_no_temp_file() {
        let fx = Fx::new();
        let env = fx.store.create(&id("app")).unwrap();
        let mut bad = sample("app");
        bad.executable = "D:\\x.exe".into();
        assert!(matches!(fx.store.write_metadata(&env, &bad), Err(StoreError::Meta(_))));
        fx.store.write_metadata(&env, &sample("app")).unwrap();
        let mut names: Vec<_> = fs::read_dir(env.root())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["cache", "config", "logs", "metadata.json", "registry", "runtime"]
        );
    }

    #[test]
    fn read_metadata_refuses_a_mismatched_id_and_a_symlinked_file() {
        let fx = Fx::new();
        let env = fx.store.create(&id("app")).unwrap();
        sample("other").write_atomic(&env.metadata_path()).unwrap();
        assert!(matches!(fx.store.read_metadata(&env), Err(StoreError::IdMismatch)));
        fs::remove_file(env.metadata_path()).unwrap();
        let outside_md = fx.outside.join("metadata.json");
        sample("app").write_atomic(&outside_md).unwrap();
        symlink(&outside_md, env.metadata_path()).unwrap();
        assert!(matches!(
            fx.store.read_metadata(&env),
            Err(StoreError::Meta(MetaError::NotRegular))
        ));
    }

    // ------------------------------------------------------------------------------------- list

    /// One good app on each side of one bad entry: the bad one is exactly one warning, in name order.
    fn list_with_bad(fx: &Fx, bad: &str) -> Vec<(&'static str, String)> {
        fx.add("aaa");
        fx.add("zzz");
        shape(&fx.store.list())
            .into_iter()
            .inspect(|(_, n)| assert!(["aaa", "zzz", bad].contains(&n.as_str()), "unexpected {n}"))
            .collect()
    }

    #[test]
    fn list_warns_on_corrupt_json() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        fs::write(env.metadata_path(), "{ not json").unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
    }

    #[test]
    fn list_warns_on_missing_metadata() {
        let fx = Fx::new();
        fx.store.create(&id("mid")).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
    }

    #[test]
    fn list_warns_on_wrong_schema_version() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        let text = serde_json::to_string(&sample("mid"))
            .unwrap()
            .replace("\"schemaVersion\":1", "\"schemaVersion\":2");
        fs::write(env.metadata_path(), text).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
        let list = fx.store.list();
        let w = list[1].as_ref().unwrap_err();
        assert!(matches!(w.error, StoreError::Meta(MetaError::SchemaVersion(2))), "{w}");
    }

    #[test]
    fn list_warns_on_an_oversize_metadata_file() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        let mut text = serde_json::to_string(&sample("mid")).unwrap();
        text.push_str(&" ".repeat(MAX_FILE_BYTES as usize)); // valid JSON, just too big
        fs::write(env.metadata_path(), text).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
        let list = fx.store.list();
        assert!(matches!(
            list[1].as_ref().unwrap_err().error,
            StoreError::Meta(MetaError::TooLarge)
        ));
    }

    #[test]
    fn list_warns_on_an_oversize_name() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        let mut md = sample("mid");
        md.name = "n".repeat(257);
        fs::write(env.metadata_path(), serde_json::to_vec(&md).unwrap()).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
    }

    #[test]
    fn list_warns_on_an_invalid_executable() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        let mut md = sample("mid");
        md.executable = "D:\\x.exe".into();
        fs::write(env.metadata_path(), serde_json::to_vec(&md).unwrap()).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
    }

    #[test]
    fn list_warns_when_the_metadata_id_differs_from_the_directory() {
        let fx = Fx::new();
        let env = fx.store.create(&id("mid")).unwrap();
        // Valid on its own, but claims to be another app (which would make `mid` shadow it).
        sample("aaa").write_atomic(&env.metadata_path()).unwrap();
        let list = list_with_bad(&fx, "mid");
        assert_eq!(list, [ok("aaa"), warn("mid"), ok("zzz")]);
        let listed = fx.store.list();
        assert!(matches!(listed[1].as_ref().unwrap_err().error, StoreError::IdMismatch));
    }

    #[test]
    fn list_warns_on_a_symlink_entry_and_never_follows_it() {
        let fx = Fx::new();
        let target = fx.outside.join("app");
        fs::create_dir(&target).unwrap();
        sample("mid").write_atomic(&target.join("metadata.json")).unwrap(); // looks like a valid app
        symlink(&target, fx.apps.join("mid")).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
        let listed = fx.store.list();
        assert!(matches!(
            listed[1].as_ref().unwrap_err().error,
            StoreError::NotADirectory
        ));
    }

    #[test]
    fn list_warns_on_a_plain_file_entry_and_a_dangling_link() {
        let fx = Fx::new();
        fs::write(fx.apps.join("mid"), "not a dir").unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
        let fx = Fx::new();
        symlink(fx.base.join("nowhere"), fx.apps.join("mid")).unwrap();
        assert_eq!(list_with_bad(&fx, "mid"), [ok("aaa"), warn("mid"), ok("zzz")]);
    }

    #[test]
    fn list_warns_on_directory_names_that_are_not_app_ids() {
        let fx = Fx::new();
        for name in ["Upper", "has space", "-lead", ".hidden", "trail.", "a..b"] {
            fs::create_dir(fx.apps.join(name)).unwrap();
        }
        fs::create_dir(fx.apps.join(OsStr::from_bytes(b"bad\xffname"))).unwrap();
        fs::create_dir(fx.apps.join("x".repeat(65))).unwrap();
        fx.add("good");
        let list = fx.store.list();
        let oks: Vec<_> = list.iter().filter(|r| r.is_ok()).collect();
        assert_eq!(oks.len(), 1);
        assert_eq!(list.len(), 9, "{:?}", shape(&list));
        for r in &list {
            if let Err(w) = r {
                assert!(matches!(w.error, StoreError::InvalidName(_)), "{w}");
            }
        }
        // sorted by directory name
        let names: Vec<_> = shape(&list).into_iter().map(|(_, n)| n).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn list_of_a_missing_apps_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("nope")).unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn list_reports_an_unreadable_apps_dir_instead_of_hiding_it() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("apps");
        fs::write(&file, "x").unwrap();
        let list = Store::new(&file).unwrap().list();
        assert_eq!(list.len(), 1);
        assert!(matches!(list[0].as_ref().unwrap_err().error, StoreError::Io(_)));
    }

    #[test]
    fn a_symlinked_apps_dir_is_trusted_configuration_and_works() {
        let fx = Fx::new();
        let link = fx.base.join("apps-link");
        symlink(&fx.apps, &link).unwrap();
        let store = Store::new(&link).unwrap();
        store.create(&id("app")).unwrap();
        assert_eq!(store.list().len(), 1);
        store.remove(&id("app")).unwrap();
        assert!(store.list().is_empty());
    }

    #[test]
    fn list_scans_at_most_the_cap_then_reports_it() {
        let fx = Fx::new();
        for i in 0..8 {
            fs::write(fx.apps.join(format!("f{i}")), "x").unwrap();
        }
        let list = fx.store.list_limited(5);
        assert_eq!(list.len(), 6, "5 examined + 1 cap marker");
        let last = list.last().unwrap().as_ref().unwrap_err();
        assert!(matches!(last.error, StoreError::TooManyEntries { max: 5 }), "{last}");
        // Exactly at the cap is not an error.
        let list = fx.store.list_limited(8);
        assert_eq!(list.len(), 8);
        assert!(
            list.iter()
                .all(|r| !matches!(r, Err(w) if matches!(w.error, StoreError::TooManyEntries { .. })))
        );
    }

    // ------------------------------------------------------------------------------------ remove

    #[test]
    fn remove_refuses_an_app_dir_that_is_a_symlink() {
        let fx = Fx::new();
        symlink(&fx.outside, fx.apps.join("evil")).unwrap();
        let err = fx.store.remove(&id("evil")).unwrap_err();
        assert!(matches!(err, StoreError::NotADirectory), "{err:?}");
        fx.assert_canary();
        assert!(
            fs::symlink_metadata(fx.apps.join("evil")).is_ok(),
            "the link itself was removed"
        );
    }

    #[test]
    fn remove_refuses_a_plain_file() {
        let fx = Fx::new();
        fs::write(fx.apps.join("file"), "x").unwrap();
        assert!(matches!(fx.store.remove(&id("file")), Err(StoreError::NotADirectory)));
        assert!(fx.apps.join("file").exists());
    }

    #[test]
    fn remove_deletes_a_leaked_link_inside_the_app_but_never_its_target() {
        let fx = Fx::new();
        let env = fx.add("app");
        let users = env.drive_c().join("users/me");
        fs::create_dir_all(&users).unwrap();
        symlink(&fx.outside, users.join("Documents")).unwrap();
        symlink(fx.outside.join("canary.txt"), env.root().join("logs/latest")).unwrap();
        fx.store.remove(&id("app")).unwrap();
        assert!(!env.root().exists());
        fx.assert_canary();
    }

    #[test]
    fn remove_of_a_missing_id_says_not_found() {
        let fx = Fx::new();
        let err = fx.store.remove(&id("ghost")).unwrap_err();
        assert!(matches!(err, StoreError::NotFound), "{err:?}");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn remove_app_dir_only_accepts_a_direct_child_of_the_apps_dir() {
        let fx = Fx::new();
        fx.add("app");
        let nested = fx.apps.join("app/config");
        assert!(matches!(
            fx.store.remove_app_dir(&nested),
            Err(StoreError::NotUnderApps)
        ));
        assert!(nested.is_dir());
        let victim = fx.base.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("f"), "x").unwrap();
        let sneaky = fx.apps.join("..").join("victim");
        assert!(matches!(
            fx.store.remove_app_dir(&sneaky),
            Err(StoreError::NotUnderApps)
        ));
        assert!(matches!(
            fx.store.remove_app_dir(&victim),
            Err(StoreError::NotUnderApps)
        ));
        assert!(matches!(
            fx.store.remove_app_dir(&fx.apps),
            Err(StoreError::NotUnderApps)
        ));
        // `apps/..` has parent `apps` but names the apps dir's parent.
        assert!(matches!(
            fx.store.remove_app_dir(&fx.apps.join("..")),
            Err(StoreError::NotUnderApps)
        ));
        assert!(fx.outside.join("canary.txt").exists());
        assert!(victim.join("f").exists());
        assert!(fx.apps.exists());
    }

    // -------------------------------------------------------------------------------- unique_id

    #[test]
    fn unique_id_returns_the_base_when_free() {
        let fx = Fx::new();
        assert_eq!(unique_id(&fx.store, &id("notepad")).unwrap(), id("notepad"));
    }

    #[test]
    fn unique_id_appends_increasing_suffixes() {
        let fx = Fx::new();
        fx.add("notepad");
        assert_eq!(unique_id(&fx.store, &id("notepad")).unwrap(), id("notepad-2"));
        fx.add("notepad-2");
        assert_eq!(unique_id(&fx.store, &id("notepad")).unwrap(), id("notepad-3"));
        // A gap is reused; a non-directory or a dangling link also counts as taken.
        fs::write(fx.apps.join("notepad-3"), "x").unwrap();
        symlink(fx.base.join("nowhere"), fx.apps.join("notepad-4")).unwrap();
        assert_eq!(unique_id(&fx.store, &id("notepad")).unwrap(), id("notepad-5"));
    }

    #[test]
    fn unique_id_keeps_a_64_byte_base_valid_and_within_the_limit() {
        let fx = Fx::new();
        let base = id(&"a".repeat(64));
        fx.add(base.as_str());
        let two = unique_id(&fx.store, &base).unwrap();
        assert_eq!(two.as_str(), format!("{}-2", "a".repeat(62)));
        fx.add(two.as_str());
        assert_eq!(
            unique_id(&fx.store, &base).unwrap().as_str(),
            format!("{}-3", "a".repeat(62))
        );
        // A cut that would leave a trailing '.' or '-' is trimmed so the id stays valid.
        let cut = id(&format!("{}-{}", "a".repeat(61), "bb")); // 64 bytes; the 62-byte cut ends in '-'
        fx.add(cut.as_str());
        let next = unique_id(&fx.store, &cut).unwrap();
        assert_eq!(next.as_str(), format!("{}-2", "a".repeat(61)));
        assert!(next.as_str().len() <= 64);
    }

    #[test]
    fn unique_id_gives_up_after_999() {
        let fx = Fx::new();
        fs::create_dir(fx.apps.join("x")).unwrap();
        for n in 2..=999 {
            fs::create_dir(fx.apps.join(format!("x-{n}"))).unwrap();
        }
        assert!(matches!(unique_id(&fx.store, &id("x")), Err(StoreError::NoUniqueId)));
        fs::remove_dir(fx.apps.join("x-999")).unwrap();
        assert_eq!(unique_id(&fx.store, &id("x")).unwrap(), id("x-999"));
    }
}
