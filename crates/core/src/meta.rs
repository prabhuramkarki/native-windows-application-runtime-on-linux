//! `metadata.json`: what the runtime records about an installed app.
//!
//! The file lives inside the app's directory, where another process (or an older version) can rewrite it, so it
//! is untrusted input. [`Metadata::read`] therefore reads at most [`MAX_FILE_BYTES`] bytes of a regular file
//! (never a symlink), rejects anything that does not parse or validate, and never panics. serde's `AppId`
//! allocates before it validates, so the read cap is what bounds that allocation. serde_json limits nesting
//! depth (128), so hostile nesting is an error, not a stack overflow. Unknown fields are ignored.
//!
//! The same [`Metadata::validate`] runs before every write, so this crate never persists a file it would
//! refuse to read.
//!
//! `executable` is the canonical text of a [`WinPath`]. The rules are `WinPath::parse` succeeds, the drive is
//! `C` (the only drive [`crate::resolve_under`] maps), there is at least one component and the text equals
//! `WinPath::to_string` (so `c:/a.exe` is refused on read and on write). Callers re-parse it before use; the text
//! is never turned into a host path by concatenation. Build values with [`Metadata::new`].
use crate::{AppId, WinPath, WinPathError};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// The schema version this crate writes.
pub const SCHEMA_VERSION: u32 = 2;
/// The oldest schema version this crate still reads. Schema 1 (Phase 2) had no `installer` field; it deserialises
/// fine into today's `Metadata` because `installer` is `#[serde(default)]`, so `1..=SCHEMA_VERSION` is accepted
/// rather than exact equality. There is no other shape difference between 1 and 2 yet, so no field-by-field
/// migration code exists: `installer: None` for a v1 file already IS its correct v2 reading.
pub const MIN_SCHEMA_VERSION: u32 = 1;
/// Largest `metadata.json` that is read, in bytes.
pub const MAX_FILE_BYTES: u64 = 64 * 1024;
/// Longest `name`, in bytes.
pub const MAX_NAME_LEN: usize = 256;
/// Longest of every other string field, in bytes.
pub const MAX_FIELD_LEN: usize = 1024;
/// Longest message kept from a parse error (those can quote file content).
const MAX_MESSAGE_LEN: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("metadata file is not a regular file")]
    NotRegular,
    #[error("metadata file is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge,
    /// `Display` may quote (clipped) file content: sanitise before printing.
    #[error("metadata is malformed: {0}")]
    Parse(String),
    #[error("unsupported schemaVersion {0} (expected {MIN_SCHEMA_VERSION}..={SCHEMA_VERSION})")]
    SchemaVersion(u64),
    #[error("field `{field}` is longer than {max} bytes")]
    TooLong { field: &'static str, max: usize },
    #[error("architecture must be \"x86\" or \"x86_64\"")]
    BadArchitecture,
    #[error("executable is not an acceptable Windows path: {0}")]
    BadExecutable(#[from] WinPathError),
    #[error("executable must be on drive C:")]
    ExecutableDrive,
    #[error("executable names the drive root, not a file")]
    ExecutableIsRoot,
    #[error("executable must be in canonical form (`C:\\dir\\file.exe`: uppercase drive, backslashes, no `.` parts)")]
    NonCanonicalExecutable,
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInfo {
    pub id: String,
    pub version: String,
}

/// What `installer::pipeline` (Phase 3 Task 6) recorded about the installer that produced this app, when it was
/// installed via `.msi`/`.exe` installer rather than as a portable executable. Added in schema version 2;
/// `#[serde(default)]` on [`Metadata::installer`] is what lets a schema-1 file (which has no `installer` key at
/// all) still deserialise, as `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallerMeta {
    /// `InstallerFamily`'s label (`"inno"`, `"nsis"`, `"installshield"`, `"wix-burn"`, `"msi"`, `"unknown"`). A
    /// plain `String` here, not the `rt_installer` enum: `runtime-core` does not depend on `runtime-installer`
    /// (the dependency runs the other way), so the family is recorded as its stable text label.
    pub family: String,
    /// The installer's own product name (an MSI's `ProductName`, or a `DisplayName` recovered from the
    /// `Uninstall` registry key the installer wrote), if one could be determined.
    pub product_name: Option<String>,
    /// The uninstaller command line recorded by the installer (an `UninstallString` value under `Uninstall`),
    /// if the installer registered one. `runtime uninstall` runs this, when present, before removing the app's
    /// environment.
    pub uninstall_command: Option<String>,
}

/// The contents of `metadata.json`. The public fields make it easy to build; `serde` alone does not validate,
/// so read and write only through [`Metadata::parse`], [`Metadata::read`] and [`Metadata::write_atomic`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub schema_version: u32,
    pub id: AppId,
    pub name: String,
    pub version: Option<String>,
    /// `"x86"` or `"x86_64"`.
    pub architecture: String,
    /// Canonical [`WinPath`] text, e.g. `C:\Program Files\App\app.exe`.
    pub executable: String,
    pub environment: String,
    pub backend: BackendInfo,
    pub subsystem: String,
    /// Unix seconds.
    pub created: u64,
    /// `Some` when this app was installed via `.msi`/`.exe` installer (schema version 2). `#[serde(default)]`
    /// so a schema-1 file (no `installer` key) still deserialises, as `None`.
    #[serde(default)]
    pub installer: Option<InstallerMeta>,
}

fn cap(field: &'static str, value: &str, max: usize) -> Result<(), MetaError> {
    if value.len() > max {
        return Err(MetaError::TooLong { field, max });
    }
    Ok(())
}

/// Keeps error text bounded: parse errors can quote the file.
fn clip(mut msg: String) -> String {
    if msg.len() > MAX_MESSAGE_LEN {
        let mut end = MAX_MESSAGE_LEN;
        while !msg.is_char_boundary(end) {
            end -= 1;
        }
        msg.truncate(end);
        msg.push_str("...");
    }
    msg
}

/// Just enough to report an unknown schema before the (possibly different) rest of the file is interpreted.
#[derive(Deserialize)]
struct Probe {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
}

/// At most [`MAX_FILE_BYTES`] bytes of `r`; one more is an error, and never more than one more is read (serde's
/// `AppId` allocates before validating, so this is what bounds memory).
fn read_capped(r: impl Read) -> Result<Vec<u8>, MetaError> {
    let mut bytes = Vec::new();
    r.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(MetaError::TooLarge);
    }
    Ok(bytes)
}

/// Opens `path` read-only with `O_NONBLOCK`: opening a FIFO (with no writer) then returns at once instead of
/// blocking forever, and the caller's fstat rejects it. For a regular file the flag changes nothing.
pub(crate) fn open_nonblocking(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)
}

/// Best effort: makes a rename in `dir` durable. Opened with `O_DIRECTORY|O_NONBLOCK`, so if `dir` was swapped for
/// a FIFO (by a process of the same uid) in the meantime, the open fails with `ENOTDIR` at once instead of
/// blocking until a writer appears. Any failure here is ignored: the rename already happened.
fn sync_dir(dir: &Path) {
    if let Ok(d) = open_dir_nonblocking(dir) {
        let _ = d.sync_all();
    }
}

/// Opens `dir` read-only, and only if it is a directory (`O_DIRECTORY`: `ENOTDIR` for a FIFO, a file, ...), without
/// blocking (`O_NONBLOCK`).
fn open_dir_nonblocking(dir: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
        .open(dir)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl Metadata {
    /// Builds metadata for a freshly installed app: schema version, `environment` `"default"` and `created` (now)
    /// are filled in; `executable` is stored as the canonical text of `executable`. Not validated: call
    /// [`Metadata::validate`] (write does it too) before anything is created on disk.
    pub fn new(
        id: AppId,
        name: String,
        version: Option<String>,
        architecture: &str,
        executable: &WinPath,
        backend: BackendInfo,
        subsystem: &str,
    ) -> Metadata {
        Metadata {
            schema_version: SCHEMA_VERSION,
            id,
            name,
            version,
            architecture: architecture.to_owned(),
            executable: executable.to_string(),
            environment: "default".to_owned(),
            backend,
            subsystem: subsystem.to_owned(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            installer: None,
        }
    }

    pub fn validate(&self) -> Result<(), MetaError> {
        if !(MIN_SCHEMA_VERSION..=SCHEMA_VERSION).contains(&self.schema_version) {
            return Err(MetaError::SchemaVersion(self.schema_version.into()));
        }
        cap("name", &self.name, MAX_NAME_LEN)?;
        if let Some(v) = &self.version {
            cap("version", v, MAX_FIELD_LEN)?;
        }
        cap("architecture", &self.architecture, MAX_FIELD_LEN)?;
        if !matches!(self.architecture.as_str(), "x86" | "x86_64") {
            return Err(MetaError::BadArchitecture);
        }
        cap("executable", &self.executable, MAX_FIELD_LEN)?;
        let exe = WinPath::parse(&self.executable)?;
        if exe.drive() != 'C' {
            return Err(MetaError::ExecutableDrive);
        }
        if exe.components().is_empty() {
            return Err(MetaError::ExecutableIsRoot);
        }
        // Canonical text only: what is stored is exactly what `WinPath::to_string` writes, so two spellings of
        // one path can never coexist and a reader never has to normalise.
        if exe.to_string() != self.executable {
            return Err(MetaError::NonCanonicalExecutable);
        }
        cap("environment", &self.environment, MAX_FIELD_LEN)?;
        cap("backend.id", &self.backend.id, MAX_FIELD_LEN)?;
        cap("backend.version", &self.backend.version, MAX_FIELD_LEN)?;
        cap("subsystem", &self.subsystem, MAX_FIELD_LEN)?;
        if let Some(installer) = &self.installer {
            cap("installer.family", &installer.family, MAX_FIELD_LEN)?;
            if let Some(p) = &installer.product_name {
                cap("installer.productName", p, MAX_FIELD_LEN)?;
            }
            if let Some(u) = &installer.uninstall_command {
                cap("installer.uninstallCommand", u, MAX_FIELD_LEN)?;
            }
        }
        Ok(())
    }

    /// Parses and validates `metadata.json` bytes (no size limit here: [`Metadata::read`] applies it).
    pub fn parse(bytes: &[u8]) -> Result<Metadata, MetaError> {
        let parse_err = |e: serde_json::Error| MetaError::Parse(clip(e.to_string()));
        let probe: Probe = serde_json::from_slice(bytes).map_err(parse_err)?;
        if !(u64::from(MIN_SCHEMA_VERSION)..=u64::from(SCHEMA_VERSION)).contains(&probe.schema_version) {
            return Err(MetaError::SchemaVersion(probe.schema_version));
        }
        let md: Metadata = serde_json::from_slice(bytes).map_err(parse_err)?;
        md.validate()?;
        Ok(md)
    }

    /// Reads and validates a `metadata.json`. Refuses non-regular files (including symlinks) and files over
    /// [`MAX_FILE_BYTES`].
    pub fn read(path: &Path) -> Result<Metadata, MetaError> {
        let before = fs::symlink_metadata(path)?;
        if !before.file_type().is_file() {
            return Err(MetaError::NotRegular);
        }
        read_checked(path, &before)
    }
}

/// Opens `path` (see [`open_nonblocking`]), requires the handle to be the very regular file `before` described,
/// and parses it.
fn read_checked(path: &Path, before: &fs::Metadata) -> Result<Metadata, MetaError> {
    let file = open_nonblocking(path)?;
    // The path could have been swapped for a symlink or a FIFO between the lstat and the open: the handle we hold
    // must be the very file we checked. `O_NONBLOCK` keeps the open of a swapped-in FIFO from blocking.
    let after = file.metadata()?;
    if !after.file_type().is_file() || (after.dev(), after.ino()) != (before.dev(), before.ino()) {
        return Err(MetaError::NotRegular);
    }
    Metadata::parse(&read_capped(file)?)
}

impl Metadata {
    /// Validates, then writes atomically: a `0600` temp file in the same directory (`O_EXCL`), `sync_all`,
    /// rename over `path`, best-effort directory fsync. The temp file is removed on every failure.
    pub fn write_atomic(&self, path: &Path) -> Result<(), MetaError> {
        self.validate()?;
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "metadata path has no file name"))?;
        let (tmp, mut file) = create_temp(dir, name)?;
        let written = file.write_all(&json).and_then(|()| file.sync_all()).and_then(|()| {
            drop(file);
            fs::rename(&tmp, path)
        });
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        sync_dir(dir);
        Ok(())
    }
}

/// A new `0600` file next to the target, created with `O_EXCL` so an existing name (even a symlink) is never
/// opened. Names are unique per process and call; a leftover from a crashed run is skipped, not reused.
fn create_temp(dir: &Path, target: &std::ffi::OsStr) -> io::Result<(std::path::PathBuf, File)> {
    let mut last = None;
    for _ in 0..16 {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut name = std::ffi::OsString::from(".");
        name.push(target);
        name.push(format!(".tmp-{}-{n}", std::process::id()));
        let tmp = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temporary file")))
}

#[cfg(test)]
pub(crate) fn sample(id: &str) -> Metadata {
    Metadata {
        schema_version: SCHEMA_VERSION,
        id: AppId::parse(id).unwrap(),
        name: "Sample App".into(),
        version: Some("1.2.3".into()),
        architecture: "x86_64".into(),
        executable: "C:\\Program Files\\Sample\\app.exe".into(),
        environment: "default".into(),
        backend: BackendInfo {
            id: "wine".into(),
            version: "wine-10.0".into(),
        },
        subsystem: "gui".into(),
        created: 1_700_000_000,
        installer: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{mkfifo, within_10s};
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn json(m: &Metadata) -> String {
        serde_json::to_string(m).unwrap()
    }

    /// The valid sample as a JSON object with one top-level key replaced (or removed when `None`).
    fn with(key: &str, value: Option<serde_json::Value>) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_str(&json(&sample("app"))).unwrap();
        let obj = v.as_object_mut().unwrap();
        match value {
            Some(x) => obj.insert(key.into(), x),
            None => obj.remove(key),
        };
        serde_json::to_vec(&v).unwrap()
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn round_trip_and_camel_case_wire_format() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        let m = sample("my-app");
        m.write_atomic(&path).unwrap();
        assert_eq!(Metadata::read(&path).unwrap(), m);
        let text = fs::read_to_string(&path).unwrap();
        for key in ["\"schemaVersion\": 2", "\"created\"", "\"backend\"", "\"executable\""] {
            assert!(text.contains(key), "{key} missing in {text}");
        }
        let mut none_version = m.clone();
        none_version.version = None;
        none_version.write_atomic(&path).unwrap();
        assert_eq!(Metadata::read(&path).unwrap(), none_version);
    }

    #[test]
    fn unknown_fields_are_ignored_and_optional_version_may_be_absent() {
        let mut v: serde_json::Value = serde_json::from_str(&json(&sample("app"))).unwrap();
        v["future"] = serde_json::json!({"a": [1, 2, 3]});
        v.as_object_mut().unwrap().remove("version");
        let m = Metadata::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(m.version, None);
    }

    #[test]
    fn missing_required_fields_are_errors() {
        for key in [
            "schemaVersion",
            "id",
            "name",
            "architecture",
            "executable",
            "environment",
            "backend",
            "subsystem",
            "created",
        ] {
            assert!(Metadata::parse(&with(key, None)).is_err(), "accepted without {key}");
        }
        let no_backend_version = with("backend", Some(serde_json::json!({"id": "wine"})));
        assert!(Metadata::parse(&no_backend_version).is_err());
    }

    #[test]
    fn wrong_types_and_bad_ids_are_errors() {
        let cases = [
            ("created", serde_json::json!(-1)),
            ("created", serde_json::json!(1.5)),
            ("created", serde_json::json!("1")),
            ("name", serde_json::json!(5)),
            ("id", serde_json::json!("../evil")),
            ("id", serde_json::json!("A")),
            ("id", serde_json::json!("")),
            ("id", serde_json::json!(7)),
        ];
        for (key, val) in cases {
            assert!(Metadata::parse(&with(key, Some(val.clone()))).is_err(), "{key}={val}");
        }
    }

    #[test]
    fn schema_version_accepts_1_and_2_and_rejects_everything_else() {
        for v in [0u64, 3, 99, u64::MAX] {
            let err = Metadata::parse(&with("schemaVersion", Some(serde_json::json!(v)))).unwrap_err();
            assert!(matches!(err, MetaError::SchemaVersion(n) if n == v), "{v}: {err:?}");
        }
        // Both ends of the supported range parse (the sample's own shape already carries `installer: None`).
        for v in [1u64, 2] {
            let bytes = with("schemaVersion", Some(serde_json::json!(v)));
            Metadata::parse(&bytes).unwrap_or_else(|e| panic!("schemaVersion {v} should parse: {e}"));
        }
        // An unknown future version with a shape we do not know is still reported as the version.
        let err = Metadata::parse(br#"{"schemaVersion":3,"totally":"different"}"#).unwrap_err();
        assert!(matches!(err, MetaError::SchemaVersion(3)), "{err:?}");
        let mut m = sample("app");
        m.schema_version = 3;
        assert!(matches!(m.validate(), Err(MetaError::SchemaVersion(3))));
        let mut m = sample("app");
        m.schema_version = 1;
        m.validate().unwrap();
    }

    /// The migration proper: genuine OLD-shape bytes (schema version 1, no `installer` key at all — not merely a
    /// `Metadata` struct literal that happens to omit it) still read, with `installer: None`.
    #[test]
    fn old_v1_metadata_with_no_installer_key_still_reads() {
        let mut v: serde_json::Value = serde_json::from_str(&json(&sample("app"))).unwrap();
        v["schemaVersion"] = serde_json::json!(1);
        let obj = v.as_object_mut().unwrap();
        assert!(obj.remove("installer").is_some(), "sample must have serialised an installer key to remove");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("installer"), "installer key must really be gone");

        let m = Metadata::parse(&bytes).unwrap();
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.installer, None);

        // Same, but through `Metadata::read` (a real file on disk), per the task's requirement.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        fs::write(&path, &bytes).unwrap();
        let read = Metadata::read(&path).unwrap();
        assert_eq!(read.schema_version, 1);
        assert_eq!(read.installer, None);
    }

    #[test]
    fn installer_meta_round_trips_and_its_string_fields_are_capped() {
        let mut m = sample("app");
        m.installer = Some(InstallerMeta {
            family: "nsis".into(),
            product_name: Some("Hello NSIS".into()),
            uninstall_command: Some("C:\\Program Files\\hello\\uninstall.exe".into()),
        });
        m.validate().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        m.write_atomic(&path).unwrap();
        assert_eq!(Metadata::read(&path).unwrap(), m);

        type Set = fn(&mut Metadata, String);
        let fields: [(&str, Set); 3] = [
            ("installer.family", |m, s| m.installer.as_mut().unwrap().family = s),
            ("installer.productName", |m, s| m.installer.as_mut().unwrap().product_name = Some(s)),
            ("installer.uninstallCommand", |m, s| {
                m.installer.as_mut().unwrap().uninstall_command = Some(s)
            }),
        ];
        for (field, set) in fields {
            let mut long = m.clone();
            set(&mut long, "a".repeat(MAX_FIELD_LEN + 1));
            let err = long.validate().unwrap_err();
            assert!(matches!(err, MetaError::TooLong { .. }), "{field}: {err:?}");
        }
    }

    #[test]
    fn architecture_must_be_x86_or_x86_64() {
        for a in ["x86", "x86_64"] {
            let mut m = sample("app");
            m.architecture = a.into();
            m.validate().unwrap();
        }
        for a in ["", "arm64", "X86", "x86_64 ", "i386", "amd64"] {
            let mut m = sample("app");
            m.architecture = a.into();
            assert!(matches!(m.validate(), Err(MetaError::BadArchitecture)), "{a:?}");
            assert!(Metadata::parse(&with("architecture", Some(a.into()))).is_err(), "{a:?}");
        }
    }

    #[test]
    fn executable_validation_table_on_write_and_read() {
        let good = ["C:\\app.exe", "C:\\Program Files\\App\\app.exe", "C:\\a\\b\\c\\d.exe"];
        for e in good {
            let mut m = sample("app");
            m.executable = e.into();
            m.validate().unwrap_or_else(|err| panic!("{e}: {err}"));
        }
        type Kind = fn(&MetaError) -> bool;
        let bad: [(&str, Kind); 9] = [
            ("D:\\app.exe", |e| matches!(e, MetaError::ExecutableDrive)),
            ("C:\\", |e| matches!(e, MetaError::ExecutableIsRoot)),
            ("\\\\server\\share\\a.exe", |e| matches!(e, MetaError::BadExecutable(_))),
            ("C:\\a\\..\\b.exe", |e| matches!(e, MetaError::BadExecutable(_))),
            ("C:\\con", |e| matches!(e, MetaError::BadExecutable(_))),
            ("C:\\a\\NUL.exe", |e| matches!(e, MetaError::BadExecutable(_))),
            ("app.exe", |e| matches!(e, MetaError::BadExecutable(_))),
            ("", |e| matches!(e, MetaError::BadExecutable(_))),
            ("\\\\?\\C:\\a.exe", |e| matches!(e, MetaError::BadExecutable(_))),
        ];
        for (e, kind) in bad {
            let mut m = sample("app");
            m.executable = e.into();
            let err = m.validate().unwrap_err();
            assert!(kind(&err), "{e:?} gave {err:?}");
            let err = Metadata::parse(&with("executable", Some(e.into()))).unwrap_err();
            assert!(kind(&err), "read {e:?} gave {err:?}");
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("metadata.json");
            assert!(m.write_atomic(&path).is_err(), "wrote {e:?}");
            assert!(!path.exists(), "left a file for {e:?}");
        }
    }

    #[test]
    fn string_fields_are_capped_on_write_and_read() {
        type Set = fn(&mut Metadata, String);
        let fields: [(&str, usize, Set); 6] = [
            ("name", MAX_NAME_LEN, |m, s| m.name = s),
            ("version", MAX_FIELD_LEN, |m, s| m.version = Some(s)),
            ("environment", MAX_FIELD_LEN, |m, s| m.environment = s),
            ("subsystem", MAX_FIELD_LEN, |m, s| m.subsystem = s),
            ("backend.id", MAX_FIELD_LEN, |m, s| m.backend.id = s),
            ("backend.version", MAX_FIELD_LEN, |m, s| m.backend.version = s),
        ];
        for (name, max, set) in fields {
            let mut ok = sample("app");
            set(&mut ok, "a".repeat(max));
            ok.validate().unwrap_or_else(|e| panic!("{name} at cap: {e}"));
            let mut long = sample("app");
            set(&mut long, "a".repeat(max + 1));
            let err = long.validate().unwrap_err();
            assert!(matches!(err, MetaError::TooLong { .. }), "{name}: {err:?}");
            let bytes = serde_json::to_vec(&long).unwrap();
            assert!(
                matches!(Metadata::parse(&bytes), Err(MetaError::TooLong { .. })),
                "read accepted long {name}"
            );
        }
        // `executable` is capped too (built from valid 200-byte components so only the cap can trip).
        let exe_of_len = |n: usize| {
            let mut s = String::from("C:\\");
            while s.len() < n {
                s.push_str(&"a".repeat((n - s.len()).min(200)));
                if s.len() < n {
                    s.push('\\');
                }
            }
            s
        };
        let mut m = sample("app");
        m.executable = exe_of_len(MAX_FIELD_LEN);
        assert_eq!(m.executable.len(), MAX_FIELD_LEN);
        m.validate().unwrap();
        m.executable = exe_of_len(MAX_FIELD_LEN + 1);
        assert!(matches!(
            m.validate(),
            Err(MetaError::TooLong {
                field: "executable",
                ..
            })
        ));
        assert!(matches!(
            Metadata::parse(&serde_json::to_vec(&m).unwrap()),
            Err(MetaError::TooLong { .. })
        ));
        // Bytes, not chars: 129 two-byte chars exceed a 256-byte name.
        let mut m = sample("app");
        m.name = "\u{e9}".repeat(129);
        assert!(matches!(m.validate(), Err(MetaError::TooLong { .. })));
    }

    #[test]
    fn parse_never_panics_on_hostile_bytes() {
        let deep_unknown = format!("{{\"x\":{}}}", "[".repeat(50_000));
        let deep_known = format!("{{\"backend\":{}", "{\"a\":".repeat(50_000));
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            b"{".to_vec(),
            b"null".to_vec(),
            b"[]".to_vec(),
            vec![0xff, 0xfe, 0x00, 0x80],
            b"{\"id\":\"\xff\"}".to_vec(),
            b"\xef\xbb\xbf{}".to_vec(),
            deep_unknown.into_bytes(),
            deep_known.into_bytes(),
            "[".repeat(60_000).into_bytes(),
            [json(&sample("app")).as_bytes(), b" trailing"].concat(),
        ];
        for c in cases {
            assert!(
                Metadata::parse(&c).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(&c[..c.len().min(30)])
            );
        }
    }

    #[test]
    fn parse_error_messages_are_clipped() {
        let big = "x".repeat(50_000);
        let bytes = with("created", Some(big.into()));
        let msg = Metadata::parse(&bytes).unwrap_err().to_string();
        assert!(msg.len() < 1024, "message is {} bytes", msg.len());
    }

    #[test]
    fn read_cap_is_64_kib() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        let body = json(&sample("app"));
        let pad = |total: usize| {
            let mut s = body.clone();
            s.push_str(&" ".repeat(total - s.len()));
            s
        };
        fs::write(&path, pad(MAX_FILE_BYTES as usize)).unwrap();
        Metadata::read(&path).expect("exactly at the cap is accepted");
        fs::write(&path, pad(MAX_FILE_BYTES as usize + 1)).unwrap();
        assert!(matches!(Metadata::read(&path), Err(MetaError::TooLarge)));
        // A much bigger (sparse) file is refused without reading it all.
        let f = File::create(&path).unwrap();
        f.set_len(1 << 32).unwrap();
        assert!(matches!(Metadata::read(&path), Err(MetaError::TooLarge)));
    }

    #[test]
    fn read_refuses_symlinks_directories_and_missing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real.json");
        sample("app").write_atomic(&real).unwrap();
        let link = tmp.path().join("metadata.json");
        symlink(&real, &link).unwrap();
        assert!(matches!(Metadata::read(&link), Err(MetaError::NotRegular)));
        let dir = tmp.path().join("dir.json");
        fs::create_dir(&dir).unwrap();
        assert!(matches!(Metadata::read(&dir), Err(MetaError::NotRegular)));
        let dangling = tmp.path().join("dangling.json");
        symlink(tmp.path().join("nope"), &dangling).unwrap();
        assert!(Metadata::read(&dangling).is_err());
        assert!(matches!(
            Metadata::read(&tmp.path().join("nope")),
            Err(MetaError::Io(_))
        ));
    }

    #[test]
    fn atomic_write_leaves_only_the_target_and_replaces_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        sample("app").write_atomic(&path).unwrap();
        let mut second = sample("app");
        second.name = "Second".into();
        second.write_atomic(&path).unwrap();
        assert_eq!(entries(tmp.path()), ["metadata.json"]);
        assert_eq!(Metadata::read(&path).unwrap().name, "Second");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn atomic_write_removes_its_temp_file_when_the_rename_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("metadata.json");
        fs::create_dir(&path).unwrap(); // rename(file -> directory) fails
        assert!(sample("app").write_atomic(&path).is_err());
        assert_eq!(entries(tmp.path()), ["metadata.json"], "temp file left behind");
        assert!(path.is_dir());
    }

    #[test]
    fn atomic_write_in_an_unwritable_directory_fails_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        let writable_anyway = File::create(dir.join("probe")).is_ok(); // running as root
        if !writable_anyway {
            let path = dir.join("metadata.json");
            assert!(sample("app").write_atomic(&path).is_err());
            assert!(entries(&dir).is_empty());
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn atomic_write_does_not_follow_a_symlink_at_the_target() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let path = tmp.path().join("metadata.json");
        symlink(&victim, &path).unwrap();
        sample("app").write_atomic(&path).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
    }

    /// Plants `count` entries named like the next temp files this process would create, starting at the
    /// current counter (other tests may bump it a little concurrently, hence the margin).
    fn plant_temp_names(dir: &Path, target: &str, count: u64, make: impl Fn(&Path)) {
        let start = TEMP_COUNTER.load(Ordering::Relaxed);
        for n in start..start + count {
            make(&dir.join(format!(".{target}.tmp-{}-{n}", std::process::id())));
        }
    }

    #[test]
    fn atomic_write_never_opens_an_existing_temp_name() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let dir = tmp.path().join("d");
        fs::create_dir(&dir).unwrap();
        // Every name it could pick is a symlink to the victim: O_EXCL refuses each, and it gives up.
        plant_temp_names(&dir, "metadata.json", 256, |p| symlink(&victim, p).unwrap());
        assert!(sample("app").write_atomic(&dir.join("metadata.json")).is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert!(!dir.join("metadata.json").exists());
    }

    #[test]
    fn atomic_write_skips_stale_temp_files_from_a_crashed_run() {
        let tmp = tempfile::tempdir().unwrap();
        plant_temp_names(tmp.path(), "metadata.json", 3, |p| fs::write(p, "stale").unwrap());
        let path = tmp.path().join("metadata.json");
        sample("app").write_atomic(&path).unwrap();
        assert_eq!(Metadata::read(&path).unwrap(), sample("app"));
        for name in entries(tmp.path()).iter().filter(|n| n.contains(".tmp-")) {
            assert_eq!(fs::read_to_string(tmp.path().join(name)).unwrap(), "stale");
        }
    }

    #[test]
    fn read_capped_never_reads_past_the_cap() {
        /// Serves spaces, but fails the read once more than cap + 1 bytes were handed out.
        struct Endless(u64);
        impl Read for Endless {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0 > MAX_FILE_BYTES + 1 {
                    return Err(io::Error::other("read past the cap"));
                }
                self.0 += buf.len() as u64;
                buf.fill(b' ');
                Ok(buf.len())
            }
        }
        assert!(matches!(read_capped(Endless(0)), Err(MetaError::TooLarge)));
        assert_eq!(
            read_capped(io::repeat(b'x').take(MAX_FILE_BYTES)).unwrap().len(),
            MAX_FILE_BYTES as usize
        );
    }

    // ---------------------------------------------------------------- Task 6: constructor, canonical exe, FIFO

    #[test]
    fn new_fills_the_fixed_fields_and_stores_canonical_text() {
        let exe = WinPath::parse("c:/Program Files/App/app.exe").unwrap();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let m = Metadata::new(
            AppId::parse("app").unwrap(),
            "App".into(),
            Some("1.0".into()),
            "x86_64",
            &exe,
            BackendInfo {
                id: "fake".into(),
                version: "1".into(),
            },
            "gui",
        );
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert_eq!(m.environment, "default");
        assert_eq!(
            m.executable, "C:\\Program Files\\App\\app.exe",
            "canonical text, not the input spelling"
        );
        assert!(
            m.created >= before && m.created > 1_600_000_000,
            "created = {}",
            m.created
        );
        m.validate().unwrap();
    }

    #[test]
    fn non_canonical_executable_text_is_rejected_on_write_and_read() {
        // Each of these parses as a WinPath but is not spelled the way `WinPath::to_string` writes it.
        for e in [
            "c:/a.exe",
            "c:\\a.exe",
            "C:/a.exe",
            "C:\\a\\.\\b.exe",
            "C:\\a/b.exe",
            "C:\\a\\b.exe\\.",
        ] {
            let mut m = sample("app");
            m.executable = e.into();
            assert!(
                matches!(m.validate(), Err(MetaError::NonCanonicalExecutable)),
                "validate {e:?}"
            );
            let err = Metadata::parse(&with("executable", Some(e.into()))).unwrap_err();
            assert!(matches!(err, MetaError::NonCanonicalExecutable), "read {e:?}: {err:?}");
            let tmp = tempfile::tempdir().unwrap();
            let path = tmp.path().join("metadata.json");
            assert!(m.write_atomic(&path).is_err(), "wrote {e:?}");
            assert!(!path.exists());
        }
    }

    #[test]
    fn a_fifo_swapped_in_after_the_lstat_cannot_hang_the_open() {
        let tmp = tempfile::tempdir().unwrap();
        let regular = tmp.path().join("regular.json");
        sample("app").write_atomic(&regular).unwrap();
        let fifo = tmp.path().join("metadata.json");
        mkfifo(&fifo);
        // What `read` would have seen at lstat time, then the path is a FIFO when it is opened.
        let before = fs::symlink_metadata(&regular).unwrap();
        let err = within_10s(move || read_checked(&fifo, &before)).unwrap_err();
        assert!(matches!(err, MetaError::NotRegular), "{err:?}");
    }

    #[test]
    fn open_nonblocking_returns_at_once_on_a_fifo_without_a_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("f");
        mkfifo(&fifo);
        let file = within_10s(move || open_nonblocking(&fifo)).unwrap();
        assert!(!file.metadata().unwrap().file_type().is_file());
    }

    #[test]
    fn syncing_a_directory_that_became_a_fifo_or_a_file_returns_at_once_and_fails_nothing() {
        // What this proves: the best-effort directory fsync never blocks and never reports an error when the
        // path is not a directory (a plain `File::open` on a FIFO with no writer blocks forever). It cannot
        // prove that a real directory is synced (not observable), only that the call is harmless.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("dir-swapped-for-a-fifo");
        mkfifo(&fifo);
        let f = fifo.clone();
        let err = within_10s(move || open_dir_nonblocking(&f)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR), "{err:?}");
        within_10s(move || sync_dir(&fifo));
        let file = tmp.path().join("file");
        fs::write(&file, "x").unwrap();
        let err = open_dir_nonblocking(&file).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ENOTDIR), "{err:?}");
        sync_dir(&file);
        assert!(open_dir_nonblocking(tmp.path()).is_ok());
        sync_dir(&tmp.path().join("missing"));
        sync_dir(tmp.path());
        // and a write into a real directory still succeeds end to end
        sample("app").write_atomic(&tmp.path().join("metadata.json")).unwrap();
        assert!(Metadata::read(&tmp.path().join("metadata.json")).is_ok());
    }

    #[test]
    fn read_of_a_planted_fifo_is_not_regular_not_a_hang() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("metadata.json");
        mkfifo(&fifo);
        let err = within_10s(move || Metadata::read(&fifo)).unwrap_err();
        assert!(matches!(err, MetaError::NotRegular), "{err:?}");
    }
}
