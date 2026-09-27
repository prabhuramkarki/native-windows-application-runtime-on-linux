//! `wrun.toml`: parsed strictly (`deny_unknown_fields` at every level) into a raw serde struct, then turned into the
//! validated [`Manifest`] by one function, [`validate`]. [`emit`] writes a validated manifest back canonically
//! (`pack`).
use crate::{PAYLOAD_PREFIX, PackageError, hex, shown};
use rt_core::unzip::{Limits, entry_path};
use rt_core::{AppId, WinPath, is_format};
use serde::Deserialize;
use std::collections::HashSet;
use std::fmt::Write as _;

/// The format revision this runtime reads and writes.
pub const FORMAT: u32 = 1;
/// Largest `wrun.toml`, in bytes.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// Most requested dependencies.
pub const MAX_DEPENDENCIES: usize = 16;
/// Largest icon file.
pub const MAX_ICON_BYTES: u64 = 1 << 20;
const MAX_NAME: usize = 256;
const MAX_VERSION: usize = 64;
const MAX_DEP_ID: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub id: AppId,
    pub name: String,
    pub version: String,
    pub arch: pe::Arch,
    pub dependencies: Vec<String>,
    /// A listed `.png` payload file.
    pub icon: Option<String>,
    pub entry: Entry,
    pub permissions: Requests,
    pub files: Vec<FileRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// `exe` is a listed payload file: the program.
    Portable { exe: String },
    /// `installer` is the only payload file; `installed_exe` is `install --exe` (a `C:`-relative Windows path).
    Installer {
        installer: String,
        installed_exe: Option<String>,
    },
}

/// What a package asks for. Requests only: nothing here is ever granted by reading a package.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Requests {
    pub network: Option<bool>,
    pub display: Option<bool>,
    pub audio: Option<bool>,
    pub gpu: Option<bool>,
}

impl Requests {
    /// The canonical permission EXPRs (`network=allow`, `gpu=on`, ...), built from the enums only, in a fixed order.
    pub fn exprs(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(v) = self.network {
            out.push(if v { "network=allow" } else { "network=deny" }.to_owned());
        }
        for (key, value) in [("display", self.display), ("audio", self.audio), ("gpu", self.gpu)] {
            if let Some(v) = value {
                out.push(format!("{key}={}", if v { "on" } else { "off" }));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRef {
    /// `payload/...`, canonical, `/`-separated.
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Raw {
    format: u32,
    id: String,
    name: String,
    version: String,
    arch: String,
    #[serde(default)]
    dependencies: Vec<String>,
    icon: Option<String>,
    entry: RawEntry,
    #[serde(default)]
    permissions: RawPermissions,
    pub(crate) files: Option<Vec<RawFile>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawEntry {
    kind: String,
    exe: Option<String>,
    installer: Option<String>,
    installed_exe: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawPermissions {
    network: Option<String>,
    display: Option<String>,
    audio: Option<String>,
    gpu: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFile {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
}

fn err(msg: String) -> PackageError {
    PackageError::Manifest(msg)
}

/// Parses and validates `wrun.toml` with the production limits.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, PackageError> {
    parse_with(bytes, &Limits::default())
}

pub(crate) fn parse_with(bytes: &[u8], limits: &Limits) -> Result<Manifest, PackageError> {
    validate(parse_raw(bytes)?, limits)
}

/// UTF-8, at most [`MAX_MANIFEST_BYTES`], strict TOML into [`Raw`]. No semantic checks.
pub(crate) fn parse_raw(bytes: &[u8]) -> Result<Raw, PackageError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(err(format!("it is larger than {MAX_MANIFEST_BYTES} bytes")));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| err("it is not UTF-8".to_owned()))?;
    // The message names keys from the file (an unknown field): cleaned and bounded like everything else.
    toml::from_str(text).map_err(|e| err(rt_core::clean_text(e.message(), 512)))
}

/// `payload/...`: canonical (as `unzip` would plan it, joined with `/`), at least one component below `payload`.
pub(crate) fn valid_payload_path(p: &str) -> bool {
    p.starts_with(PAYLOAD_PREFIX) && !p.contains('\\') && entry_path(p).is_ok_and(|c| c.len() >= 2 && c.join("/") == p)
}

fn valid_dep_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_DEP_ID
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let nibble = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        out[i] = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    Some(out)
}

fn switch(key: &str, value: Option<String>, on: &str, off: &str) -> Result<Option<bool>, PackageError> {
    match value.as_deref() {
        None => Ok(None),
        Some(v) if v == on => Ok(Some(true)),
        Some(v) if v == off => Ok(Some(false)),
        Some(v) => Err(err(format!(
            "permissions.{key} is {}: it must be \"{on}\" or \"{off}\"",
            shown(v)
        ))),
    }
}

/// Every rule of the manifest that does not need the archive (the container cross-check is `read`'s).
pub(crate) fn validate(raw: Raw, limits: &Limits) -> Result<Manifest, PackageError> {
    if raw.format != FORMAT {
        return Err(err(format!(
            "format {} is not supported (this runtime reads format {FORMAT})",
            raw.format
        )));
    }
    let id = AppId::parse(&raw.id).map_err(|e| err(format!("id {}: {e}", shown(&raw.id))))?;
    let name = raw.name;
    if name.is_empty() || name.len() > MAX_NAME || name.chars().any(|c| c.is_control() || is_format(c)) {
        return Err(err(format!(
            "name {} must be 1 to {MAX_NAME} bytes without control or format characters",
            shown(&name)
        )));
    }
    let version = raw.version;
    if version.is_empty()
        || version.len() > MAX_VERSION
        || !version
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'~' | b'-'))
    {
        return Err(err(format!(
            "version {} must be 1 to {MAX_VERSION} characters of 0-9 A-Z a-z . + ~ -",
            shown(&version)
        )));
    }
    let arch = match raw.arch.as_str() {
        "x86" => pe::Arch::X86,
        "x86_64" => pe::Arch::X86_64,
        other => return Err(err(format!("arch {} must be \"x86\" or \"x86_64\"", shown(other)))),
    };
    if raw.dependencies.len() > MAX_DEPENDENCIES {
        return Err(err(format!("more than {MAX_DEPENDENCIES} dependencies")));
    }
    let mut seen = HashSet::new();
    for d in &raw.dependencies {
        if !valid_dep_id(d) {
            return Err(err(format!("dependency {} is not a package id", shown(d))));
        }
        if !seen.insert(d.as_str()) {
            return Err(err(format!("dependency {} is listed twice", shown(d))));
        }
    }

    let Some(raw_files) = raw.files else {
        return Err(err(
            "there is no [[files]] table (build packages with `runtime pack`)".to_owned()
        ));
    };
    // `wrun.toml` itself is an entry too.
    if raw_files.len() >= limits.max_entries {
        return Err(err(format!("more than {} files", limits.max_entries - 1)));
    }
    let mut files = Vec::with_capacity(raw_files.len());
    let mut paths = HashSet::new();
    for f in raw_files {
        if !valid_payload_path(&f.path) {
            return Err(err(format!(
                "file path {} is not a canonical path below payload/",
                shown(&f.path)
            )));
        }
        if !paths.insert(f.path.clone()) {
            return Err(err(format!("file {} is listed twice", shown(&f.path))));
        }
        let sha256 = parse_sha256(&f.sha256).ok_or_else(|| {
            err(format!(
                "file {}: sha256 must be 64 lowercase hex characters",
                shown(&f.path)
            ))
        })?;
        files.push(FileRef {
            path: f.path,
            size: f.size,
            sha256,
        });
    }
    let listed = |what: &str, p: &str| -> Result<(), PackageError> {
        if paths.contains(p) {
            Ok(())
        } else {
            Err(err(format!("{what} {} is not a listed payload file", shown(p))))
        }
    };

    let e = raw.entry;
    let entry = match e.kind.as_str() {
        "portable" => {
            let (Some(exe), None, None) = (e.exe, &e.installer, &e.installed_exe) else {
                return Err(err(
                    "a portable entry has `exe` and neither `installer` nor `installedExe`".to_owned(),
                ));
            };
            listed("entry.exe", &exe)?;
            Entry::Portable { exe }
        }
        "installer" => {
            let (Some(installer), None) = (e.installer, &e.exe) else {
                return Err(err("an installer entry has `installer` and no `exe`".to_owned()));
            };
            listed("entry.installer", &installer)?;
            if files.len() != 1 {
                return Err(err(
                    "an installer package holds exactly one payload file, the installer".to_owned(),
                ));
            }
            if let Some(p) = &e.installed_exe
                && WinPath::parse(&format!("C:\\{}", p.replace('/', "\\"))).is_err()
            {
                return Err(err(format!(
                    "entry.installedExe {} is not a valid Windows path",
                    shown(p)
                )));
            }
            Entry::Installer {
                installer,
                installed_exe: e.installed_exe,
            }
        }
        other => {
            return Err(err(format!(
                "entry.kind {} must be \"portable\" or \"installer\"",
                shown(other)
            )));
        }
    };

    if let Some(icon) = &raw.icon {
        listed("icon", icon)?;
        let size = files.iter().find(|f| &f.path == icon).map_or(0, |f| f.size);
        if !icon.to_ascii_lowercase().ends_with(".png") || size > MAX_ICON_BYTES {
            return Err(err(format!(
                "icon {} must be a .png file of at most {MAX_ICON_BYTES} bytes",
                shown(icon)
            )));
        }
    }

    let p = raw.permissions;
    let permissions = Requests {
        network: switch("network", p.network, "allow", "deny")?,
        display: switch("display", p.display, "on", "off")?,
        audio: switch("audio", p.audio, "on", "off")?,
        gpu: switch("gpu", p.gpu, "on", "off")?,
    };

    Ok(Manifest {
        id,
        name,
        version,
        arch,
        dependencies: raw.dependencies,
        icon: raw.icon,
        entry,
        permissions,
        files,
    })
}

/// A TOML basic string. Validated values hold no control characters; they are escaped anyway.
fn q(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The canonical text of a validated manifest: fixed key order, `[[files]]` in the manifest's order.
pub(crate) fn emit(m: &Manifest) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "format = {FORMAT}");
    let _ = writeln!(s, "id = {}", q(m.id.as_str()));
    let _ = writeln!(s, "name = {}", q(&m.name));
    let _ = writeln!(s, "version = {}", q(&m.version));
    let arch = if m.arch == pe::Arch::X86 { "x86" } else { "x86_64" };
    let _ = writeln!(s, "arch = {}", q(arch));
    if !m.dependencies.is_empty() {
        let deps: Vec<String> = m.dependencies.iter().map(|d| q(d)).collect();
        let _ = writeln!(s, "dependencies = [{}]", deps.join(", "));
    }
    if let Some(icon) = &m.icon {
        let _ = writeln!(s, "icon = {}", q(icon));
    }
    s.push_str("\n[entry]\n");
    match &m.entry {
        Entry::Portable { exe } => {
            let _ = writeln!(s, "kind = \"portable\"\nexe = {}", q(exe));
        }
        Entry::Installer {
            installer,
            installed_exe,
        } => {
            let _ = writeln!(s, "kind = \"installer\"\ninstaller = {}", q(installer));
            if let Some(p) = installed_exe {
                let _ = writeln!(s, "installedExe = {}", q(p));
            }
        }
    }
    let exprs = m.permissions.exprs();
    if !exprs.is_empty() {
        s.push_str("\n[permissions]\n");
        for e in exprs {
            let (k, v) = e.split_once('=').expect("exprs are key=value");
            let _ = writeln!(s, "{k} = {}", q(v));
        }
    }
    for f in &m.files {
        let _ = write!(
            s,
            "\n[[files]]\npath = {}\nsize = {}\nsha256 = {}\n",
            q(&f.path),
            f.size,
            q(&hex(&f.sha256))
        );
    }
    s
}
