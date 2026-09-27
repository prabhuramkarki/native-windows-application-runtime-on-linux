//! The reader: [`open`] validates the container and the manifest and cross-checks them without reading any payload
//! byte; [`Package::verify`], [`Package::unpack`] and [`Package::extract_one`] stream payload files through sha256.
use crate::manifest::{MAX_MANIFEST_BYTES, Manifest, parse_with};
use crate::{MANIFEST_NAME, PAYLOAD_PREFIX, PackageError, SIGNATURE_NAME, sha256, shown};
use rt_core::ZipError;
use rt_core::unzip::{self, Archive, Limits, Plan, PlannedFile};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

const MODE_TYPE_MASK: u32 = 0o170_000;
const MODE_REG: u32 = 0o100_000;
const MODE_DIR: u32 = 0o040_000;

/// An opened, validated package. Holds the archive open; payload bytes are read only by the methods below.
pub struct Package {
    pub manifest: Manifest,
    /// sha256 of the raw `wrun.toml` bytes.
    pub digest: [u8; 32],
    archive: Archive,
    plan: Plan,
    limits: Limits,
}

fn layout(msg: String) -> PackageError {
    PackageError::Layout(msg)
}

/// Opens a `.wrun` with the production limits: the container rules, the manifest and the cross-check of the
/// manifest's `[[files]]` against the central directory. Reads no payload data.
pub fn open(file: File) -> Result<Package, PackageError> {
    open_with(file, Limits::default())
}

pub(crate) fn open_with(file: File, limits: Limits) -> Result<Package, PackageError> {
    let (mut archive, plan) = unzip::open(file, &limits)?;
    check_entries(&mut archive)?;
    if plan.skipped != 0 {
        // check_entries refuses every entry the planner skips; kept as a second guard.
        return Err(layout("the archive holds links or special files".to_owned()));
    }
    let first = plan
        .files
        .first()
        .filter(|f| f.index == 0)
        .ok_or_else(|| layout(format!("the first entry must be the file {MANIFEST_NAME}")))?;
    if first.size > MAX_MANIFEST_BYTES as u64 {
        return Err(PackageError::Manifest(format!(
            "it is larger than {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let mut budget = MAX_MANIFEST_BYTES as u64;
    let bytes = unzip::read_entry(&mut archive, first, &mut budget, &limits)?;
    let digest = sha256(&bytes);
    let manifest = parse_with(&bytes, &limits)?;
    cross_check(&manifest, &plan)?;
    Ok(Package {
        manifest,
        digest,
        archive,
        plan,
        limits,
    })
}

/// The package rules on raw central-directory entries (the planner has already applied its own).
fn check_entries(archive: &mut Archive) -> Result<(), PackageError> {
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let e = archive
            .by_index_raw(i)
            .map_err(|e| layout(rt_core::clean_text(&e.to_string(), 200)))?;
        let Ok(name) = std::str::from_utf8(e.name_raw()) else {
            return Err(layout(format!("entry {i} has a name that is not UTF-8")));
        };
        // The crate decodes names without the UTF-8 flag as CP437, and may take a name from an extra field:
        // only a name that means the same thing both ways is accepted.
        if e.name() != name {
            return Err(layout(format!("entry {} has an ambiguous name encoding", shown(name))));
        }
        let mode_type = e.unix_mode().map_or(0, |m| m & MODE_TYPE_MASK);
        names.push((name.to_owned(), mode_type));
    }
    if names.iter().any(|(n, _)| n == SIGNATURE_NAME) {
        return Err(PackageError::Signed);
    }
    for (i, (name, mode_type)) in names.iter().enumerate() {
        if name.contains('\\') {
            return Err(layout(format!("entry {} uses `\\` (names use `/` only)", shown(name))));
        }
        if ![0, MODE_REG, MODE_DIR].contains(mode_type) {
            return Err(layout(format!(
                "entry {} is a link or a special file (only files and directories)",
                shown(name)
            )));
        }
        let is_dir = *mode_type == MODE_DIR || name.ends_with('/');
        if i == 0 {
            if name != MANIFEST_NAME || is_dir {
                return Err(layout(format!("the first entry must be the file {MANIFEST_NAME}")));
            }
            continue;
        }
        if !name.starts_with(PAYLOAD_PREFIX) {
            return Err(layout(format!(
                "entry {} is outside payload/ (only {MANIFEST_NAME} and payload/ are allowed)",
                shown(name)
            )));
        }
        let stem = name.strip_suffix('/').unwrap_or(name);
        if !unzip::entry_path(name).is_ok_and(|c| c.join("/") == stem) {
            return Err(layout(format!("entry {} is not a canonical name", shown(name))));
        }
    }
    Ok(())
}

fn joined(f: &PlannedFile) -> String {
    f.path.join("/")
}

/// `[[files]]` equals exactly the payload files of the archive, each with the declared size.
fn cross_check(manifest: &Manifest, plan: &Plan) -> Result<(), PackageError> {
    let listed: HashMap<&str, u64> = manifest.files.iter().map(|f| (f.path.as_str(), f.size)).collect();
    for f in plan.files.iter().skip(1) {
        let path = joined(f);
        match listed.get(path.as_str()) {
            None => {
                return Err(layout(format!(
                    "payload file {} is not listed in [[files]]",
                    shown(&path)
                )));
            }
            Some(&size) if size != f.size => return Err(PackageError::Integrity { path: shown(&path) }),
            Some(_) => {}
        }
    }
    if plan.files.len() - 1 != manifest.files.len() {
        let present: std::collections::HashSet<String> = plan.files.iter().map(joined).collect();
        let missing = manifest
            .files
            .iter()
            .find(|f| !present.contains(&f.path))
            .map_or("", |f| &f.path);
        return Err(layout(format!("listed file {} is not in the archive", shown(missing))));
    }
    Ok(())
}

/// A streaming mismatch of `path` as the package-level error.
fn integrity(e: ZipError, path: &str) -> PackageError {
    match e {
        ZipError::Integrity { .. } | ZipError::ShortEntry { .. } | ZipError::LiesAboutSize { .. } => {
            PackageError::Integrity { path: shown(path) }
        }
        other => other.into(),
    }
}

impl Package {
    fn expected(&self, path: &str) -> Option<[u8; 32]> {
        self.manifest.files.iter().find(|f| f.path == path).map(|f| f.sha256)
    }

    /// Streams every payload file through sha256 (nothing is written).
    pub fn verify(&mut self) -> Result<(), PackageError> {
        let digests = self.digests();
        for f in self.plan.files.iter().skip(1) {
            let path = joined(f);
            let expected = digests[&path];
            unzip::copy_verified(&mut self.archive, f, &mut io::sink(), expected, &self.limits)
                .map_err(|e| integrity(e, &path))?;
        }
        Ok(())
    }

    /// Writes `wrun.toml` and the payload tree below `dest`, which must not exist (it is created `0755`; its parent
    /// must exist). Every file is verified while streaming; on any error `dest` is removed.
    pub fn unpack(&mut self, dest: &Path) -> Result<(), PackageError> {
        DirBuilder::new()
            .mode(0o755)
            .create(dest)
            .map_err(|source| PackageError::Io {
                what: "create the destination directory",
                source,
            })?;
        let digests = self.digests();
        let digest = self.digest;
        let lookup = |p: &[String]| -> Option<[u8; 32]> {
            if p == [MANIFEST_NAME] {
                Some(digest)
            } else {
                digests.get(&p.join("/")).copied()
            }
        };
        let r = unzip::extract_verified(&mut self.archive, &self.plan, dest, &self.limits, &lookup);
        if let Err(e) = r {
            let _ = fs::remove_dir_all(dest);
            return Err(match e {
                ZipError::Integrity { name } => PackageError::Integrity { path: name },
                other => other.into(),
            });
        }
        Ok(())
    }

    /// Writes the listed payload file `path` to `dest` (`create_new`, `0600`), verified while streaming; on any error
    /// `dest` is removed.
    pub fn extract_one(&mut self, path: &str, dest: &Path) -> Result<(), PackageError> {
        let expected = self
            .expected(path)
            .ok_or_else(|| layout(format!("{} is not a listed payload file", shown(path))))?;
        let file = self
            .plan
            .files
            .iter()
            .skip(1)
            .find(|f| joined(f) == path)
            .expect("cross_check: every listed file is planned")
            .clone();
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
            .map_err(|source| PackageError::Io {
                what: "create the extracted file",
                source,
            })?;
        let r = unzip::copy_verified(&mut self.archive, &file, &mut out, expected, &self.limits);
        drop(out);
        if let Err(e) = r {
            let _ = fs::remove_file(dest);
            return Err(integrity(e, path));
        }
        Ok(())
    }

    /// Every payload file's sha256 by its `payload/...` path.
    pub fn digests(&self) -> BTreeMap<String, [u8; 32]> {
        self.manifest.files.iter().map(|f| (f.path.clone(), f.sha256)).collect()
    }
}
