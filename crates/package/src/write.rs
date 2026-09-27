//! The writer: `pack DIR OUT` turns `DIR/wrun.toml` (without `[[files]]`) and `DIR/payload/` into a reproducible
//! `.wrun`: files sorted by path bytes, the zip minimum timestamp (1980-01-01), mode 0644, no directory entries,
//! deflate at the default level, the manifest re-serialised canonically with the generated `[[files]]`. The output
//! is opened and verified with the reader before success is reported: the writer never produces what the reader
//! refuses.
use crate::manifest::{MAX_MANIFEST_BYTES, RawFile, emit, parse_raw, valid_payload_path, validate};
use crate::read::open_with;
use crate::{MANIFEST_NAME, PackageError, hex, sha256, shown};
use rt_core::unzip::Limits;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

fn io_err(what: &'static str) -> impl FnOnce(io::Error) -> PackageError {
    move |source| PackageError::Io { what, source }
}

fn layout(msg: String) -> PackageError {
    PackageError::Layout(msg)
}

/// Packs `dir` into `out` (which must not exist; it is removed again on any error). Returns the package digest.
pub fn pack(dir: &Path, out: &Path) -> Result<[u8; 32], PackageError> {
    pack_with(dir, out, &Limits::default())
}

pub(crate) fn pack_with(dir: &Path, out: &Path, limits: &Limits) -> Result<[u8; 32], PackageError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(out)
        .map_err(io_err("create the output file"))?;
    let r = build(dir, file, out, limits);
    if r.is_err() {
        let _ = fs::remove_file(out);
    }
    r
}

/// Opens a regular file without following a final symlink.
fn open_regular(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)
}

fn build(dir: &Path, file: File, out: &Path, limits: &Limits) -> Result<[u8; 32], PackageError> {
    let manifest_path = dir.join(MANIFEST_NAME);
    let meta = fs::symlink_metadata(&manifest_path).map_err(io_err("read wrun.toml"))?;
    if !meta.is_file() || meta.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(PackageError::Manifest(format!(
            "{MANIFEST_NAME} must be a regular file of at most {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    let mut text = Vec::new();
    open_regular(&manifest_path)
        .and_then(|f| f.take(MAX_MANIFEST_BYTES as u64 + 1).read_to_end(&mut text))
        .map_err(io_err("read wrun.toml"))?;
    let mut raw = parse_raw(&text)?;
    if raw.files.is_some() {
        return Err(PackageError::Manifest(
            "it already has [[files]]: pack generates them from payload/".to_owned(),
        ));
    }
    for entry in fs::read_dir(dir).map_err(io_err("list the package directory"))? {
        let name = entry.map_err(io_err("list the package directory"))?.file_name();
        if name != MANIFEST_NAME && name != "payload" {
            return Err(layout(format!(
                "{} is neither {MANIFEST_NAME} nor payload/ (nothing else can be packed)",
                shown(&name.to_string_lossy())
            )));
        }
    }

    let mut found = Vec::new();
    walk(&dir.join("payload"), "payload", &mut found, limits)?;
    found.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut files = Vec::with_capacity(found.len());
    for (path, abs) in &found {
        let (size, digest) = hash_file(abs)?;
        if size > limits.max_entry_bytes {
            return Err(layout(format!(
                "{} is larger than the reader's per-file limit",
                shown(path)
            )));
        }
        files.push(RawFile {
            path: path.clone(),
            size,
            sha256: hex(&digest),
        });
    }
    let total = files.iter().fold(0u64, |t, f| t.saturating_add(f.size));
    if total > limits.max_total_bytes {
        return Err(layout("the payload is larger than the reader's total limit".to_owned()));
    }
    raw.files = Some(files);
    let manifest = validate(raw, limits)?;
    let canonical = emit(&manifest);
    if canonical.len() > MAX_MANIFEST_BYTES {
        return Err(PackageError::Manifest(format!(
            "the generated manifest is larger than {MAX_MANIFEST_BYTES} bytes (too many files)"
        )));
    }

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644);
    let mut zip = ZipWriter::new(file);
    let zerr = |e: zip::result::ZipError| layout(rt_core::clean_text(&e.to_string(), 200));
    zip.start_file(MANIFEST_NAME, options).map_err(zerr)?;
    zip.write_all(canonical.as_bytes())
        .map_err(io_err("write the package"))?;
    for (f, (_, abs)) in manifest.files.iter().zip(&found) {
        let method = if too_compressible(abs, f.size, limits)? {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        let opts = options
            .compression_method(method)
            .large_file(f.size > u64::from(u32::MAX));
        zip.start_file(f.path.as_str(), opts).map_err(zerr)?;
        let mut src = open_regular(abs).map_err(io_err("read a payload file"))?;
        io::copy(&mut src, &mut zip).map_err(io_err("write the package"))?;
    }
    zip.finish()
        .map_err(zerr)?
        .sync_all()
        .map_err(io_err("write the package"))?;

    // The reader must accept what was written, with the same bytes (a file changed while packing fails here).
    let mut package = open_with(File::open(out).map_err(io_err("reopen the package"))?, limits.clone())?;
    package.verify()?;
    debug_assert_eq!(package.manifest, manifest);
    debug_assert_eq!(package.digest, sha256(canonical.as_bytes()));
    Ok(package.digest)
}

/// Collects the regular files below `abs` as (`payload/...` path, host path). Symlinks, special files, names that
/// are not UTF-8 or that the reader would refuse are errors; so are more files than the reader accepts.
fn walk(abs: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>, limits: &Limits) -> Result<(), PackageError> {
    let meta = fs::symlink_metadata(abs).map_err(io_err("read payload/"))?;
    if !meta.is_dir() {
        return Err(layout(format!("{} must be a directory", shown(rel))));
    }
    for entry in fs::read_dir(abs).map_err(io_err("list payload/"))? {
        let entry = entry.map_err(io_err("list payload/"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(layout(format!("a name below {} is not UTF-8", shown(rel))));
        };
        let path = format!("{rel}/{name}");
        if !valid_payload_path(&path) {
            return Err(layout(format!("{} is a name the reader would refuse", shown(&path))));
        }
        let ft = entry.file_type().map_err(io_err("list payload/"))?;
        if ft.is_dir() {
            walk(&entry.path(), &path, out, limits)?;
        } else if ft.is_file() {
            out.push((path, entry.path()));
            // `wrun.toml` is an entry too.
            if out.len() >= limits.max_entries {
                return Err(layout(format!(
                    "more than {} payload files (the reader's limit)",
                    limits.max_entries - 1
                )));
            }
        } else {
            return Err(layout(format!(
                "{} is a symlink or a special file (only regular files are packed)",
                shown(&path)
            )));
        }
    }
    Ok(())
}

/// Whether deflating the file would trip the reader's zip-bomb ratio guard (only files over its floor): such a file
/// is stored instead. Deflated here at the level `zip` uses, with half the ratio as the margin.
fn too_compressible(path: &Path, size: u64, limits: &Limits) -> Result<bool, PackageError> {
    if size <= limits.ratio_floor {
        return Ok(false);
    }
    struct Count(u64);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0 += b.len() as u64;
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut enc = flate2::write::DeflateEncoder::new(Count(0), flate2::Compression::default());
    let mut src = open_regular(path).map_err(io_err("read a payload file"))?;
    io::copy(&mut src, &mut enc).map_err(io_err("read a payload file"))?;
    let compressed = enc.finish().map_err(io_err("read a payload file"))?.0;
    Ok(size / compressed.max(1) > limits.max_ratio / 2)
}

fn hash_file(path: &Path) -> Result<(u64, [u8; 32]), PackageError> {
    let mut f = open_regular(path).map_err(io_err("read a payload file"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(io_err("read a payload file"))?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((size, hasher.finalize().into()))
}
