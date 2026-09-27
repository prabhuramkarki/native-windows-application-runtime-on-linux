//! Shared helpers: packages are built in memory with the `zip` writer (stored entries), then patched byte-wise for
//! what the writer will not produce (hostile names, lying sizes, special modes).
use crate::read::{Package, open_with};
use crate::{PackageError, hex, sha256};
use rt_core::unzip::Limits;
use std::io::{Cursor, Write};
use std::path::Path;
use zip::write::SimpleFileOptions;

mod hostile;
mod mutate;
mod roundtrip;

pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const S_IFCHR: u32 = 0o020_000;

pub fn stored() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644)
}

/// A zip of `entries` in this order, stored.
pub fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        w.start_file(*name, stored()).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// The payload of the valid package.
pub fn payload() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("payload/App/app.exe", b"MZ not really a program".to_vec()),
        ("payload/App/data.bin", vec![7u8; 3000]),
        ("payload/app.png", b"\x89PNG icon".to_vec()),
    ]
}

pub const HEAD: &str = r#"format = 1
id = "example-app"
name = "Example App"
version = "1.2.0"
arch = "x86_64"
dependencies = ["vcrun2022"]
icon = "payload/app.png"

[entry]
kind = "portable"
exe = "payload/App/app.exe"

[permissions]
network = "allow"
gpu = "on"
"#;

/// `[[files]]` for `files`, honest.
pub fn files_toml(files: &[(&str, Vec<u8>)]) -> String {
    files
        .iter()
        .map(|(p, d)| {
            format!(
                "\n[[files]]\npath = \"{p}\"\nsize = {}\nsha256 = \"{}\"\n",
                d.len(),
                hex(&sha256(d))
            )
        })
        .collect()
}

pub fn valid_manifest() -> String {
    format!("{HEAD}{}", files_toml(&payload()))
}

/// `wrun.toml` (the given text) first, then `files`.
pub fn package_of(manifest: &str, files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut entries: Vec<(&str, &[u8])> = vec![("wrun.toml", manifest.as_bytes())];
    entries.extend(files.iter().map(|(p, d)| (*p, d.as_slice())));
    zip_of(&entries)
}

pub fn valid_package() -> Vec<u8> {
    package_of(&valid_manifest(), &payload())
}

/// Opens `bytes` as a package with the given limits (the file lives in `dir`).
pub fn open_in(dir: &Path, bytes: &[u8], limits: Limits) -> Result<Package, PackageError> {
    let path = dir.join("in.wrun");
    std::fs::write(&path, bytes).unwrap();
    open_with(std::fs::File::open(&path).unwrap(), limits)
}

pub fn open_bytes(bytes: &[u8]) -> Result<(tempfile::TempDir, Package), PackageError> {
    let tmp = tempfile::tempdir().unwrap();
    let p = open_in(tmp.path(), bytes, Limits::default())?;
    Ok((tmp, p))
}

pub fn open_err(bytes: &[u8]) -> PackageError {
    match open_bytes(bytes) {
        Ok(_) => panic!("the package was accepted"),
        Err(e) => e,
    }
}

/// Replaces every occurrence of `from` (a name, in both headers) with `to` of the same length.
pub fn rename_everywhere(mut zip: Vec<u8>, from: &[u8], to: &[u8]) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let mut i = 0;
    let mut hits = 0;
    while i + from.len() <= zip.len() {
        if &zip[i..i + from.len()] == from {
            zip[i..i + from.len()].copy_from_slice(to);
            hits += 1;
        }
        i += 1;
    }
    assert!(hits >= 2, "{} not found in both headers", String::from_utf8_lossy(from));
    zip
}

/// Offset of the central-directory header of the entry called `name`.
fn central_header(zip: &[u8], name: &str) -> usize {
    (0..zip.len() - 46)
        .find(|&i| {
            &zip[i..i + 4] == b"PK\x01\x02" && {
                let len = usize::from(u16::from_le_bytes([zip[i + 28], zip[i + 29]]));
                zip.get(i + 46..i + 46 + len) == Some(name.as_bytes())
            }
        })
        .unwrap_or_else(|| panic!("no central header for {name}"))
}

/// Sets the Unix mode (external attributes, high half) of `name` in the central directory.
pub fn set_mode(mut zip: Vec<u8>, name: &str, mode: u32) -> Vec<u8> {
    let at = central_header(&zip, name);
    zip[at + 5] = 3; // made by Unix
    zip[at + 38..at + 42].copy_from_slice(&(mode << 16).to_le_bytes());
    zip
}

/// Sets the declared (uncompressed) size of `name` in the central directory.
pub fn set_declared_size(mut zip: Vec<u8>, name: &str, size: u32) -> Vec<u8> {
    let at = central_header(&zip, name);
    zip[at + 24..at + 28].copy_from_slice(&size.to_le_bytes());
    zip
}
