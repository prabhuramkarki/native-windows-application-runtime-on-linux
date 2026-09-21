//! Bounded, panic-free parser for a raw VS_VERSIONINFO resource.
//!
//! The bytes come from an untrusted installer, so nothing here indexes, and all arithmetic on
//! sizes taken from the file is checked or saturating. pelite's own `VersionInfo` is not used:
//! its TLV walker slices out of range on crafted input.
//!
//! Layout of every block (little-endian): `wLength wValueLength wType szKey[] <pad to 4>
//! Value <pad to 4> Children...`. `wLength` covers the header, key, value and children but not
//! the padding after the block. Text values count `wValueLength` in UTF-16 words (`wType == 1`),
//! binary values in bytes (`wType == 0`).
use crate::model::VersionInfo;
use pelite::resources::{FindError, Name, Resources};
use std::cell::Cell;
use std::collections::BTreeMap;

const HEADER: usize = 6;
/// Longest key or string value, in UTF-16 code units, excluding the NUL.
const MAX_UNITS: usize = 1024;
const MAX_STRINGS: usize = 256;
/// Blocks visited in total, however the tree is shaped. Each visit advances by >= 8 bytes.
const MAX_BLOCKS: usize = 4096;
const FIXED_SIGNATURE: u32 = 0xFEEF_04BD;
const FIXED_SIZE: usize = 52;

/// The raw RT_VERSION bytes: resource id 1 if present, else the first id, first language.
/// `FindError::NotFound` means the image has no version resource. The structure of the bytes is
/// not looked at.
pub(crate) fn find<'a>(res: &Resources<'a>) -> Result<&'a [u8], FindError> {
    let ids = res.root()?.get_dir(Name::VERSION)?;
    let langs = match ids.get_dir(Name::Id(1)) {
        Err(FindError::NotFound) => ids.first_dir()?,
        other => other?,
    };
    Ok(langs.first_data()?.bytes()?)
}

/// Parses a VS_VERSIONINFO resource. Err says why it is malformed, or empty.
///
/// Only the first `StringTable` is read (Windows itself picks by language; the first table is
/// the resource's primary one). `VarFileInfo` is ignored. An over-long key or string, more than
/// 1024 units or 256 entries, is an Err: nothing is truncated silently.
pub(crate) fn parse(bytes: &[u8]) -> Result<VersionInfo, String> {
    let budget = Cell::new(MAX_BLOCKS);
    let root = read_block(bytes)?;
    if root.key != "VS_VERSION_INFO" {
        let shown: String = root.key.chars().take(32).collect();
        return Err(format!("root block is {shown:?}, expected \"VS_VERSION_INFO\""));
    }
    let fixed = fixed_file_version(root.value);

    let mut strings = BTreeMap::new();
    let mut entries = 0usize;
    for info in Children::new(root.children, &budget) {
        let info = info?;
        if info.key != "StringFileInfo" {
            continue; // VarFileInfo and anything unknown
        }
        let Some(table) = Children::new(info.children, &budget).next() else {
            continue;
        };
        let table = table?;
        for entry in Children::new(table.children, &budget) {
            let entry = entry?;
            entries += 1;
            if entries > MAX_STRINGS {
                return Err(format!("more than {MAX_STRINGS} string entries"));
            }
            let text: Vec<u16> = units(entry.value).take_while(|&u| u != 0).collect();
            if text.len() > MAX_UNITS {
                let shown: String = entry.key.chars().take(32).collect();
                return Err(format!("value of {shown:?} is longer than {MAX_UNITS} UTF-16 units"));
            }
            strings.insert(entry.key, String::from_utf16_lossy(&text));
        }
        break; // first StringTable only
    }

    let file_version = strings.get("FileVersion").cloned().or(fixed);
    if strings.is_empty() && file_version.is_none() {
        return Err("no strings and no fixed file info".into());
    }
    Ok(VersionInfo { file_version, strings })
}

struct Block<'a> {
    key: String,
    /// Bytes: `wValueLength` bytes for `wType == 0`, `wValueLength` words for `wType == 1`.
    value: &'a [u8],
    children: &'a [u8],
    /// wLength clamped to the bytes the parent had left. Always >= HEADER.
    len: usize,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_le_bytes(b.get(at..end)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_le_bytes(b.get(at..end)?.try_into().ok()?))
}

fn units(b: &[u8]) -> impl Iterator<Item = u16> + '_ {
    b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c))
}

fn align4(n: usize) -> usize {
    n.saturating_add(3) & !3
}

/// Reads the block at the start of `data` (everything the parent has left from that point).
fn read_block(data: &[u8]) -> Result<Block<'_>, String> {
    let (Some(length), Some(value_len), Some(w_type)) = (u16_at(data, 0), u16_at(data, 2), u16_at(data, 4)) else {
        return Err("block header is truncated".into());
    };
    let length = usize::from(length);
    if length < HEADER {
        return Err(format!(
            "block length {length} is smaller than its {HEADER}-byte header"
        ));
    }
    let body = data.get(..length.min(data.len())).ok_or("block is truncated")?;

    // Key: UTF-16, NUL-terminated, at most MAX_UNITS units.
    let mut n = 0usize;
    loop {
        if n > MAX_UNITS {
            return Err(format!("block key is longer than {MAX_UNITS} UTF-16 units"));
        }
        match u16_at(body, HEADER + 2 * n) {
            None => return Err("block key is not NUL-terminated inside its block".into()),
            Some(0) => break,
            Some(_) => n += 1,
        }
    }
    let key_bytes = body.get(HEADER..HEADER + 2 * n).ok_or("block key is truncated")?;
    let key = String::from_utf16_lossy(&units(key_bytes).collect::<Vec<_>>());

    // The value may legitimately be absent with the padding running past a short block.
    let value_off = align4(HEADER + 2 * (n + 1)).min(body.len());
    let value_size = if w_type == 1 {
        usize::from(value_len) * 2
    } else {
        usize::from(value_len)
    };
    let value_end = value_off
        .checked_add(value_size)
        .filter(|&e| e <= body.len())
        .ok_or_else(|| {
            format!(
                "value of {value_size} bytes overruns block {:?}",
                key.chars().take(32).collect::<String>()
            )
        })?;
    let value = body.get(value_off..value_end).ok_or("value is truncated")?;
    let children = body
        .get(align4(value_end).min(body.len())..)
        .ok_or("children are truncated")?;
    Ok(Block {
        key,
        value,
        children,
        len: body.len(),
    })
}

/// Sibling blocks, one after another. Yields one Err and then stops on a malformed block.
/// `budget` is shared across the whole tree.
struct Children<'a> {
    rest: &'a [u8],
    budget: &'a Cell<usize>,
}

impl<'a> Children<'a> {
    fn new(rest: &'a [u8], budget: &'a Cell<usize>) -> Self {
        Self { rest, budget }
    }
}

impl<'a> Iterator for Children<'a> {
    type Item = Result<Block<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.len() < HEADER {
            return None; // end, or padding
        }
        let Some(left) = self.budget.get().checked_sub(1) else {
            self.rest = &[];
            return Some(Err(format!("more than {MAX_BLOCKS} blocks")));
        };
        self.budget.set(left);
        match read_block(self.rest) {
            Ok(b) => {
                // len >= HEADER, so every step moves forward by at least 8 bytes.
                self.rest = self.rest.get(align4(b.len)..).unwrap_or(&[]);
                Some(Ok(b))
            }
            Err(e) => {
                self.rest = &[];
                Some(Err(e))
            }
        }
    }
}

/// "Major.Minor.Build.Revision" from a VS_FIXEDFILEINFO value, if its signature is right.
fn fixed_file_version(v: &[u8]) -> Option<String> {
    if v.len() < FIXED_SIZE || u32_at(v, 0)? != FIXED_SIGNATURE {
        return None;
    }
    let (ms, ls) = (u32_at(v, 8)?, u32_at(v, 12)?);
    Some(format!("{}.{}.{}.{}", ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    fn pad4(b: &mut Vec<u8>) {
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
    }

    /// One block; wLength is filled in from the assembled size.
    fn block(key: &str, w_type: u16, value_len: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0, 0];
        b.extend(value_len.to_le_bytes());
        b.extend(w_type.to_le_bytes());
        b.extend(utf16z(key));
        pad4(&mut b);
        b.extend(value);
        for c in children {
            pad4(&mut b);
            b.extend(c);
        }
        let len = u16::try_from(b.len()).unwrap();
        b[..2].copy_from_slice(&len.to_le_bytes());
        b
    }

    fn string(k: &str, v: &str) -> Vec<u8> {
        let val = utf16z(v);
        block(k, 1, u16::try_from(val.len() / 2).unwrap(), &val, &[])
    }

    fn fixed(ms: u32, ls: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for w in [FIXED_SIGNATURE, 0x0001_0000, ms, ls] {
            v.extend(w.to_le_bytes());
        }
        v.resize(FIXED_SIZE, 0);
        v
    }

    fn table(strings: &[Vec<u8>]) -> Vec<u8> {
        block("040904B0", 1, 0, &[], strings)
    }

    fn version(fixed: &[u8], strings: &[Vec<u8>]) -> Vec<u8> {
        let sfi = block("StringFileInfo", 1, 0, &[], &[table(strings)]);
        let var = block(
            "VarFileInfo",
            1,
            0,
            &[],
            &[block("Translation", 0, 4, &[9, 4, 0xB0, 4], &[])],
        );
        block(
            "VS_VERSION_INFO",
            0,
            u16::try_from(fixed.len()).unwrap(),
            fixed,
            &[sfi, var],
        )
    }

    fn valid() -> Vec<u8> {
        version(
            &fixed(0x0001_0002, 0x0003_0004),
            &[string("FileVersion", "9.8.7.6"), string("ProductName", "Widget Pro")],
        )
    }

    #[test]
    fn well_formed_block_is_read_exactly() {
        let v = parse(&valid()).unwrap();
        assert_eq!(v.file_version.as_deref(), Some("9.8.7.6"));
        let want: BTreeMap<String, String> = [("FileVersion", "9.8.7.6"), ("ProductName", "Widget Pro")]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        assert_eq!(v.strings, want);
    }

    #[test]
    fn fixed_struct_is_the_fallback_for_file_version() {
        let v = parse(&version(
            &fixed(0x0001_0002, 0x0003_0004),
            &[string("ProductName", "P")],
        ))
        .unwrap();
        assert_eq!(v.file_version.as_deref(), Some("1.2.3.4"));
        let v = parse(&version(&fixed(0xFFFF_0000, 0x0000_FFFF), &[])).unwrap();
        assert_eq!(v.file_version.as_deref(), Some("65535.0.0.65535"));
        assert!(v.strings.is_empty());
    }

    #[test]
    fn fixed_struct_needs_its_signature_and_size() {
        let mut bad = fixed(1, 1);
        bad[0] ^= 0xFF;
        assert!(
            parse(&version(&bad, &[]))
                .unwrap_err()
                .contains("no strings and no fixed")
        );
        assert!(parse(&version(&fixed(1, 1)[..40], &[])).is_err());
    }

    #[test]
    fn empty_version_is_an_error_not_an_empty_success() {
        let e = parse(&version(&[], &[])).unwrap_err();
        assert!(e.contains("no strings and no fixed file info"), "{e}");
    }

    #[test]
    fn only_the_first_string_table_is_used() {
        let t1 = block("040904B0", 1, 0, &[], &[string("ProductName", "First")]);
        let t2 = block("040704B0", 1, 0, &[], &[string("ProductName", "Second")]);
        let sfi = block("StringFileInfo", 1, 0, &[], &[t1, t2]);
        let v = parse(&block("VS_VERSION_INFO", 0, 52, &fixed(0, 0), &[sfi])).unwrap();
        assert_eq!(v.strings["ProductName"], "First");
    }

    /// The reviewer's crash input: pelite slices out of range on it.
    #[test]
    fn crash_input_is_an_error_not_a_panic() {
        let bytes: Vec<u8> = [10u16, 0, 0, 0x41, 0].into_iter().flat_map(u16::to_le_bytes).collect();
        assert_eq!(bytes.len(), 10);
        let e = parse(&bytes).unwrap_err();
        assert!(e.contains("VS_VERSION_INFO"), "{e}"); // key "A": well terminated, wrong name
        // Same shape with the right key: the key fills the block, nothing follows it.
        let mut root = block("VS_VERSION_INFO", 0, 0, &[], &[]);
        root.truncate(38);
        let root = with_word(root, 0, 38);
        assert!(parse(&root).unwrap_err().contains("no strings"));
    }

    #[test]
    fn every_truncation_of_a_valid_block_is_handled() {
        let v = valid();
        for n in 0..=v.len() {
            let cut = v[..n].to_vec();
            assert!(catch_unwind(|| parse(&cut)).is_ok(), "panicked at prefix {n}");
        }
        assert!(
            parse(&v[..v.len() - 1]).is_ok(),
            "clamped wLength tolerates a short tail"
        );
    }

    fn with_word(mut b: Vec<u8>, at: usize, w: u16) -> Vec<u8> {
        b[at..at + 2].copy_from_slice(&w.to_le_bytes());
        b
    }

    #[test]
    fn hostile_lengths_are_errors() {
        let v = valid();
        for len in [0u16, 1, 5, 7, 9, 0xFFFF] {
            let m = with_word(v.clone(), 0, len);
            let r = catch_unwind(|| parse(&m));
            assert!(r.is_ok(), "panicked for root wLength {len}");
        }
        assert!(parse(&with_word(v.clone(), 0, 0)).unwrap_err().contains("smaller than"));
        // wLength larger than the buffer is clamped, so the block still parses.
        assert!(parse(&with_word(v.clone(), 0, 0xFFFF)).is_ok());
        // A value that runs past its block.
        assert!(parse(&with_word(v.clone(), 2, 0xFFFF)).unwrap_err().contains("value"));
        // Child wLength beyond the parent, odd, zero: never a panic.
        for at in 0..v.len().saturating_sub(1) {
            for w in [0u16, 1, 6, 7, 0x7FFF, 0xFFFF] {
                let m = with_word(v.clone(), at, w);
                assert!(catch_unwind(|| parse(&m)).is_ok(), "panicked: word {w:#x} at {at}");
            }
        }
    }

    #[test]
    fn key_without_a_nul_is_an_error() {
        let mut b = block("VS_VERSION_INFO", 0, 0, &[], &[]);
        let n = b.len();
        b[HEADER..n].fill(0x41);
        assert!(parse(&b).unwrap_err().contains("NUL"));
    }

    #[test]
    fn wrong_root_key_is_an_error() {
        let e = parse(&block("SOMETHING_ELSE", 0, 0, &[], &[])).unwrap_err();
        assert!(e.contains("VS_VERSION_INFO"), "{e}");
    }

    #[test]
    fn mutated_blocks_never_panic() {
        let seed = valid();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..30_000 {
            let mut m = seed.clone();
            for _ in 0..=(next() % 4) {
                let at = (next() as usize) % m.len();
                m[at] = next() as u8;
            }
            if next() % 4 == 0 {
                m.truncate((next() as usize) % (m.len() + 1));
            }
            assert!(catch_unwind(|| parse(&m)).is_ok(), "panicked on iteration {i}: {m:?}");
        }
    }

    fn long(n: usize) -> String {
        "x".repeat(n)
    }

    #[test]
    fn string_and_key_lengths_are_bounded() {
        let ok = parse(&version(&fixed(0, 0), &[string("K", &long(1024))])).unwrap();
        assert_eq!(ok.strings["K"].len(), 1024);
        let e = parse(&version(&fixed(0, 0), &[string("K", &long(1025))])).unwrap_err();
        assert!(e.contains("1024"), "{e}");
        let e = parse(&version(&fixed(0, 0), &[string(&long(1025), "v")])).unwrap_err();
        assert!(e.contains("1024"), "{e}");
        assert!(parse(&version(&fixed(0, 0), &[string(&long(1024), "v")])).is_ok());
    }

    #[test]
    fn entry_count_is_bounded() {
        let many = |n: usize| (0..n).map(|i| string(&format!("K{i}"), "v")).collect::<Vec<_>>();
        // Table wLength is a u16, so 256 tiny entries just fit.
        let v = parse(&version(&fixed(0, 0), &many(256))).unwrap();
        assert_eq!(v.strings.len(), 256);
        let e = parse(&version(&fixed(0, 0), &many(257))).unwrap_err();
        assert!(e.contains("256"), "{e}");
    }

    #[test]
    fn block_count_is_bounded_on_a_flat_pile_of_headers() {
        // ~8000 empty 8-byte sibling blocks under the root: must stop, not walk them all.
        let mut root = block("VS_VERSION_INFO", 0, 0, &[], &[]);
        while root.len() + 8 <= usize::from(u16::MAX) {
            root.extend([8, 0, 0, 0, 0, 0, 0, 0]);
        }
        let root = with_word(root, 0, u16::MAX);
        let e = parse(&root).unwrap_err();
        assert!(e.contains("4096"), "{e}");
    }

    fn pe_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            if ft.is_dir() {
                pe_files(&path, out);
            } else if ft.is_file() {
                let ext = path.extension().and_then(|x| x.to_str()).map(str::to_ascii_lowercase);
                if matches!(ext.as_deref(), Some("exe" | "dll")) {
                    out.push(path);
                }
            }
        }
    }

    type Strings = BTreeMap<String, String>;

    /// pelite's view of the file: `(strings of the first Translation's table, every table)`, or
    /// None when pelite cannot read a version resource at all.
    fn pelite_strings(bytes: &[u8]) -> Option<(Strings, Vec<Strings>)> {
        use pelite::pe64::Pe as _;
        // pelite hands out references into the buffer: it must be 8-aligned.
        let mut words = vec![0u64; bytes.len().div_ceil(8)];
        // SAFETY: `words` owns at least `bytes.len()` initialised bytes.
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), bytes.len()) }.copy_from_slice(bytes);
        // SAFETY: same buffer, shared borrow.
        let aligned = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), bytes.len()) };
        let run = || {
            let vi = match pelite::PeFile::from_bytes(aligned).ok()? {
                pelite::Wrap::T32(f) => {
                    use pelite::pe32::Pe as _;
                    f.resources().ok()?.version_info().ok()?
                }
                pelite::Wrap::T64(f) => f.resources().ok()?.version_info().ok()?,
            };
            let mut first = BTreeMap::new();
            if let Some(&lang) = vi.translation().first() {
                vi.strings(lang, |k, v| {
                    first.insert(k.to_owned(), v.to_owned());
                });
            }
            let tables = vi
                .file_info()
                .strings
                .values()
                .map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .collect();
            Some((first, tables))
        };
        catch_unwind(run).ok().flatten()
    }

    /// Compares this parser with pelite's on real binaries.
    /// `RUNTIME_SAMPLES=dir1:dir2 cargo test -p runtime-pe --lib -- --ignored --nocapture oracle`
    #[test]
    #[ignore = "needs RUNTIME_SAMPLES pointing at real Windows binaries"]
    fn oracle_matches_pelite_on_real_binaries() {
        let samples = std::env::var("RUNTIME_SAMPLES").expect("set RUNTIME_SAMPLES=dir1:dir2");
        let mut files = Vec::new();
        for d in samples.split(':').filter(|d| !d.is_empty()) {
            pe_files(std::path::Path::new(d), &mut files);
        }
        files.sort();
        let (mut compared, mut skipped) = (0, 0);
        for path in &files {
            let Ok(bytes) = std::fs::read(path) else { continue };
            let name = path.display();
            let info = crate::analyze::analyze(&bytes);
            let theirs = pelite_strings(&bytes).filter(|(first, tables)| !first.is_empty() || !tables.is_empty());
            let (Some((first, tables)), Ok(info)) = (theirs, &info) else {
                skipped += 1;
                let shown = info
                    .map(|i| (i.version.is_some(), i.warnings))
                    .map_err(|e| e.to_string());
                println!("skip (pelite reads no version strings): {name} -> {shown:?}");
                continue;
            };
            let ours = info
                .version
                .clone()
                .unwrap_or_else(|| panic!("{name}: no version; warnings {:?}", info.warnings));
            assert!(
                info.warnings.iter().all(|w| !w.starts_with("version info")),
                "{name}: {:?}",
                info.warnings
            );
            if first.is_empty() {
                // pelite looks the table up by the Translation entry, which some files get wrong.
                assert!(
                    tables.contains(&ours.strings),
                    "{name}: not one of pelite's tables {tables:?}"
                );
                println!("ok (pelite found no table for the Translation; matches one of its tables): {name}");
            } else {
                for key in ["ProductName", "FileDescription", "CompanyName", "FileVersion"] {
                    assert_eq!(ours.strings.get(key), first.get(key), "{name}: {key}");
                }
                println!(
                    "ok: {name} ProductName={:?} FileDescription={:?} CompanyName={:?} FileVersion={:?}",
                    ours.strings.get("ProductName"),
                    ours.strings.get("FileDescription"),
                    ours.strings.get("CompanyName"),
                    ours.file_version
                );
            }
            compared += 1;
        }
        println!(
            "{} PE files found, {compared} compared with pelite, {skipped} skipped",
            files.len()
        );
    }
}
