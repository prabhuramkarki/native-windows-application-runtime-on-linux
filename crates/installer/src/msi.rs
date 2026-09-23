//! A bounded, panic-free reader for the three MSI "structural facts" this project needs —
//! `ProductName`, `ProductCode`, `UpgradeCode` — read out of a `.msi`'s underlying OLE2/Compound
//! File Binary ([MS-CFB]) container and its `_Property` table.
//!
//! **Crate spike (Task 4).** Two candidates exist, both by the same author (mdsteele): `cfb 0.15`
//! (a generic CFB reader) and `msi 0.10` (MSI-specific, built on top of `cfb`). A 10 000-iteration
//! xorshift byte-flip/truncate fuzz of `tests/fixtures/build/hello.msi` (the same method as the
//! `.lnk` spike in `lnk.rs`) found `msi::Package::open` panics on 4 of 10 000 mutations:
//! `called \`Option::unwrap()\` on a \`None\` value` at `msi-0.10.0/src/internal/package.rs:319`
//! (`row[0].as_str().unwrap()`, reached once a corrupted `_Tables` stream row decodes to a
//! non-string `Value`). The *same* fuzz harness against `cfb::CompoundFile::open` alone found zero
//! panics in 10 000 iterations, and reading its non-test source (`sector.rs`, `direntry.rs`,
//! `alloc.rs`) found no unchecked `.unwrap()`/indexing reachable from file bytes. But using `cfb`
//! alone would still mean hand-writing the MSI-specific string-pool/table decoding on top of it —
//! exactly the part that made `msi` crash — so adopting it buys little. Given that, and this
//! project's repeated precedent (`pe::version`'s header doc, `lnk.rs`'s module doc) of hand-rolling
//! once a library's hostile-input posture is not provably acceptable, this whole module is
//! hand-rolled: no new dependency, nothing added to `docs/THIRD_PARTY.md`.
//!
//! **What is read**, all straight from the [MS-CFB] container format (verified against
//! `tests/fixtures/build/hello.msi` with `msiinfo export ... Property` and a Python `olefile`
//! script during development, both independent of this code):
//!   1. The 512-byte CFB header, then the FAT (via the header's inline DIFAT plus, if needed, the
//!      DIFAT sector chain), then the directory sector chain, then the mini-FAT and the root
//!      entry's own "mini stream" (every stream in a small `.msi` like the fixture is under the
//!      4096-byte mini-stream cutoff and so lives entirely inside the mini stream, addressed via
//!      the mini-FAT — this project's PE/`.lnk` work never needed FAT-of-a-FAT-of-a-stream
//!      indirection like this, so both the regular and the mini path are implemented and tested).
//!   2. The directory's entries are read as one flat array and matched *by decoded name*
//!      (`decode_stream_name`, MSI's fixed base64-ish obfuscation, [MS-CFB] does not define it but
//!      it is universal to every MSI tool) against `"_StringPool"`, `"_StringData"`, and the table
//!      name `"Property"`. **The red-black sibling/child tree in each directory entry is never
//!      walked**: every real `.msi` (confirmed against the fixture) stores its streams as direct
//!      children of the root storage with no nested storages, so a flat linear scan over all
//!      parsed entries finds everything a real file has, while remaining safe regardless of a
//!      corrupted tree (`left_sibling`/`right_sibling`/`child` are parsed but never dereferenced,
//!      so a garbage or cyclic pointer there cannot affect this reader at all).
//!   3. `_StringPool`/`_StringData` decode the string pool ([MS-CFB] does not cover this either;
//!      it is MSI's own format: a `u32` codepage id with a high-bit "long string refs" flag,
//!      followed by `(u16 length, u16 refcount)` records — or `(0, refcount>0)` followed by a
//!      `u32` real length, for the rare string over 64 KiB — each consuming that many bytes of
//!      `_StringData` in order).
//!   4. `Property` is decoded as exactly the two `String`-category columns the MSI schema always
//!      gives it (`Property`, `Value` — this is fixed by the Windows Installer SDK's own schema,
//!      not something inferred per-file, the same kind of "hardcode the one fixed shape" call this
//!      project already makes for `.lnk`'s `StringData` field order). Row storage is
//!      **column-major**: all `N` `Property` string-pool refs, then all `N` `Value` refs, `N`
//!      derived from `stream length / row width` (each ref is 2 bytes, or 3 with long string
//!      refs). This module never reads `_Columns`/`_Tables` and never resolves any other table:
//!      general MSI table-relationship parsing is explicitly out of scope (see [`MsiError`]).
//!
//! **Bounds.** [`MAX_MSI_BYTES`] caps the whole input up front. Every sector/mini-sector index is
//! checked against the actual file (or mini-stream) length before it is used to slice bytes
//! (`checked_mul`/`checked_add`, never raw indexing). Every chain walk (FAT-sector-chain,
//! mini-FAT-chain, the DIFAT sector chain) carries its own hop budget derived from an
//! already-size-validated array, so a cyclic or dangling chain ends in a clean [`MsiError`], never
//! an infinite loop or a panic. A stream's declared size is checked against a fixed cap
//! ([`MAX_STREAM_BYTES`]) *before* any chain is walked for it, and the actual bytes recovered from
//! the chain are checked to be at least that many *after* — so both an absurdly large declared
//! size and a declared size the real chain does not back up are clean, named errors, never a
//! silent truncation and never an oversized allocation.

/// Whole-input cap: this reader has no business processing an oversized `.msi` just to read three
/// property strings. Generous relative to any real `.msi` (`hello.msi` is 52 KiB).
pub const MAX_MSI_BYTES: usize = 256 * 1024 * 1024;
/// Cap on the (declared, then actually recovered) size of any one of the three streams this
/// reader touches (`_StringPool`, `_StringData`, the `Property` table stream).
const MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;
/// Cap on the root entry's own "mini stream" (every small stream in the file lives inside it).
const MAX_MINISTREAM_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on directory entries read from the directory sector chain (128 bytes each): generous next
/// to any real `.msi`'s table+summary-stream count.
const MAX_DIR_ENTRIES: usize = 65536;
/// Cap on strings read from `_StringPool`. MSI itself caps table rows at 65536 (see
/// `read_property_rows`); string pool entries are bounded the same way.
const MAX_STRINGS: usize = 65536;
/// Hard ceiling on DIFAT-sector hops while collecting FAT sector locations, independent of the
/// (attacker-controlled) header field: bounds a cyclic or dangling DIFAT chain (a DIFAT sector can
/// legally contribute zero new FAT sector locations — e.g. every entry `FREE_SECTOR` — so unlike
/// the length-bounded chain walks below, this loop needs its own hop cap to terminate). Even the
/// largest file this reader accepts ([`MAX_MSI_BYTES`] at the smallest, 512-byte, sector size)
/// needs on the order of 30-40 DIFAT hops to cover every sector; 8192 leaves generous headroom
/// while still failing in milliseconds, not the ~11s that `1 << 20` took in a debug build.
const MAX_DIFAT_HOPS: u32 = 8192;

const CFB_MAGIC: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const BYTE_ORDER_MARK: u16 = 0xfffe;
const MINI_SECTOR_SHIFT: u16 = 6;
const MINI_SECTOR_LEN: u64 = 1 << MINI_SECTOR_SHIFT; // 64
const DIR_ENTRY_LEN: usize = 128;
const NUM_DIFAT_ENTRIES_IN_HEADER: usize = 109;
const HEADER_LEN: usize = 512;

const FREE_SECTOR: u32 = 0xFFFF_FFFF;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const MAX_REGULAR_SECTOR: u32 = 0xFFFF_FFFA;

const OBJ_TYPE_STREAM: u8 = 2;
const OBJ_TYPE_ROOT: u8 = 5;

/// The subset of a `.msi` this project needs. See the module doc for exactly what is (and is not)
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiInfo {
    pub product_name: String,
    pub product_code: String,
    /// `None` when the `Property` table has no `UpgradeCode` row (legal: MSI does not require
    /// one, e.g. packages that are never meant to upgrade another).
    pub upgrade_code: Option<String>,
}

/// Why [`MsiInfo::read`] refused a whole file outright. Never carries attacker-controlled bytes
/// (only fixed, hand-written text and, where useful, a plain field name).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MsiError {
    #[error("too short for a CFB header ({len} bytes, need at least {HEADER_LEN})")]
    Truncated { len: usize },
    #[error("input is larger than the {MAX_MSI_BYTES}-byte cap for a structural-facts read")]
    TooLarge,
    #[error("bad CFB magic number: not an OLE2 compound file")]
    BadMagic,
    #[error("unsupported or inconsistent CFB header: {0}")]
    UnsupportedHeader(String),
    #[error("{0}")]
    Malformed(String),
    #[error("no `Property` table stream found in this .msi")]
    MissingPropertyTable,
    #[error("`Property` table has no {0:?} row")]
    MissingProperty(&'static str),
}

fn malformed(msg: impl Into<String>) -> MsiError {
    MsiError::Malformed(msg.into())
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

/// A parsed CFB header: exactly the fields needed to build the FAT, walk the directory chain and
/// find the mini stream. See the module doc's point 1 for the algorithm this drives.
struct CfbHeader {
    sector_size: u64,
    num_fat_sectors: u32,
    first_dir_sector: u32,
    mini_stream_cutoff: u64,
    first_minifat_sector: u32,
    num_minifat_sectors: u32,
    first_difat_sector: u32,
    initial_difat_entries: [u32; NUM_DIFAT_ENTRIES_IN_HEADER],
}

impl CfbHeader {
    fn parse(bytes: &[u8]) -> Result<CfbHeader, MsiError> {
        if bytes.len() < HEADER_LEN {
            return Err(MsiError::Truncated { len: bytes.len() });
        }
        let header = &bytes[..HEADER_LEN];
        if header[0..8] != CFB_MAGIC {
            return Err(MsiError::BadMagic);
        }
        let version_number = u16_at(header, 26).ok_or_else(|| malformed("truncated CFB header (version)"))?;
        let expected_sector_shift = match version_number {
            3 => 9u16,
            4 => 12u16,
            other => {
                return Err(MsiError::UnsupportedHeader(format!(
                    "CFB version {other} is not supported (only 3 or 4 are)"
                )));
            }
        };
        let byte_order_mark = u16_at(header, 28).ok_or_else(|| malformed("truncated CFB header (byte order)"))?;
        if byte_order_mark != BYTE_ORDER_MARK {
            return Err(MsiError::UnsupportedHeader("wrong byte-order mark".into()));
        }
        let sector_shift = u16_at(header, 30).ok_or_else(|| malformed("truncated CFB header (sector shift)"))?;
        if sector_shift != expected_sector_shift {
            return Err(MsiError::UnsupportedHeader(format!(
                "sector shift {sector_shift} does not match CFB version {version_number}"
            )));
        }
        let mini_sector_shift =
            u16_at(header, 32).ok_or_else(|| malformed("truncated CFB header (mini sector shift)"))?;
        if mini_sector_shift != MINI_SECTOR_SHIFT {
            return Err(MsiError::UnsupportedHeader("wrong mini sector shift".into()));
        }
        let num_fat_sectors = u32_at(header, 44).ok_or_else(|| malformed("truncated CFB header (FAT sectors)"))?;
        let first_dir_sector =
            u32_at(header, 48).ok_or_else(|| malformed("truncated CFB header (first dir sector)"))?;
        let mini_stream_cutoff =
            u32_at(header, 56).ok_or_else(|| malformed("truncated CFB header (mini stream cutoff)"))?;
        let first_minifat_sector =
            u32_at(header, 60).ok_or_else(|| malformed("truncated CFB header (first minifat sector)"))?;
        let num_minifat_sectors =
            u32_at(header, 64).ok_or_else(|| malformed("truncated CFB header (minifat sectors)"))?;
        let mut first_difat_sector =
            u32_at(header, 68).ok_or_else(|| malformed("truncated CFB header (first difat sector)"))?;
        if first_difat_sector == FREE_SECTOR {
            // Some writers use FREE_SECTOR where END_OF_CHAIN is meant (no DIFAT sectors at all).
            first_difat_sector = END_OF_CHAIN;
        }
        let mut initial_difat_entries = [FREE_SECTOR; NUM_DIFAT_ENTRIES_IN_HEADER];
        for (i, entry) in initial_difat_entries.iter_mut().enumerate() {
            *entry = u32_at(header, 76 + i * 4).ok_or_else(|| malformed("truncated CFB header (inline DIFAT)"))?;
        }
        Ok(CfbHeader {
            sector_size: 1u64 << sector_shift,
            num_fat_sectors,
            first_dir_sector,
            mini_stream_cutoff: u64::from(mini_stream_cutoff),
            first_minifat_sector,
            num_minifat_sectors,
            first_difat_sector,
            initial_difat_entries,
        })
    }
}

/// One parsed 128-byte directory entry: only the fields this reader ever uses.
#[derive(Debug, Clone)]
struct DirEntry {
    /// Decoded name (MSI's stream-name obfuscation already undone). Empty for a slot whose raw
    /// name length was malformed, which just makes it unmatchable rather than aborting the parse.
    name: String,
    obj_type: u8,
    start_sector: u32,
    stream_len: u64,
}

fn read_sector(bytes: &[u8], sector_size: u64, idx: u32) -> Result<&[u8], MsiError> {
    if idx > MAX_REGULAR_SECTOR {
        return Err(malformed("sector chain uses a reserved marker as a real sector index"));
    }
    let start = u64::from(idx)
        .checked_add(1)
        .and_then(|n| n.checked_mul(sector_size))
        .ok_or_else(|| malformed("sector offset overflow"))?;
    let end = start
        .checked_add(sector_size)
        .ok_or_else(|| malformed("sector offset overflow"))?;
    if end > bytes.len() as u64 {
        return Err(malformed("sector runs past the end of the file"));
    }
    Ok(&bytes[start as usize..end as usize])
}

fn mini_sector(mini_stream: &[u8], idx: u32) -> Result<&[u8], MsiError> {
    if idx > MAX_REGULAR_SECTOR {
        return Err(malformed(
            "mini-FAT chain uses a reserved marker as a real sector index",
        ));
    }
    let start = u64::from(idx)
        .checked_mul(MINI_SECTOR_LEN)
        .ok_or_else(|| malformed("mini-sector offset overflow"))?;
    let end = start
        .checked_add(MINI_SECTOR_LEN)
        .ok_or_else(|| malformed("mini-sector offset overflow"))?;
    if end > mini_stream.len() as u64 {
        return Err(malformed("mini-sector runs past the end of the mini stream"));
    }
    Ok(&mini_stream[start as usize..end as usize])
}

/// Builds the FAT: an entry per sector in the file, giving the next sector in whatever chain it
/// belongs to (or one of `FREE_SECTOR`/`END_OF_CHAIN`/etc.). FAT *sector locations* come from the
/// header's 109 inline DIFAT entries, then (if more are needed) the DIFAT sector chain — bounded
/// by [`MAX_DIFAT_HOPS`], not by the header's own (attacker-controlled) sector count.
fn build_fat(bytes: &[u8], header: &CfbHeader) -> Result<Vec<u32>, MsiError> {
    let num_fat_sectors = u64::from(header.num_fat_sectors);
    let declared_bytes = num_fat_sectors
        .checked_mul(header.sector_size)
        .ok_or_else(|| malformed("FAT sector count overflow"))?;
    if declared_bytes > bytes.len() as u64 {
        return Err(malformed("FAT sector count is larger than the file"));
    }
    let mut locations = Vec::new();
    for &entry in &header.initial_difat_entries {
        if locations.len() as u64 >= num_fat_sectors {
            break;
        }
        if entry != FREE_SECTOR {
            locations.push(entry);
        }
    }
    let mut next = header.first_difat_sector;
    let mut hops = 0u32;
    let entries_per_difat_sector = (header.sector_size / 4).saturating_sub(1) as usize;
    while (locations.len() as u64) < num_fat_sectors {
        if next == END_OF_CHAIN || next == FREE_SECTOR {
            break;
        }
        if hops >= MAX_DIFAT_HOPS {
            return Err(malformed("DIFAT sector chain did not terminate within the hop budget"));
        }
        hops += 1;
        let sector = read_sector(bytes, header.sector_size, next)?;
        for i in 0..entries_per_difat_sector {
            if (locations.len() as u64) >= num_fat_sectors {
                break;
            }
            let v = u32_at(sector, i * 4).ok_or_else(|| malformed("truncated DIFAT sector"))?;
            if v != FREE_SECTOR {
                locations.push(v);
            }
        }
        next = u32_at(sector, entries_per_difat_sector * 4)
            .ok_or_else(|| malformed("truncated DIFAT sector (next pointer)"))?;
    }
    if (locations.len() as u64) < num_fat_sectors {
        return Err(malformed("DIFAT chain did not yield enough FAT sector locations"));
    }
    let mut fat = Vec::with_capacity((num_fat_sectors * header.sector_size / 4) as usize);
    for &loc in &locations {
        let sector = read_sector(bytes, header.sector_size, loc)?;
        for chunk in sector.as_chunks::<4>().0 {
            fat.push(u32::from_le_bytes(*chunk));
        }
    }
    Ok(fat)
}

/// Walks a regular-sector chain starting at `start`, stopping at `END_OF_CHAIN` or once
/// `declared_len` bytes have been collected. Errors cleanly (never panics, never over-allocates)
/// when: `declared_len` exceeds `max_bytes` (checked *before* any sector is read — the "huge
/// declared stream size" guard), the chain does not actually contain `declared_len` bytes, or the
/// chain does not terminate within a hop budget derived from `fat.len()` (a cycle).
fn read_chain(
    bytes: &[u8],
    fat: &[u32],
    sector_size: u64,
    start: u32,
    declared_len: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, MsiError> {
    if declared_len > max_bytes {
        return Err(malformed(
            "declared stream size exceeds the bound for a structural-facts read",
        ));
    }
    let declared = usize::try_from(declared_len).map_err(|_| malformed("declared stream size does not fit usize"))?;
    let mut out = Vec::with_capacity(declared.min(1 << 20));
    let mut cur = start;
    let hop_budget = fat.len().saturating_add(1);
    let mut hops = 0usize;
    while cur != END_OF_CHAIN && out.len() < declared {
        if hops >= hop_budget {
            return Err(malformed("sector chain longer than the FAT itself (a cycle?)"));
        }
        hops += 1;
        let sector = read_sector(bytes, sector_size, cur)?;
        out.extend_from_slice(sector);
        cur = *fat
            .get(cur as usize)
            .ok_or_else(|| malformed("sector chain refers outside the FAT"))?;
    }
    if out.len() < declared {
        return Err(malformed("stream data is shorter than its declared size"));
    }
    out.truncate(declared);
    Ok(out)
}

/// Same as [`read_chain`] but over the mini stream, in 64-byte mini-sectors addressed by the
/// mini-FAT.
fn read_minichain(
    mini_stream: &[u8],
    minifat: &[u32],
    start: u32,
    declared_len: u64,
    max_bytes: u64,
) -> Result<Vec<u8>, MsiError> {
    if declared_len > max_bytes {
        return Err(malformed(
            "declared stream size exceeds the bound for a structural-facts read",
        ));
    }
    let declared = usize::try_from(declared_len).map_err(|_| malformed("declared stream size does not fit usize"))?;
    let mut out = Vec::with_capacity(declared.min(1 << 20));
    let mut cur = start;
    let hop_budget = minifat.len().saturating_add(1);
    let mut hops = 0usize;
    while cur != END_OF_CHAIN && out.len() < declared {
        if hops >= hop_budget {
            return Err(malformed("mini-FAT chain longer than the mini-FAT itself (a cycle?)"));
        }
        hops += 1;
        let sector = mini_sector(mini_stream, cur)?;
        out.extend_from_slice(sector);
        cur = *minifat
            .get(cur as usize)
            .ok_or_else(|| malformed("mini-FAT chain refers outside the mini-FAT"))?;
    }
    if out.len() < declared {
        return Err(malformed("stream data is shorter than its declared size"));
    }
    out.truncate(declared);
    Ok(out)
}

/// Reads the directory sector chain in full (capped at [`MAX_DIR_ENTRIES`] `* 128` bytes; there is
/// no separate "declared directory length" field to check against, unlike a real stream).
fn read_directory_bytes(bytes: &[u8], fat: &[u32], header: &CfbHeader) -> Result<Vec<u8>, MsiError> {
    let max_bytes = (MAX_DIR_ENTRIES * DIR_ENTRY_LEN) as u64;
    let mut out = Vec::new();
    let mut cur = header.first_dir_sector;
    let hop_budget = fat.len().saturating_add(1);
    let mut hops = 0usize;
    while cur != END_OF_CHAIN {
        if out.len() as u64 >= max_bytes {
            return Err(malformed(
                "directory sector chain is larger than the bound for a structural-facts read",
            ));
        }
        if hops >= hop_budget {
            return Err(malformed(
                "directory sector chain longer than the FAT itself (a cycle?)",
            ));
        }
        hops += 1;
        let sector = read_sector(bytes, header.sector_size, cur)?;
        out.extend_from_slice(sector);
        cur = *fat
            .get(cur as usize)
            .ok_or_else(|| malformed("directory chain refers outside the FAT"))?;
    }
    Ok(out)
}

fn parse_dir_entries(dir_bytes: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    for chunk in dir_bytes.as_chunks::<DIR_ENTRY_LEN>().0 {
        let chunk: &[u8] = chunk;
        let obj_type = chunk[66];
        // A malformed name length just leaves this entry's name empty (unmatchable), rather than
        // aborting the whole directory read over one bad slot.
        let name = (|| -> Option<String> {
            let name_len_bytes = u16_at(chunk, 64)?;
            if name_len_bytes == 0 {
                return Some(String::new());
            }
            if name_len_bytes > 64 || name_len_bytes % 2 != 0 {
                return None;
            }
            let name_len_chars = (name_len_bytes / 2 - 1) as usize;
            let mut units = Vec::with_capacity(name_len_chars);
            for i in 0..name_len_chars {
                units.push(u16_at(chunk, i * 2)?);
            }
            Some(String::from_utf16_lossy(&units))
        })()
        .unwrap_or_default();
        let start_sector = u32_at(chunk, 116).unwrap_or(END_OF_CHAIN);
        let stream_len = chunk
            .get(120..128)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
            .unwrap_or(0);
        entries.push(DirEntry {
            name,
            obj_type,
            start_sector,
            stream_len,
        });
    }
    entries
}

/// Undoes MSI's stream-name obfuscation (not part of [MS-CFB]; MSI's own, universal-to-every-tool
/// convention for CFB stream names — see the module doc). Returns the decoded name and whether the
/// stream was a table (a `\u{4840}` prefix). Never panics: `char::from_u32` inputs here are always
/// in a valid range by construction (ASCII digits/letters/`.`/`_`), but if this were ever wrong we
/// fall back to a private-use replacement rather than unwrapping.
fn decode_stream_name(name: &str) -> (String, bool) {
    const TABLE_PREFIX: u32 = 0x4840;
    fn from_b64(value: u32) -> char {
        let c = if value < 10 {
            b'0' + value as u8
        } else if value < 36 {
            b'A' + (value - 10) as u8
        } else if value < 62 {
            b'a' + (value - 36) as u8
        } else if value == 62 {
            return '.';
        } else {
            return '_';
        };
        c as char
    }
    let mut out = String::new();
    let mut is_table = false;
    let mut chars = name.chars().peekable();
    if chars.peek().map(|c| *c as u32) == Some(TABLE_PREFIX) {
        is_table = true;
        chars.next();
    }
    for chr in chars {
        let value = chr as u32;
        if (0x3800..0x4800).contains(&value) {
            let v = value - 0x3800;
            out.push(from_b64(v & 0x3f));
            out.push(from_b64(v >> 6));
        } else if (0x4800..0x4840).contains(&value) {
            out.push(from_b64(value - 0x4800));
        } else {
            out.push(chr);
        }
    }
    (out, is_table)
}

/// The string pool: `_StringPool` (lengths/refcounts) plus `_StringData` (the concatenated bytes).
struct StringPool {
    strings: Vec<String>,
    long_refs: bool,
}

impl StringPool {
    fn parse(pool_bytes: &[u8], data_bytes: &[u8]) -> Result<StringPool, MsiError> {
        // A missing or too-short pool is not itself an error here: it just means every string
        // reference resolves to "", which then surfaces as a clear `MissingProperty` once the
        // required `ProductName`/`ProductCode` rows cannot be found (see `MsiInfo::read`).
        if pool_bytes.len() < 4 {
            return Ok(StringPool {
                strings: Vec::new(),
                long_refs: false,
            });
        }
        let codepage_word = u32_at(pool_bytes, 0).expect("checked len >= 4 above");
        let long_refs = codepage_word & 0x8000_0000 != 0;
        let mut strings = Vec::new();
        let mut pos = 4usize;
        let mut data_pos = 0usize;
        while pos + 4 <= pool_bytes.len() {
            let length_field = u16_at(pool_bytes, pos).expect("bounds checked by loop condition");
            let refcount = u16_at(pool_bytes, pos + 2).expect("bounds checked by loop condition");
            pos += 4;
            let length = if length_field == 0 && refcount > 0 {
                let long_len =
                    u32_at(pool_bytes, pos).ok_or_else(|| malformed("truncated long-string length in _StringPool"))?;
                pos += 4;
                long_len
            } else {
                u32::from(length_field)
            };
            if strings.len() >= MAX_STRINGS {
                return Err(malformed("too many strings in _StringPool for a structural-facts read"));
            }
            let len = length as usize;
            let end = data_pos
                .checked_add(len)
                .ok_or_else(|| malformed("string length overflow"))?;
            let raw = data_bytes
                .get(data_pos..end)
                .ok_or_else(|| malformed("_StringData is shorter than _StringPool declares"))?;
            strings.push(decode_pool_string(raw));
            data_pos = end;
        }
        Ok(StringPool { strings, long_refs })
    }

    /// `num` is the 1-based string-pool reference; `0` and out-of-range both resolve to `""`
    /// (matching the convention every MSI tool uses for a null string reference).
    fn get(&self, num: u32) -> &str {
        if num == 0 {
            return "";
        }
        self.strings.get((num - 1) as usize).map(String::as_str).unwrap_or("")
    }
}

/// Decodes one `_StringData` slice. MSI strings are ordinarily this package's declared codepage
/// (not modelled here: parsing the full MSI codepage table is out of scope, see the module doc);
/// UTF-8 is tried first (wixl and most modern tools write UTF-8), falling back to a byte-for-byte
/// Latin-1-style mapping, which is lossy for non-ASCII single-byte codepages but always succeeds
/// and never panics. Every string this project actually needs from `hello.msi` (a product name, a
/// manufacturer, two GUIDs) is plain ASCII, well within both paths.
fn decode_pool_string(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(s) => s.to_owned(),
        Err(_) => raw.iter().map(|&b| b as char).collect(),
    }
}

/// Reads the `Property` table's rows. Column-major storage, two `String`-category columns
/// (`Property`, `Value` — fixed by the MSI schema, see the module doc): `N` `Property` refs then
/// `N` `Value` refs, `N = stream.len() / row_width`.
fn read_property_rows(stream: &[u8], pool: &StringPool) -> Result<Vec<(String, String)>, MsiError> {
    let ref_width = if pool.long_refs { 3 } else { 2 };
    let row_width = ref_width * 2;
    let num_rows = stream.len() / row_width;
    // MSI itself caps table rows at 65536 (a widely cited installer-tooling limit); enforced here
    // too as a sanity bound, not because we expect to be handed a legitimate table anywhere near
    // it.
    if num_rows > MAX_STRINGS {
        return Err(malformed("Property table has an implausible number of rows"));
    }
    let read_ref = |at: usize| -> Result<u32, MsiError> {
        let lo = u16_at(stream, at).ok_or_else(|| malformed("truncated Property table row"))? as u32;
        if ref_width == 3 {
            let hi = *stream
                .get(at + 2)
                .ok_or_else(|| malformed("truncated Property table row"))?;
            Ok(lo | (u32::from(hi) << 16))
        } else {
            Ok(lo)
        }
    };
    let mut property_refs = Vec::with_capacity(num_rows);
    for r in 0..num_rows {
        property_refs.push(read_ref(r * ref_width)?);
    }
    let value_col_start = num_rows * ref_width;
    let mut value_refs = Vec::with_capacity(num_rows);
    for r in 0..num_rows {
        value_refs.push(read_ref(value_col_start + r * ref_width)?);
    }
    Ok(property_refs
        .into_iter()
        .zip(value_refs)
        .map(|(p, v)| (pool.get(p).to_owned(), pool.get(v).to_owned()))
        .collect())
}

impl MsiInfo {
    /// Reads the three structural facts out of a `.msi`. Never panics on any byte sequence (see
    /// the module doc for the fuzz evidence backing the design, and `msi/tests.rs` for
    /// hostile/truncated/corrupted inputs exercised directly). `Err` covers: the file is not a CFB
    /// container at all, its FAT/directory/mini-FAT bookkeeping is inconsistent enough that the
    /// rest cannot be located reliably, it declares a size this reader refuses to trust, or the
    /// `Property` table (or one of its two required rows) is simply absent.
    pub fn read(bytes: &[u8]) -> Result<MsiInfo, MsiError> {
        if bytes.len() > MAX_MSI_BYTES {
            return Err(MsiError::TooLarge);
        }
        let header = CfbHeader::parse(bytes)?;
        let fat = build_fat(bytes, &header)?;
        let dir_bytes = read_directory_bytes(bytes, &fat, &header)?;
        let entries = parse_dir_entries(&dir_bytes);
        let root = entries
            .iter()
            .find(|e| e.obj_type == OBJ_TYPE_ROOT)
            .ok_or_else(|| malformed("no root directory entry"))?;

        let minifat_declared_bytes = u64::from(header.num_minifat_sectors)
            .checked_mul(header.sector_size)
            .ok_or_else(|| malformed("mini-FAT sector count overflow"))?;
        if minifat_declared_bytes > bytes.len() as u64 {
            return Err(malformed("mini-FAT sector count is larger than the file"));
        }
        let minifat_raw = read_chain(
            bytes,
            &fat,
            header.sector_size,
            header.first_minifat_sector,
            minifat_declared_bytes,
            minifat_declared_bytes,
        )?;
        let minifat: Vec<u32> = minifat_raw
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
            .collect();
        let mini_stream = read_chain(
            bytes,
            &fat,
            header.sector_size,
            root.start_sector,
            root.stream_len,
            MAX_MINISTREAM_BYTES,
        )?;

        let stream_bytes = |entry: &DirEntry| -> Result<Vec<u8>, MsiError> {
            if entry.stream_len >= header.mini_stream_cutoff {
                read_chain(
                    bytes,
                    &fat,
                    header.sector_size,
                    entry.start_sector,
                    entry.stream_len,
                    MAX_STREAM_BYTES,
                )
            } else {
                read_minichain(
                    &mini_stream,
                    &minifat,
                    entry.start_sector,
                    entry.stream_len,
                    MAX_STREAM_BYTES,
                )
            }
        };

        let mut string_pool_bytes = None;
        let mut string_data_bytes = None;
        let mut property_bytes = None;
        for entry in &entries {
            if entry.obj_type != OBJ_TYPE_STREAM {
                continue;
            }
            let (decoded, is_table) = decode_stream_name(&entry.name);
            if !is_table {
                continue;
            }
            match decoded.as_str() {
                "_StringPool" => string_pool_bytes = Some(stream_bytes(entry)?),
                "_StringData" => string_data_bytes = Some(stream_bytes(entry)?),
                "Property" => property_bytes = Some(stream_bytes(entry)?),
                _ => {}
            }
        }
        let property_bytes = property_bytes.ok_or(MsiError::MissingPropertyTable)?;
        let pool = StringPool::parse(
            &string_pool_bytes.unwrap_or_default(),
            &string_data_bytes.unwrap_or_default(),
        )?;
        let rows = read_property_rows(&property_bytes, &pool)?;

        let mut product_name = None;
        let mut product_code = None;
        let mut upgrade_code = None;
        for (key, value) in rows {
            match key.as_str() {
                "ProductName" => product_name = Some(value),
                "ProductCode" => product_code = Some(value),
                "UpgradeCode" => upgrade_code = Some(value),
                _ => {}
            }
        }
        Ok(MsiInfo {
            product_name: product_name.ok_or(MsiError::MissingProperty("ProductName"))?,
            product_code: product_code.ok_or(MsiError::MissingProperty("ProductCode"))?,
            upgrade_code,
        })
    }
}

#[cfg(test)]
mod tests;
