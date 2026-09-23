use super::*;
use std::panic::catch_unwind;
use std::path::Path;
use std::time::{Duration, Instant};

/// A binary built by `tools/build-fixtures.sh` (needs Wine/wixl; the file is not committed).
fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"))
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// The inverse of `decode_stream_name`, hand-written the same way (test-only helper; never a
/// panic on the fixed, all-ASCII table/column names used by the tests below).
fn encode_stream_name(name: &str, is_table: bool) -> String {
    fn to_b64(ch: char) -> Option<u32> {
        if ch.is_ascii_digit() {
            Some(ch as u32 - '0' as u32)
        } else if ch.is_ascii_uppercase() {
            Some(10 + ch as u32 - 'A' as u32)
        } else if ch.is_ascii_lowercase() {
            Some(36 + ch as u32 - 'a' as u32)
        } else if ch == '.' {
            Some(62)
        } else if ch == '_' {
            Some(63)
        } else {
            None
        }
    }
    let mut out = String::new();
    if is_table {
        out.push('\u{4840}');
    }
    let mut chars = name.chars().peekable();
    while let Some(ch1) = chars.next() {
        if let Some(v1) = to_b64(ch1) {
            if let Some(&ch2) = chars.peek()
                && let Some(v2) = to_b64(ch2)
            {
                out.push(char::from_u32(0x3800 + (v2 << 6) + v1).unwrap());
                chars.next();
                continue;
            }
            out.push(char::from_u32(0x4800 + v1).unwrap());
        } else {
            out.push(ch1);
        }
    }
    out
}

/// `decode_stream_name` against the *real* encoded names read out of `hello.msi` with a Python
/// `olefile` script during development (independent of this Rust code): confirms our hand-rolled
/// decode matches what the fixture actually contains, not just our own encoder's round trip.
#[test]
fn decode_stream_name_matches_the_real_fixtures_encoded_names() {
    assert_eq!(
        decode_stream_name("\u{4840}\u{4559}\u{44f2}\u{4568}\u{4737}"),
        ("Property".to_string(), true)
    );
    assert_eq!(
        decode_stream_name("\u{4840}\u{3f3f}\u{4577}\u{446c}\u{3b6a}\u{45e4}\u{4824}"),
        ("_StringData".to_string(), true)
    );
    assert_eq!(
        encode_stream_name("Property", true),
        "\u{4840}\u{4559}\u{44f2}\u{4568}\u{4737}"
    );
}

// --- a minimal, spec-valid synthetic CFB v3 (512-byte sector) container -------------------------
//
// Layout (each region exactly one 512-byte sector): header, FAT sector, directory sector (4
// entries: root + `_StringPool` + `_StringData` + `Property`), mini-FAT sector, and one data
// sector holding the root's whole "mini stream" (three 64-byte mini-sectors: pool, data,
// property). Every stream is comfortably under the mini-stream cutoff, same as every stream in
// the real fixture.

const SECTOR: usize = 512;

fn dir_entry(name: &str, obj_type: u8, start_sector: u32, stream_len: u64) -> [u8; DIR_ENTRY_LEN] {
    let mut e = [0u8; DIR_ENTRY_LEN];
    let units: Vec<u16> = name.encode_utf16().collect();
    for (i, u) in units.iter().enumerate() {
        put_u16(&mut e, i * 2, *u);
    }
    put_u16(&mut e, 64, ((units.len() + 1) * 2) as u16);
    e[66] = obj_type;
    e[67] = 1; // color: unused by this reader
    put_u32(&mut e, 68, 0xFFFF_FFFF); // left sibling: NOSTREAM (never walked)
    put_u32(&mut e, 72, 0xFFFF_FFFF); // right sibling
    put_u32(&mut e, 76, 0xFFFF_FFFF); // child
    put_u32(&mut e, 116, start_sector);
    put_u64(&mut e, 120, stream_len);
    e
}

/// Builds a minimal `.msi`-shaped CFB file whose `Property` table has exactly `rows`. Returns the
/// bytes and the file offset of the `Property` directory entry's `stream_len` field (valid
/// whether or not `include_property_table`, for tests that mutate it directly).
fn build_msi(rows: &[(&str, &str)], include_property_table: bool) -> (Vec<u8>, usize) {
    let mut strings: Vec<&str> = Vec::new();
    let mut refs: Vec<(u32, u32)> = Vec::new();
    for (k, v) in rows {
        strings.push(k);
        let kref = strings.len() as u32;
        strings.push(v);
        let vref = strings.len() as u32;
        refs.push((kref, vref));
    }
    let mut pool_bytes = vec![0u8; 4]; // codepage word: id 0, no long string refs
    let mut data_bytes = Vec::new();
    for s in &strings {
        assert!(s.is_ascii(), "test strings must be ASCII (byte length == char length)");
        pool_bytes.extend_from_slice(&(s.len() as u16).to_le_bytes());
        pool_bytes.extend_from_slice(&1u16.to_le_bytes()); // refcount
        data_bytes.extend_from_slice(s.as_bytes());
    }
    let mut property_bytes = Vec::new();
    for (kref, _) in &refs {
        property_bytes.extend_from_slice(&(*kref as u16).to_le_bytes());
    }
    for (_, vref) in &refs {
        property_bytes.extend_from_slice(&(*vref as u16).to_le_bytes());
    }
    assert!(
        pool_bytes.len() <= 64 && data_bytes.len() <= 64 && property_bytes.len() <= 64,
        "fixture too big for one 64-byte mini-sector each; add another mini-sector if this ever grows"
    );

    let mut ministream = vec![0u8; SECTOR];
    ministream[0..pool_bytes.len()].copy_from_slice(&pool_bytes);
    ministream[64..64 + data_bytes.len()].copy_from_slice(&data_bytes);
    ministream[128..128 + property_bytes.len()].copy_from_slice(&property_bytes);

    let mut dir = Vec::new();
    dir.extend_from_slice(&dir_entry("Root Entry", OBJ_TYPE_ROOT, 3, SECTOR as u64));
    dir.extend_from_slice(&dir_entry(
        &encode_stream_name("_StringPool", true),
        OBJ_TYPE_STREAM,
        0,
        pool_bytes.len() as u64,
    ));
    dir.extend_from_slice(&dir_entry(
        &encode_stream_name("_StringData", true),
        OBJ_TYPE_STREAM,
        1,
        data_bytes.len() as u64,
    ));
    let property_entry_index = 3;
    if include_property_table {
        dir.extend_from_slice(&dir_entry(
            &encode_stream_name("Property", true),
            OBJ_TYPE_STREAM,
            2,
            property_bytes.len() as u64,
        ));
    } else {
        dir.extend_from_slice(&[0u8; DIR_ENTRY_LEN]);
    }
    assert_eq!(dir.len(), SECTOR);

    let mut fat = vec![0xFFu8; SECTOR]; // 0xFF repeated == FREE_SECTOR (0xFFFF_FFFF) for every u32 slot
    put_u32(&mut fat, 0, 0xFFFF_FFFD); // FAT_SECTOR: describes sector 0 (itself)
    put_u32(&mut fat, 4, END_OF_CHAIN); // sector 1 (directory): single sector
    put_u32(&mut fat, 8, END_OF_CHAIN); // sector 2 (mini-FAT): single sector
    put_u32(&mut fat, 12, END_OF_CHAIN); // sector 3 (mini stream data): single sector

    let mut minifat = vec![0u8; SECTOR];
    put_u32(&mut minifat, 0, END_OF_CHAIN); // mini-sector 0 (string pool)
    put_u32(&mut minifat, 4, END_OF_CHAIN); // mini-sector 1 (string data)
    put_u32(&mut minifat, 8, END_OF_CHAIN); // mini-sector 2 (property)

    let mut header = vec![0u8; HEADER_LEN];
    header[0..8].copy_from_slice(&CFB_MAGIC);
    put_u16(&mut header, 26, 3); // version 3
    put_u16(&mut header, 28, BYTE_ORDER_MARK);
    put_u16(&mut header, 30, 9); // sector shift -> 512-byte sectors
    put_u16(&mut header, 32, MINI_SECTOR_SHIFT);
    put_u32(&mut header, 44, 1); // num_fat_sectors
    put_u32(&mut header, 48, 1); // first_dir_sector
    put_u32(&mut header, 56, 4096); // mini stream cutoff
    put_u32(&mut header, 60, 2); // first_minifat_sector
    put_u32(&mut header, 64, 1); // num_minifat_sectors
    put_u32(&mut header, 68, END_OF_CHAIN); // first_difat_sector: none needed
    put_u32(&mut header, 76, 0); // initial_difat_entries[0]: FAT is sector 0
    for i in 1..NUM_DIFAT_ENTRIES_IN_HEADER {
        put_u32(&mut header, 76 + i * 4, 0xFFFF_FFFF); // FREE_SECTOR: unused slot
    }

    let mut out = header;
    out.extend_from_slice(&fat);
    out.extend_from_slice(&dir);
    out.extend_from_slice(&minifat);
    out.extend_from_slice(&ministream);

    // dir sector starts right after header+fat (sector index 1 -> file offset (1+1)*SECTOR).
    let dir_file_offset = HEADER_LEN + SECTOR;
    let property_stream_len_offset = dir_file_offset + property_entry_index * DIR_ENTRY_LEN + 120;
    (out, property_stream_len_offset)
}

// --- the real fixture ----------------------------------------------------------------------- //

#[test]
fn hello_msi_fixture_reads_the_exact_documented_facts() {
    let bytes = fixture("hello.msi");
    let info = MsiInfo::read(&bytes).expect("hello.msi should parse");
    assert_eq!(info.product_name, "Runtime Fixture MSI");
    assert_eq!(info.product_code, "{8965C2A7-9312-4D38-A0C4-76FAE288CAA7}");
    assert_eq!(
        info.upgrade_code.as_deref(),
        Some("{99B86B86-FA62-4A0C-AA31-8D2DB4C7CBEE}")
    );
}

// --- the synthetic minimal container ---------------------------------------------------------- //

#[test]
fn synthetic_minimal_msi_reads_its_rows() {
    let (bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    let info = MsiInfo::read(&bytes).expect("synthetic minimal .msi should parse");
    assert_eq!(info.product_name, "A");
    assert_eq!(info.product_code, "B");
    assert_eq!(info.upgrade_code, None);
}

#[test]
fn synthetic_msi_with_upgrade_code_reads_all_three() {
    let (bytes, _) = build_msi(
        &[("ProductName", "A"), ("ProductCode", "B"), ("UpgradeCode", "C")],
        true,
    );
    let info = MsiInfo::read(&bytes).expect("synthetic .msi should parse");
    assert_eq!(info.product_name, "A");
    assert_eq!(info.product_code, "B");
    assert_eq!(info.upgrade_code.as_deref(), Some("C"));
}

#[test]
fn missing_property_table_is_a_clear_error() {
    let (bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], false);
    assert_eq!(MsiInfo::read(&bytes), Err(MsiError::MissingPropertyTable));
}

#[test]
fn a_missing_required_row_is_a_clear_error_not_an_empty_string() {
    let (bytes, _) = build_msi(&[("ProductCode", "B")], true);
    assert_eq!(MsiInfo::read(&bytes), Err(MsiError::MissingProperty("ProductName")));
}

// --- truncation / corruption: never panic, always a clean, bounded error --------------------- //

#[test]
fn truncated_before_the_header_ends_is_a_clean_error() {
    let bytes = fixture("hello.msi");
    for len in [0, 1, 8, 100, HEADER_LEN - 1] {
        match MsiInfo::read(&bytes[..len]) {
            Err(MsiError::Truncated { len: got }) => assert_eq!(got, len),
            other => panic!("len {len}: expected Truncated, got {other:?}"),
        }
    }
}

#[test]
fn bad_magic_is_rejected() {
    let mut bytes = fixture("hello.msi");
    bytes[0] = 0;
    assert_eq!(MsiInfo::read(&bytes), Err(MsiError::BadMagic));
}

#[test]
fn bad_byte_order_mark_is_rejected() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    put_u16(&mut bytes, 28, 0x0000);
    assert!(matches!(MsiInfo::read(&bytes), Err(MsiError::UnsupportedHeader(_))));
}

#[test]
fn sector_shift_inconsistent_with_the_version_is_rejected() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    put_u16(&mut bytes, 30, 12); // version 3 requires sector shift 9, not 12
    assert!(matches!(MsiInfo::read(&bytes), Err(MsiError::UnsupportedHeader(_))));
}

#[test]
fn unsupported_cfb_version_is_rejected() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    put_u16(&mut bytes, 26, 7);
    assert!(matches!(MsiInfo::read(&bytes), Err(MsiError::UnsupportedHeader(_))));
}

#[test]
fn input_larger_than_the_cap_is_rejected_quickly() {
    let bytes = vec![0u8; MAX_MSI_BYTES + 1];
    let started = Instant::now();
    assert_eq!(MsiInfo::read(&bytes), Err(MsiError::TooLarge));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn fat_sector_count_larger_than_the_file_is_rejected_without_reading_huge_data() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    put_u32(&mut bytes, 44, 0xFFFF_FF00); // num_fat_sectors: absurd, file is a few KiB
    let started = Instant::now();
    let err = MsiInfo::read(&bytes).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn declared_stream_size_over_the_bound_is_rejected_before_any_chain_is_walked() {
    let (mut bytes, property_len_off) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    put_u64(&mut bytes, property_len_off, MAX_STREAM_BYTES + 1);
    let started = Instant::now();
    let err = MsiInfo::read(&bytes).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn stream_shorter_than_its_declared_size_is_an_error_not_a_silent_truncation() {
    let (mut bytes, property_len_off) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    // The real Property stream is 8 bytes, backed by exactly one 64-byte mini-sector whose chain
    // ends there (mini-FAT[2] = END_OF_CHAIN). Declare more than that one mini-sector can ever
    // supply, so the chain runs out before the declared length is reached.
    put_u64(&mut bytes, property_len_off, 70);
    let err = MsiInfo::read(&bytes).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
}

#[test]
fn a_cyclic_directory_chain_is_rejected_not_an_infinite_loop() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    // FAT[1] (the directory sector's own chain entry) pointed past END_OF_CHAIN at itself.
    put_u32(&mut bytes, HEADER_LEN + 4, 1);
    let started = Instant::now();
    let err = MsiInfo::read(&bytes).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn a_cyclic_minifat_chain_is_rejected_not_an_infinite_loop() {
    let (mut bytes, _) = build_msi(&[("ProductName", "A"), ("ProductCode", "B")], true);
    // minifat[2] (the Property stream's own mini-sector) pointed at itself instead of EOC.
    let minifat_off = HEADER_LEN + SECTOR * 3;
    put_u32(&mut bytes, minifat_off + 8, 2);
    let started = Instant::now();
    let err = MsiInfo::read(&bytes).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}

/// Isolated `build_fat` test: forces the DIFAT-sector-chain path (needed once a file has more than
/// the 109 FAT-sector locations that fit inline in the header), which no other test exercises
/// (`hello.msi` and the synthetic fixture above both need only one FAT sector).
#[test]
fn a_110th_fat_sector_is_reached_through_one_difat_sector() {
    let entries_per_difat_sector = SECTOR / 4 - 1; // 127
    let num_fat_sectors: u32 = 110;
    // Sector layout: sectors 0..109 are dummy FAT sectors (content irrelevant), sector 109 is the
    // one DIFAT sector, sector 110 is the 110th FAT sector.
    let total_sectors = 111usize;
    let mut bytes = vec![0u8; HEADER_LEN + total_sectors * SECTOR];

    let mut header = vec![0u8; HEADER_LEN];
    header[0..8].copy_from_slice(&CFB_MAGIC);
    put_u16(&mut header, 26, 3);
    put_u16(&mut header, 28, BYTE_ORDER_MARK);
    put_u16(&mut header, 30, 9);
    put_u16(&mut header, 32, MINI_SECTOR_SHIFT);
    put_u32(&mut header, 44, num_fat_sectors);
    put_u32(&mut header, 48, END_OF_CHAIN); // first_dir_sector: unused by this isolated test
    put_u32(&mut header, 56, 4096);
    put_u32(&mut header, 60, END_OF_CHAIN); // first_minifat_sector: unused
    put_u32(&mut header, 64, 0);
    put_u32(&mut header, 68, 109); // first_difat_sector
    put_u32(&mut header, 72, 1); // num_difat_sectors
    for i in 0..NUM_DIFAT_ENTRIES_IN_HEADER {
        put_u32(&mut header, 76 + i * 4, i as u32); // FAT sectors 0..108 located at sectors 0..108
    }
    bytes[..HEADER_LEN].copy_from_slice(&header);

    // Sector 109: the DIFAT sector. One real entry (FAT sector 109 is at sector index 110), the
    // rest FREE_SECTOR, terminated by END_OF_CHAIN.
    let difat_sector_off = HEADER_LEN + 109 * SECTOR;
    for i in 0..entries_per_difat_sector {
        put_u32(&mut bytes, difat_sector_off + i * 4, 0xFFFF_FFFF);
    }
    put_u32(&mut bytes, difat_sector_off, 110); // slot 0: the 110th FAT sector's location
    put_u32(
        &mut bytes,
        difat_sector_off + entries_per_difat_sector * 4,
        END_OF_CHAIN,
    );

    let parsed = CfbHeader::parse(&bytes).expect("header should parse");
    let fat = build_fat(&bytes, &parsed).expect("DIFAT chain should be followed");
    assert_eq!(fat.len(), num_fat_sectors as usize * (SECTOR / 4));
}

/// Unlike the FAT/mini-FAT chain walks (bounded by their own strictly-growing byte count
/// regardless of hop count), a DIFAT sector all of whose entries are `FREE_SECTOR` adds *zero* new
/// FAT sector locations per hop, so a DIFAT sector whose "next" pointer loops back to itself would
/// hang forever without [`MAX_DIFAT_HOPS`]. Isolated `build_fat` test, same shape as the 110th-FAT-
/// sector test above but with the one DIFAT sector pointing at itself.
#[test]
fn a_self_looping_difat_sector_is_rejected_not_an_infinite_loop() {
    let entries_per_difat_sector = SECTOR / 4 - 1;
    let num_fat_sectors: u32 = 200; // more than fits inline, forces the DIFAT chain to be walked
    // The file must be at least `num_fat_sectors * SECTOR` bytes, or `build_fat`'s upfront
    // "declared FAT size exceeds the file" check would reject it before the DIFAT loop even
    // starts (a different, cheaper guard tested elsewhere) — most of this space is never read.
    let mut bytes = vec![0u8; HEADER_LEN + num_fat_sectors as usize * SECTOR];

    let mut header = vec![0u8; HEADER_LEN];
    header[0..8].copy_from_slice(&CFB_MAGIC);
    put_u16(&mut header, 26, 3);
    put_u16(&mut header, 28, BYTE_ORDER_MARK);
    put_u16(&mut header, 30, 9);
    put_u16(&mut header, 32, MINI_SECTOR_SHIFT);
    put_u32(&mut header, 44, num_fat_sectors);
    put_u32(&mut header, 48, END_OF_CHAIN);
    put_u32(&mut header, 56, 4096);
    put_u32(&mut header, 60, END_OF_CHAIN);
    put_u32(&mut header, 64, 0);
    put_u32(&mut header, 68, 1); // first_difat_sector: the self-looping sector below
    put_u32(&mut header, 72, 1);
    for i in 0..NUM_DIFAT_ENTRIES_IN_HEADER {
        put_u32(&mut header, 76 + i * 4, 0xFFFF_FFFF); // inline DIFAT: nothing usable either
    }
    bytes[..HEADER_LEN].copy_from_slice(&header);

    // Sector 1: every entry FREE_SECTOR (contributes no locations), "next" pointer loops to itself.
    let difat_sector_off = HEADER_LEN + SECTOR;
    for i in 0..entries_per_difat_sector {
        put_u32(&mut bytes, difat_sector_off + i * 4, 0xFFFF_FFFF);
    }
    put_u32(&mut bytes, difat_sector_off + entries_per_difat_sector * 4, 1);

    let parsed = CfbHeader::parse(&bytes).expect("header should parse");
    let started = Instant::now();
    let err = build_fat(&bytes, &parsed).unwrap_err();
    assert!(matches!(err, MsiError::Malformed(_)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );
}

// --- mutation checks (guards temporarily removed by hand, see the task report for the exact
// names and what was observed) ---
// - `truncated_before_the_header_ends_is_a_clean_error` fails if the `bytes.len() < HEADER_LEN`
//   check in `CfbHeader::parse` is removed (it then panics on the header slice).
// - `bad_magic_is_rejected` fails if the magic-number check is removed.
// - `fat_sector_count_larger_than_the_file_is_rejected_without_reading_huge_data` fails (times
//   out or panics trying to allocate/slice) if `build_fat`'s upfront
//   `declared_bytes > bytes.len()` check is removed.
// - `declared_stream_size_over_the_bound_is_rejected_before_any_chain_is_walked` fails if the
//   `declared_len > max_bytes` check at the top of `read_chain`/`read_minichain` is removed.
// - `stream_shorter_than_its_declared_size_is_an_error_not_a_silent_truncation` fails (returns Ok
//   with a truncated value instead of Err) if the `out.len() < declared` check is removed.
// - `a_cyclic_directory_chain_is_rejected_not_an_infinite_loop` and
//   `a_cyclic_minifat_chain_is_rejected_not_an_infinite_loop` hang (never return) if the
//   `hops >= hop_budget` checks are removed.
// - `a_110th_fat_sector_is_reached_through_one_difat_sector` fails if the DIFAT-sector-chain walk
//   in `build_fat` is removed or broken (falls back to only the 109 inline entries).
// - `mutated_hello_msi_never_panics` is the blanket check: any single guard's removal that turns
//   a clean error into a panic on some byte pattern is expected to be caught by this test too.

/// Xorshift PRNG, matching `lnk.rs`'s fuzz test.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// The spike evidence from the module doc, turned into a permanent regression test: 10 000
/// xorshift-mutated (byte-flip or truncate) variants of the real `hello.msi` must never panic
/// `MsiInfo::read`, however they are corrupted. (This is the same harness that found `msi 0.10`
/// panicking on 4 of 10 000 mutations of this exact fixture.)
#[test]
fn mutated_hello_msi_never_panics() {
    let template = fixture("hello.msi");
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    for n in 0..10_000u64 {
        let mut m = template.clone();
        if rng.next().is_multiple_of(5) {
            let len = m.len();
            m.truncate((rng.next() as usize) % (len + 1));
        } else {
            for _ in 0..=(rng.next() % 8) {
                let len = m.len();
                if len == 0 {
                    break;
                }
                let at = (rng.next() as usize) % len;
                m[at] ^= (rng.next() & 0xff) as u8;
            }
        }
        let r = catch_unwind(|| MsiInfo::read(&m));
        assert!(r.is_ok(), "panicked on iteration {n}");
    }
}
