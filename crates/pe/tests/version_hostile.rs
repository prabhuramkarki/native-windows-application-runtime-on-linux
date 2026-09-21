//! VERSIONINFO resources reached through a real resource directory. Version data is untrusted:
//! analysis must return, and must say when a version resource was unusable.
mod common;
use common::*;

/// An image whose only section is `.rsrc` (RVA `Builder::rva(0)`) holding `data` as RT_VERSION.
fn image(data: &[u8]) -> Builder {
    let base = Builder::rva(0);
    let rsrc = rsrc_version_section(base, data);
    let len = rsrc.len() as u32;
    Builder::x64().section(".rsrc", DATA_R, rsrc).dir(2, base, len)
}

fn words(w: &[u16]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// One VS_VERSIONINFO-style block; wLength is filled in.
fn block(key: &str, w_type: u16, value_len: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let pad4 = |b: &mut Vec<u8>| b.resize(b.len().next_multiple_of(4), 0);
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
    let len = b.len() as u16;
    b[..2].copy_from_slice(&len.to_le_bytes());
    b
}

fn string(k: &str, v: &str) -> Vec<u8> {
    let val = utf16z(v);
    block(k, 1, (val.len() / 2) as u16, &val, &[])
}

#[test]
fn well_formed_version_resource_is_read_through_the_directory() {
    let mut fixed = vec![0u8; 52];
    fixed[..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    let table = block(
        "040904B0",
        1,
        0,
        &[],
        &[string("FileVersion", "3.1.4.1"), string("ProductName", "Pi")],
    );
    let sfi = block("StringFileInfo", 1, 0, &[], &[table]);
    let data = block("VS_VERSION_INFO", 0, 52, &fixed, &[sfi]);
    let i = analyze(&image(&data));
    let v = i.version.expect("version info");
    assert_eq!(v.file_version.as_deref(), Some("3.1.4.1"));
    assert_eq!(v.strings.get("ProductName").map(String::as_str), Some("Pi"));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

/// pelite 0.10.0 parses this "successfully" and then slices out of range in `translation()`.
#[test]
fn crafted_version_resource_does_not_panic_and_is_reported() {
    let data = words(&[10, 0, 0, 0x41, 0]);
    assert_eq!(data.len(), 10);
    let i = analyze(&image(&data));
    assert!(i.version.is_none(), "{:?}", i.version);
    assert!(
        i.warnings.iter().any(|w| w.starts_with("version info")),
        "{:?}",
        i.warnings
    );
}

#[test]
fn empty_and_tiny_version_resources_are_reported() {
    for data in [vec![], vec![1u8], words(&[6, 0, 0]), vec![0xFF; 64]] {
        let i = analyze(&image(&data));
        assert!(i.version.is_none());
        assert!(
            i.warnings.iter().any(|w| w.starts_with("version info")),
            "{data:?}: {:?}",
            i.warnings
        );
    }
}

#[test]
fn version_resource_with_no_content_is_reported_not_returned_empty() {
    let data = block("VS_VERSION_INFO", 0, 0, &[], &[]);
    let i = analyze(&image(&data));
    assert!(i.version.is_none());
    assert!(
        i.warnings
            .iter()
            .any(|w| w.contains("no strings and no fixed file info")),
        "{:?}",
        i.warnings
    );
}

#[test]
fn data_entry_outside_the_resource_directory_is_reported() {
    let base = Builder::rva(0);
    let mut rsrc = rsrc_version_section(base, &[0; 16]);
    // Point OffsetToData (at 72) past the end of the directory.
    rsrc[72..76].copy_from_slice(&(base + 0x800).to_le_bytes());
    let len = rsrc.len() as u32;
    let i = analyze(&Builder::x64().section(".rsrc", DATA_R, rsrc).dir(2, base, len));
    assert!(i.version.is_none());
    assert!(
        i.warnings.iter().any(|w| w.starts_with("version info")),
        "{:?}",
        i.warnings
    );
}

#[test]
fn misaligned_resource_directory_is_reported_not_dereferenced() {
    let base = Builder::rva(0);
    let rsrc = rsrc_version_section(base, &[0; 16]);
    let len = rsrc.len() as u32 - 2;
    for skew in [1, 2, 3] {
        let i = analyze(
            &Builder::x64()
                .section(".rsrc", DATA_R, rsrc.clone())
                .dir(2, base + skew, len),
        );
        assert!(i.version.is_none());
        assert!(
            i.warnings.iter().any(|w| w.starts_with("resources")),
            "{skew}: {:?}",
            i.warnings
        );
    }
}

#[test]
fn tiny_pe_without_a_resource_directory_is_silent() {
    let i = analyze(&Builder::x64().section(".text", CODE_RX, vec![0xC3]));
    assert!(i.version.is_none());
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

#[test]
fn resource_directory_without_a_version_type_is_silent() {
    let base = Builder::rva(0);
    let mut rsrc = rsrc_version_section(base, &[0; 16]);
    rsrc[16..20].copy_from_slice(&24u32.to_le_bytes()); // type 24 (manifest), not 16
    let len = rsrc.len() as u32;
    let i = analyze(&Builder::x64().section(".rsrc", DATA_R, rsrc).dir(2, base, len));
    assert!(i.version.is_none());
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

#[test]
fn corrupt_resource_directory_entries_are_reported() {
    let base = Builder::rva(0);
    let good = rsrc_version_section(base, &[0; 16]);
    let cases: [(&str, usize, u32); 3] = [
        ("data entry offset not 4-aligned", 68, 74),
        ("data entry offset out of range", 68, 0x00FF_FFF0),
        ("subdirectory offset out of range", 20, 0x8000_0000 | 0x00FF_FFF0),
    ];
    for (what, at, value) in cases {
        let mut rsrc = good.clone();
        rsrc[at..at + 4].copy_from_slice(&value.to_le_bytes());
        let len = rsrc.len() as u32;
        let i = analyze(&Builder::x64().section(".rsrc", DATA_R, rsrc).dir(2, base, len));
        assert!(i.version.is_none(), "{what}");
        assert!(
            i.warnings.iter().any(|w| w.starts_with("version info")),
            "{what}: {:?}",
            i.warnings
        );
    }
}

/// Random damage to a valid resource directory plus VERSIONINFO: analysis must always return.
#[test]
fn mutated_resource_sections_never_panic() {
    let mut fixed = vec![0u8; 52];
    fixed[..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    let table = block(
        "040904B0",
        1,
        0,
        &[],
        &[string("FileVersion", "1.0"), string("ProductName", "P")],
    );
    let data = block(
        "VS_VERSION_INFO",
        0,
        52,
        &fixed,
        &[block("StringFileInfo", 1, 0, &[], &[table])],
    );
    let base = Builder::rva(0);
    let seed = rsrc_version_section(base, &data);
    let len = seed.len() as u32;
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for _ in 0..5_000 {
        let mut rsrc = seed.clone();
        for _ in 0..=(next() % 4) {
            let at = next() as usize % rsrc.len();
            rsrc[at] = next() as u8;
        }
        let img = Builder::x64().section(".rsrc", DATA_R, rsrc).dir(2, base, len).build();
        pe::analyze(&img).expect("analyze");
    }
}
