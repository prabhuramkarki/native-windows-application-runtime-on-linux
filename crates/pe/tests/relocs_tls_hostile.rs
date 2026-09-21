//! Hostile base-relocation blocks, hostile TLS callback arrays, and PE32 (x86) coverage.
mod common;
use common::*;
use std::time::{Duration, Instant};

const SEC: usize = 0x200; // file alignment used by the builder

fn base() -> u32 {
    Builder::rva(0)
}

fn relocs(b: Builder, data: Vec<u8>) -> pe::PeInfo {
    let len = data.len() as u32;
    analyze(&b.section(".reloc", DATA_R, data).dir(5, base(), len))
}

fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// Two HIGHLOW (type 3) fixups and one ABSOLUTE padding word: exactly 2 fixups, 16 bytes.
fn good_block32(page: u32) -> Vec<u8> {
    reloc_block(page, 16, &[0x3010, 0x3018, 0x0000, 0x0000])
}

// ---- PE32 (x86) ----------------------------------------------------------------------------

#[test]
fn pe32_highlow_fixups_are_counted() {
    let i = relocs(Builder::x86(), cat(&[good_block32(0x1000), good_block32(0x2000)]));
    assert_eq!(i.warnings, Vec::<String>::new());
    assert_eq!(i.format, pe::Format::Pe32);
    assert_eq!(i.relocation_count, 4);
}

#[test]
fn pe32_tls_callbacks_are_counted_as_4_byte_vas() {
    let b = base();
    let i = analyze(&Builder::x86().section(".tls", DATA_RW, tls_data32(b)).dir(9, b, 24));
    assert_eq!(i.warnings, Vec::<String>::new());
    assert_eq!(i.tls.unwrap().callback_count, 2);
}

// ---- relocation block damage ---------------------------------------------------------------

/// SizeOfBlock 0: pelite steps over the 8-byte header only, so what should have been the block
/// body is read as the next block header. We warn about the block and keep pelite's step.
#[test]
fn reloc_block_size_zero_is_reported() {
    // Block 0 is a bare header (size 0) followed by a good block. Stepping 8 bytes lands on the
    // good block, which is counted.
    let i = relocs(
        Builder::x64(),
        cat(&[reloc_block(0x1000, 0, &[]), good_block32(0x2000)]),
    );
    assert_eq!(i.relocation_count, 2);
    assert_eq!(
        i.warnings,
        [
            "relocations: 1 malformed blocks (SizeOfBlock under 8 or past the end of the directory), first at directory offset 0x0"
        ]
    );
}

#[test]
fn reloc_block_size_four_is_reported() {
    let i = relocs(
        Builder::x64(),
        cat(&[reloc_block(0x1000, 4, &[]), good_block32(0x2000)]),
    );
    assert_eq!(i.relocation_count, 2);
    assert_eq!(
        i.warnings,
        [
            "relocations: 1 malformed blocks (SizeOfBlock under 8 or past the end of the directory), first at directory offset 0x0"
        ]
    );
}

/// The last block claims 64 bytes but only 12 remain: its 2 words are counted, and it is reported.
#[test]
fn reloc_truncated_last_block_is_reported() {
    let i = relocs(
        Builder::x64(),
        cat(&[good_block32(0x1000), reloc_block(0x2000, 64, &[0x3010, 0x3018])]),
    );
    assert_eq!(i.relocation_count, 4);
    assert_eq!(
        i.warnings,
        [
            "relocations: 1 malformed blocks (SizeOfBlock under 8 or past the end of the directory), first at directory offset 0x10"
        ]
    );
}

/// Fewer than 8 bytes after the last block cannot hold a header: they are ignored, and counted.
#[test]
fn reloc_trailing_bytes_are_reported() {
    let mut data = good_block32(0x1000);
    data.extend([0xAA; 6]);
    let i = relocs(Builder::x64(), data);
    assert_eq!(i.relocation_count, 2);
    assert_eq!(i.warnings, ["relocations: 6 trailing bytes ignored"]);
}

/// pelite rounds SizeOfBlock up to 4 with a wrapping add: 0xFFFFFFFD..=0xFFFFFFFF wrap to 0, so its
/// iterator never advances and yields the first block forever (a hang, not a panic). Our walk
/// must terminate, and quickly.
#[test]
fn reloc_block_size_near_u32_max_does_not_hang() {
    for size in [0xFFFF_FFFC, 0xFFFF_FFFD, 0xFFFF_FFFE, 0xFFFF_FFFF] {
        let started = Instant::now();
        let i = relocs(Builder::x64(), reloc_block(0x1000, size, &[0x3010, 0x3018]));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "size {size:#x} took {:?}",
            started.elapsed()
        );
        assert_eq!(i.relocation_count, 2, "size {size:#x}");
        assert_eq!(
            i.warnings,
            [
                "relocations: 1 malformed blocks (SizeOfBlock under 8 or past the end of the directory), first at directory offset 0x0"
            ],
            "size {size:#x}"
        );
    }
}

// ---- TLS callback array --------------------------------------------------------------------

/// The callback array (AddressOfCallBacks) runs to the end of its section with no zero
/// terminator. pelite's `callbacks()` scans for the terminator and returns `Err(Bounds)` when it
/// runs out of section first, never a partial slice, so nothing is counted and the failure is
/// reported through `tls callbacks: ...`.
#[test]
fn tls_callbacks_without_terminator_are_reported_and_not_counted() {
    let b = base();
    let image_base = 0x1_4000_0000u64;
    let va = |off: u32| image_base + u64::from(b + off);
    // Directory at 0; callbacks at SEC - 16 with two entries and no terminator.
    let data = Bytes::default()
        .u64(va(48))
        .u64(va(56))
        .u64(va(56))
        .u64(va(SEC as u32 - 16))
        .u32(0)
        .u32(0)
        .pad_to(SEC - 16)
        .u64(image_base + 0x1000)
        .u64(image_base + 0x1010)
        .0;
    assert_eq!(data.len(), SEC);
    let i = analyze(&Builder::x64().section(".tls", DATA_RW, data).dir(9, b, 40));
    assert_eq!(i.warnings, ["tls callbacks: bounds check failed"]);
    assert_eq!(i.tls.unwrap().callback_count, 0);
}

// ---- fewer than 16 data directories ---------------------------------------------------------

/// NumberOfRvaAndSizes = 2: directories 2.. do not exist. That is not damage: no warnings, and no
/// version info.
#[test]
fn two_data_directories_parse_silently() {
    let b = base();
    let i = analyze(&Builder {
        num_dirs: 2,
        ..Builder::x64().section(".idata", DATA_RW, imports_data(b)).dir(1, b, 40)
    });
    assert_eq!(i.warnings, Vec::<String>::new());
    assert!(i.version.is_none());
    assert_eq!(i.imports.len(), 1);
    assert_eq!((i.relocation_count, i.tls.is_none(), i.exports.len()), (0, true, 0));
}

#[test]
fn zero_data_directories_parse_silently() {
    let i = analyze(&Builder {
        num_dirs: 0,
        ..Builder::x64().section(".text", CODE_RX, vec![0x90; 16])
    });
    assert_eq!(i.warnings, Vec::<String>::new());
    assert!(i.version.is_none());
    assert!(i.imports.is_empty());
}

/// Some linkers (Wine's builtin stubs, 2 of 1432 real files checked) emit a relocation directory
/// of exactly one all-zero block header to say "no relocations". That is not damage.
#[test]
fn empty_relocation_table_idiom_is_silent() {
    let i = relocs(Builder::x64(), reloc_block(0, 0, &[]));
    assert_eq!(i.warnings, Vec::<String>::new());
    assert_eq!(i.relocation_count, 0);
}
