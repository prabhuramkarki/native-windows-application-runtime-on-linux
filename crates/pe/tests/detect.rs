mod common;
use common::*;
use pe::FileKind;

#[test]
fn detects_formats_by_header_not_extension() {
    assert_eq!(pe::detect(&Builder::x64().build()), FileKind::Pe);
    assert_eq!(
        pe::detect(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0]),
        FileKind::Msi
    );
    assert_eq!(pe::detect(b"PK\x03\x04rest"), FileKind::Zip);
    assert_eq!(pe::detect(b"#!/bin/sh\n"), FileKind::Unknown);
    assert_eq!(pe::detect(b""), FileKind::Unknown);
    // "MZ" alone, or an e_lfanew pointing outside the file, is not a PE.
    assert_eq!(pe::detect(b"MZ"), FileKind::Unknown);
    let mut lying = Builder::x64().build();
    lying[0x3C..0x40].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(pe::detect(&lying), FileKind::Unknown);
}
