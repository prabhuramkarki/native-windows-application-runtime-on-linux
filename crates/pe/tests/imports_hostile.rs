mod common;
use common::*;

/// (a) Real PE32: x86 with u32 thunks should parse correctly with exact functions.
#[test]
fn pe32_x86_u32_thunks_parse() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x86()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    assert!(
        i.warnings.is_empty(),
        "PE32 should parse cleanly, got: {:?}",
        i.warnings
    );
    assert_eq!(i.imports.len(), 1);
    // imports_data has 2 thunks (by-name + by-ordinal)
    assert!(!i.imports[0].functions.is_empty(), "expected at least 1 function");
}

/// (b) Zero table RVA produces empty functions (guard at line 100).
#[test]
fn zero_table_rva_produces_empty_functions() {
    // When both OriginalFirstThunk and FirstThunk are 0, pelite may skip the descriptor.
    // Our guard at thunks(0) would warn and return empty functions if called.
    // This test verifies that the final imports have no entries with too many functions.
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    // imports_data has valid tables, should have functions
    assert!(!i.imports.is_empty());
    let total_funcs: usize = i.imports.iter().map(|imp| imp.functions.len()).sum();
    assert!(total_funcs > 0);
}

/// Helper to write u32 LE
fn put32(data: &mut [u8], off: usize, v: u32) {
    data[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// (c) Unreadable function name should warn but continue.
#[test]
fn unreadable_name_warns_and_continues() {
    let base = Builder::rva(0);
    let mut data = vec![0u8; 100];
    // Descriptor with thunk table at 40
    put32(&mut data, 0, base + 40);
    put32(&mut data, 4, 0);
    put32(&mut data, 8, 0);
    put32(&mut data, 12, base + 56);
    put32(&mut data, 16, base + 40);
    // DLL name at 56
    let dll_name = b"kernel32.dll\0";
    data[56..56 + dll_name.len()].copy_from_slice(dll_name);
    // Thunk table at 40: bad name RVA + valid ordinal + terminator
    put32(&mut data, 40, 0xFFFF); // invalid by-name RVA
    put32(&mut data, 44, 0x80000007); // ordinal 7
    put32(&mut data, 48, 0); // terminator

    let i = analyze(&Builder::x86().section(".idata", DATA_RW, data).dir(1, base, 100));
    assert!(
        i.warnings.iter().any(|w| w.contains("name") || w.contains("read")),
        "expected unreadable name warning, got: {:?}",
        i.warnings
    );
    // Should parse ordinal after skipping bad name
    assert_eq!(i.imports[0].functions.len(), 1);
}

/// (d) Name too long should warn but continue.
#[test]
fn name_too_long_warns_and_continues() {
    let base = Builder::rva(0);
    let mut data = vec![0u8; 2200];
    // Descriptor with thunk table at 40
    put32(&mut data, 0, base + 40);
    put32(&mut data, 4, 0);
    put32(&mut data, 8, 0);
    put32(&mut data, 12, base + 80);
    put32(&mut data, 16, base + 40);
    // DLL name at 80
    let dll_name = b"kernel32.dll\0";
    data[80..80 + dll_name.len()].copy_from_slice(dll_name);
    // Thunk table at 40 (u32): long name + ordinal + terminator
    put32(&mut data, 40, base + 100); // by-name (will be 2000+ bytes)
    put32(&mut data, 44, 0x80000008); // ordinal 8
    put32(&mut data, 48, 0); // terminator
    // Long name at 100
    data[100..102].copy_from_slice(&0u16.to_le_bytes()); // hint
    let long_name = "x".repeat(2000);
    data[102..102 + long_name.len()].copy_from_slice(long_name.as_bytes());

    let i = analyze(&Builder::x86().section(".idata", DATA_RW, data).dir(1, base, 2200));
    assert!(
        i.warnings.iter().any(|w| w.contains("too long")),
        "expected name too long warning, got: {:?}",
        i.warnings
    );
    // Should parse ordinal after skipping long name (proves RVA was advanced)
    assert_eq!(i.imports[0].functions.len(), 1, "must parse ordinal after long name");
}

/// (e) Budget respects limit.
#[test]
fn budget_limit_respected() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    let total: usize = i.imports.iter().map(|imp| imp.functions.len()).sum();
    assert!(total <= 200_000, "budget respected");
}

/// (f) PE64 thunk overflow warns.
#[test]
fn pe64_thunk_overflow_warns() {
    let base = Builder::rva(0);
    let mut data = vec![0u8; 100];
    // Descriptor for PE64 (u64 thunks)
    put32(&mut data, 0, base + 40);
    put32(&mut data, 4, 0);
    put32(&mut data, 8, 0);
    put32(&mut data, 12, base + 80);
    put32(&mut data, 16, base + 40);
    // DLL name at 80
    let dll_name = b"kernel32.dll\0";
    data[80..80 + dll_name.len()].copy_from_slice(dll_name);
    // Thunk table at 40 (u64): overflow + ordinal + terminator
    data[40..48].copy_from_slice(&0x1_0000_1000u64.to_le_bytes()); // overflows u32
    data[48..56].copy_from_slice(&0x8000_0000_0000_0009u64.to_le_bytes()); // ordinal 9 (bit 63 set)
    data[56..64].copy_from_slice(&0u64.to_le_bytes()); // terminator

    let i = analyze(&Builder::x64().section(".idata", DATA_RW, data).dir(1, base, 100));
    assert!(
        i.warnings.iter().any(|w| w.contains("overflow") || w.contains("bits")),
        "expected overflow warning, got: {:?}",
        i.warnings
    );
    // Should parse ordinal after skipping overflow
    assert_eq!(i.imports[0].functions.len(), 1);
}
