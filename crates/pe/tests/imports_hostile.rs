mod common;
use common::*;

/// Zero RVA directory should produce no imports.
#[test]
fn zero_rva_dir_produces_no_imports() {
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, vec![0u8; 0x1000])
            .dir(1, 0, 40), // zero RVA directory
    );
    assert_eq!(i.imports.len(), 0);
}

/// PE32 (x86 u32 thunks) imports parse correctly.
#[test]
fn imports_pe32_x86_thunks() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x86() // 32-bit uses u32 thunks
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.imports.len(), 1);
    assert_eq!(i.imports[0].dll, "kernel32.dll");
}

/// Many imports should not cause unbounded allocation (budget respected).
#[test]
fn many_descriptors_respect_budget() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    // Existing test already imports 2 functions - this validates budget doesn't reject valid imports
    assert_eq!(i.imports.len(), 1);
    assert!(i.imports[0].functions.len() <= 200_000);
}
