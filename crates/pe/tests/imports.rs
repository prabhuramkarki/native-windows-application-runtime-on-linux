mod common;
use common::*;
use pe::ImportedFn;

/// Regression: GNU ld emits import lookup tables that are only 4-byte aligned in PE32+ images.
/// pelite's `int()` rejects these ("address misaligned"), so we walk thunks ourselves.
#[test]
fn imports_survive_unaligned_thunks_x64() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.imports.len(), 1);
    assert_eq!(i.imports[0].dll, "kernel32.dll");
    assert!(!i.imports[0].delay);
    assert_eq!(
        i.imports[0].functions,
        vec![ImportedFn::Name("ExitProcess".into()), ImportedFn::Ordinal(5)]
    );
}

#[test]
fn delay_imports_are_reported_and_flagged() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".didat", DATA_RW, delay_data(base))
            .dir(13, base, 64),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.imports.len(), 1);
    assert!(i.imports[0].delay);
    assert_eq!(i.imports[0].dll, "dxgi.dll");
    assert_eq!(
        i.imports[0].functions,
        vec![ImportedFn::Name("CreateDXGIFactory".into()), ImportedFn::Ordinal(7)]
    );
}
