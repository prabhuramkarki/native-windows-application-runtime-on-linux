mod common;
use common::*;

#[test]
fn relocations_count_real_fixups_only() {
    let base = Builder::rva(0);
    let i = analyze(&Builder::x64().section(".reloc", DATA_R, reloc_data()).dir(5, base, 16));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.relocation_count, 2);
}

#[test]
fn tls_callbacks_are_counted() {
    let base = Builder::rva(0);
    let i = analyze(&Builder::x64().section(".tls", DATA_RW, tls_data(base)).dir(9, base, 40));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.tls.unwrap().callback_count, 2);
}
