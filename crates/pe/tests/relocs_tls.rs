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

#[test]
fn tls_callbacks_oob_are_reported() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".tls", DATA_RW, tls_data_oob_callbacks(base))
            .dir(9, base, 40),
    );
    assert!(!i.warnings.is_empty(), "expected warning for OOB callbacks");
    assert!(
        i.warnings.iter().any(|w| w.contains("tls callbacks")),
        "warning should mention 'tls callbacks': {:?}",
        i.warnings
    );
    assert_eq!(i.tls.unwrap().callback_count, 0);
}

#[test]
fn tls_with_no_callbacks_is_silent() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".tls", DATA_RW, tls_data_no_callbacks(base))
            .dir(9, base, 40),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.tls.unwrap().callback_count, 0);
}

#[test]
fn highadj_parameter_word_is_not_a_relocation() {
    // HIGHADJ (type 4) is followed by one extra word carrying its low 16 bits. That word can look
    // like any type; here 0xA123 would count as a DIR64 fixup if read as an entry.
    let base = Builder::rva(0);
    let words = [0x4010, 0xA123, 0xA020, 0x0000];
    let data = reloc_block(0x1000, 8 + 2 * words.len() as u32, &words);
    let len = data.len() as u32;
    let i = analyze(&Builder::x64().section(".reloc", DATA_R, data).dir(5, base, len));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.relocation_count, 2); // HIGHADJ and the DIR64 after its parameter word
}
