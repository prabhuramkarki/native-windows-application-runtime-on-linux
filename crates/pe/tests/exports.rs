mod common;
use common::*;

#[test]
fn exports_with_ordinal_base_forwarder_and_unused_slot() {
    let base = Builder::rva(0);
    let data = exports_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    let got: Vec<_> = i
        .exports
        .iter()
        .map(|e| (e.name.as_deref(), e.ordinal, e.forwarder.as_deref()))
        .collect();
    assert_eq!(
        got,
        vec![
            (Some("Alpha"), 10, None),
            (Some("Fwd"), 11, Some("NTDLL.RtlAllocateHeap"))
        ]
    );
}
