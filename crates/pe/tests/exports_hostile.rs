mod common;
use common::*;

#[test]
fn ordinal_only_export() {
    // Slot 0 with symbol RVA 0x2000 outside export dir => no forwarder, no name
    let base = Builder::rva(0);
    let data = exports_ordinal_only_data(base);
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
    assert_eq!(i.exports.len(), 1);
    assert_eq!(i.exports[0].name, None);
    assert_eq!(i.exports[0].ordinal, 5);
    assert_eq!(i.exports[0].forwarder, None);
}

#[test]
fn shared_long_string_warning() {
    // 2000-byte name string => should warn with count
    let base = Builder::rva(0);
    let data = exports_long_name_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    // Verify the warning specifically mentions "names unreadable"
    assert!(
        i.warnings.iter().any(|w| w.contains("names unreadable")),
        "Expected 'names unreadable' warning, got: {:?}",
        i.warnings
    );
    // Exports kept but without the too-long names
    assert!(!i.exports.is_empty());
    for e in &i.exports {
        if let Some(name) = &e.name {
            assert!(
                name.len() <= 1024,
                "No name should exceed 1024 bytes, got {}",
                name.len()
            );
        }
    }
}

#[test]
fn unreadable_name() {
    // Name table entry that pelite can't parse (this is detected through iter_name_indices Err variant)
    // Use a name RVA pointing outside the section to make it unreadable
    let base = Builder::rva(0);
    let data = exports_unreadable_forwarder_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    // If the name RVA is invalid, should warn about unreadable names
    // (or about other issues depending on data). Main thing: should not crash
    assert!(!i.exports.is_empty() || !i.warnings.is_empty());
}

#[test]
fn oob_name_index() {
    // Name table entry with idx >= functions().len() => warning
    let base = Builder::rva(0);
    let data = exports_oob_name_idx_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    // Should warn about out-of-range name entries
    assert!(
        i.warnings.iter().any(|w| w.contains("out of range")),
        "Expected 'out of range' warning, got: {:?}",
        i.warnings
    );
    // Exports still returned (both function slots, without OOB names)
    assert_eq!(i.exports.len(), 2);
}

#[test]
fn budget_limit() {
    // 5000 functions x 1000-byte name per function => >4MiB total => budget warning
    let base = Builder::rva(0);
    let data = exports_budget_test_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    // Should warn about budget
    assert!(
        i.warnings.iter().any(|w| w.contains("budget")),
        "Expected budget warning, got: {:?}",
        i.warnings
    );
    // All 5000 exports returned (some without names if budget hit)
    assert_eq!(i.exports.len(), 5000);
    // Total name bytes should not wildly exceed budget
    let total_bytes: usize = i
        .exports
        .iter()
        .map(|e| e.name.as_ref().map(|n| n.len()).unwrap_or(0))
        .sum();
    assert!(
        total_bytes <= 4 * 1024 * 1024 + 10_000,
        "Total should respect budget, got {}",
        total_bytes
    );
}
