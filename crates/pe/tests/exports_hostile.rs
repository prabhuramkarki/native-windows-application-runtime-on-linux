mod common;
use common::*;

/// A plain-symbol RVA: non-zero and below every section, so never inside the export directory.
const SYM: u32 = 0x10;

fn run(data: Vec<u8>, dir_size: u32) -> pe::PeInfo {
    let base = Builder::rva(0);
    analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, dir_size),
    )
}

/// Directory size covers the whole section, like a linker-emitted export directory.
fn run_all(data: Vec<u8>) -> pe::PeInfo {
    let len = data.len() as u32;
    run(data, len)
}

fn assert_warnings(i: &pe::PeInfo, expected: &[&str]) {
    assert_eq!(i.warnings, expected, "warnings");
}

fn assert_bounded(i: &pe::PeInfo) {
    for e in &i.exports {
        assert!(
            e.name.as_ref().is_none_or(|n| n.len() <= 1024),
            "name too long: {:?}",
            e.name.as_ref().map(String::len)
        );
        assert!(
            e.forwarder.as_ref().is_none_or(|n| n.len() <= 1024),
            "forwarder too long: {:?}",
            e.forwarder.as_ref().map(String::len)
        );
    }
}

fn cstr_of(len: usize, fill: u8) -> Vec<u8> {
    let mut v = vec![fill; len];
    v.push(0);
    v
}

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
fn shared_long_name_is_dropped_with_counted_warning() {
    // Two name entries share one NUL-terminated 2000-byte name.
    let base = Builder::rva(0);
    let tail_rva = base + exports_tail_off(2, 2) as u32;
    let data = exports_raw(
        base,
        10,
        &[SYM, SYM],
        &[(tail_rva, 0), (tail_rva, 1)],
        &cstr_of(2000, b'a'),
    );
    let i = run_all(data);
    assert_warnings(&i, &["exports: 2 names too long (first at name entry 0)"]);
    assert_eq!(i.exports.len(), 2);
    assert!(i.exports.iter().all(|e| e.name.is_none() && e.forwarder.is_none()));
    assert_bounded(&i);
}

#[test]
fn shared_long_forwarder_is_dropped_with_counted_warning() {
    // Slots 0 and 2 forward to one 2000-byte string, slot 1 to a short one. The export is kept,
    // without its forwarder, and the loss is reported.
    let base = Builder::rva(0);
    let tail_off = exports_tail_off(3, 0);
    let long_rva = base + tail_off as u32;
    let short_rva = long_rva + 2001;
    let mut tail = cstr_of(2000, b'b');
    tail.extend_from_slice(b"NTDLL.Ok\0");
    let data = exports_raw(base, 1, &[long_rva, short_rva, long_rva], &[], &tail);
    let i = run_all(data);
    assert_warnings(&i, &["exports: 2 forwarders too long (first at index 0)"]);
    let got: Vec<_> = i.exports.iter().map(|e| (e.ordinal, e.forwarder.as_deref())).collect();
    assert_eq!(got, vec![(1, None), (2, Some("NTDLL.Ok")), (3, None)]);
    assert_bounded(&i);
}

#[test]
fn string_length_boundary_is_1024_bytes() {
    // 1024-byte strings are kept; 1025-byte strings are "too long". Names and forwarders alike.
    let base = Builder::rva(0);
    let tail_rva = base + exports_tail_off(4, 2) as u32;
    let (n_ok, n_bad) = (tail_rva, tail_rva + 1025);
    let (f_ok, f_bad) = (n_bad + 1026, n_bad + 1026 + 1025);
    let mut tail = cstr_of(1024, b'n');
    tail.extend(cstr_of(1025, b'm'));
    tail.extend(cstr_of(1024, b'f'));
    tail.extend(cstr_of(1025, b'g'));
    let data = exports_raw(base, 0, &[SYM, SYM, f_ok, f_bad], &[(n_ok, 0), (n_bad, 1)], &tail);
    let i = run_all(data);
    assert_warnings(
        &i,
        &[
            "exports: 1 names too long (first at name entry 1)",
            "exports: 1 forwarders too long (first at index 3)",
        ],
    );
    assert_eq!(i.exports.len(), 4);
    assert_eq!(i.exports[0].name.as_deref(), Some("n".repeat(1024).as_str()));
    assert_eq!(i.exports[1].name, None);
    assert_eq!(i.exports[2].forwarder.as_deref(), Some("f".repeat(1024).as_str()));
    assert_eq!(i.exports[3].forwarder, None);
    assert_bounded(&i);
}

#[test]
fn unterminated_strings_are_reported_distinctly() {
    // The last section bytes are non-NUL, so a name and a forwarder run off the end of the
    // mapped data. That is "unterminated", not "too long".
    let base = Builder::rva(0);
    let tail_off = exports_tail_off(2, 1);
    let tail_rva = base + tail_off as u32;
    let tail = vec![b'x'; 0x200 - tail_off]; // section is exactly one file-alignment unit
    let data = exports_raw(base, 1, &[SYM, tail_rva + 1], &[(tail_rva, 0)], &tail);
    assert_eq!(data.len(), 0x200);
    let i = run_all(data);
    assert_warnings(
        &i,
        &[
            "exports: 1 names unterminated (first at name entry 0)",
            "exports: 1 forwarders unterminated (first at index 1)",
        ],
    );
    assert_eq!(i.exports.len(), 2);
}

#[test]
fn unreadable_forwarders_are_counted_and_other_exports_survive() {
    // Directory Size (0x1000) is far larger than the mapped section (0x200), so RVA base+0x800
    // is "inside the export directory" (=> a forwarder) yet in no section (=> unreadable).
    let base = Builder::rva(0);
    let unmapped = base + 0x800;
    let good_fwd = base + exports_tail_off(4, 1) as u32;
    let data = exports_raw(
        base,
        20,
        &[good_fwd, unmapped, SYM, unmapped],
        &[(good_fwd + 16, 1)],
        &[b"NTDLL.Good\0".as_slice(), &[0; 5], b"Broken\0"].concat(),
    );
    assert!(data.len() < 0x200);
    let i = run(data, 0x1000);
    assert_warnings(&i, &["exports: 2 forwarders unreadable (first at index 1)"]);
    // Every slot is still listed. An unreadable forwarder keeps its ordinal and name but has
    // forwarder None; the aggregate warning is what records that it was a forwarder.
    let got: Vec<_> = i
        .exports
        .iter()
        .map(|e| (e.name.as_deref(), e.ordinal, e.forwarder.as_deref()))
        .collect();
    assert_eq!(
        got,
        vec![
            (None, 20, Some("NTDLL.Good")),
            (Some("Broken"), 21, None),
            (None, 22, None),
            (None, 23, None),
        ]
    );
}

#[test]
fn out_of_range_name_index_is_ignored_and_counted() {
    // One name entry whose index (5) is past the two function slots.
    let base = Builder::rva(0);
    let name_rva = base + exports_tail_off(2, 1) as u32;
    let data = exports_raw(base, 10, &[SYM, SYM], &[(name_rva, 5)], b"OutOfBounds\0");
    let i = run_all(data);
    assert_warnings(&i, &["exports: 1 name entries out of range (first at index 5)"]);
    assert_eq!(i.exports.len(), 2);
    assert!(i.exports.iter().all(|e| e.name.is_none() && e.forwarder.is_none()));
}

#[test]
fn budget_limit() {
    // 5000 symbols, each named by one shared 1000-byte string => 5 MB of names, over the 4 MiB
    // budget. Exports stay listed; names stop once the budget is spent.
    const N: u32 = 5000;
    let text_rva = Builder::rva(0);
    let base = Builder::rva(1);
    let tail_rva = base + exports_tail_off(N as usize, N as usize) as u32;
    let funcs = vec![text_rva; N as usize]; // real symbols in .text, outside the export directory
    let names: Vec<_> = (0..N).map(|i| (tail_rva, i as u16)).collect();
    let data = exports_raw(base, 1, &funcs, &names, &cstr_of(1000, b'n'));
    let len = data.len() as u32;
    let i = pe::analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".text", CODE_RX, vec![0xC3; 16])
        .section(".edata", DATA_R, data)
        .dir(0, base, len)
        .build(),
    )
    .expect("analyze");
    assert_eq!(i.exports.len(), N as usize);
    assert!(
        i.exports.iter().all(|e| e.forwarder.is_none()),
        "symbols must not be forwarders"
    );
    let named = i.exports.iter().filter(|e| e.name.is_some()).count();
    let total: usize = i.exports.iter().filter_map(|e| e.name.as_ref()).map(String::len).sum();
    assert!(total <= 4 * 1024 * 1024, "total {total} exceeds budget");
    assert_eq!(named, 4 * 1024 * 1024 / 1000, "names kept until the budget is spent");
    assert_eq!(total, named * 1000);
    assert_warnings(
        &i,
        &["exports: string budget (~4194304 bytes) exhausted at 4194000 bytes"],
    );
}

#[test]
fn many_entries_pointing_at_one_huge_string_stay_cheap() {
    // 65535 name entries and 65535 forwarder slots all point at one ~390 KiB run with no NUL.
    // A per-entry scan to the NUL would cost ~390 KiB * 131070 ~ 51 GB; bounded reads cost at
    // most 1025 bytes each. Result is the same either way (too long), so assert wall time.
    const N: usize = 65_535;
    let base = Builder::rva(0);
    let tail_off = exports_tail_off(N, N);
    let tail_rva = base + tail_off as u32;
    let tail = vec![b'A'; 1024 * 1024 - tail_off]; // total = 1 MiB, a file-alignment multiple
    let funcs = vec![tail_rva; N];
    let names: Vec<_> = (0..N).map(|i| (tail_rva, i as u16)).collect();
    let data = exports_raw(base, 1, &funcs, &names, &tail);
    assert_eq!(data.len() % 0x200, 0);
    let t = std::time::Instant::now();
    let i = run_all(data);
    let took = t.elapsed();
    assert_warnings(
        &i,
        &[
            "exports: 65535 names too long (first at name entry 0)",
            "exports: 65535 forwarders too long (first at index 0)",
        ],
    );
    assert_eq!(i.exports.len(), N);
    assert!(
        took < std::time::Duration::from_secs(5),
        "took {took:?}: string reads are not bounded"
    );
}

#[test]
fn oversized_tables_are_truncated_with_warning() {
    // 65537 function slots and 65537 name entries: only 65536 of each are read, and it says so.
    const N: usize = 65_537;
    let base = Builder::rva(0);
    let name_rva = base + exports_tail_off(N, N) as u32;
    let funcs = vec![SYM; N];
    let names: Vec<_> = (0..N).map(|i| (name_rva, (i % 65_536) as u16)).collect();
    let i = run_all(exports_raw(base, 1, &funcs, &names, b"n\0"));
    assert_warnings(
        &i,
        &[
            "exports: name table has 65537 entries, only the first 65536 were read",
            "exports: function table has 65537 entries, only the first 65536 were read",
        ],
    );
    assert_eq!(i.exports.len(), 65_536);
}

#[test]
fn absurd_counts_warn_without_panic() {
    let base = Builder::rva(0);
    let mut data = exports_raw(base, 1, &[SYM], &[], b"");
    data[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // NumberOfFunctions
    data[24..28].copy_from_slice(&u32::MAX.to_le_bytes()); // NumberOfNames
    let i = run_all(data);
    assert!(i.exports.is_empty());
    assert_eq!(i.warnings.len(), 1, "{:?}", i.warnings);
    assert!(i.warnings[0].starts_with("exports: "), "{:?}", i.warnings);
}

#[test]
fn directory_size_near_u32_max_does_not_overflow() {
    // dir rva + dir size overflows u32; the forwarder range check must not panic (debug builds
    // have overflow checks) and must still classify slots.
    let base = Builder::rva(0);
    let fwd = base + exports_tail_off(2, 0) as u32;
    let data = exports_raw(base, 1, &[fwd, SYM], &[], b"NTDLL.Ok\0");
    let i = run(data, u32::MAX);
    assert_warnings(&i, &[]);
    let got: Vec<_> = i.exports.iter().map(|e| (e.ordinal, e.forwarder.as_deref())).collect();
    assert_eq!(got, vec![(1, Some("NTDLL.Ok")), (2, None)]);
}

#[test]
fn unreadable_name_is_counted_and_other_names_survive() {
    // Name 0 points at an RVA in no section; name 1 is fine.
    let base = Builder::rva(0);
    let good = base + exports_tail_off(2, 2) as u32;
    let data = exports_raw(base, 1, &[SYM, SYM], &[(base + 0x800, 0), (good, 1)], b"Good\0");
    let i = run_all(data);
    assert_warnings(&i, &["exports: 1 names unreadable (first at name entry 0)"]);
    let got: Vec<_> = i.exports.iter().map(|e| e.name.as_deref()).collect();
    assert_eq!(got, vec![None, Some("Good")]);
}

#[test]
fn forwarder_range_is_half_open() {
    // Directory is [base, base + 0x100): base is inside, base + 0xFF is inside, base + 0x100 and
    // base - 1 are plain symbols.
    let base = Builder::rva(0);
    let mut tail = vec![0u8; 0xFF - exports_tail_off(4, 0)];
    tail.extend_from_slice(b"F\0");
    let data = exports_raw(base, 1, &[base - 1, base, base + 0xFF, base + 0x100], &[], &tail);
    let i = run(data, 0x100);
    assert_warnings(&i, &[]);
    let got: Vec<_> = i.exports.iter().map(|e| e.forwarder.as_deref()).collect();
    assert_eq!(got, vec![None, Some(""), Some("F"), None]);
}
