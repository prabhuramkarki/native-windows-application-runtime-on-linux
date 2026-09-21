//! Hostile import and delay-import tables. Every test asserts the exact warnings (or their
//! absence), so each fails when the guard it targets is removed.
mod common;
use common::*;
use pe::ImportedFn::{Name, Ordinal};
use std::time::{Duration, Instant};

const K32: &str = "kernel32.dll";
const SEC: usize = 0x200; // file alignment used by the builder

fn base() -> u32 {
    Builder::rva(0)
}

fn img(b: Builder, sec: &'static str, data: Vec<u8>, dir: usize) -> pe::PeInfo {
    let len = data.len() as u32;
    analyze(&b.section(sec, DATA_RW, data).dir(dir, base(), len))
}

fn run64(data: Vec<u8>) -> pe::PeInfo {
    img(Builder::x64(), ".idata", data, 1)
}

fn run32(data: Vec<u8>) -> pe::PeInfo {
    img(Builder::x86(), ".idata", data, 1)
}

fn run_delay(data: Vec<u8>) -> pe::PeInfo {
    img(Builder::x64(), ".didat", data, 13)
}

fn u64s(words: impl IntoIterator<Item = u64>) -> Vec<u8> {
    words.into_iter().flat_map(u64::to_le_bytes).collect()
}

fn u32s(words: impl IntoIterator<Item = u32>) -> Vec<u8> {
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}

/// (a) A real PE32 image with u32 thunks parses to the exact functions, with no warnings.
#[test]
fn pe32_x86_u32_thunks_parse() {
    let i = run32(imports_data32(base()));
    assert_eq!(i.format, pe::Format::Pe32);
    assert_eq!(i.warnings, Vec::<String>::new());
    assert_eq!(i.imports.len(), 1);
    assert_eq!(i.imports[0].dll, K32);
    assert!(!i.imports[0].delay);
    assert_eq!(i.imports[0].functions, vec![Name("ExitProcess".into()), Ordinal(5)]);
}

/// (b) pelite ends the descriptor list at the first descriptor whose FirstThunk is 0, so a regular
/// descriptor with OriginalFirstThunk == FirstThunk == 0 never reaches the thunk walker: the "zero
/// table RVA" guard is only reachable through delay imports (next test). What must not happen is
/// bogus functions, or descriptors after it being silently dropped: say where the list ended.
#[test]
fn zero_table_descriptor_ends_the_list_and_says_so() {
    let b = base();
    let tail_off = imports_tail_off(2) as u32;
    let table = b + tail_off + 16;
    let mut tail = Bytes::default().cstr(K32).pad_to(16).0;
    tail.extend(u64s([0x8000_0000_0000_0001, 0]));
    // Descriptor 1 has a name but no table at all; descriptor 2 (not reached) is fine.
    let data = imports_raw(&[(table, b + tail_off, table), (0, b + tail_off, 0)], &tail);
    let i = run64(data);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: descriptor 1 (RVA {:#x}) has FirstThunk 0 but other fields set; list ends there",
            b + 20
        )]
    );
    assert_eq!(i.imports.len(), 1);
    assert_eq!(i.imports[0].functions, vec![Ordinal(1)]);
}

/// Old linkers omit the lookup table: OriginalFirstThunk == 0 falls back to FirstThunk.
#[test]
fn missing_lookup_table_falls_back_to_iat() {
    let b = base();
    let tail_off = imports_tail_off(1) as u32;
    let table = b + tail_off + 16;
    let mut tail = Bytes::default().cstr(K32).pad_to(16).0;
    tail.extend(u64s([0x8000_0000_0000_0004, 0]));
    let i = run64(imports_raw(&[(0, b + tail_off, table)], &tail));
    assert_eq!(i.warnings, Vec::<String>::new());
    assert_eq!(i.imports[0].functions, vec![Ordinal(4)]);
}

#[test]
fn zero_table_delay_descriptor_warns_and_has_no_functions() {
    let name = base() + delay_tail_off(1) as u32;
    let i = run_delay(delay_raw(
        &[[1, name, 0, 0, 0, 0, 0, 0]],
        &Bytes::default().cstr("dxgi.dll").0,
    ));
    assert_eq!(i.warnings, ["delay imports: dxgi.dll zero table RVA"]);
    assert_eq!(i.imports.len(), 1);
    assert!(i.imports[0].delay);
    assert!(i.imports[0].functions.is_empty());
}

/// A zero import-directory RVA is pelite's `Error::Null`: no imports, and not worth a warning.
#[test]
fn zero_rva_dir_produces_no_imports() {
    for size in [0, 40] {
        let i = analyze(
            &Builder::x64()
                .section(".idata", DATA_RW, imports_data(base()))
                .dir(1, 0, size),
        );
        assert!(i.imports.is_empty(), "size {size}");
        assert_eq!(i.warnings, Vec::<String>::new(), "size {size}");
    }
}

/// (c) A thunk table that runs into the end of its section with no terminator: the functions
/// before the cut are kept, the truncation is reported, and there is no false "not terminated
/// within 65536 entries" warning.
#[test]
fn table_cut_by_section_end_keeps_functions_and_warns() {
    let b = base();
    let tail = Bytes::default().cstr(K32).pad_to(24).u16(0).cstr("Foo").0; // name at 40, hint/name at 64
    let table = b + SEC as u32 - 24;
    let mut data = imports_raw(&[(table, b + 40, table)], &tail);
    data.resize(SEC - 24, 0);
    data.extend(u64s([u64::from(b + 64), 0x8000_0000_0000_0003, 0x8000_0000_0000_0004]));
    assert_eq!(data.len(), SEC);
    let i = run64(data);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: kernel32.dll truncated table at RVA {:#x}",
            b + SEC as u32
        )]
    );
    assert_eq!(i.imports[0].functions, vec![Name("Foo".into()), Ordinal(3), Ordinal(4)]);
}

/// (d) Five descriptors share one 60_000-thunk table, so the shared 200_000 budget runs out in
/// the fourth. Nothing beyond the budget is returned, and each table that hit the wall says so.
#[test]
fn shared_import_budget_stops_at_200_000_thunks() {
    const N: usize = 60_000;
    let b = base();
    let (name, hint, table) = (b + 120, b + 136, 144u32);
    let tail = Bytes::default().cstr(K32).pad_to(16).u16(0).cstr("A").pad_to(24).0;
    let mut data = imports_raw(&[(b + table, name, b + table); 5], &tail);
    data.extend(u64s(std::iter::repeat_n(u64::from(hint), N).chain([0])));
    let t = Instant::now();
    let i = run64(data);
    let took = t.elapsed();
    let total: usize = i.imports.iter().map(|m| m.functions.len()).sum();
    assert_eq!(total, 200_000);
    assert_eq!(i.imports.len(), 5);
    assert_eq!(
        i.warnings,
        [
            "imports: kernel32.dll budget exhausted at 20000 functions",
            "imports: kernel32.dll budget exhausted at 0 functions"
        ]
    );
    assert!(took < Duration::from_secs(5), "took {took:?}");
}

/// The bytes of all retained function names are budgeted (4 MiB) too: 5000 thunks sharing one
/// 1000-byte name would otherwise materialise 5 MB from a 40 KB file (and 200 MB at 200_000).
#[test]
fn imported_name_bytes_are_budgeted() {
    const N: usize = 5000;
    let b = base();
    let hint = b + 56; // hint/name entry 16 bytes into the tail, which starts at offset 40
    let tail = Bytes::default()
        .cstr(K32)
        .pad_to(16)
        .u16(0)
        .cstr(&"x".repeat(1000))
        .pad_to(1032)
        .0;
    let table = b + 40 + 1032;
    let mut data = imports_raw(&[(table, b + 40, table)], &tail);
    data.extend(u64s(std::iter::repeat_n(u64::from(hint), N).chain([0])));
    let i = run64(data);
    let kept = 4 * 1024 * 1024 / 1000;
    assert_eq!(i.imports[0].functions.len(), kept);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: kernel32.dll: {} names dropped, string budget exhausted (first at name RVA {:#x})",
            N - kept,
            hint + 2
        )]
    );
}

/// Thunks pointing at one huge NUL-free string must stay cheap: an unbounded scan would cost
/// ~196_605 x ~780 KB = 150 GB. Results are the same either way (too long), so assert wall time.
#[test]
fn many_thunks_pointing_at_one_huge_string_stay_cheap() {
    const N: usize = 65_535; // per table; three descriptors share it, all under the 200_000 budget
    let b = base();
    let tail_off = imports_tail_off(3);
    let table = 16usize;
    let huge = table + 4 * (N + 1);
    let hint = b + (tail_off + huge) as u32;
    let mut tail = Bytes::default().cstr(K32).pad_to(table).0;
    tail.extend(u32s(std::iter::repeat_n(hint, N).chain([0])));
    tail.resize(1024 * 1024 - tail_off, b'A'); // no NUL to the end of the section
    let t = b + (tail_off + table) as u32;
    let data = imports_raw(&[(t, b + tail_off as u32, t); 3], &tail);
    assert_eq!(data.len(), 1024 * 1024);
    let started = Instant::now();
    let i = run32(data);
    let took = started.elapsed();
    let expected = format!(
        "imports: kernel32.dll: {N} names too long (first at name RVA {:#x})",
        hint + 2
    );
    assert_eq!(i.warnings, [expected.clone(), expected.clone(), expected]);
    assert_eq!(i.imports.len(), 3);
    assert!(i.imports.iter().all(|m| m.functions.is_empty()));
    assert!(
        took < Duration::from_secs(5),
        "took {took:?}: name reads are not bounded"
    );
}

/// (e) A thunk table with 65_536 entries then a terminator is complete; one more entry is not.
#[test]
fn thunk_table_cap_warning_only_when_really_capped() {
    for (n, capped) in [(65_536usize, false), (65_537, true)] {
        let b = base();
        let tail = Bytes::default().cstr(K32).pad_to(16).0;
        let t = b + imports_tail_off(1) as u32 + 16;
        let mut data = imports_raw(&[(t, b + imports_tail_off(1) as u32, t)], &tail);
        data.extend(u32s(std::iter::repeat_n(0x8000_0001, n).chain([0])));
        let i = run32(data);
        let expected: Vec<String> = if capped {
            vec!["imports: kernel32.dll thunk table not terminated within 65536 entries".into()]
        } else {
            vec![]
        };
        assert_eq!(i.warnings, expected, "{n} thunks");
        assert_eq!(i.imports[0].functions.len(), 65_536, "{n} thunks");
    }
}

/// Descriptor limit for regular imports: 4096 are read; a 4097th is reported.
#[test]
fn import_descriptor_limit_boundary() {
    for (n, over) in [(4096usize, false), (4097, true)] {
        let b = base();
        let off = imports_tail_off(n);
        let name = b + off as u32;
        let t = b + off as u32 + 16;
        let mut tail = Bytes::default().cstr(K32).pad_to(16).0;
        tail.extend(u64s([0x8000_0000_0000_0001, 0]));
        let i = run64(imports_raw(&vec![(t, name, t); n], &tail));
        let expected: Vec<String> = if over {
            vec!["imports: descriptor limit (4096) exceeded".into()]
        } else {
            vec![]
        };
        assert_eq!(i.warnings, expected, "{n} descriptors");
        assert_eq!(i.imports.len(), 4096, "{n} descriptors");
    }
}

/// (f) Descriptor-level warnings carry the descriptor index and its RVA.
#[test]
fn unreadable_dll_name_names_descriptor_and_rva() {
    let b = base();
    let name = b + imports_tail_off(2) as u32;
    let table = name + 16;
    let mut tail = Bytes::default().cstr(K32).pad_to(16).0;
    tail.extend(u64s([0x8000_0000_0000_0001, 0]));
    let i = run64(imports_raw(&[(table, name, table), (table, 0x0900_0000, table)], &tail));
    assert_eq!(
        i.warnings,
        [format!(
            "imports: unreadable DLL name (descriptor 1, RVA {:#x})",
            b + 20
        )]
    );
    assert_eq!(i.imports.len(), 1);
}

/// DLL names are read through the same bounded reader as function names: too long, or running
/// off the end of the section with no NUL, is reported instead of copied.
#[test]
fn overlong_and_unterminated_dll_names_are_rejected() {
    let b = base();
    let off = imports_tail_off(1);
    let long = [imports_raw(&[(0x1234, b + off as u32, 0x1234)], &[]), vec![b'x'; 1500]].concat();
    let i = run64(long);
    assert_eq!(
        i.warnings,
        [format!("imports: DLL name too long (descriptor 0, RVA {b:#x})")]
    );
    assert!(i.imports.is_empty());

    let mut open = imports_raw(&[(0x1234, b + SEC as u32 - 10, 0x1234)], &[]);
    open.resize(SEC - 10, 0);
    open.extend([b'y'; 10]); // runs to the end of the section, no NUL
    let i = run64(open);
    assert_eq!(
        i.warnings,
        [format!("imports: unterminated DLL name (descriptor 0, RVA {b:#x})")]
    );
    assert!(i.imports.is_empty());
}

#[test]
fn unterminated_function_name_warns_and_continues() {
    let b = base();
    let tail_off = imports_tail_off(1);
    let table = b + tail_off as u32 + 16;
    let hint = SEC as u32 - 6; // u16 hint + "abcd", section ends with no NUL
    let mut data = imports_raw(
        &[(table, b + tail_off as u32, table)],
        &Bytes::default().cstr(K32).pad_to(16).0,
    );
    data.extend(u64s([u64::from(b + hint), 0x8000_0000_0000_0002, 0]));
    data.resize(SEC - 6, 0);
    data.extend(b"\0\0abcd");
    let i = run64(data);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: kernel32.dll: 1 names unterminated (first at name RVA {:#x})",
            b + hint + 2
        )]
    );
    assert_eq!(i.imports[0].functions, vec![Ordinal(2)]);
}

/// (g) An unreadable function name warns and the walk continues.
#[test]
fn unreadable_name_warns_and_continues() {
    let b = base();
    let tail_off = imports_tail_off(1);
    let table = b + tail_off as u32 + 16;
    let mut data = imports_raw(
        &[(table, b + tail_off as u32, table)],
        &Bytes::default().cstr(K32).pad_to(16).0,
    );
    data.extend(u32s([0xFFFF, 0x8000_0007, 0])); // bad by-name RVA, ordinal 7, terminator
    let i = run32(data);
    assert_eq!(
        i.warnings,
        ["imports: kernel32.dll: 1 names unreadable (first at name RVA 0x10001)"]
    );
    assert_eq!(i.imports[0].functions, vec![Ordinal(7)]);
}

/// (h) A 2000-byte function name is dropped with a warning, and the walk carries on.
#[test]
fn name_too_long_warns_and_continues() {
    let b = base();
    let tail_off = imports_tail_off(1);
    let table = b + tail_off as u32 + 16;
    let hint = b + tail_off as u32 + 32;
    let mut tail = Bytes::default().cstr(K32).pad_to(16).0;
    tail.extend(u32s([hint, 0x8000_0008, 0]));
    let mut data = imports_raw(&[(table, b + tail_off as u32, table)], &tail);
    data.resize(tail_off + 32, 0);
    data.extend([0, 0]);
    data.extend(vec![b'x'; 2000]);
    let i = run32(data);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: kernel32.dll: 1 names too long (first at name RVA {:#x})",
            hint + 2
        )]
    );
    assert_eq!(
        i.imports[0].functions,
        vec![Ordinal(8)],
        "must carry on after the long name"
    );
}

/// (i) PE32+ thunk values with bits above 31 (other than the ordinal flag) are rejected.
#[test]
fn pe64_thunk_overflow_warns() {
    let b = base();
    let tail_off = imports_tail_off(1);
    let table = b + tail_off as u32 + 16;
    let mut data = imports_raw(
        &[(table, b + tail_off as u32, table)],
        &Bytes::default().cstr(K32).pad_to(16).0,
    );
    data.extend(u64s([0x1_0000_1000, 0x8000_0000_0000_0009, 0]));
    let i = run64(data);
    assert_eq!(
        i.warnings,
        [format!(
            "imports: kernel32.dll: 1 thunk values overflow 31 bits (first at thunk RVA {table:#x})"
        )]
    );
    assert_eq!(i.imports[0].functions, vec![Ordinal(9)]);
}

/// Delay-import descriptors: `[attributes, DllNameRVA, module, IAT, INT, ..]` with a shared
/// one-ordinal INT.
fn delay_boundary_data(n: usize) -> Vec<u8> {
    let b = base();
    let name = b + delay_tail_off(n) as u32;
    let t = name + 16;
    let mut tail = Bytes::default().cstr("dxgi.dll").pad_to(16).0;
    tail.extend(u64s([0x8000_0000_0000_0007, 0]));
    delay_raw(&vec![[1, name, 0, t, t, 0, 0, 0]; n], &tail)
}

/// (j) 4096 descriptors plus a terminator are complete (no false "not terminated"); 4097 are not.
#[test]
fn delay_descriptor_boundaries() {
    for (n, imports, over) in [(4095usize, 4095usize, false), (4096, 4096, false), (4097, 4096, true)] {
        let i = run_delay(delay_boundary_data(n));
        let expected: Vec<String> = if over {
            vec!["delay imports: descriptor table not terminated within 4096 entries".into()]
        } else {
            vec![]
        };
        assert_eq!(i.warnings, expected, "{n} descriptors");
        assert_eq!(i.imports.len(), imports, "{n} descriptors");
        assert!(i.imports.iter().all(|m| m.delay && m.functions == [Ordinal(7)]));
    }
}

#[test]
fn delay_truncated_descriptor_names_index_and_rva() {
    let b = base();
    let table = b + 16;
    let mut data = Bytes::default().cstr("dxgi.dll").pad_to(16).0;
    data.extend(u64s([0x8000_0000_0000_0007, 0]));
    data.resize(SEC - 48, 0);
    data.extend(u32s([1, b, 0, table, table, 0, 0, 0])); // descriptor 0, complete
    data.extend([0xFF; 16]); // descriptor 1: only half is inside the section
    assert_eq!(data.len(), SEC);
    let i = analyze(
        &Builder::x64()
            .section(".didat", DATA_RW, data)
            .dir(13, b + SEC as u32 - 48, 64),
    );
    assert_eq!(
        i.warnings,
        [format!(
            "delay imports: truncated descriptor (descriptor 1, RVA {:#x})",
            b + SEC as u32 - 16
        )]
    );
    assert_eq!(i.imports.len(), 1);
}

#[test]
fn delay_va_based_descriptor_names_index_and_rva() {
    let b = base();
    let name = b + delay_tail_off(2) as u32;
    let table = name + 16;
    let mut tail = Bytes::default().cstr("dxgi.dll").pad_to(16).0;
    tail.extend(u64s([0x8000_0000_0000_0007, 0]));
    let i = run_delay(delay_raw(
        &[[1, name, 0, table, table, 0, 0, 0], [0, name, 0, table, table, 0, 0, 0]],
        &tail,
    ));
    assert_eq!(
        i.warnings,
        [format!(
            "delay imports: VA-based descriptor unsupported (descriptor 1, RVA {:#x})",
            b + 32
        )]
    );
    assert_eq!(i.imports.len(), 1);
}

#[test]
fn delay_bad_dll_names_name_index_and_rva() {
    let b = base();
    let name = b + delay_tail_off(3) as u32;
    let table = name + 1520;
    let mut tail = Bytes::default().cstr("dxgi.dll").pad_to(16).0;
    tail.extend(vec![b'x'; 1500]); // name at +16: 1500 bytes, then the (zero) padding NUL
    tail.resize(1520, 0);
    tail.extend(u64s([0x8000_0000_0000_0007, 0]));
    let i = run_delay(delay_raw(
        &[
            [1, name, 0, table, table, 0, 0, 0],
            [1, 0x0900_0000, 0, table, table, 0, 0, 0],
            [1, name + 16, 0, table, table, 0, 0, 0],
        ],
        &tail,
    ));
    assert_eq!(
        i.warnings,
        [
            format!("delay imports: unreadable DLL name (descriptor 1, RVA {:#x})", b + 32),
            format!("delay imports: DLL name too long (descriptor 2, RVA {:#x})", b + 64),
        ]
    );
    assert_eq!(i.imports.len(), 1);
}
