//! Tests against Windows binaries built by tools/build-fixtures.sh (needs mingw-w64).
use pe::{Arch, Format, ImportedFn, Kind, Subsystem};
use std::path::PathBuf;

fn bytes(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"))
}

fn load(name: &str) -> pe::PeInfo {
    pe::analyze(&bytes(name)).expect("analyze fixture")
}

#[test]
fn version_info_is_read_from_the_hello_fixture() {
    let v = load("hello64.exe").version.expect("VERSIONINFO resource");
    assert_eq!(v.file_version.as_deref(), Some("1.2.3.4"));
    assert_eq!(
        v.strings.get("ProductName").map(String::as_str),
        Some("Runtime Fixture")
    );
}

#[test]
fn hello64_is_a_console_x64_exe_importing_kernel32() {
    let i = load("hello64.exe");
    assert_eq!((i.format, i.arch, i.kind), (Format::Pe32Plus, Arch::X86_64, Kind::Exe));
    assert_eq!(i.subsystem, Subsystem::Console);
    let k32 = i
        .imports
        .iter()
        .find(|m| m.dll.eq_ignore_ascii_case("kernel32.dll"))
        .expect("kernel32 import");
    // Every mingw CRT startup installs an unhandled-exception filter.
    assert!(
        k32.functions
            .contains(&ImportedFn::Name("SetUnhandledExceptionFilter".into()))
    );
    // ...and registers TLS callbacks.
    assert!(i.tls.as_ref().is_some_and(|t| t.callback_count >= 1));
    // The build script passes --dynamicbase --nxcompat.
    assert!(i.aslr && i.nx);
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

#[test]
fn hello32_is_pe32_x86() {
    let i = load("hello32.exe");
    assert_eq!(
        (i.format, i.arch, i.subsystem),
        (Format::Pe32, Arch::X86, Subsystem::Console)
    );
}

#[test]
fn gui64_uses_the_gui_subsystem() {
    assert_eq!(load("gui64.exe").subsystem, Subsystem::Gui);
}

/// `tools/fixtures/hello.rc` declares `IDI_ICON1 ICON "icon.ico"` (Task 3: added so
/// `rt_desktop::icon`'s extraction has a real PE icon resource to test against, alongside its own
/// synthetic fixtures). `tools/fixtures/icon.ico` is a Pillow-generated 32x32 icon, which Pillow
/// happens to encode as a PNG stream (not a classic DIB) even at this size — real ICO files can
/// carry either, and `windres` accepts both.
#[test]
fn hello64_carries_the_icon_resource_added_for_task_3() {
    let bytes = bytes("hello64.exe");
    let entries = pe::find_group_icon(&bytes).unwrap().expect("group icon resource");
    assert_eq!(entries.len(), 1);
    let e = entries[0];
    assert_eq!((e.width, e.height), (32, 32));
    let data = pe::icon_bytes(&bytes, e.id)
        .unwrap()
        .expect("icon data for the group's own id");
    assert!(
        data.starts_with(b"\x89PNG"),
        "expected a PNG-in-ICO entry, got {:?}",
        &data[..data.len().min(8)]
    );
}

#[test]
fn exports64_dll_exports_add_and_mul_and_is_relocatable() {
    let i = load("exports64.dll");
    assert_eq!(i.kind, Kind::Dll);
    let names: Vec<_> = i.exports.iter().filter_map(|e| e.name.as_deref()).collect();
    assert!(names.contains(&"add") && names.contains(&"mul"), "{names:?}");
    assert!(i.relocation_count > 0);
    assert!(i.aslr);
}
