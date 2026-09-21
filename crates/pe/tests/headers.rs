mod common;
use common::*;
use pe::{Arch, Format, Kind, Subsystem};

#[test]
fn non_pe_input_is_rejected() {
    assert!(matches!(pe::analyze(b"hello"), Err(pe::Error::NotPe)));
}

#[test]
fn architecture_format_kind_subsystem() {
    let x64 = analyze(&Builder::x64());
    assert_eq!(
        (x64.format, x64.arch, x64.kind, x64.subsystem),
        (Format::Pe32Plus, Arch::X86_64, Kind::Exe, Subsystem::Console)
    );
    assert_eq!(x64.image_base, 0x1_4000_0000);
    assert!(x64.aslr && x64.nx);

    let x86 = analyze(&Builder::x86());
    assert_eq!((x86.format, x86.arch), (Format::Pe32, Arch::X86));

    let arm = analyze(&Builder {
        machine: 0xAA64,
        ..Builder::x64()
    });
    assert_eq!(arm.arch, Arch::Arm64);
    let ec = analyze(&Builder {
        machine: 0xA641,
        ..Builder::x64()
    });
    assert_eq!(ec.arch, Arch::Arm64Ec);

    let gui_dll = analyze(&Builder {
        dll: true,
        subsystem: 2,
        ..Builder::x64()
    });
    assert_eq!((gui_dll.kind, gui_dll.subsystem), (Kind::Dll, Subsystem::Gui));

    let driver = analyze(&Builder {
        subsystem: 1,
        ..Builder::x64()
    });
    assert_eq!(driver.subsystem, Subsystem::Native);
}

#[test]
fn sections_report_permissions() {
    let i = analyze(
        &Builder::x64()
            .section(".text", CODE_RX, vec![0xC3])
            .section(".data", DATA_RW, vec![0; 8]),
    );
    assert_eq!(i.sections.len(), 2);
    let text = &i.sections[0];
    assert_eq!(
        (text.name.as_str(), text.virtual_address, text.executable, text.writable),
        (".text", 0x1000, true, false)
    );
    let data = &i.sections[1];
    assert_eq!((data.executable, data.writable, data.readable), (false, true, true));
    assert_eq!(i.entry_point_rva, 0x1000);
}

#[test]
fn absent_tables_are_empty_not_errors() {
    let i = analyze(&Builder::x64());
    assert!(i.imports.is_empty() && i.exports.is_empty() && i.tls.is_none() && i.version.is_none());
    assert_eq!(i.relocation_count, 0);
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

#[test]
fn dotnet_is_detected_from_clr_directory() {
    let plain = analyze(&Builder::x86());
    assert!(!plain.dotnet);
    let managed = analyze(
        &Builder::x86()
            .section(".text", CODE_RX, vec![0; 72])
            .dir(14, Builder::rva(0), 72),
    );
    assert!(managed.dotnet);
}

#[test]
fn rejects_section_whose_file_offset_disagrees_with_rva() {
    let mut img = Builder::x64().section(".text", CODE_RX, vec![0xC3]).build();
    let raw_ptr_at = 0x44 + 20 + 240 + 20; // first section header, PointerToRawData
    img[raw_ptr_at..raw_ptr_at + 4].copy_from_slice(&0x404u32.to_le_bytes());
    assert!(matches!(pe::analyze(&img), Err(pe::Error::Malformed(_))));
}

#[test]
fn unaligned_input_slice_is_handled() {
    let img = Builder::x64().section(".text", CODE_RX, vec![0xC3]).build();
    let mut buf = vec![0u8; img.len() + 8];
    let off = (9 - buf.as_ptr() as usize % 8) % 8; // make the slice start at address % 8 == 1
    buf[off..off + img.len()].copy_from_slice(&img);
    let view = &buf[off..off + img.len()];
    assert_eq!(view.as_ptr() as usize % 8, 1);
    assert_eq!(pe::analyze(view).unwrap().arch, Arch::X86_64);
}
