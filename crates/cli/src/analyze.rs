use crate::safe::safe;
use pe::{FileKind, PeInfo, Subsystem};
use serde_json::json;
use std::{fmt::Write, io, path::Path};

const CAP: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB; ponytail: mmap if throughput becomes critical

pub fn run(file: &Path, as_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file_str = file.to_string_lossy().to_string();
    // Check file type before opening to avoid blocking on FIFOs
    let stat = std::fs::metadata(file).map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    if !stat.is_file() {
        return Err(format!("{}: not a regular file", safe(&file_str)).into());
    }
    let file_handle = std::fs::File::open(file).map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    // Re-check the opened handle: the path may have been swapped for a FIFO/device since the stat above.
    let opened = file_handle
        .metadata()
        .map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    if !opened.is_file() {
        return Err(format!("{}: not a regular file", safe(&file_str)).into());
    }
    // Pre-size to the file (capped) so read_to_end does not grow and copy a large buffer.
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len().min(CAP + 1)).unwrap_or(0));
    use std::io::Read;
    (&file_handle)
        .take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    if bytes.len() as u64 > CAP {
        return Err(format!("{}: file too large (> 4 GiB)", safe(&file_str)).into());
    }
    let kind = pe::detect(&bytes);
    tracing::debug!(target: "pe", ?kind, bytes = bytes.len(), "detected");
    let info = match kind {
        FileKind::Pe => Some(pe::analyze(&bytes)?),
        FileKind::Unknown => return Err("not a Windows binary or installer (unrecognised format)".into()),
        FileKind::Msi | FileKind::Zip => None,
    };

    let text = if as_json {
        format!(
            "{}\n",
            serde_json::to_string_pretty(&json!({ "kind": kind, "pe": info }))?
        )
    } else if let Some(i) = &info {
        render(file, i)
    } else {
        format!("{}: {kind:?} package (not analysed further yet)\n", safe(&file_str))
    };
    // A closed pipe (e.g. `| head`) is the reader's choice, not an error.
    use std::io::Write;
    match std::io::stdout().lock().write_all(text.as_bytes()) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}

fn render(file: &Path, i: &PeInfo) -> String {
    let mut o = String::new();
    let file_str = file.to_string_lossy().to_string();
    let _ = writeln!(o, "File:       {}", safe(&file_str));
    let _ = writeln!(
        o,
        "Format:     {:?} {:?} {:?} ({:?})",
        i.format, i.arch, i.kind, i.subsystem
    );
    let _ = writeln!(
        o,
        "Protection: ASLR={} NX={} signed={} (unverified)",
        i.aslr, i.nx, i.signed
    );
    let _ = writeln!(o, ".NET:       {}", i.dotnet);
    if let Some(v) = &i.version {
        let _ = writeln!(o, "Version:    {}", safe(v.file_version.as_deref().unwrap_or("?")));
        for k in ["ProductName", "CompanyName", "FileDescription"] {
            if let Some(s) = v.strings.get(k) {
                let _ = writeln!(o, "  {k}: {}", safe(s));
            }
        }
    }
    if let Some(inst) = &i.installer {
        let _ = writeln!(o, "Installer:  {:?} (marker: {})", inst.kind, safe(inst.evidence));
    }
    let _ = writeln!(
        o,
        "Sections:   {}",
        i.sections.iter().map(|s| safe(&s.name)).collect::<Vec<_>>().join(" ")
    );
    let _ = writeln!(o, "Imports:");
    for imp in &i.imports {
        let delay = if imp.delay { " [delay]" } else { "" };
        let _ = writeln!(o, "  {} ({}){delay}", safe(&imp.dll), imp.functions.len());
    }
    let _ = writeln!(
        o,
        "Exports:    {}   Relocations: {}   TLS callbacks: {}",
        i.exports.len(),
        i.relocation_count,
        i.tls.as_ref().map_or(0, |t| t.callback_count)
    );
    if i.subsystem == Subsystem::Native {
        let _ = writeln!(o, "UNSUPPORTED: kernel-mode driver");
    }
    for w in &i.warnings {
        let _ = writeln!(o, "warning: {}", safe(w));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use pe::{Arch, Format, Import, ImportedFn, Installer, InstallerKind, Kind, Section, VersionInfo};
    use std::collections::BTreeMap;

    #[test]
    fn render_names_unknown_arch_and_subsystem_with_their_raw_values() {
        let mut info = sample_info();
        info.arch = Arch::Other(0x01C4);
        info.machine = 0x01C4;
        info.subsystem = pe::Subsystem::Other(9);
        info.subsystem_raw = 9;
        let rendered = render(Path::new("x.exe"), &info);
        assert!(
            rendered.contains("Format:     Pe32Plus Other(452) Exe (Other(9))"),
            "{rendered}"
        );
    }

    fn sample_info() -> PeInfo {
        PeInfo {
            format: Format::Pe32Plus,
            arch: Arch::X86_64,
            machine: 0x8664,
            kind: Kind::Exe,
            subsystem: pe::Subsystem::Console,
            subsystem_raw: 3,
            image_base: 0x140000000,
            entry_point_rva: 0x1000,
            size_of_image: 0x10000,
            aslr: true,
            nx: true,
            signed: false,
            dotnet: false,
            sections: vec![],
            imports: vec![],
            exports: vec![],
            relocation_count: 0,
            tls: None,
            version: None,
            installer: None,
            warnings: vec![],
        }
    }

    #[test]
    fn render_sanitizes_all_strings() {
        let hostile_string = "hostile\x1b]0;pwned\x07\n\r\u{9b}\u{202e}\u{2067}";
        let mut strings = BTreeMap::new();
        strings.insert("ProductName".to_string(), hostile_string.to_string());
        strings.insert("FileDescription".to_string(), "Größe 日本語".to_string());

        let info = PeInfo {
            format: Format::Pe32Plus,
            arch: Arch::X86_64,
            machine: 0x8664,
            kind: Kind::Exe,
            subsystem: pe::Subsystem::Console,
            subsystem_raw: 3,
            image_base: 0x140000000,
            entry_point_rva: 0x1000,
            size_of_image: 0x10000,
            aslr: true,
            nx: true,
            signed: false,
            dotnet: false,
            sections: vec![Section {
                name: hostile_string.to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_size: 0x1000,
                readable: true,
                writable: false,
                executable: true,
            }],
            imports: vec![Import {
                dll: hostile_string.to_string(),
                delay: false,
                functions: vec![ImportedFn::Name("Function".to_string())],
            }],
            exports: vec![],
            relocation_count: 0,
            tls: None,
            version: Some(VersionInfo {
                file_version: Some(hostile_string.to_string()),
                strings,
            }),
            installer: Some(Installer {
                kind: InstallerKind::InnoSetup,
                evidence: hostile_string,
            }),
            warnings: vec![hostile_string.to_string()],
        };

        let rendered = render(Path::new(hostile_string), &info);

        // Ensure no dangerous characters or bidi controls in output
        assert!(!rendered.contains('\x1b'), "ESC character found in output");
        assert!(!rendered.contains('\r'), "CR character found in output");
        assert!(!rendered.contains('\u{9b}'), "8-bit CSI found in output");

        // Assert all bidi controls in range U+202A..U+202E / U+2066..U+2069 are escaped
        for c in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert!(
                !rendered.contains(c),
                "Bidi character U+{:04X} found in output",
                c as u32
            );
        }

        // Ensure ordinary Unicode survives
        assert!(
            rendered.contains("Größe 日本語"),
            "Unicode text was not preserved in output"
        );

        // Ensure no extra lines were injected (exact line count: File, Format, Protection,
        // .NET, Version, ProductName, FileDescription, Installer, Sections, Imports,
        // Import dll, Exports, warning = 13 lines)
        let line_count = rendered.lines().count();
        assert_eq!(
            line_count, 13,
            "Expected exactly 13 lines, got {}: {}",
            line_count, rendered
        );
    }
}
