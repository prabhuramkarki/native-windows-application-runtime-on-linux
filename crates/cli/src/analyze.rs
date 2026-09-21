use pe::{FileKind, PeInfo, Subsystem};
use serde_json::json;
use std::{fmt::Write, io, path::Path};

const CAP: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB

pub(crate) fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

pub fn run(file: &Path, as_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file_str = file.to_string_lossy().to_string();
    let file_handle = std::fs::File::open(file).map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    let metadata = file_handle
        .metadata()
        .map_err(|e| format!("{}: {e}", safe(&file_str)))?;
    if !metadata.is_file() {
        return Err(format!("{}: not a regular file", safe(&file_str)).into());
    }
    let mut bytes = Vec::new();
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

    let stdout = std::io::stdout();
    use std::io::Write;
    let mut stdout_locked = stdout.lock();

    if as_json {
        let json_out = serde_json::to_string_pretty(&json!({ "kind": kind, "pe": info }))?;
        if let Err(e) = writeln!(stdout_locked, "{}", json_out) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(Box::new(e));
        }
    } else {
        match &info {
            Some(i) => {
                let rendered = render(file, i);
                if let Err(e) = write!(stdout_locked, "{}", rendered) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(Box::new(e));
                }
            }
            None => {
                if let Err(e) = writeln!(
                    stdout_locked,
                    "{}: {kind:?} package (not analysed further yet)",
                    safe(&file_str)
                ) {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(Box::new(e));
                }
            }
        }
    }
    Ok(())
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
    fn safe_escapes_control_characters() {
        // ESC character (U+001B)
        assert!(!safe("\x1b]0;pwned\x07").contains('\x1b'));
        // Newline
        assert!(!safe("line1\nline2").contains('\n'));
        // Carriage return
        assert!(!safe("text\roverwrite").contains('\r'));
        // 8-bit CSI (U+009B)
        assert!(!safe("\u{9b}[31m").contains('\u{9b}'));
    }

    #[test]
    fn safe_escapes_bidi_overrides() {
        // Left-to-right override
        assert!(!safe("\u{202a}text").contains('\u{202a}'));
        // Right-to-left override
        assert!(!safe("\u{202b}text").contains('\u{202b}'));
        // Pop directional formatting
        assert!(!safe("\u{202c}text").contains('\u{202c}'));
        // Left-to-right isolate
        assert!(!safe("\u{2066}text").contains('\u{2066}'));
        // Right-to-left isolate
        assert!(!safe("\u{2067}text").contains('\u{2067}'));
        // First strong isolate
        assert!(!safe("\u{2068}text").contains('\u{2068}'));
        // Pop directional isolate
        assert!(!safe("\u{2069}text").contains('\u{2069}'));
    }

    #[test]
    fn safe_preserves_unicode() {
        assert_eq!(safe("Größe 日本語"), "Größe 日本語");
    }

    #[test]
    fn render_sanitizes_all_strings() {
        let hostile_string = "hostile\x1b]0;pwned\x07\n\r\u{9b}";
        let mut strings = BTreeMap::new();
        strings.insert("ProductName".to_string(), hostile_string.to_string());

        let info = PeInfo {
            format: Format::Pe32Plus,
            arch: Arch::X86_64,
            kind: Kind::Exe,
            subsystem: pe::Subsystem::Console,
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

        // Ensure no dangerous characters in output
        assert!(!rendered.contains('\x1b'), "ESC character found in output");
        assert!(!rendered.contains('\r'), "CR character found in output");
        assert!(!rendered.contains('\u{9b}'), "8-bit CSI found in output");
        assert!(!rendered.contains('\u{202a}'), "bidi override found in output");

        // Ensure no extra lines were injected
        let line_count = rendered.lines().count();
        // Expected: File, Format, Protection, .NET, Version, ProductName, Sections, Imports, Import dll, Exports, warning
        assert!(line_count < 20, "Too many lines, possible injection: {}", line_count);
    }
}
