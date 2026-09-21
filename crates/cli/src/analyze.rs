use pe::{FileKind, PeInfo, Subsystem};
use serde_json::json;
use std::{fmt::Write, path::Path};

pub fn run(file: &Path, as_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
    let kind = pe::detect(&bytes);
    tracing::debug!(target: "pe", ?kind, bytes = bytes.len(), "detected");
    let info = match kind {
        FileKind::Pe => Some(pe::analyze(&bytes)?),
        FileKind::Unknown => return Err("not a Windows binary or installer (unrecognised format)".into()),
        FileKind::Msi | FileKind::Zip => None,
    };
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "kind": kind, "pe": info }))?
        );
    } else {
        match &info {
            Some(i) => print!("{}", render(file, i)),
            None => println!("{}: {kind:?} package (not analysed further yet)", file.display()),
        }
    }
    Ok(())
}

fn render(file: &Path, i: &PeInfo) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "File:       {}", file.display());
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
        let _ = writeln!(o, "Version:    {}", v.file_version.as_deref().unwrap_or("?"));
        for k in ["ProductName", "CompanyName", "FileDescription"] {
            if let Some(s) = v.strings.get(k) {
                let _ = writeln!(o, "  {k}: {s}");
            }
        }
    }
    if let Some(inst) = &i.installer {
        let _ = writeln!(o, "Installer:  {:?} (marker: {})", inst.kind, inst.evidence);
    }
    let _ = writeln!(
        o,
        "Sections:   {}",
        i.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(" ")
    );
    let _ = writeln!(o, "Imports:");
    for imp in &i.imports {
        let delay = if imp.delay { " [delay]" } else { "" };
        let _ = writeln!(o, "  {} ({}){delay}", imp.dll, imp.functions.len());
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
        let _ = writeln!(o, "warning: {w}");
    }
    o
}
