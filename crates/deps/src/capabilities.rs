//! Import-to-capability table: which PE imports mean an app needs a package from the manifest.
//!
//! Keys are normalised import names (ASCII-lowercase, no trailing `.dll`); values are capability names as they
//! appear in a manifest package's `provides`. Anything not listed maps to nothing: most DLLs an app imports are
//! Wine builtins that need no package, so an unknown import is never an error.

/// `(import, capability)`, strictly sorted by import (a test checks), so lookup is a binary search.
pub const TABLE: &[(&str, &str)] = &[
    // Visual C++ 2015-2022 redistributable DLLs (what the x64 Minimum and Additional runtime MSIs of `vc_redist`
    // 14.44 install): Wine's builtins, where they exist, are partial. Provided by the bundled `vcrun2022`.
    ("concrt140", "concrt140"),
    // DXVK 2.x/3.x ships no d3d10.dll/d3d10_1.dll; Wine's builtin d3d10 and d3d10_1 sit on d3d10core, which DXVK
    // replaces, so both need DXVK's d3d10core.
    ("d3d10", "d3d10core"),
    ("d3d10_1", "d3d10core"),
    ("d3d10core", "d3d10core"),
    // Direct3D 11 and 9 and DXGI: provided by DXVK.
    ("d3d11", "d3d11"),
    // Direct3D 12: VKD3D-Proton would provide it, but it ships only .tar.zst (unsupported), so no bundled package
    // provides `d3d12` yet and it resolves to nothing, like `dotnet`.
    ("d3d12", "d3d12"),
    // Direct3D 8 (DXVK 2.4+ ships d3d8 on top of its d3d9).
    ("d3d8", "d3d8"),
    ("d3d9", "d3d9"),
    ("dxgi", "dxgi"),
    ("mfc140", "mfc140"),
    ("mfc140u", "mfc140u"),
    ("mfcm140", "mfcm140"),
    ("mfcm140u", "mfcm140u"),
    // The .NET Framework loader: every managed executable imports mscoree. No package provides `dotnet` yet, so
    // this resolves to nothing until one is added.
    ("mscoree", "dotnet"),
    ("msvcp140", "msvcp140"),
    ("msvcp140_1", "msvcp140_1"),
    ("msvcp140_2", "msvcp140_2"),
    ("msvcp140_atomic_wait", "msvcp140_atomic_wait"),
    ("msvcp140_codecvt_ids", "msvcp140_codecvt_ids"),
    ("vcamp140", "vcamp140"),
    ("vccorlib140", "vccorlib140"),
    ("vcomp140", "vcomp140"),
    ("vcruntime140", "vcruntime140"),
    ("vcruntime140_1", "vcruntime140_1"),
    ("vcruntime140_threads", "vcruntime140_threads"),
];

/// Longest import name worth normalising; anything longer cannot be in the table (bounds work on hostile input).
const MAX_IMPORT_LEN: usize = 64;

/// The capability an imported DLL needs, if any. `D3D11.DLL`, `d3d11.dll` and `d3d11` all give `d3d11`.
pub fn capability_for(import: &str) -> Option<&'static str> {
    if import.len() > MAX_IMPORT_LEN {
        return None;
    }
    let lower = import.to_ascii_lowercase();
    let base = lower.strip_suffix(".dll").unwrap_or(&lower);
    TABLE.binary_search_by(|(k, _)| (*k).cmp(base)).ok().map(|i| TABLE[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Manifest;

    #[test]
    fn table_is_strictly_sorted_lowercase_base_names() {
        assert!(TABLE.windows(2).all(|w| w[0].0 < w[1].0), "unsorted or duplicate key");
        for (k, v) in TABLE {
            assert!(
                !k.is_empty() && !k.ends_with(".dll") && *k == k.to_ascii_lowercase(),
                "{k}"
            );
            assert!(
                !v.is_empty() && !v.ends_with(".dll") && *v == v.to_ascii_lowercase(),
                "{v}"
            );
        }
    }

    #[test]
    fn table_and_bundled_provides_agree() {
        let m = Manifest::bundled();
        // Known gaps (Task 8 report): no bundled .NET; VKD3D-Proton ships only .tar.zst.
        let unprovided = ["dotnet", "d3d12"];
        for (_, cap) in TABLE.iter().filter(|(_, c)| !unprovided.contains(c)) {
            assert!(
                m.packages.iter().any(|p| p.provides.iter().any(|x| x == cap)),
                "{cap} has no provider"
            );
        }
        for p in &m.packages {
            for name in &p.provides {
                assert!(
                    TABLE.iter().any(|(_, c)| c == name),
                    "{}: {name} is not in the table",
                    p.id
                );
                assert!(
                    !unprovided.contains(&name.as_str()),
                    "{name} is provided now: update the test"
                );
            }
        }
    }

    #[test]
    fn lookup_normalises_and_ignores_unknown() {
        for name in ["d3d11", "d3d11.dll", "D3D11.DLL", "D3d11.Dll"] {
            assert_eq!(capability_for(name), Some("d3d11"), "{name}");
        }
        assert_eq!(capability_for("d3d10.dll"), Some("d3d10core"));
        assert_eq!(capability_for("MSCOREE.dll"), Some("dotnet"));
        let long = "d".repeat(100_000);
        for name in [
            "",
            ".dll",
            "kernel32.dll",
            "d3d11.dll.dll",
            "d3d11\0",
            "\u{e9}d3d11",
            " d3d11",
            &long,
        ] {
            assert_eq!(capability_for(name), None, "{name:?}");
        }
    }
}
