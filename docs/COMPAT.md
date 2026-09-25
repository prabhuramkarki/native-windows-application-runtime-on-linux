# Compatibility matrix

<!-- Generated from crates/cli/compat.toml; do not edit by hand. Regenerate with:
     cargo run -q -p runtime-cli -- compat > docs/COMPAT.md -->

Each row is something that was really run: `ci:<job>` is a CI job that ran it, `manual:<date>` a person on that
day. A program that is not listed has not been tested.

| App | Version | Status | Wine | GPU | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| hello64.exe (fixture) | - | works | 10.0 | - | ci:wine-e2e | runtime install + run of a 64-bit console program: prints its greeting, exits 7 (e2e_mvp_loop) |
| hello32.exe (fixture) | - | works | 10.0 | - | ci:wine-e2e | runtime run of a 32-bit (WoW64) console program: prints its greeting, exits 7; app recorded as x86 |
| fs64.exe (fixture) | - | works | 10.0 | - | ci:wine-e2e | file probe: an app reads back what it wrote, a second app's prefix does not see it, no Z: drive |
| hello-nsis.exe (fixture) | - | works | 10.0 | - | ci:wine-e2e | NSIS installer run silently: installs, .desktop entry, program auto-discovered and run (exit 7), uninstalled |
| hello.msi (fixture) | - | works | 10.0 | - | ci:wine-e2e | MSI installer run silently through msiexec: installs, .desktop entry, program run (exit 7), uninstalled |
| exports64.dll in a zip/tar.gz package (fixture) | - | works | 10.0 | - | ci:wine-e2e | dependency archive install into system32, byte-identical, with a native,builtin DLL override set via reg.exe |
