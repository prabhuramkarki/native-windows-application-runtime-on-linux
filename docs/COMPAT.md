# Compatibility matrix

<!-- Generated from crates/cli/compat.toml; do not edit by hand. Regenerate with:
     cargo run -q -p runtime-cli -- compat > docs/COMPAT.md -->

Each row is something that was really run: `ci:<job>` is a CI job run that passed, `manual:<date>` was run by
hand on that date on the recorded Wine and GPU. A program that is not listed has not been tested.

| App | Version | Status | Wine | GPU | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| hello64.exe (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | runtime install + run of a 64-bit console program: prints its greeting, exits 7 (e2e_mvp_loop_install_list_run_logs_doctor_remove). Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
| hello32.exe (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | runtime run of a 32-bit (WoW64) console program: prints its greeting, exits 7; app recorded as x86. Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
| fs64.exe (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | file probe: an app reads back what it wrote and a second app's prefix does not see it (e2e_a_second_app_cannot_see_the_first_apps_files); no Z: drive (e2e_hardening_is_visible_from_inside_the_app). Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
| hello-nsis.exe (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | NSIS installer run silently: installs, .desktop entry, program auto-discovered and run (exit 7); environment and .desktop entry removed by `runtime uninstall` (the NSIS uninstaller itself is not run). Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
| hello.msi (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | MSI installer run silently through msiexec: installs, .desktop entry, program run (exit 7), recorded msiexec uninstall run by `runtime uninstall` without warnings. Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
| exports64.dll in a zip/tar.gz package (fixture) | - | works | 10.0 (Ubuntu 10.0~repack-12ubuntu1) | - | manual:2026-09-26 | dependency archive install into system32, byte-identical, with a native,builtin DLL override set via reg.exe. Also run by the wine-e2e CI job (configured, not yet run on a hosted runner). |
