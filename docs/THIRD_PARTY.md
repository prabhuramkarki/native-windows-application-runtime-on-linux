# Third-party inventory

## Rust crates linked into the runtime

| Crate | Licence | Used for | Notes |
|---|---|---|---|
| pelite 0.10 | MIT | PE parsing (`pe` crate) | Five hazards found by hostile-input testing, all guarded in our code (`crates/pe/src`): (1) `int()` rejects the 4-byte-aligned import lookup tables GNU ld emits: thunk arrays are walked by hand (`analyze.rs`). (2) Alignment is checked against the RVA, not the file offset: `analyze.rs::check_layout` rejects mismatched sections, and unaligned input is copied. (3) `VersionInfo` slices unchecked and panics on a crafted resource: replaced by our own parser (`version.rs`). (4) `resources()` dereferences a misaligned directory (SIGABRT in debug builds): `res_rva % 4` guard in `analyze.rs`. (5) The base-relocation block iterator never terminates on `SizeOfBlock` 0xFFFFFFFD..FF: own block walk in `analyze.rs`. Also: no delay-import support (handled by hand), unbounded `derva_c_str` (all strings go through `read_bounded`), and `ordinal_base()` truncates Base to u16 (we read the u32 field). |
| memchr | Unlicense OR MIT | Installer marker search; also the bounded NUL-terminated string reader (`read_bounded`) in `analyze.rs` | |
| serde, serde_json | MIT OR Apache-2.0 | Serialisation | |
| thiserror | MIT OR Apache-2.0 | Error types | |
| clap | MIT OR Apache-2.0 | CLI | |
| tracing, tracing-subscriber | MIT | Structured logging | |
| tempfile | MIT OR Apache-2.0 | Temporary directories in tests | Dev-dependency only (`runtime-core`); never linked into release binaries. |

This table lists direct dependencies only. `cargo deny` (see `deny.toml`) governs the whole transitive set and its licence allow-list. For example `unicode-ident` (pulled in by the proc-macro crates) is `(MIT OR Apache-2.0) AND Unicode-3.0`, which is why `Unicode-3.0` is in `deny.toml`.

## External components (run as separate processes, never linked)

| Component | Licence | Phase | Notes |
|---|---|---|---|
| Wine | LGPL-2.1-or-later | 2 | Invoked as a subprocess; keep the process boundary. |
| DXVK | zlib | 4 | Downloaded with user consent. |
| VKD3D-Proton | LGPL-2.1 | 4 | Downloaded with user consent. |
| FEX-Emu, Box64 | MIT | 9 | CPU translation backends. |
| Mesa | MIT | - | System dependency. |

Rule: never copy Wine or ReactOS source into this project unless the project licence is chosen accordingly (open decision in the roadmap).
