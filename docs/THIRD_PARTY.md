# Third-party inventory

## Rust crates linked into the runtime

| Crate | Licence | Used for | Notes |
|---|---|---|---|
| pelite 0.10 | MIT | PE parsing (`pe` crate) | Alignment is checked against the RVA, not the file offset (found by mutation testing); guarded in `crates/pe/src/analyze.rs::check_layout`. No delay-import support and `int()` rejects 4-byte-aligned thunk tables: both handled in our code. |
| memchr | Unlicense OR MIT | Installer marker search | |
| serde, serde_json | MIT OR Apache-2.0 | Serialisation | |
| thiserror | MIT OR Apache-2.0 | Error types | |
| clap | MIT OR Apache-2.0 | CLI | |
| tracing, tracing-subscriber | MIT | Structured logging | |

## External components (run as separate processes, never linked)

| Component | Licence | Phase | Notes |
|---|---|---|---|
| Wine | LGPL-2.1-or-later | 2 | Invoked as a subprocess; keep the process boundary. |
| DXVK | zlib | 4 | Downloaded with user consent. |
| VKD3D-Proton | LGPL-2.1 | 4 | Downloaded with user consent. |
| FEX-Emu, Box64 | MIT | 9 | CPU translation backends. |
| Mesa | MIT | - | System dependency. |

Rule: never copy Wine or ReactOS source into this project unless the project licence is chosen accordingly (open decision in the roadmap).
