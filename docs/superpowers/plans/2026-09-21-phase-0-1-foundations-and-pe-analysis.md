# Phase 0 + 1: Foundations and PE Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust workspace with a robust, header-based PE analysis library (`pe` crate) and a `runtime analyze <file> [--json]` command, proven against synthetic images, mingw-built fixtures and real-world binaries.

**Architecture:** `pe` wraps the `pelite` parser behind our own model types (`PeInfo`, `Import`, `Export`, ...) so a future native loader (Phase 8) is not coupled to a third-party API. The three things `pelite` cannot do safely (delay-imports, unaligned import thunks, alignment on hostile files) are handled in our layer. Detection is header-based only; file extensions are never consulted. `cli` is a thin `clap` front end.

**Tech Stack:** Rust 2024 (stable), `pelite` 0.10, `memchr`, `serde`/`serde_json`, `thiserror`, `clap`, `tracing`; mingw-w64 (C) for Windows test fixtures; `file(1)` as an independent oracle.

**Spec:** Master prompt (§6, §32-34, §36 Stage 1, §48) and roadmap `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` (Phases 0-1).

## Global Constraints

- Never require root; no global host modification (§47, §50.5-6).
- Do not rely on file extensions: detect formats from headers (§6).
- The PE parser is a security boundary: it is fed untrusted installers. It must never panic on any input.
- Do not claim compatibility without testing (§35). `warnings` are reported, never swallowed.
- Keep `docs/THIRD_PARTY.md` current in the same commit as any new dependency (§40, §50.13).
- Every task ends with green `cargo test`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check`.

## Deviations from the roadmap (deliberate)

| Roadmap said | This plan does | Why |
|---|---|---|
| `cargo fuzz` on the parser | 30,000-iteration deterministic mutation test (Task 9) | cargo-fuzz needs nightly. The mutation test already found a real `pelite` soundness bug during planning. Add a fuzz target later once CI has nightly. |
| Resources: version info, icons, manifest | Version info only | Icon extraction has no consumer until Phase 3 (`.desktop` generation). |
| Shared logging module for §33 categories | `tracing` with `target: "pe"` used directly | One crate logs today; extract a shared module in Phase 2 when `core` exists. |
| ADR files for D1-D8 | Roadmap section 1 is the record | Avoid duplicated documents. |

## Findings from planning (why the code looks the way it does)

These were found by running the code against 24 real Windows binaries on the author's machine (x86, x64, ARM64, installers, MSVC and mingw builds) and by mutation testing:

1. **`pelite`'s `int()` rejects mingw x64 import tables** ("address misaligned", 0 functions reported) because GNU ld emits 4-byte-aligned thunk arrays. We walk thunks ourselves with unaligned reads.
2. **`pelite` has no delay-import support.** Delay-loaded `d3d12.dll`/`dxgi.dll` are exactly what Phase 4 needs for graphics detection, so we parse `IMAGE_DELAYLOAD_DESCRIPTOR` by hand.
3. **`pelite` checks alignment against the RVA, not the real file offset.** A hostile section table makes it return misaligned references (UB; Rust 1.98 debug builds abort). `check_layout` rejects such images, and `Aligned` copies unaligned caller buffers.
4. **mingw binaries do not import `ExitProcess`**, so fixture tests assert `SetUnhandledExceptionFilter` instead.

## Verification status of this plan

Everything below was executed in a scratch copy of the final tree on Ubuntu with mingw-w64 13 (GCC 13-win32) and Wine 10.0:

- **Replay:** each task's tests fail before its implementation and pass after; clippy `-D warnings` is clean at every stage; the final tree passes rustfmt. The edits in Tasks 5-8 reproduce the final `analyze.rs` byte-for-byte.
- **Fixtures:** `tools/build-fixtures.sh` builds all six binaries; `file(1)` reports the expected PE32/PE32+, console/GUI/DLL, x86/x86-64; `wine hello64.exe` prints `hello from windows` and exits 7.
- **All 23 tests in the final workspace pass**, including the fixture-based assertions in Tasks 8, 10 and 11 and the 30,000-iteration corruption test.
- **Real binaries:** the oracle test matched `file(1)` on 24/24 PE files (x86, x64, ARM64, MSVC and mingw builds, one real installer), with no parse warnings.
- **Not executed:** `cargo-deny` and the GitHub workflow (CI runs them on first push).

## File Structure

```text
Cargo.toml  rust-toolchain.toml  rustfmt.toml  deny.toml  .gitignore
.github/workflows/ci.yml
docs/THIRD_PARTY.md
tools/build-fixtures.sh
tools/fixtures/{hello.c,hello.rc,gui.c,exports.c}
tests/fixtures/build/            (generated, gitignored)
crates/pe/
  Cargo.toml
  src/lib.rs        re-exports + Error
  src/model.rs      PeInfo and friends (plain serialisable data)
  src/detect.rs     FileKind + detect(): PE / MSI(OLE) / ZIP by header
  src/analyze.rs    analyze(): safety guards + one macro stamped out for PE32 and PE32+
  src/installer.rs  installer-family markers (heuristic, evidence reported)
  tests/common/mod.rs   synthetic PE builder + table layouts
  tests/{detect,headers,imports,exports,relocs_tls,meta,robust,fixtures,real_world}.rs
crates/cli/
  Cargo.toml
  src/main.rs       clap + tracing init
  src/analyze.rs    `runtime analyze`
  tests/analyze.rs
```

---
## Task 1: Workspace, tooling, CI and licence inventory

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `.gitignore`, `.github/workflows/ci.yml`, `docs/THIRD_PARTY.md`
- Create: `crates/pe/Cargo.toml`, `crates/pe/src/lib.rs`, `crates/cli/Cargo.toml`, `crates/cli/src/main.rs`

**Interfaces:**
- Produces: a buildable workspace with binary `runtime` (package `runtime-cli`) and library `pe` (package `runtime-pe`). Later tasks add source files only.

- [ ] **Step 1: Initialise git** (the directory is not a repository yet)

```bash
cd /home/prabhuram/Desktop/personal-projects/native-windows-application-runtime-on-linux
git init -b main
```

- [ ] **Step 2: Write the workspace files**

`Cargo.toml`:

```toml
[workspace]
resolver = "3"
members = ["crates/*"]

[workspace.package]
version = "0.0.1"
edition = "2024"
publish = false

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`rustfmt.toml`:

```toml
max_width = 120
```

`.gitignore`:

```text
/target
/tests/fixtures/build/
.remember/
```

`crates/pe/Cargo.toml` (all `pe` dependencies declared up front; later tasks only add code):

```toml
[package]
name = "runtime-pe"
version.workspace = true
edition.workspace = true
publish.workspace = true

[lib]
name = "pe"

[dependencies]
pelite = "0.10"
memchr = "2"
serde.workspace = true
thiserror.workspace = true
```

`crates/pe/src/lib.rs`:

```rust
//! Header-based analysis of Windows binaries. Never trusts file extensions.
```

`crates/cli/Cargo.toml`:

```toml
[package]
name = "runtime-cli"
version.workspace = true
edition.workspace = true
publish.workspace = true

[[bin]]
name = "runtime"
path = "src/main.rs"

[dependencies]
runtime-pe = { path = "../pe" }
clap = { version = "4", features = ["derive"] }
serde_json.workspace = true
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

`crates/cli/src/main.rs`:

```rust
fn main() {}
```

- [ ] **Step 3: Write CI, licence policy and inventory**

`.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: sudo apt-get update && sudo apt-get install -y mingw-w64
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - run: tools/build-fixtures.sh
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

`deny.toml` (project licence is undecided, so workspace crates are treated as private):

```toml
[graph]
targets = ["x86_64-unknown-linux-gnu"]

[licenses]
allow = ["MIT", "Apache-2.0", "Unicode-3.0"]

[licenses.private]
ignore = true

[bans]
multiple-versions = "warn"
```

`docs/THIRD_PARTY.md`:

```markdown
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
```

- [ ] **Step 4: Verify the workspace builds and is clean**

Run: `cargo build --workspace && cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all succeed; `running 0 tests`. If `cargo fmt --check` complains about the two stub files, run `cargo fmt --all`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore: cargo workspace, CI, licence inventory"
```

---
## Task 2: Windows test fixtures (mingw-w64)

**Files:**
- Create: `tools/fixtures/hello.c`, `tools/fixtures/hello.rc`, `tools/fixtures/gui.c`, `tools/fixtures/exports.c`, `tools/build-fixtures.sh`

**Interfaces:**
- Produces: `tests/fixtures/build/{hello,gui,exports}{64,32}.{exe,dll}`: `hello64.exe`, `hello32.exe`, `gui64.exe`, `gui32.exe`, `exports64.dll`, `exports32.dll`. `hello*.exe` exits with code 7 and prints `hello from windows` (Phase 2 reuses it), and carries a VERSIONINFO resource (`ProductName` = "Runtime Fixture", version 1.2.3.4). All are linked with `--dynamicbase --nxcompat`.

- [ ] **Step 1: Install host tools** (needs your sudo; type it in the prompt with the `!` prefix)

```text
! sudo apt install mingw-w64 wine vulkan-tools
```

Verify: `x86_64-w64-mingw32-gcc --version` and `i686-w64-mingw32-gcc --version` both print a version.

- [ ] **Step 2: Write the fixture sources**

`tools/fixtures/hello.c`:

```c
#include <stdio.h>
int main(void) {
    puts("hello from windows");
    return 7; /* non-zero on purpose: Phase 2 tests exit-code propagation */
}
```

`tools/fixtures/hello.rc`:

```c
#include <windows.h>
VS_VERSION_INFO VERSIONINFO
FILEVERSION 1,2,3,4
PRODUCTVERSION 1,2,3,4
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "FileVersion", "1.2.3.4"
      VALUE "ProductName", "Runtime Fixture"
      VALUE "FileDescription", "hello fixture"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 1200
  END
END
```

`tools/fixtures/gui.c`:

```c
#include <windows.h>
int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    MessageBoxA(NULL, "hello", "fixture", MB_OK);
    return 0;
}
```

`tools/fixtures/exports.c`:

```c
#include <windows.h>
__declspec(dllexport) int add(int a, int b) { return a + b; }
__declspec(dllexport) int mul(int a, int b) { return a * b; }
BOOL WINAPI DllMain(HINSTANCE i, DWORD reason, LPVOID reserved) { return TRUE; }
```

`tools/build-fixtures.sh` (then `chmod +x tools/build-fixtures.sh`):

```sh
#!/bin/sh
# Builds Windows test executables into tests/fixtures/build/ (gitignored). Needs mingw-w64.
set -eu
cd "$(dirname "$0")/.."
out=tests/fixtures/build
mkdir -p "$out"
for arch in x86_64 i686; do
  tag=64; [ "$arch" = i686 ] && tag=32
  cc="$arch-w64-mingw32-gcc"; rc="$arch-w64-mingw32-windres"
  command -v "$cc" >/dev/null || { echo "missing $cc: sudo apt install mingw-w64" >&2; exit 1; }
  flags="-O1 -Wall -Wl,--dynamicbase -Wl,--nxcompat"
  "$rc" -i tools/fixtures/hello.rc -O coff -o "$out/hello$tag.res.o"
  "$cc" $flags -o "$out/hello$tag.exe" tools/fixtures/hello.c "$out/hello$tag.res.o"
  "$cc" $flags -mwindows -o "$out/gui$tag.exe" tools/fixtures/gui.c
  "$cc" $flags -shared -o "$out/exports$tag.dll" tools/fixtures/exports.c
  rm -f "$out/hello$tag.res.o"
done
ls -l "$out"
```

- [ ] **Step 3: Build and inspect**

Run: `tools/build-fixtures.sh && file tests/fixtures/build/*`
Expected: six files; `file` reports:
`exports32.dll` PE32 ... (DLL) ... Intel 80386, `exports64.dll` PE32+ ... (DLL) ... x86-64, `gui*.exe` ... (GUI), `hello*.exe` ... (console).

- [ ] **Step 4: (manual Phase 0 exit check) run a fixture under Wine**

Run: `wine tests/fixtures/build/hello64.exe; echo exit=$?`
Expected: prints `hello from windows` then `exit=7`. (First run creates `~/.wine`; that is fine for this manual check only. Phase 2 uses isolated prefixes.)

- [ ] **Step 5: Commit**

```bash
git add tools && git commit -m "test: mingw-built Windows fixtures"
```

---
## Task 3: `pe` types and header-based format detection

**Files:**
- Create: `crates/pe/src/model.rs`, `crates/pe/src/detect.rs`, `crates/pe/tests/common/mod.rs`, `crates/pe/tests/detect.rs`
- Modify: `crates/pe/src/lib.rs`

**Interfaces:**
- Produces (used by every later task):
  - `pe::FileKind { Pe, Msi, Zip, Unknown }`, `pe::detect(&[u8]) -> FileKind`
  - `pe::Error { NotPe, Malformed(String) }`
  - All model types in `model.rs` (`PeInfo`, `Format`, `Arch`, `Kind`, `Subsystem`, `Section`, `Import`, `ImportedFn`, `Export`, `Tls`, `VersionInfo`, `Installer`, `InstallerKind`)
  - Test-only: `common::Builder` (synthetic PE images), `common::Bytes` (table assembler), constants `DATA_R`, `DATA_RW`, `CODE_RX`

- [ ] **Step 1: Write the synthetic PE builder** (lets unit tests craft exact layouts with no Windows toolchain)

`crates/pe/tests/common/mod.rs`:

```rust
//! Synthetic PE builder: lets unit tests craft exact header/table layouts without a Windows
//! toolchain. Layout: 0x400 bytes of headers, then one 0x1000-aligned section per entry.
#![allow(dead_code)]

pub const DATA_R: u32 = 0x4000_0040; // initialised data, readable
pub const DATA_RW: u32 = 0xC000_0040;
pub const CODE_RX: u32 = 0x6000_0020;

pub struct Builder {
    pub pe32plus: bool,
    pub machine: u16,
    pub dll: bool,
    pub subsystem: u16,
    pub sections: Vec<(&'static str, u32, Vec<u8>)>,
    /// (data directory index, rva, size)
    pub dirs: Vec<(usize, u32, u32)>,
    pub overlay: Vec<u8>,
}

impl Builder {
    pub fn x64() -> Self {
        Self {
            pe32plus: true,
            machine: 0x8664,
            dll: false,
            subsystem: 3,
            sections: vec![],
            dirs: vec![],
            overlay: vec![],
        }
    }
    pub fn x86() -> Self {
        Self {
            pe32plus: false,
            machine: 0x014C,
            ..Self::x64()
        }
    }
    /// RVA of the nth section.
    pub fn rva(index: usize) -> u32 {
        0x1000 * (index as u32 + 1)
    }
    pub fn section(mut self, name: &'static str, chars: u32, data: Vec<u8>) -> Self {
        self.sections.push((name, chars, data));
        self
    }
    pub fn dir(mut self, index: usize, rva: u32, size: u32) -> Self {
        self.dirs.push((index, rva, size));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let opt_size = if self.pe32plus { 240 } else { 224 };
        let mut out = vec![0u8; 0x400];
        out[..2].copy_from_slice(b"MZ");
        put32(&mut out, 0x3C, 0x40);
        out[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        put16(&mut out, fh, self.machine);
        put16(&mut out, fh + 2, self.sections.len() as u16);
        put16(&mut out, fh + 16, opt_size);
        let mut chars = 0x0002 | if self.pe32plus { 0x0020 } else { 0x0100 };
        if self.dll {
            chars |= 0x2000;
        }
        put16(&mut out, fh + 18, chars);
        let oh = fh + 20;
        put16(&mut out, oh, if self.pe32plus { 0x20B } else { 0x10B });
        if !self.sections.is_empty() {
            put32(&mut out, oh + 16, Self::rva(0)); // entry point
        }
        if self.pe32plus {
            put64(&mut out, oh + 24, 0x1_4000_0000);
        } else {
            put32(&mut out, oh + 28, 0x40_0000);
        }
        put32(&mut out, oh + 32, 0x1000); // section alignment
        put32(&mut out, oh + 36, 0x200); // file alignment
        put32(&mut out, oh + 56, Self::rva(self.sections.len())); // size of image
        put32(&mut out, oh + 60, 0x400); // size of headers
        put16(&mut out, oh + 68, self.subsystem);
        put16(&mut out, oh + 70, 0x0140); // DYNAMIC_BASE | NX_COMPAT
        let (num_dirs, dirs) = if self.pe32plus {
            (oh + 108, oh + 112)
        } else {
            (oh + 92, oh + 96)
        };
        put32(&mut out, num_dirs, 16);
        for &(i, rva, size) in &self.dirs {
            put32(&mut out, dirs + i * 8, rva);
            put32(&mut out, dirs + i * 8 + 4, size);
        }
        let mut sh = oh + opt_size as usize;
        for (i, (name, chars, data)) in self.sections.iter().enumerate() {
            let raw_ptr = out.len() as u32;
            out[sh..sh + name.len()].copy_from_slice(name.as_bytes());
            put32(&mut out, sh + 8, data.len() as u32); // virtual size
            put32(&mut out, sh + 12, Self::rva(i));
            put32(&mut out, sh + 16, data.len().div_ceil(0x200) as u32 * 0x200);
            put32(&mut out, sh + 20, raw_ptr);
            put32(&mut out, sh + 36, *chars);
            sh += 40;
            out.extend_from_slice(data);
            out.resize(out.len().next_multiple_of(0x200), 0);
        }
        out.extend_from_slice(&self.overlay);
        out
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Little-endian byte assembler for hand-laid table data.
#[derive(Default)]
pub struct Bytes(pub Vec<u8>);
impl Bytes {
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn cstr(mut self, s: &str) -> Self {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
    /// Zero-pad up to absolute offset `at` within the section.
    pub fn pad_to(mut self, at: usize) -> Self {
        assert!(self.0.len() <= at, "layout overlap at {at}");
        self.0.resize(at, 0);
        self
    }
}
```

- [ ] **Step 2: Write the failing test**

`crates/pe/tests/detect.rs`:

```rust
mod common;
use common::*;
use pe::FileKind;

#[test]
fn detects_formats_by_header_not_extension() {
    assert_eq!(pe::detect(&Builder::x64().build()), FileKind::Pe);
    assert_eq!(
        pe::detect(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0, 0]),
        FileKind::Msi
    );
    assert_eq!(pe::detect(b"PK\x03\x04rest"), FileKind::Zip);
    assert_eq!(pe::detect(b"#!/bin/sh\n"), FileKind::Unknown);
    assert_eq!(pe::detect(b""), FileKind::Unknown);
    // "MZ" alone, or an e_lfanew pointing outside the file, is not a PE.
    assert_eq!(pe::detect(b"MZ"), FileKind::Unknown);
    let mut lying = Builder::x64().build();
    lying[0x3C..0x40].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(pe::detect(&lying), FileKind::Unknown);
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p runtime-pe --test detect`
Expected: FAIL: compile errors `unresolved import pe::FileKind`, `cannot find function detect in crate pe`.

- [ ] **Step 4: Write the model, detection and lib**

`crates/pe/src/model.rs`:

```rust
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe32,
    Pe32Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm64,
    Arm64Ec,
    Other(u16),
}

impl Arch {
    pub fn from_machine(m: u16) -> Self {
        match m {
            0x014C => Arch::X86,
            0x8664 => Arch::X86_64,
            0xAA64 => Arch::Arm64,
            0xA641 => Arch::Arm64Ec,
            other => Arch::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Exe,
    Dll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Subsystem {
    /// Kernel-mode drivers use this. Unsupported (master prompt §29).
    Native,
    Gui,
    Console,
    Efi,
    Other(u16),
}

impl Subsystem {
    pub fn from_raw(v: u16) -> Self {
        match v {
            1 => Subsystem::Native,
            2 => Subsystem::Gui,
            3 => Subsystem::Console,
            10 => Subsystem::Efi,
            other => Subsystem::Other(other),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedFn {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub dll: String,
    /// True for delay-load imports (resolved on first call, not at load).
    pub delay: bool,
    pub functions: Vec<ImportedFn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u32,
    /// `DLL.Function` when the export forwards to another module.
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tls {
    pub callback_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    /// ProductName, CompanyName, FileDescription, ...
    pub strings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    InnoSetup,
    Nsis,
    InstallShield,
    WixBurn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Installer {
    pub kind: InstallerKind,
    /// The marker that matched. Heuristic, not proof.
    pub evidence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub format: Format,
    pub arch: Arch,
    pub kind: Kind,
    pub subsystem: Subsystem,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub aslr: bool,
    pub nx: bool,
    /// An Authenticode blob is present. NOT verified.
    pub signed: bool,
    pub dotnet: bool,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocation_count: usize,
    pub tls: Option<Tls>,
    pub version: Option<VersionInfo>,
    pub installer: Option<Installer>,
    /// Tables that exist but failed to parse. Analysis continues past them.
    pub warnings: Vec<String>,
}
```

`crates/pe/src/detect.rs`:

```rust
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Pe,
    /// OLE2 compound file: MSI packages (and legacy Office files; refine when needed).
    Msi,
    Zip,
    Unknown,
}

const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

pub fn detect(bytes: &[u8]) -> FileKind {
    if is_pe(bytes) {
        FileKind::Pe
    } else if bytes.starts_with(OLE_MAGIC) {
        FileKind::Msi
    } else if bytes.starts_with(b"PK\x03\x04") {
        FileKind::Zip
    } else {
        FileKind::Unknown
    }
}

fn is_pe(b: &[u8]) -> bool {
    if !b.starts_with(b"MZ") {
        return false;
    }
    let Some(off) = b.get(0x3C..0x40).map(|s| u32::from_le_bytes(s.try_into().unwrap())) else {
        return false;
    };
    b.get(off as usize..).is_some_and(|rest| rest.starts_with(b"PE\0\0"))
}
```

`crates/pe/src/lib.rs` (replace the file):

```rust
//! Header-based analysis of Windows binaries. Never trusts file extensions.
mod detect;
mod model;

pub use detect::{FileKind, detect};
pub use model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a PE file")]
    NotPe,
    #[error("malformed PE: {0}")]
    Malformed(String),
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p runtime-pe --test detect`
Expected: `1 passed`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): model types and header-based format detection"
```

---
## Task 4: `analyze()` for headers, sections and safety guards

**Files:**
- Create: `crates/pe/src/analyze.rs`, `crates/pe/tests/headers.rs`
- Modify: `crates/pe/src/lib.rs`, `crates/pe/tests/common/mod.rs` (append helper)

**Interfaces:**
- Consumes: Task 3 types, `Builder`.
- Produces: `pe::analyze(&[u8]) -> Result<PeInfo, pe::Error>`; fills `format`, `arch`, `kind`, `subsystem`, `image_base`, `entry_point_rva`, `size_of_image`, `aslr`, `nx`, `signed`, `dotnet`, `sections`. Tables (`imports`, `exports`, `relocation_count`, `tls`, `version`) are empty placeholders here; Tasks 5-8 fill them by replacing marked single lines.
- Test helper produced: `common::analyze(&Builder) -> PeInfo`.

Design notes baked into this task (see "Findings"): `analyze` (a) rejects non-PE with `Error::NotPe`, (b) copies caller buffers that are not 8-byte aligned, (c) rejects images whose section file offsets disagree with their RVAs mod 8 (`check_layout`), because `pelite` would otherwise hand out misaligned references. One macro is stamped out for PE32 and PE32+ because `pelite::pe32::Pe` and `pelite::pe64::Pe` are unrelated traits with identical APIs.

- [ ] **Step 1: Append the test helper to `crates/pe/tests/common/mod.rs`**

```rust
pub fn analyze(b: &Builder) -> pe::PeInfo {
    pe::analyze(&b.build()).expect("analyze")
}
```

- [ ] **Step 2: Write the failing tests**

`crates/pe/tests/headers.rs`:

```rust
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
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p runtime-pe --test headers`
Expected: FAIL: `cannot find function analyze in crate pe`.

- [ ] **Step 4: Implement**

`crates/pe/src/analyze.rs` (new file):

```rust
use crate::{Error, FileKind, detect, model::*};
use pelite::{PeFile, Wrap};

pub fn analyze(bytes: &[u8]) -> Result<PeInfo, Error> {
    if detect(bytes) != FileKind::Pe {
        return Err(Error::NotPe);
    }
    // pelite hands out `&T` straight into the buffer, so the buffer must be 8-aligned.
    let copy;
    let bytes = if bytes.as_ptr().align_offset(8) == 0 {
        bytes
    } else {
        copy = Aligned::new(bytes);
        copy.bytes()
    };
    let file = PeFile::from_bytes(bytes).map_err(|e| Error::Malformed(e.to_string()))?;
    check_layout(&file)?;
    let info = match file {
        Wrap::T32(f) => info32(f),
        Wrap::T64(f) => info64(f),
    };
    Ok(info)
}

/// pelite checks alignment against the RVA, not the real file offset. If a section's raw
/// pointer and RVA disagree mod 8, it would return misaligned references (UB) for tables in
/// that section. Real linkers never produce this; corrupted or hostile files do.
fn check_layout(file: &PeFile<'_>) -> Result<(), Error> {
    let bad = file
        .section_headers()
        .iter()
        .any(|s| s.SizeOfRawData != 0 && s.PointerToRawData.wrapping_sub(s.VirtualAddress) % 8 != 0);
    if bad {
        return Err(Error::Malformed(
            "section file offset and RVA are misaligned relative to each other".into(),
        ));
    }
    Ok(())
}

struct Aligned {
    words: Vec<u64>,
    len: usize,
}

impl Aligned {
    fn new(src: &[u8]) -> Self {
        let mut words = vec![0u64; src.len().div_ceil(8)];
        // SAFETY: `words` owns at least `src.len()` initialised bytes; u8 has no alignment needs.
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), src.len()) }.copy_from_slice(src);
        Self { words, len: src.len() }
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: same buffer as above, shared borrow.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

const DIR_SECURITY: usize = 4;
const DIR_CLR: usize = 14;

// pelite's pe32 and pe64 modules expose identical APIs behind different traits, so the
// extraction body is stamped out once per word size.
macro_rules! extract {
    ($fn_name:ident, $pe:ident, $format:expr, $word:ty, $ord_flag:expr) => {
        fn $fn_name(f: pelite::$pe::PeFile<'_>) -> PeInfo {
            use pelite::$pe::Pe;
            let fh = f.file_header();
            let oh = f.optional_header();
            let dirs = f.data_directory();
            // (rva, size) of a data directory; (0, 0) when absent.
            let dir = |i: usize| dirs.get(i).map_or((0, 0), |d| (d.VirtualAddress, d.Size));

            let sections = f
                .section_headers()
                .iter()
                .map(|s| Section {
                    name: s
                        .name()
                        .map(str::to_owned)
                        .unwrap_or_else(|b| String::from_utf8_lossy(b).into_owned()),
                    virtual_address: s.VirtualAddress,
                    virtual_size: s.VirtualSize,
                    raw_size: s.SizeOfRawData,
                    readable: s.Characteristics & 0x4000_0000 != 0,
                    writable: s.Characteristics & 0x8000_0000 != 0,
                    executable: s.Characteristics & 0x2000_0000 != 0,
                })
                .collect();

            let imports = Vec::new();

            let exports = Vec::new();

            let relocation_count = 0;

            let tls = None;

            let version = None;

            PeInfo {
                format: $format,
                arch: Arch::from_machine(fh.Machine),
                kind: if fh.Characteristics & 0x2000 != 0 {
                    Kind::Dll
                } else {
                    Kind::Exe
                },
                subsystem: Subsystem::from_raw(oh.Subsystem),
                image_base: oh.ImageBase as u64,
                entry_point_rva: oh.AddressOfEntryPoint,
                size_of_image: oh.SizeOfImage,
                aslr: oh.DllCharacteristics & 0x0040 != 0,
                nx: oh.DllCharacteristics & 0x0100 != 0,
                signed: dir(DIR_SECURITY).1 != 0,
                dotnet: dir(DIR_CLR).0 != 0,
                sections,
                imports,
                exports,
                relocation_count,
                tls,
                version,
                installer: None,
                warnings: Vec::new(),
            }
        }
    };
}

extract!(info32, pe32, Format::Pe32, u32, 0x8000_0000u32);
extract!(info64, pe64, Format::Pe32Plus, u64, 0x8000_0000_0000_0000u64);
```

`crates/pe/src/lib.rs` (replace the file):

```rust
//! Header-based analysis of Windows binaries. Never trusts file extensions.
mod analyze;
mod detect;
mod model;

pub use analyze::analyze;
pub use detect::{FileKind, detect};
pub use model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a PE file")]
    NotPe,
    #[error("malformed PE: {0}")]
    Malformed(String),
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p runtime-pe`
Expected: `detect` 1 passed, `headers` 7 passed.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): analyze headers and sections with alignment guards"
```

---
## Task 5: Imports, including delay-load imports and unaligned thunks

**Files:**
- Modify: `crates/pe/src/analyze.rs`, `crates/pe/tests/common/mod.rs` (append)
- Create: `crates/pe/tests/imports.rs`

**Interfaces:**
- Consumes: `analyze`, `Builder`, `Bytes`.
- Produces: `PeInfo.imports: Vec<Import>` with `Import { dll, delay, functions: Vec<ImportedFn> }`; `PeInfo.warnings` now populated. Test helpers `common::imports_data(base)` and `common::delay_data(base)`.

- [ ] **Step 1: Append the table layouts to `crates/pe/tests/common/mod.rs`**

```rust
#[rustfmt::skip]
pub fn imports_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(base + 68).u32(0).u32(0).u32(base + 48).u32(base + 68) // descriptor: OFT, ts, fwd, name, FT
        .pad_to(20 + 20) // null terminator descriptor
        .pad_to(48)
        .cstr("kernel32.dll")
        .pad_to(68) // 68 % 8 == 4: deliberately misaligned
        .u64(u64::from(base + 96)) // by name
        .u64(0x8000_0000_0000_0005) // by ordinal 5
        .u64(0)
        .pad_to(96)
        .u16(0)
        .cstr("ExitProcess")
        .0
}

#[rustfmt::skip]
pub fn delay_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(1).u32(base + 64).u32(0).u32(base + 112).u32(base + 80).u32(0).u32(0).u32(0) // descriptor
        .pad_to(64) // (terminator descriptor is the zeroed 32..64)
        .cstr("dxgi.dll")
        .pad_to(80)
        .u64(u64::from(base + 128))
        .u64(0x8000_0000_0000_0007)
        .u64(0)
        .pad_to(128)
        .u16(0)
        .cstr("CreateDXGIFactory")
        .0
}
```

- [ ] **Step 2: Write the failing tests**

`crates/pe/tests/imports.rs`:

```rust
mod common;
use common::*;
use pe::ImportedFn;

/// Regression: GNU ld emits import lookup tables that are only 4-byte aligned in PE32+ images.
/// pelite's `int()` rejects these ("address misaligned"), so we walk thunks ourselves.
#[test]
fn imports_survive_unaligned_thunks_x64() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".idata", DATA_RW, imports_data(base))
            .dir(1, base, 40),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.imports.len(), 1);
    assert_eq!(i.imports[0].dll, "kernel32.dll");
    assert!(!i.imports[0].delay);
    assert_eq!(
        i.imports[0].functions,
        vec![ImportedFn::Name("ExitProcess".into()), ImportedFn::Ordinal(5)]
    );
}

#[test]
fn delay_imports_are_reported_and_flagged() {
    let base = Builder::rva(0);
    let i = analyze(
        &Builder::x64()
            .section(".didat", DATA_RW, delay_data(base))
            .dir(13, base, 64),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.imports.len(), 1);
    assert!(i.imports[0].delay);
    assert_eq!(i.imports[0].dll, "dxgi.dll");
    assert_eq!(
        i.imports[0].functions,
        vec![ImportedFn::Name("CreateDXGIFactory".into()), ImportedFn::Ordinal(7)]
    );
}
```

`imports_survive_unaligned_thunks_x64` is a regression test for the real bug where `pelite::int()` returned "address misaligned" for mingw x64 executables.

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p runtime-pe --test imports`
Expected: FAIL: both tests (`imports` is empty).

- [ ] **Step 4: Implement** (four edits to `crates/pe/src/analyze.rs`)

Find:

```rust
            use pelite::$pe::Pe;
```

Replace with:

```rust
            use pelite::$pe::Pe;
            let mut warnings = Vec::new();
```

Find:

```rust
                warnings: Vec::new(),
```

Replace with:

```rust
                warnings,
```

Find:

```rust
const DIR_SECURITY: usize = 4;
```

Replace with:

```rust
const DIR_SECURITY: usize = 4;
const DIR_DELAY_IMPORT: usize = 13;
```

Find:

```rust
            let imports = Vec::new();
```

Replace with:

```rust
            // Walk an import thunk array by hand. pelite's `int()` demands aligned tables and
            // rejects the 4-byte-aligned ones GNU ld emits for PE32+.
            let thunks = |mut rva: u32| {
                let mut functions = Vec::new();
                for _ in 0..65_536 {
                    let Ok(v) = f.derva_copy::<$word>(rva) else { break };
                    if v == 0 {
                        break;
                    }
                    if v & $ord_flag != 0 {
                        functions.push(ImportedFn::Ordinal((v & 0xFFFF) as u16));
                    } else if let Ok(n) = f.derva_c_str((v as u32).wrapping_add(2)) {
                        functions.push(ImportedFn::Name(n.to_string()));
                    }
                    rva = rva.wrapping_add(std::mem::size_of::<$word>() as u32);
                }
                functions
            };

            let mut imports = Vec::new();
            match f.imports() {
                Ok(list) => {
                    for desc in list {
                        let Ok(dll) = desc.dll_name() else {
                            warnings.push("imports: unreadable DLL name".to_owned());
                            continue;
                        };
                        let d = desc.image();
                        // Fall back to the IAT when the lookup table is absent (old linkers).
                        let table = if d.OriginalFirstThunk != 0 {
                            d.OriginalFirstThunk
                        } else {
                            d.FirstThunk
                        };
                        imports.push(Import {
                            dll: dll.to_string(),
                            delay: false,
                            functions: thunks(table),
                        });
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("imports: {e}")),
            }

            // pelite has no delay-import support: walk IMAGE_DELAYLOAD_DESCRIPTOR (8 x u32) by hand.
            if dir(DIR_DELAY_IMPORT).0 != 0 {
                let mut rva = dir(DIR_DELAY_IMPORT).0;
                for _ in 0..4096 {
                    let Ok(d) = f.derva_copy::<[u32; 8]>(rva) else {
                        warnings.push("delay imports: truncated descriptor".to_owned());
                        break;
                    };
                    if d[1] == 0 {
                        break;
                    }
                    rva = rva.wrapping_add(32);
                    if d[0] & 1 == 0 {
                        warnings.push("delay imports: VA-based descriptor unsupported".to_owned());
                        continue;
                    }
                    let Ok(dll) = f.derva_c_str(d[1]) else {
                        warnings.push("delay imports: unreadable DLL name".to_owned());
                        continue;
                    };
                    imports.push(Import {
                        dll: dll.to_string(),
                        delay: true,
                        functions: thunks(d[4]),
                    });
                }
            }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p runtime-pe`
Expected: all pass (`imports` 2 passed).

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): imports incl. delay-load and unaligned thunks"
```

---
## Task 6: Exports (named, ordinal-only, forwarders)

**Files:**
- Modify: `crates/pe/src/analyze.rs`, `crates/pe/tests/common/mod.rs` (append)
- Create: `crates/pe/tests/exports.rs`

**Interfaces:**
- Produces: `PeInfo.exports: Vec<Export>` with `Export { name: Option<String>, ordinal: u32, forwarder: Option<String> }`. Unused function slots are skipped. `ordinal = ordinal_base + index`.

- [ ] **Step 1: Append the layout to `crates/pe/tests/common/mod.rs`**

```rust
/// Ordinal base 10; slot 0 named "Alpha", slot 1 named "Fwd" forwarding to ntdll, slot 2 unused.
#[rustfmt::skip]
pub fn exports_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(0).u32(0).u16(0).u16(0).u32(base + 40).u32(10).u32(3).u32(2).u32(base + 64).u32(base + 80).u32(base + 96)
        .pad_to(40)
        .cstr("mylib.dll")
        .pad_to(64)
        .u32(0x2000).u32(base + 112).u32(0)
        .pad_to(80)
        .u32(base + 144).u32(base + 152)
        .pad_to(96)
        .u16(0).u16(1)
        .pad_to(112)
        .cstr("NTDLL.RtlAllocateHeap")
        .pad_to(144)
        .cstr("Alpha")
        .pad_to(152)
        .cstr("Fwd")
        .0
}
```

- [ ] **Step 2: Write the failing test**

`crates/pe/tests/exports.rs`:

```rust
mod common;
use common::*;

#[test]
fn exports_with_ordinal_base_forwarder_and_unused_slot() {
    let base = Builder::rva(0);
    let data = exports_data(base);
    let len = data.len() as u32;
    let i = analyze(
        &Builder {
            dll: true,
            ..Builder::x64()
        }
        .section(".edata", DATA_R, data)
        .dir(0, base, len),
    );
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    let got: Vec<_> = i
        .exports
        .iter()
        .map(|e| (e.name.as_deref(), e.ordinal, e.forwarder.as_deref()))
        .collect();
    assert_eq!(
        got,
        vec![
            (Some("Alpha"), 10, None),
            (Some("Fwd"), 11, Some("NTDLL.RtlAllocateHeap"))
        ]
    );
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p runtime-pe --test exports`
Expected: FAIL (`got` is empty).

- [ ] **Step 4: Implement** (two edits to `crates/pe/src/analyze.rs`)

Find:

```rust
use pelite::{PeFile, Wrap};
```

Replace with:

```rust
use pelite::{PeFile, Wrap};
use std::collections::BTreeMap;
```

Find:

```rust
            let exports = Vec::new();
```

Replace with:

```rust
            let mut exports = Vec::new();
            match f.exports() {
                Ok(ex) => {
                    let base = ex.ordinal_base() as u32;
                    match ex.by() {
                        Ok(by) => {
                            let mut names = BTreeMap::new();
                            for (name, idx) in by.iter_name_indices() {
                                if let Ok(n) = name {
                                    names.insert(idx, n.to_string());
                                }
                            }
                            for idx in 0..by.functions().len().min(65_536) {
                                let forwarder = match by.index(idx) {
                                    Ok(pelite::$pe::exports::Export::Forward(fwd)) => Some(fwd.to_string()),
                                    Ok(pelite::$pe::exports::Export::Symbol(&0)) => continue, // unused slot
                                    Ok(_) => None,
                                    Err(_) => continue,
                                };
                                exports.push(Export {
                                    name: names.remove(&idx),
                                    ordinal: base + idx as u32,
                                    forwarder,
                                });
                            }
                        }
                        Err(e) => warnings.push(format!("exports: {e}")),
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("exports: {e}")),
            }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p runtime-pe`
Expected: all pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): exports with ordinal base and forwarders"
```

---
## Task 7: Base relocations and TLS

**Files:**
- Modify: `crates/pe/src/analyze.rs`, `crates/pe/tests/common/mod.rs` (append)
- Create: `crates/pe/tests/relocs_tls.rs`

**Interfaces:**
- Produces: `PeInfo.relocation_count` (fixups only; `ABSOLUTE` padding entries are not counted) and `PeInfo.tls: Option<Tls { callback_count }>`. These feed Phase 8's loader design and `doctor`.

- [ ] **Step 1: Append the layouts to `crates/pe/tests/common/mod.rs`**

```rust
/// One block covering page 0x1000: two DIR64 fixups plus one ABSOLUTE padding entry.
#[rustfmt::skip]
pub fn reloc_data() -> Vec<u8> {
    Bytes::default().u32(0x1000).u32(16).u16(0xA010).u16(0xA018).u16(0x0000).u16(0x0000).0
}

#[rustfmt::skip]
pub fn tls_data(base: u32) -> Vec<u8> {
    let image_base = 0x1_4000_0000u64;
    let va = |off: u32| image_base + u64::from(base + off);
    Bytes::default()
        .u64(va(48)).u64(va(56)).u64(va(56)).u64(va(64)).u32(0).u32(0)
        .pad_to(64)
        .u64(image_base + 0x1000).u64(image_base + 0x1010).u64(0)
        .0
}
```

- [ ] **Step 2: Write the failing tests**

`crates/pe/tests/relocs_tls.rs`:

```rust
mod common;
use common::*;

#[test]
fn relocations_count_real_fixups_only() {
    let base = Builder::rva(0);
    let i = analyze(&Builder::x64().section(".reloc", DATA_R, reloc_data()).dir(5, base, 16));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.relocation_count, 2);
}

#[test]
fn tls_callbacks_are_counted() {
    let base = Builder::rva(0);
    let i = analyze(&Builder::x64().section(".tls", DATA_RW, tls_data(base)).dir(9, base, 40));
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!(i.tls.unwrap().callback_count, 2);
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p runtime-pe --test relocs_tls`
Expected: FAIL both.

- [ ] **Step 4: Implement** (two edits to `crates/pe/src/analyze.rs`)

Find:

```rust
            let relocation_count = 0;
```

Replace with:

```rust
            let mut relocation_count = 0;
            match f.base_relocs() {
                Ok(r) => relocation_count = r.fold(0usize, |n, _rva, ty| n + usize::from(ty != 0)),
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("relocations: {e}")),
            }
```

Find:

```rust
            let tls = None;
```

Replace with:

```rust
            let mut tls = None;
            match f.tls() {
                Ok(t) => {
                    tls = Some(Tls {
                        callback_count: t.callbacks().map(|c| c.len()).unwrap_or(0),
                    })
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("tls: {e}")),
            }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p runtime-pe`
Expected: all pass.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): relocation count and TLS callbacks"
```

---
## Task 8: Version info and installer-family markers

**Files:**
- Create: `crates/pe/src/installer.rs`, `crates/pe/tests/meta.rs`, `crates/pe/tests/fixtures.rs`
- Modify: `crates/pe/src/lib.rs`, `crates/pe/src/analyze.rs`

**Interfaces:**
- Produces: `PeInfo.version: Option<VersionInfo { file_version, strings }>` (`strings` holds ProductName, CompanyName, FileDescription, ...); `PeInfo.installer: Option<Installer { kind, evidence }>`. Installer detection is a heuristic: `evidence` names the marker that matched, and nothing claims certainty. Phase 3 uses both to name apps and pick silent-install flags.

Note: `.NET` detection (CLR data directory) already landed in Task 4.

- [ ] **Step 1: Write the failing tests**

`crates/pe/tests/meta.rs`:

```rust
mod common;
use common::*;
use pe::InstallerKind;

#[test]
fn installer_markers() {
    let inno = Builder {
        overlay: b"....Inno Setup Setup Data (6.2.0)....".to_vec(),
        ..Builder::x86()
    };
    assert_eq!(analyze(&inno).installer.unwrap().kind, InstallerKind::InnoSetup);
    let nsis = Builder {
        overlay: b"\xef\xbe\xad\xdeNullsoftInst".to_vec(),
        ..Builder::x86()
    };
    assert_eq!(analyze(&nsis).installer.unwrap().kind, InstallerKind::Nsis);
    let burn = Builder::x86().section(".wixburn", DATA_R, vec![0; 16]);
    assert_eq!(analyze(&burn).installer.unwrap().kind, InstallerKind::WixBurn);
    assert!(analyze(&Builder::x86()).installer.is_none());
}
```

`crates/pe/tests/fixtures.rs` (Task 11 appends more tests here; this one needs Task 2's fixtures):

```rust
//! Tests against Windows binaries built by tools/build-fixtures.sh (needs mingw-w64).
use std::path::PathBuf;

fn load(name: &str) -> pe::PeInfo {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build").join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"));
    pe::analyze(&bytes).expect("analyze fixture")
}

#[test]
fn version_info_is_read_from_the_hello_fixture() {
    let v = load("hello64.exe").version.expect("VERSIONINFO resource");
    assert_eq!(v.file_version.as_deref(), Some("1.2.3.4"));
    assert_eq!(v.strings.get("ProductName").map(String::as_str), Some("Runtime Fixture"));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p runtime-pe --test meta --test fixtures`
Expected: `installer_markers` FAILS (`installer` is `None`); `version_info_...` FAILS (`VERSIONINFO resource`: `version` is `None`).

- [ ] **Step 3: Implement**

`crates/pe/src/installer.rs` (new file):

```rust
use crate::model::{Installer, InstallerKind, PeInfo};
use memchr::memmem;

const MARKERS: &[(InstallerKind, &str)] = &[
    (InstallerKind::InnoSetup, "Inno Setup Setup Data"),
    (InstallerKind::Nsis, "NullsoftInst"),
    (InstallerKind::InstallShield, "InstallShield"),
];

pub fn detect(bytes: &[u8], info: &PeInfo) -> Option<Installer> {
    if info.sections.iter().any(|s| s.name == ".wixburn") {
        return Some(Installer {
            kind: InstallerKind::WixBurn,
            evidence: ".wixburn section",
        });
    }
    MARKERS.iter().find_map(|&(kind, marker)| {
        memmem::find(bytes, marker.as_bytes()).map(|_| Installer { kind, evidence: marker })
    })
}
```

`crates/pe/src/lib.rs` (add one line):

Find:

```rust
mod detect;
```

Replace with:

```rust
mod detect;
mod installer;
```

Four edits to `crates/pe/src/analyze.rs`:

Find:

```rust
use crate::{Error, FileKind, detect, model::*};
```

Replace with:

```rust
use crate::{Error, FileKind, detect, installer, model::*};
```

Find:

```rust
    let info = match file {
```

Replace with:

```rust
    let mut info = match file {
```

Find:

```rust
    };
    Ok(info)
```

Replace with:

```rust
    };
    info.installer = installer::detect(bytes, &info);
    Ok(info)
```

Find:

```rust
            let version = None;
```

Replace with:

```rust
            let mut version = None;
            match f.resources() {
                Ok(res) => {
                    if let Ok(vi) = res.version_info() {
                        let mut strings = BTreeMap::new();
                        if let Some(&lang) = vi.translation().first() {
                            vi.strings(lang, |k, v| {
                                strings.insert(k.to_owned(), v.to_owned());
                            });
                        }
                        let file_version = strings.get("FileVersion").cloned().or_else(|| {
                            vi.fixed().map(|x| {
                                let v = x.dwFileVersion;
                                format!("{}.{}.{}.{}", v.Major, v.Minor, v.Patch, v.Build)
                            })
                        });
                        version = Some(VersionInfo {
                            file_version,
                            strings,
                        });
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("resources: {e}")),
            }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p runtime-pe`
Expected: all pass (unit-level suites). The fixture test needs Task 2's fixtures.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(pe): version info and installer-family markers"
```

---
## Task 9: Robustness (corruption test) and real-world oracle

**Files:**
- Create: `crates/pe/tests/robust.rs`, `crates/pe/tests/real_world.rs`

**Interfaces:**
- Consumes: everything from Tasks 3-8.
- Produces: the two guards that make `pe` safe to point at untrusted files. No new public API.

- [ ] **Step 1: Write the robustness test**

`crates/pe/tests/robust.rs`:

```rust
mod common;
use common::*;

/// Every table at once, so mutations hit real structures rather than empty space.
fn rich_sample() -> Vec<u8> {
    let r = Builder::rva;
    Builder::x64()
        .section(".idata", DATA_RW, imports_data(r(0)))
        .section(".didat", DATA_RW, delay_data(r(1)))
        .section(".edata", DATA_R, exports_data(r(2)))
        .section(".reloc", DATA_R, reloc_data())
        .section(".tls", DATA_RW, tls_data(r(4)))
        .dir(1, r(0), 40)
        .dir(13, r(1), 64)
        .dir(0, r(2), 160)
        .dir(5, r(3), 16)
        .dir(9, r(4), 40)
        .build()
}

#[test]
fn rich_sample_parses_cleanly() {
    let i = pe::analyze(&rich_sample()).unwrap();
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!((i.imports.len(), i.exports.len(), i.relocation_count), (2, 2, 2));
}

/// The parser is a security boundary (it is fed untrusted installers): corrupt or truncate a
/// valid image thousands of ways and require that it never panics. Debug builds also trap
/// integer overflow. (cargo-fuzz needs nightly; add a fuzz target once CI has one.)
#[test]
fn corrupted_input_never_panics() {
    let original = rich_sample();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for n in 0..30_000 {
        let mut m = original.clone();
        if next() % 5 == 0 {
            m.truncate(next() as usize % m.len());
        } else {
            for _ in 0..=next() % 6 {
                // Bias towards the headers and table area, where structure lives.
                let span = if next() % 2 == 0 { 0x200 } else { m.len() };
                let at = next() as usize % span.min(m.len());
                m[at] = next() as u8;
            }
        }
        let r = std::panic::catch_unwind(|| {
            let _ = pe::analyze(&m);
            let _ = pe::detect(&m);
        });
        assert!(r.is_ok(), "panicked on iteration {n}");
    }
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p runtime-pe --test robust`
Expected: `2 passed` (~1 s). If `corrupted_input_never_panics` fails, it printed the iteration; that is a real parser bug (during planning it found the `pelite` alignment issue now handled by `check_layout`). Fix `analyze.rs`, never weaken the test.

- [ ] **Step 3: Write the real-world oracle test** (ignored by default; compares against `file(1)`)

`crates/pe/tests/real_world.rs`:

```rust
//! Oracle test against real binaries. Ignored by default: run with
//!   RUNTIME_SAMPLES=/dir1:/dir2 cargo test -p runtime-pe --test real_world -- --ignored --nocapture
//! Compares our analysis with `file(1)` for every .exe/.dll/.sys/.ocx found (extension is only
//! used to *find* candidates here; detection itself never looks at it).
use pe::{Arch, Format, Kind, Subsystem};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() {
            walk(&p, out);
        } else if ft.is_file() {
            let ext = p.extension().and_then(|x| x.to_str()).map(str::to_ascii_lowercase);
            if matches!(ext.as_deref(), Some("exe" | "dll" | "sys" | "ocx")) {
                out.push(p);
            }
        }
    }
}

#[test]
#[ignore]
fn matches_file_command_on_real_binaries() {
    let roots = std::env::var("RUNTIME_SAMPLES").expect("set RUNTIME_SAMPLES=/dir1:/dir2");
    let mut files = vec![];
    for r in roots.split(':') {
        walk(Path::new(r), &mut files);
    }
    let (mut checked, mut failures) = (0, vec![]);
    for f in &files {
        let Ok(bytes) = fs::read(f) else { continue };
        if pe::detect(&bytes) != pe::FileKind::Pe {
            continue;
        }
        let oracle = String::from_utf8(Command::new("file").arg("-b").arg(f).output().unwrap().stdout).unwrap();
        let info = match pe::analyze(&bytes) {
            Ok(i) => i,
            Err(e) => {
                failures.push(format!("{}: analyze failed: {e} (file says: {oracle})", f.display()));
                continue;
            }
        };
        checked += 1;
        let mut bad = vec![];
        if oracle.contains("PE32+") != (info.format == Format::Pe32Plus) {
            bad.push("format");
        }
        let want_arch = if oracle.contains("x86-64") {
            Some(Arch::X86_64)
        } else if oracle.contains("Intel 80386") {
            Some(Arch::X86)
        } else if oracle.contains("ARM64") {
            Some(Arch::Arm64)
        } else {
            None
        };
        if want_arch.is_some_and(|a| a != info.arch) {
            bad.push("arch");
        }
        if oracle.contains("(DLL)") != (info.kind == Kind::Dll) {
            bad.push("kind");
        }
        if oracle.contains("(console)") && info.subsystem != Subsystem::Console
            || oracle.contains("(GUI)") && info.subsystem != Subsystem::Gui
        {
            bad.push("subsystem");
        }
        if !bad.is_empty() {
            failures.push(format!("{}: {bad:?} differ from file(1): {oracle}", f.display()));
        }
        if !info.warnings.is_empty() {
            println!("note {}: {:?}", f.display(), info.warnings);
        }
    }
    println!("checked {checked} PE files");
    assert!(checked > 0, "no PE files found under RUNTIME_SAMPLES");
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
```

- [ ] **Step 4: Run it on real binaries**

Point it at any directories containing Windows binaries (installers, portable apps, `node_modules` packages that vendor `.exe`/`.dll`, Wine's DLLs after installing Wine):

Run: `RUNTIME_SAMPLES=$HOME/Downloads:$HOME/Desktop cargo test -p runtime-pe --test real_world -- --ignored --nocapture`
Expected: `checked N PE files` and `1 passed`. Any `format`/`arch`/`kind`/`subsystem` mismatch against `file(1)` is a bug to investigate. `note ...: [warnings]` lines list tables that failed to parse; look at each. (On the author's machine: 24/24 matched, no warnings.)

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "test(pe): corruption robustness and real-world oracle"
```

---
## Task 10: `runtime analyze` CLI

**Files:**
- Create: `crates/cli/src/analyze.rs`, `crates/cli/tests/analyze.rs`
- Modify: `crates/cli/src/main.rs`

**Interfaces:**
- Consumes: `pe::detect`, `pe::analyze`, `pe::PeInfo`.
- Produces: `runtime analyze <file> [--json]`. Exit 0 for PE/MSI/ZIP; exit 1 with `error: ...` on stderr for unknown formats or malformed PE. JSON shape: `{"kind": "pe|msi|zip", "pe": <PeInfo or null>}`. Logging goes to stderr, controlled by `RUNTIME_LOG` (e.g. `RUNTIME_LOG=pe=debug`).

Needs Task 2's fixtures (`hello64.exe`).

- [ ] **Step 1: Write the failing tests**

`crates/cli/tests/analyze.rs`:

```rust
use std::{path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

fn runtime(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_runtime")).args(args).output().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("runtime-cli-test-{}-{name}", std::process::id()))
}

#[test]
fn analyze_json_describes_a_pe() {
    let out = runtime(&[
        "analyze".as_ref(),
        "--json".as_ref(),
        fixture("hello64.exe").as_os_str(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "pe");
    assert_eq!(v["pe"]["format"], "pe32_plus");
    assert_eq!(v["pe"]["arch"], "x86_64");
    assert_eq!(v["pe"]["subsystem"], "console");
}

#[test]
fn analyze_ignores_the_file_extension() {
    let disguised = scratch("disguised.txt");
    std::fs::copy(fixture("hello64.exe"), &disguised).unwrap();
    let out = runtime(&["analyze".as_ref(), "--json".as_ref(), disguised.as_os_str()]);
    let _ = std::fs::remove_file(&disguised);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "pe");
}

#[test]
fn analyze_rejects_a_non_windows_file_even_if_named_exe() {
    let fake = scratch("fake.exe");
    std::fs::write(&fake, "just some text, not a program\n").unwrap();
    let out = runtime(&["analyze".as_ref(), fake.as_os_str()]);
    let _ = std::fs::remove_file(&fake);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognised format"));
}

#[test]
fn analyze_human_output_lists_imports() {
    let out = runtime(&["analyze".as_ref(), fixture("hello64.exe").as_os_str()]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Pe32Plus X86_64 Exe (Console)"), "{text}");
    assert!(text.to_lowercase().contains("kernel32.dll"), "{text}");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p runtime-cli`
Expected: FAIL: the binary has no `analyze` subcommand (`unrecognized subcommand`).

- [ ] **Step 3: Implement**

`crates/cli/src/main.rs` (replace the file):

```rust
mod analyze;

use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(name = "runtime", version, about = "Run Windows applications on Linux")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect a Windows binary or installer (header-based, extension ignored)
    Analyze {
        file: PathBuf,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("RUNTIME_LOG"))
        .with_writer(std::io::stderr)
        .init();
    let result = match Cli::parse().cmd {
        Cmd::Analyze { file, json } => analyze::run(&file, json),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
```

`crates/cli/src/analyze.rs` (new file):

```rust
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p runtime-cli`
Expected: `4 passed`.

- [ ] **Step 5: Try it by hand**

Run: `cargo run -q -- analyze tests/fixtures/build/hello64.exe`
Expected: human-readable report starting `Format:     Pe32Plus X86_64 Exe (Console)` with a `KERNEL32.dll` import row. `cargo run -q -- analyze --json <file>` prints JSON. On a PE with delay-loaded DLLs the row shows `[delay]`.

- [ ] **Step 6: Lint and commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add -A && git commit -m "feat(cli): runtime analyze"
```

---
## Task 11: Fixture assertions and the Phase 1 exit gate

**Files:**
- Modify: `crates/pe/tests/fixtures.rs`

**Interfaces:**
- Consumes: Task 2 fixtures, `pe::analyze`.
- Produces: ground truth from a real linker (mingw) for x64, x86, GUI subsystem, and a DLL with exports and relocations.

- [ ] **Step 1: Extend `crates/pe/tests/fixtures.rs`**

Add this line to the imports at the top of the file:

```rust
use pe::{Arch, Format, ImportedFn, Kind, Subsystem};
```

Then append:

```rust
#[test]
fn hello64_is_a_console_x64_exe_importing_kernel32() {
    let i = load("hello64.exe");
    assert_eq!((i.format, i.arch, i.kind), (Format::Pe32Plus, Arch::X86_64, Kind::Exe));
    assert_eq!(i.subsystem, Subsystem::Console);
    let k32 = i.imports.iter().find(|m| m.dll.eq_ignore_ascii_case("kernel32.dll")).expect("kernel32 import");
    // Every mingw CRT startup installs an unhandled-exception filter.
    assert!(k32.functions.contains(&ImportedFn::Name("SetUnhandledExceptionFilter".into())));
    // ...and registers TLS callbacks.
    assert!(i.tls.as_ref().is_some_and(|t| t.callback_count >= 1));
    // The build script passes --dynamicbase --nxcompat.
    assert!(i.aslr && i.nx);
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
}

#[test]
fn hello32_is_pe32_x86() {
    let i = load("hello32.exe");
    assert_eq!((i.format, i.arch, i.subsystem), (Format::Pe32, Arch::X86, Subsystem::Console));
}

#[test]
fn gui64_uses_the_gui_subsystem() {
    assert_eq!(load("gui64.exe").subsystem, Subsystem::Gui);
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
```

- [ ] **Step 2: Run the whole workspace**

Run: `tools/build-fixtures.sh && cargo test --workspace`
Expected: everything passes. If a fixture test fails on a different mingw version, run `cargo run -q -- analyze --json tests/fixtures/build/<file>` and decide whether the parser or the expectation is wrong.

- [ ] **Step 3: Full quality gate**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
RUNTIME_SAMPLES=$HOME/Downloads:$HOME/Desktop cargo test -p runtime-pe --test real_world -- --ignored --nocapture
```

- [ ] **Step 4: Phase 1 exit checklist** (from the roadmap; tick each)

- [ ] `runtime analyze` is correct on all fixtures and on at least 10 real-world binaries you supply, including: 7-Zip or Notepad++ portable, a VC++ redistributable, a .NET app (expect `.NET: true`), an Inno Setup installer and an NSIS installer (expect the matching `Installer:` line), an ARM64 DLL if you have one.
- [ ] The oracle test reports no mismatches vs `file(1)`.
- [ ] `corrupted_input_never_panics` passes.
- [ ] Any `warning:` lines seen on real binaries have been triaged (parser bug, or genuinely malformed input).
- [ ] CI is green (push to a remote first).

- [ ] **Step 5: Commit and tag**

```bash
git add -A && git commit -m "test(pe): fixture assertions; Phase 1 exit gate"
git tag v0.0.1
```

---

## Self-review against the roadmap

**Phase 0 coverage:** workspace + CI + clippy/fmt (Task 1), fixtures (Task 2), licence inventory + `cargo deny` (Task 1), logging (Task 10, `tracing`/`RUNTIME_LOG`; shared module deferred, see Deviations), host tools + manual Wine check (Task 2).

**Phase 1 coverage:** PE32/PE32+, x86/x64/ARM64/ARM64EC, header-based detection (Tasks 3-4); sections (4); imports incl. delay-load (5); exports incl. forwarders (6); relocations, TLS (7); version info, installer families, .NET, MSI/ZIP sniffing (3, 4, 8); `analyze` CLI + `--json` (10); parser hardening (4, 9); real-world validation (9, 11). Not done, by design: icons and manifest (Phase 3), Authenticode *verification* (only presence is reported), bound imports.

**Type consistency:** every name used in later tasks (`Builder`, `Bytes`, `DATA_R/DATA_RW/CODE_RX`, `common::analyze`, `imports_data`, `delay_data`, `exports_data`, `reloc_data`, `tls_data`, `PeInfo` fields) is defined in the task that introduces it. Tasks 5-8 patch `analyze.rs` by replacing uniquely-marked lines; the replay used exactly these edits and reproduced the verified file byte-for-byte.

## Next plan

After the Phase 1 gate: write the Phase 2 plan (environments + `CompatBackend` + Wine backend). It reuses `tools/fixtures` (`hello64.exe` exits 7; `gui64.exe`) and `pe::analyze` for `doctor`'s import-vs-prefix check.

---

## Execution notes (added after the phase was implemented)

**The code blocks in this plan are not what shipped for Tasks 5-8 and Task 10.** Review found the plan's versions unsafe against hostile input (`crates/pe` is a security boundary: it must never panic or abort, must bound its work, and must report what it could not read). The repository holds the hardened code, which supersedes:

- **Tasks 5-8** (imports and delay imports, exports, relocations and TLS, version info and installers): the plan's `analyze.rs` blocks are replaced by hand-written walkers with per-table and whole-file budgets, bounded string reads (`read_bounded`, using `memchr`, at most 1025 bytes per string) and aggregated warnings.
- **Task 10** (`runtime analyze`): the plan's raw `println!` of file-supplied strings is replaced by `safe()` sanitisation (control characters and bidi overrides escaped), a size cap, regular-file checks before and after `open`, and a single `BrokenPipe` path.
- **Task 9b** was added (not in this plan): completion of the hostile-input work deferred from Tasks 5-9, and the `pe` mutation/corruption tests.
- **`crates/pe/src/version.rs`** was added: our own bounded VS_VERSIONINFO parser. pelite is used only to locate the raw RT_VERSION bytes. The resource language is chosen as en-US (0x0409), then neutral (0), then the first entry.

**pelite 0.10 hazards found, and where each is guarded**

1. Its `int()` rejects the 4-byte-aligned import lookup tables GNU ld emits for PE32+: the thunk arrays are walked by hand with `derva_copy` (`analyze.rs`, the `thunks` closure).
2. It checks alignment against the RVA, not the file offset, so a section whose raw pointer and RVA differ mod 8 yields misaligned references (UB): `check_layout` rejects such an image as `Malformed`; an unaligned input slice is copied to an 8-aligned buffer (`Aligned`).
3. `VersionInfo` slices out of range on a crafted 10-byte resource and panics: replaced by `version::parse`.
4. `resources()` dereferences a directory at a non-4-aligned RVA, which is a debug-build SIGABRT (a non-unwinding panic): guarded by the `res_rva % 4` check, reported as a warning.
5. The base-relocation block iterator loops forever on `SizeOfBlock` 0xFFFFFFFD..0xFFFFFFFF (wrapping round-up): replaced by our own block walk that always advances at least 8 bytes.

Related: pelite's `derva_c_str` scans to the NUL without a limit; all import, export and forwarder strings go through `read_bounded` instead.

**`PeInfo.warnings` are free-form text.** Wording changes between versions (it did during this phase, by ruling). Consumers must not parse them; the structured fields are the contract. A warning means the field it concerns may be incomplete.

**Changes after the final whole-branch review:** JSON `arch` and `subsystem` are always strings (`"other"` when unknown) with the raw numbers in `machine` and `subsystem_raw`; VERSIONINFO language selection; export tables declared but missing now warn; ordinal base is read as a u32; HIGHADJ relocation parameter words are not counted as fixups.

**Deferred and accepted** (the controller's ledger under `.superpowers/sdd/` is not committed; this is its summary):

- PE32 is not fuzzed by the structure-aware mutator (it only builds x64 images); PE32 has hostile-input tests but no mutation coverage.
- The version parser is lossy on malformation: one over-long string, more than 256 entries or a malformed first table drops all version info (with a warning). Only the first `StringTable` of the chosen language is read.
- DLL names are outside the 4 MiB retained-name budget (about 8 MiB worst case).
- `safe()` does not escape LRM, RLM, ALM, U+2028, U+2029 or zero-width characters; clap's argument-error echo and `tracing` output are not routed through it. JSON output carries raw file strings (see the `--json` help).
- Hang regressions (relocation loop) are caught only by a CI timeout, not a per-test watchdog; the bounded-read test is timing-based.
- CLI: no "file too large" test and no broken-pipe test; the check after `open` cannot close a swap-to-FIFO race; the FIFO test's guard is created after `spawn`.
- The `real_world` oracle depends on `file(1)` wording (`(native)`, `Intel i386`).
- `check_layout` rejects hand-built images whose raw pointers Windows would round down.
- Five commits carry a `Claude Haiku 4.5` co-author trailer; history was not rewritten.

**Phase 1 exit checklist items NOT done** (they need things the implementation session did not have): the 10+ user-supplied real binaries (7-Zip or Notepad++ portable, a VC++ redistributable, a .NET app, Inno Setup and NSIS installers, an ARM64 DLL), and "CI green" (nothing was pushed to a remote, so `.github/workflows/ci.yml` has never run). `v0.0.1` was not tagged.
