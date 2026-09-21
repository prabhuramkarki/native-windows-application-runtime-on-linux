# Native Windows application runtime on Linux

A Linux runtime for running Windows applications. **Status: Phase 0-1 only.** What exists today is
PE analysis: a hardened parser for untrusted Windows executables (`crates/pe`) and the
`runtime analyze` command that reports what a binary is and needs (`crates/cli`). Nothing here runs
a Windows program yet; environments, a Wine backend and the rest come in later phases.

```sh
cargo build                          # stable Rust 1.88 or newer
tools/build-fixtures.sh              # builds test .exe/.dll files into tests/fixtures/build; needs mingw-w64
cargo test --workspace               # needs the fixtures above
RUNTIME_SAMPLES=dir1:dir2 cargo test -p runtime-pe --test real_world -- --ignored --nocapture
                                     # oracle: compares every PE under those dirs with file(1); ignored by default
cargo run -p runtime-cli -- analyze [--json] <file>   # binary name: `runtime`
```

`analyze` detects the format from the file's contents, not its extension. `--json` output is the
stable interface; the warning lines in it are free-form text, do not parse them. Strings in the
output come from the analysed file: the human output escapes control and bidi characters, the JSON
does not, so sanitise before displaying it.

The roadmap and the Phase 0-1 plan, with notes on where the code departs from it, are in
`docs/superpowers/plans/`. Third-party components and licences: `docs/THIRD_PARTY.md`.
