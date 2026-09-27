# The `.wrun` package format (v1)

A `.wrun` is one file that holds a Windows app together with a description of what it is and what it asks for.
`runtime import app.wrun` installs it as an app. The package can only **request** dependencies and permissions:
the user grants them afterwards with the same commands as for any other app. `.exe`, `.msi` and `.zip` files remain
first-class; a `.wrun` is optional.

This page is for package authors. The design and its reasons are in
[the Phase 6D spec](superpowers/specs/2026-09-27-backend-interface-and-wrun-design.md), sections 3 and 5; the
threat model is in [SECURITY.md](SECURITY.md), "Backends and `.wrun` packages (Phase 6D)".

## Making a package

Lay out a directory with a `wrun.toml` (without a `[[files]]` table) and a `payload/` tree, and nothing else:

```text
hello/
  wrun.toml
  payload/
    Hello/
      hello.exe
```

```toml
format = 1
id = "hello"
name = "Hello"
version = "1.0.0"
arch = "x86_64"
dependencies = ["vcrun2022"]

[entry]
kind = "portable"
exe = "payload/Hello/hello.exe"

[permissions]
network = "allow"
```

Then pack it, check it, and (optionally) unpack it again. The session below is from the `hello64.exe` test fixture:

```console
$ runtime pack hello -o hello.wrun
Packed: hello.wrun
Digest: a5dbf12a0b56eb2677fca9282187fec8970fb1d924ec8c40e6e415a032d8a48e
unsigned: its origin is not verified

$ runtime inspect hello.wrun
Package:   hello 1.0.0
Name:      Hello
Arch:      x86_64
Kind:      portable (payload/Hello/hello.exe)
Files:     1 (126040 bytes)
Digest:    a5dbf12a0b56eb2677fca9282187fec8970fb1d924ec8c40e6e415a032d8a48e
unsigned: its origin is not verified
Already installed: no
It would request:
  dependency vcrun2022: needs your consent when you run `runtime deps hello --install`
  permission network=allow: not granted; you can grant it with `runtime permissions hello --set=network=allow`

$ runtime unpack hello.wrun -o out     # out/wrun.toml now has the generated [[files]] table
Unpacked into out
```

`runtime inspect --json` prints the same facts as one object: `{id, name, version, arch, kind, entry, files, bytes,
digest, signed, installed, requests: {dependencies: [{id, consent}], permissions: [EXPR]}}`. `inspect` and `unpack`
verify every file and run nothing; `inspect` writes nothing.

`runtime pack` is reproducible: the same directory gives the same bytes on any machine. It sorts files by path
bytes, uses the zip minimum timestamp (1980-01-01) and mode 0644, writes no directory entries, and re-serialises
the manifest canonically with the generated `[[files]]` table. Files are deflated, except that a file which deflate
would compress past the reader's bomb guard is stored instead. `pack` opens and verifies its own output before it
reports success. It refuses:

- symlinks and special files (FIFOs, devices, sockets);
- names the reader would refuse, including names with `\` or that are not UTF-8;
- anything in the directory other than `wrun.toml` and `payload/`;
- a `wrun.toml` that already has `[[files]]`;
- an existing output file;
- input over the reader's limits.

On any error the output file is removed.

## The container

A `.wrun` is a zip archive. It is read with the same hardened zip planner as `runtime install`, with the same
limits: at most 20,000 entries, 4 GiB per file and in total, and a 1000:1 compression ratio for entries over
1 MiB. On top of that:

- The first central-directory entry is a file named exactly `wrun.toml`, at most 64 KiB.
- Every other entry is below `payload/`. `wrun.sig` is reserved for signed packages and refused in v1 ("signed
  packages need a newer runtime"). Any other name is refused.
- Names are UTF-8, use `/` only and are canonical (no `.` or empty components). The zip planner's rules apply too.
  It refuses `..`, absolute paths, drive letters, `:`, control and format characters, reserved device names, a
  trailing dot or space, case collisions, duplicates, and a name that is both a file and a directory.
- Symlink, device, FIFO and socket entries are refused. So are encrypted entries and compression methods other than
  stored and deflate.

## The manifest (`wrun.toml`)

TOML, UTF-8, at most 64 KiB. Unknown keys are an error at every level, so a `[signature]` table, a `filesystem`
permission or a `scripts` key are refused, not ignored.

| Key | Rule |
|---|---|
| `format` | Required, `1`. |
| `id` | Required. The app id: lowercase letters, digits and `-`, at most 64 bytes. It becomes the app id unchanged. |
| `name` | Required. 1 to 256 bytes, no control or format characters (refused, not stripped). |
| `version` | Required. 1 to 64 characters of `0-9 A-Z a-z . + ~ -`. |
| `arch` | Required. `"x86"` or `"x86_64"`. For a portable package it must equal the program's PE architecture. |
| `dependencies` | Optional. At most 16 unique ids of the bundled dependency manifest (`runtime deps list`); an unknown id is refused by `inspect` and `import`. |
| `icon` | Optional. A listed payload file whose name ends in `.png`, at most 1 MiB. Only that is checked: the PNG content is not validated, the icon is not recorded in the app's metadata, and nothing uses it yet (menu entries use the program's own icon). |
| `[entry] kind` | Required. `"portable"` or `"installer"`. |
| `[entry] exe` | Portable: the program, a listed payload file. |
| `[entry] installer` | Installer: the installer (`.msi` or a recognised installer `.exe`), which must be the only payload file. |
| `[entry] installedExe` | Installer, optional: the installed program as a `C:`-relative Windows path (`Program Files/App/app.exe`), like `runtime install --exe`. |
| `[permissions]` | Optional requests: `network = "allow"\|"deny"`, `display`, `audio`, `gpu` = `"on"\|"off"`. Nothing else. |
| `[[files]]` | Written by `pack`: one `{path, size, sha256}` per payload file (lowercase hex). It must equal exactly the set of payload files with their sizes. |

The **package digest** is the sha256 of the raw `wrun.toml` bytes. It covers every file's hash. `inspect` prints
it, the imported app's metadata records it, and a future signature will sign it.

**Known v1 limit.** Each `[[files]]` entry takes about 130 bytes, so the 64 KiB manifest holds roughly 450 payload
files. An app with more files should ship as an installer-kind package: one payload file, the installer.

## What `runtime import` does

1. It opens the package and checks the container and the manifest. It refuses unknown dependency ids, `--silent` or
   `--network` on a portable package (they are installer-only flags; exit 1), an id that is already installed, and
   an architecture the backend cannot run. Nothing is written before these checks.
2. It prints the `inspect` summary.
3. **Portable:** the payload is copied to `drive_c/Program Files/<id>/`, with the `payload/` prefix stripped, through
   the same install service as `runtime install`. Every file's sha256 is checked while it is written. A mismatch,
   an unlisted file or a program whose architecture differs from `arch` fails the import, and the half-built app is
   removed. The app is named by `name`.
4. **Installer:** the installer is extracted and verified into a private staging directory, run through the same
   sandboxed installer pipeline as `runtime install setup.exe` (no network unless the user passes `--network`), then
   removed. The installer's own product name is used, not the manifest's `name`. If the pipeline cannot tell which
   program was installed and `installedExe` is not set, nothing is installed and the candidates are printed, as
   with `install`.
5. It prints `Installed: <id>` and, for each request, the command that would grant it.

## What a package cannot do

- **Grant anything.** Import writes no `permissions.toml`, so the app gets the default profile: no network, no host
  directories. It installs no dependency. A requested dependency appears in `runtime deps <id>` as "(requested by
  the package)" and still needs `runtime deps <id> --install`, with per-package consent for proprietary ones.
  `runtime permissions <id>` and the GUI show each request that the profile does not grant, as "requested by the
  package (not granted)".
- **Say its own words in a request.** Requests are stored as fixed strings built from the enums above
  (`network=allow`, `gpu=on`, ...), never copied from the file.
- **Ask for host files or looser limits.** There is no filesystem or resource-limit key.
- **Run code on import.** There are no scripts, hooks or "run after install"; import never starts the app. An
  installer-kind package runs its installer in the installer sandbox, which is what installing it means.
- **Replace an app.** An existing id is refused, and nothing of the existing app is read, locked or changed. There
  is no upgrade, overwrite or `--force` in v1: `runtime remove <id>` first.
- **Prove who made it.** v1 packages are unsigned, and every command says "unsigned: its origin is not verified".
  Treat a `.wrun` from a stranger like a `setup.exe` from a stranger.

An import that was killed (for example a cancelled job) can leave a half-built app under the package's id: `runtime
remove <id>` clears it, then import again. A killed import's staged installer is removed by the next import.
