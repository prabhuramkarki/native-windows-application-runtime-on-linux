# Phase 5, sub-project A: per-app permissions and the bubblewrap run sandbox (design)

Status: approved by the controller on the user's standing instruction (2026-09-25: self-approve with recommended
choices). Phase 5 (roadmap: "Sandbox + permissions") is split in three; this is the first and the one that makes
`runtime run` sandboxed at all. 5B (Landlock, seccomp, cgroup limits) and 5C (xdg-desktop-portal "ask" flows) get
their own specs. Threat model, as the roadmap states it: assume the app (and anything it downloaded) is malicious;
Wine is NOT a security boundary; bubblewrap is.

## 1. Purpose and success criteria

Today `runtime run` runs the program as the user with the whole home directory reachable (`docs/SECURITY.md`,
"Phase 2 is NOT a sandbox"). After this sub-project it runs inside a bubblewrap sandbox built from a per-app
permission profile, with least privilege by default and every relaxation an explicit, recorded user action.

Success criteria:

1. `runtime run <app>` starts the program inside bubblewrap by default: the host's `$HOME`, other apps' prefixes,
   the runtime's own data root and the app's own `permissions.toml` are not visible or not writable from inside.
2. Default profile (no `permissions.toml`): no network, no host directories, GUI baseline allowed (X11/Wayland
   display, PulseAudio-compatible audio, GPU nodes), because a Windows GUI app cannot function without them and
   Phase 4 verified they work (DXVK renders on real Wine). Each of network, display, audio, gpu and extra host
   directories is a switch in the profile.
3. `runtime permissions <app>` shows the profile; `--set` changes it (validated, atomic write, refused while the
   app runs); `--reset` restores the default. `runtime sandbox <app>` prints exactly the `bwrap` command line a run
   would use and whether the host can sandbox at all, without starting anything.
4. No silent fallback: if `bwrap` is missing or cannot create the sandbox, `run` fails with an install hint;
   `runtime run --unsandboxed` is the explicit, per-invocation escape hatch and says so on stderr.
5. All Phase 2-4 real-Wine exit apps (console fixtures, GUI headless where CI runs it, installers, DXVK D3D11
   fixture) still work under the default sandbox, and an escape-attempt suite passes: a program inside cannot read
   `~/.ssh`-like files in the real home, cannot write outside its prefix/home, cannot see other apps' prefixes,
   cannot rewrite its own `permissions.toml`, cannot reach the network when denied.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Profile storage | `<app root>/permissions.toml`, strict TOML (`deny_unknown_fields`, size cap), NOT bound into the sandbox | Same embedded-TOML discipline as the manifest; unbound so a malicious app cannot widen its own profile. |
| Default | network deny; display, audio, gpu allow; no host dirs | Least privilege that still runs GUI apps; roadmap: "never a silent default" for anything broader. |
| Unsupported | camera and USB have no keys: they are always denied and `--set camera=...` is an error | Nothing implements them; an accepted-but-ignored key would be a lie. |
| Host directory grants | `filesystem = [{path, access = "ro"|"rw"}]`; refuse `/`, `$HOME` itself, paths at or above/below the runtime data root, and a fixed sensitive list (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.password-store`, the runtime's own dirs) | A profile must not be able to re-expose the secrets the sandbox exists to hide, even by user error. |
| Sandbox hook | A new crate `crates/sandbox` (`rt_sandbox`): `Permissions` model + `AppSandbox` implementing `rt_core::Sandbox`; it derives the app from the command's `WINEPREFIX` | Works for installed apps AND `run <file>` (no AppEnv needed); keeps `InstallerSandbox` untouched. |
| Where it attaches | Only the final app spawn (`RunOptions` gains an optional sandbox); prepare/`wineboot`/`wineserver -k` helpers stay on the plain launcher | A sandboxed `wineserver -k` would run in a fresh PID namespace and never see the app's wineserver. |
| Terminal | `--new-session` (blocks TIOCSTI injection into the host tty); `runtime run` keeps Ctrl-C working by forwarding SIGINT/SIGTERM to the sandbox's process group | Otherwise the app is outside the foreground group and Ctrl-C dies silently. Verified in Task 3, not assumed. |

Non-goals here: seccomp, Landlock, cgroup limits (5B); portals and interactive "ask" prompts (5C); per-file
ACLs; network filtering by host/port; the installer sandbox (unchanged).

## 3. Components

- `crates/sandbox/src/permissions.rs`: `Permissions { network: Network, display, audio, gpu: bool, filesystem: Vec<FsGrant> }`,
  `parse`/`to_toml`/`default()`, path validation (`validate_grant(path, home, data_root) -> Result<PathBuf, _>`),
  `apply_set(&mut Permissions, &str)` for the `--set` mini-language: `network=allow|deny`, `display|audio|gpu=on|off`,
  `fs+=<abs path>:ro|rw`, `fs-=<abs path>`. Load/store with the same no-follow, size-capped, atomic-write helpers
  the metadata uses.
- `crates/sandbox/src/render.rs`: `AppSandbox::wrap(cmd) -> Command` (pure argv builder over an injected `Host`
  view: env lookup and `exists`), the bwrap profile: `--die-with-parent --new-session --unshare-pid --unshare-uts
  --unshare-ipc [--unshare-net]`, fresh `/proc`, `/dev` (+ dev-bind of `/dev/dri`, `/dev/nvidia*` when `gpu`, plus
  read-only `/sys` device nodes Mesa reads), private `/tmp`, read-only system binds (the installer sandbox's
  `RO_BINDS`, the Wine dll dirs, the small set of `/etc` files Wine and TLS need), the prefix and the app's
  `runtime/home` read-write (NOT the app root), an empty runtime dir with only the granted sockets bound
  (Wayland socket, X11 socket dir + Xauthority, `pulse/native`), granted host directories, and the host environment
  reduced to the launcher's allowlist plus exactly what each granted feature needs.
- `crates/sandbox/src/lib.rs`: `find_bwrap`, `probe()` that really tries `bwrap --unshare-all ... true` once so
  `runtime sandbox` and `doctor` can say "cannot create user namespaces" instead of failing on first run.
- `crates/core/src/run.rs`: `RunOptions.sandbox: Option<Arc<dyn Sandbox>>` applied to the app spawn only.
- CLI: `permissions`, `sandbox`, `run --unsandboxed`; doctor: one "Sandbox" check (bwrap present and working,
  active profile summary for an app).

## 4. Testing

Pure renderer tests over `Command` introspection for every switch and refusal; permission parser hostile tests;
real-bwrap tests (skipped with a visible message when bwrap or user namespaces are missing, required in CI via
`RUNTIME_REQUIRE_BWRAP=1`) for the escape suite; the existing real-Wine e2e apps re-run with the sandbox on.

## 5. Risks

- GPU/audio/display pass-through under bwrap is the fiddly part (roadmap): verified on this host (Wayland session,
  AMD + NVIDIA + llvmpipe, PulseAudio-compatible socket) with the D3D11 fixture; other hosts are covered by
  `runtime sandbox` output and `doctor`, not by CI.
- NVIDIA proprietary nodes and driver library locations vary; missing optional nodes are skipped
  (`--dev-bind-try`), and GPU trouble is diagnosable with `runtime sandbox <app>` and `--unsandboxed`.
- Wine binaries outside `/usr` (WineHQ `/opt/wine-*`) must be bound via the backend's dll dirs, as the installer
  sandbox already notes.
