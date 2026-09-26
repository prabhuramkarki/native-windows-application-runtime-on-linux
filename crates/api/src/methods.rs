//! The host-fact methods of [`Runtime`]: `doctor`, `graphics_info`, `sandbox_info`, `deps_plan`. They gather through
//! [`crate::host`] exactly what the CLI's `doctor`, `graphics info`, `sandbox <app>` and `deps <app>` gather, and
//! return it cleaned. Nothing is written, no Wine session starts and nothing is downloaded; the only processes are
//! the bounded host probes (`vulkaninfo`, bwrap's probe, the `systemd-run` scope probe, `wine --version`).
//!
//! **Probe freshness.** The Vulkan probe is cached per `Runtime` for [`PROBE_TTL`] (`rt_core::Cached`), the
//! `systemd-run` scope probe process-wide for the same time (`rt_sandbox::RealHost::scopes`); the bwrap probe, the
//! hardening probe and Wine discovery run on every call. A long-lived daemon therefore never serves a host fact
//! older than 30 s.
use crate::error::ApiError;
use crate::host;
use crate::runtime::{Runtime, unavailable};
use crate::types::*;
use rt_core::{HostVulkan, host_verdict};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a host probe result is reused.
pub const PROBE_TTL: Duration = Duration::from_secs(30);

impl Runtime {
    /// The host's Vulkan, probed at most once per [`PROBE_TTL`].
    fn vulkan(&self) -> Arc<HostVulkan> {
        self.vulkan.get_at(Instant::now(), self.vulkan_probe)
    }

    /// `runtime doctor [<app>]`: the same checks, areas, statuses and verdict. An app id must be valid
    /// (`invalid_argument`) and installed (`not_found`); everything wrong with the app itself is a check, not an
    /// error (a missing Wine too: a failing check with the install hint).
    pub fn doctor(&self, target: DoctorTarget) -> Result<DoctorView, ApiError> {
        let vulkan = self.vulkan();
        let verdict = |min| host_verdict(&vulkan, min);
        let facts = match target {
            DoctorTarget::System => host::doctor::Facts::system(),
            DoctorTarget::App(id) => {
                let env = self.env(&id)?;
                host::doctor::Facts::app(&self.store, env.id(), &verdict)
            }
        };
        let report = host::doctor::report(&facts, &vulkan);
        Ok(DoctorView::from_report(&report, facts.plan.as_ref()))
    }

    /// `runtime graphics info`: the Vulkan devices and whether they meet each bundled package's minimum.
    pub fn graphics_info(&self) -> GraphicsView {
        GraphicsView::from_host(&self.vulkan(), &host::graphics::bundled_needs())
    }

    /// `runtime sandbox <app>`. A profile that cannot be used, a program that cannot be resolved or a command
    /// Wine cannot build is `unavailable` (never replaced by a default); a missing bwrap or Wine is part of the
    /// answer.
    pub fn sandbox_info(&self, id: &str) -> Result<SandboxView, ApiError> {
        let env = self.env(id)?;
        let st = host::sandbox::status(&self.store, &env).map_err(unavailable)?;
        let source = if st.source == "default" {
            PermSource::Default
        } else {
            PermSource::File
        };
        Ok(SandboxView::from_status(&st, source))
    }

    /// `runtime deps <app>` without `--install`: the plan (reads the metadata and the executable; the Vulkan probe
    /// runs only if a package needs Vulkan).
    pub fn deps_plan(&self, id: &str) -> Result<DepsPlanView, ApiError> {
        let env = self.env(id)?;
        let md = self.store.read_metadata(&env).map_err(unavailable)?;
        let manifest = rt_deps::Manifest::bundled();
        let plan = rt_deps::plan_for_app(&env, &md, manifest, &|min| host_verdict(&self.vulkan(), min));
        Ok(DepsPlanView::from_plan(&plan, manifest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use rt_core::{AppId, BackendInfo, Metadata, Store, VulkanDevice, WinPath, is_format};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/build")
            .join(name);
        fs::read(&p).unwrap_or_else(|e| panic!("fixture {} ({e}): run tools/build-fixtures.sh", p.display()))
    }

    fn gpu(api: (u32, u32)) -> HostVulkan {
        HostVulkan {
            tool_found: true,
            loader_found: true,
            devices: vec![VulkanDevice {
                name: "fake\u{202e}gpu".into(),
                device_type: "PHYSICAL_DEVICE_TYPE_DISCRETE_GPU".into(),
                api,
                driver: "drv\u{1b}[31m".into(),
            }],
        }
    }

    fn rt(probe: fn() -> HostVulkan) -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("apps")).unwrap();
        let mut rt = Runtime::with_store(store);
        rt.vulkan_probe = probe;
        (dir, rt)
    }

    /// Installs `bytes` as `C:\Program Files\<id>\game.exe` of a new app `id` (a prefix with just that file).
    fn app(rt: &Runtime, id: &str, bytes: &[u8]) {
        let id = AppId::parse(id).unwrap();
        let env = rt.store.create(&id).unwrap();
        let dir = env.drive_c().join("Program Files").join(id.as_str());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("game.exe"), bytes).unwrap();
        let exe = WinPath::parse(&format!(r"C:\Program Files\{id}\game.exe")).unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: "wine-10.0".into(),
        };
        let md = Metadata::new(id, "Game".into(), None, "x86_64", &exe, backend, "console");
        rt.store.write_metadata(&env, &md).unwrap();
    }

    /// `hello64.exe` with its `msvcrt.dll` import renamed to `d3d11.dll`: the plan is DXVK.
    fn d3d11_exe() -> Vec<u8> {
        let mut b = fixture("hello64.exe");
        let at = b
            .windows(11)
            .position(|w| w.eq_ignore_ascii_case(b"msvcrt.dll\0"))
            .unwrap();
        b[at..at + 11].copy_from_slice(b"d3d11.dll\0\0");
        b
    }

    /// Every entry below `root` with its type, size, mode and mtime.
    fn tree(root: &Path) -> Vec<String> {
        use std::os::unix::fs::MetadataExt;
        let mut out = vec![];
        let mut todo = vec![root.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in fs::read_dir(&d).into_iter().flatten().flatten() {
                let m = fs::symlink_metadata(e.path()).unwrap();
                out.push(format!(
                    "{} {:o} {} {}.{}",
                    e.path().display(),
                    m.mode(),
                    m.len(),
                    m.mtime(),
                    m.mtime_nsec()
                ));
                if m.is_dir() {
                    todo.push(e.path());
                }
            }
        }
        out.sort();
        out
    }

    fn clean(s: &str) -> bool {
        !s.chars().any(|c| c.is_control() || is_format(c))
    }

    #[test]
    fn deps_plan_is_the_plan_the_cli_prints_and_writes_nothing() {
        let (d, rt) = rt(|| gpu((1, 3)));
        app(&rt, "game", &d3d11_exe());
        let before = tree(d.path());
        let v = rt.deps_plan("game").unwrap();
        assert_eq!(tree(d.path()), before, "deps_plan wrote something");
        // What `runtime deps` formats: the same plan function over the same app.
        let store = Store::new(d.path().join("apps")).unwrap();
        let env = store.get(&AppId::parse("game").unwrap()).unwrap();
        let md = store.read_metadata(&env).unwrap();
        let m = rt_deps::Manifest::bundled();
        let want = rt_deps::plan_for_app(&env, &md, m, &|min| host_verdict(&gpu((1, 3)), min));
        assert_eq!(v, DepsPlanView::from_plan(&want, m));
        assert_eq!(v.entries.len(), 1);
        let e = &v.entries[0];
        assert_eq!(
            (e.package.as_str(), e.action, e.consent, e.blocked_reason.as_deref()),
            ("dxvk", PlanAction::Install, ConsentView::NotNeeded, None)
        );
        assert_eq!(e.version.as_deref(), Some(m.get("dxvk").unwrap().version.as_str()));
    }

    #[test]
    fn deps_plan_blocks_dxvk_without_a_usable_vulkan_and_says_why() {
        let (_d, rt) = rt(|| gpu((1, 1)));
        app(&rt, "game", &d3d11_exe());
        let v = rt.deps_plan("game").unwrap();
        assert_eq!(v.entries[0].action, PlanAction::Blocked);
        let why = v.entries[0].blocked_reason.as_deref().unwrap();
        assert!(why.contains("no Vulkan device supports API 1.3 (best is 1.1)"), "{why}");
    }

    #[test]
    fn deps_plan_errors_have_kinds() {
        let (_d, rt) = rt(|| gpu((1, 3)));
        assert_eq!(rt.deps_plan("a/b").unwrap_err().kind, ErrorKind::InvalidArgument);
        assert_eq!(rt.deps_plan("nope").unwrap_err().kind, ErrorKind::NotFound);
        app(&rt, "x", b"MZ");
        let env = rt.store.get(&AppId::parse("x").unwrap()).unwrap();
        fs::write(env.metadata_path(), "{").unwrap();
        assert_eq!(rt.deps_plan("x").unwrap_err().kind, ErrorKind::Unavailable);
    }

    #[test]
    fn deps_plan_of_a_program_that_cannot_be_read_says_so_in_a_warning() {
        let (_d, rt) = rt(|| gpu((1, 3)));
        app(&rt, "broken", "not a program \x1b[31m\u{202e}".as_bytes());
        let v = rt.deps_plan("broken").unwrap();
        assert!(v.entries.is_empty());
        assert!(!v.warnings.is_empty(), "{v:?}");
        assert!(v.warnings.iter().all(|w| clean(w)), "{v:?}");
    }

    #[test]
    fn graphics_info_reports_the_injected_probe_cleaned() {
        let (_d, rt) = rt(|| gpu((1, 3)));
        let g = rt.graphics_info();
        assert_eq!(g.verdict, VulkanState::Usable);
        assert_eq!(
            g.devices,
            vec![GpuView {
                name: "fakegpu".into(),
                device_type: "DISCRETE_GPU".into(),
                api: "1.3".into(),
                driver: "drv[31m".into()
            }]
        );
        assert!(g.loader && g.tool_found && g.reason.is_none());
        let needs = host::graphics::bundled_needs();
        assert_eq!(g.per_package.len(), needs.len());
        assert!(g.per_package.iter().all(|p| p.ok == Some(true)), "{g:?}");
        // Below the minimum: unusable, each package not met.
        let (_d, rt) = self::rt(|| gpu((1, 1)));
        let g = rt.graphics_info();
        assert_eq!(g.verdict, VulkanState::Unusable);
        assert!(g.reason.as_deref().unwrap().contains("best is 1.1"), "{g:?}");
        assert!(g.per_package.iter().all(|p| p.ok == Some(false)), "{g:?}");
        // No loader (what `RUNTIME_VULKAN_LOADER=absent` gives the real probe): unusable, the tool never ran.
        let (_d, rt) = self::rt(|| rt_core::probe_host(&|| panic!("the tool must not run"), false));
        let g = rt.graphics_info();
        assert_eq!(
            (g.verdict, g.loader, g.tool_found),
            (VulkanState::Unusable, false, false)
        );
        // The tool gave nothing: unknown, never blocking.
        let (_d, rt) = self::rt(|| rt_core::probe_host(&|| None, true));
        let g = rt.graphics_info();
        assert_eq!(g.verdict, VulkanState::Unknown);
        assert!(g.per_package.iter().all(|p| p.ok.is_none()));
    }

    static PROBES: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn the_vulkan_probe_is_shared_by_calls_within_its_ttl() {
        let (_d, rt) = rt(|| {
            PROBES.fetch_add(1, Ordering::SeqCst);
            gpu((1, 3))
        });
        app(&rt, "game", &d3d11_exe());
        rt.graphics_info();
        rt.graphics_info();
        rt.deps_plan("game").unwrap();
        assert_eq!(PROBES.load(Ordering::SeqCst), 1, "one probe for three calls");
        // Expiry itself is `rt_core::Cached`'s (tested there with an injected clock); the TTL is 30 s.
        assert_eq!(PROBE_TTL, Duration::from_secs(30));
    }

    #[test]
    fn deps_plan_without_a_package_that_needs_vulkan_never_probes() {
        let (_d, rt) = rt(|| panic!("probed although nothing needs Vulkan"));
        app(&rt, "plain", &fixture("hello64.exe"));
        assert!(rt.deps_plan("plain").unwrap().entries.is_empty());
    }

    #[test]
    fn sandbox_info_refuses_an_invalid_profile_instead_of_the_default() {
        let (_d, rt) = rt(|| gpu((1, 3)));
        app(&rt, "p", &fixture("hello64.exe"));
        let env = rt.store.get(&AppId::parse("p").unwrap()).unwrap();
        fs::write(env.root().join("permissions.toml"), "version = 1\nbogus = 1\n").unwrap();
        let e = rt.sandbox_info("p").unwrap_err();
        assert_eq!(e.kind, ErrorKind::Unavailable);
        assert!(e.message.contains("permissions.toml is refused"), "{}", e.message);
        assert_eq!(rt.sandbox_info("nope").unwrap_err().kind, ErrorKind::NotFound);
        assert_eq!(rt.sandbox_info("..").unwrap_err().kind, ErrorKind::InvalidArgument);
        assert_eq!(
            rt.doctor(DoctorTarget::App("nope".into())).unwrap_err().kind,
            ErrorKind::NotFound
        );
        assert_eq!(
            rt.doctor(DoctorTarget::App("a b".into())).unwrap_err().kind,
            ErrorKind::InvalidArgument
        );
    }

    #[test]
    fn the_new_views_round_trip_in_camel_case() {
        let (_d, rt) = rt(|| gpu((1, 1)));
        app(&rt, "game", &d3d11_exe());
        let j = serde_json::to_value(rt.deps_plan("game").unwrap()).unwrap();
        assert_eq!(j["entries"][0]["action"], "blocked");
        assert_eq!(j["entries"][0]["consent"], "notNeeded");
        assert!(j["entries"][0]["blockedReason"].is_string());
        let _: DepsPlanView = serde_json::from_value(j).unwrap();
        let j = serde_json::to_value(rt.graphics_info()).unwrap();
        assert_eq!(j["verdict"], "unusable");
        assert!(j["perPackage"][0]["minVulkan"].is_string() && j["toolFound"].is_boolean());
        let _: GraphicsView = serde_json::from_value(j).unwrap();
        for t in [DoctorTarget::System, DoctorTarget::App("x".into())] {
            let j = serde_json::to_value(&t).unwrap();
            assert_eq!(serde_json::from_value::<DoctorTarget>(j).unwrap(), t);
        }
        let v = DoctorView {
            subject: SubjectView::App {
                id: "a".into(),
                name: None,
                version: Some("1".into()),
            },
            verdict: "may_fail".into(),
            checks: vec![CheckView {
                area: "graphics".into(),
                status: "warn".into(),
                text: "t".into(),
            }],
            missing_dependencies: 1,
            notes: vec![],
        };
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(j["subject"]["kind"], "app");
        assert!(j["missingDependencies"].is_number());
        assert_eq!(serde_json::from_value::<DoctorView>(j).unwrap(), v);
        let a = Availability::Unavailable { reason: "r".into() };
        let j = serde_json::to_value(&a).unwrap();
        assert_eq!(
            (j["state"].as_str(), j["reason"].as_str()),
            (Some("unavailable"), Some("r"))
        );
        assert_eq!(serde_json::from_value::<Availability>(j).unwrap(), a);
    }
}
