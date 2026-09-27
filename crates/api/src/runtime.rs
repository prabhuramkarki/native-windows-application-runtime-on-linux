//! [`Runtime`]: the read-only methods. Nothing here writes or locks; everything read is untrusted. The methods
//! that gather host facts (and start the bounded host probes) are in [`crate::methods`].
use crate::error::{ApiError, ErrorKind};
use crate::types::*;
use crate::{API_VERSION, PROTOCOL};
use rt_core::{AppEnv, AppId, Store, StoreError};
use rt_sandbox::{GrantCtx, load_opt};

pub struct Runtime {
    pub(crate) store: Store,
    /// The host's Vulkan, probed at most once per `methods::PROBE_TTL`.
    pub(crate) vulkan: rt_core::Cached<rt_core::HostVulkan>,
    /// How the host's Vulkan is probed (tests inject one).
    pub(crate) vulkan_probe: fn() -> rt_core::HostVulkan,
    /// The `runtime` binary `sandbox_info` names as the sandbox's shim; `None`: this process (right for the CLI).
    pub(crate) runtime_exe: Option<std::path::PathBuf>,
}

// The daemon shares one `Runtime` between connection threads.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<Runtime>()
};

pub(crate) fn unavailable(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorKind::Unavailable, e.to_string())
}

impl Runtime {
    /// The store at the user's apps directory (`rt_core::apps_dir`).
    pub fn open() -> Result<Runtime, ApiError> {
        let dir = rt_core::apps_dir().map_err(unavailable)?;
        Ok(Runtime::with_store(Store::new(dir).map_err(unavailable)?))
    }

    pub fn with_store(store: Store) -> Runtime {
        Runtime {
            store,
            vulkan: rt_core::Cached::new(crate::methods::PROBE_TTL),
            vulkan_probe: crate::host::graphics::probe,
            runtime_exe: None,
        }
    }

    /// Names `exe` (the `runtime` binary) as the sandbox's `sandbox-init` shim in `sandbox_info`. A caller that is
    /// not `runtime` itself (a daemon, a GUI) must set it: by default the calling executable is named.
    pub fn with_runtime_exe(mut self, exe: std::path::PathBuf) -> Runtime {
        self.runtime_exe = Some(exe);
        self
    }

    pub fn version(&self) -> VersionInfo {
        VersionInfo {
            api: API_VERSION.to_owned(),
            runtime: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: PROTOCOL.to_owned(),
            write: false,
        }
    }

    /// Every usable app; entries that are not one are counted in `skipped`.
    pub fn apps(&self) -> AppList {
        let mut apps = Vec::new();
        let mut skipped = 0;
        for entry in self.store.list() {
            match entry {
                Ok((_, md)) => apps.push(AppSummary::from_metadata(&md)),
                Err(_) => skipped += 1,
            }
        }
        AppList { apps, skipped }
    }

    /// `id` must be a valid `AppId` (`invalid_argument`) naming an installed app (`not_found`) whose metadata
    /// reads (`unavailable`).
    pub(crate) fn env(&self, id: &str) -> Result<AppEnv, ApiError> {
        let id = AppId::parse(id)
            .map_err(|e| ApiError::new(ErrorKind::InvalidArgument, format!("not a valid app id: {e}")))?;
        self.store.get(&id).map_err(|e| match e {
            StoreError::NotFound => ApiError::new(ErrorKind::NotFound, format!("no app named {id} is installed")),
            e => unavailable(e),
        })
    }

    /// Metadata, recorded dependencies, installer info and whether the prefix exists (never its contents).
    pub fn app(&self, id: &str) -> Result<AppDetail, ApiError> {
        let env = self.env(id)?;
        let md = self.store.read_metadata(&env).map_err(unavailable)?;
        Ok(AppDetail::from_parts(&env, &md))
    }

    /// The profile `runtime permissions` shows, through the same loader and context. A profile that cannot be
    /// used is `unavailable`, never replaced by the default.
    pub fn permissions(&self, id: &str) -> Result<PermissionsView, ApiError> {
        let env = self.env(id)?;
        let ctx = GrantCtx::from_env().map_err(unavailable)?;
        self.permissions_with(&env, &ctx)
    }

    fn permissions_with(&self, env: &AppEnv, ctx: &GrantCtx) -> Result<PermissionsView, ApiError> {
        let loaded = load_opt(env.root(), ctx).map_err(unavailable)?;
        let source = if loaded.is_some() {
            PermSource::File
        } else {
            PermSource::Default
        };
        let profile = loaded.unwrap_or_default();
        let mut view = PermissionsView::from_profile(&profile, source);
        // Informational: unreadable metadata only means no requests are shown (the profile is what matters).
        if let Some(pkg) = self.store.read_metadata(env).ok().and_then(|md| md.package) {
            view.requested = requests_not_granted(&profile, &pkg.requested_permissions);
        }
        Ok(view)
    }

    pub fn compat(&self) -> CompatView {
        CompatView {
            records: crate::compat::bundled()
                .records
                .iter()
                .map(CompatRecord::from_record)
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::{BackendInfo, DependencyRecord, InstallerMeta, Metadata, WinPath, is_format};
    use rt_sandbox::Permissions;
    use std::path::Path;

    fn rt() -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("apps")).unwrap();
        (dir, Runtime::with_store(store))
    }

    fn add(rt: &Runtime, id: &str, tweak: impl FnOnce(&mut Metadata)) -> AppEnv {
        let id = AppId::parse(id).unwrap();
        let env = rt.store.create(&id).unwrap();
        let exe = WinPath::parse(r"C:\app\a.exe").unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: "10.0".into(),
        };
        let mut md = Metadata::new(id, "App".into(), Some("1.0".into()), "x86_64", &exe, backend, "gui");
        tweak(&mut md);
        rt.store.write_metadata(&env, &md).unwrap();
        env
    }

    fn ctx(dir: &Path) -> GrantCtx {
        GrantCtx {
            home: dir.join("home"),
            extra_homes: vec![],
            data_root: dir.join("data"),
            runtime_dir: None,
        }
    }

    fn clean(s: &str) -> bool {
        !s.chars().any(|c| c.is_control() || is_format(c))
    }

    /// A legal `WinPath` component (no control characters) that still carries a bidi override and zero-width.
    const HOSTILE_FILE: &str = "x\u{202e}y\u{200b}z";
    const HOSTILE: &str = "a\x1b[31m\u{202e}b\u{200b}c\nd\u{0085}e";

    #[test]
    fn apps_counts_skipped_entries() {
        let (dir, rt) = rt();
        for id in ["one", "two", "three"] {
            add(&rt, id, |_| {});
        }
        let apps = dir.path().join("apps");
        std::fs::create_dir(apps.join("corrupt")).unwrap();
        std::fs::write(apps.join("corrupt/metadata.json"), "{nope").unwrap();
        let list = rt.apps();
        assert_eq!((list.apps.len(), list.skipped), (3, 1));
        assert_eq!(list.apps[0].id, "one");
        let (_d, empty) = self::rt();
        assert_eq!(
            empty.apps(),
            AppList {
                apps: vec![],
                skipped: 0
            }
        );
    }

    #[test]
    fn bad_and_unknown_ids_have_distinct_kinds() {
        let (_d, rt) = rt();
        for bad in ["bad/../id", "", "..", "A B", "a\0b"] {
            assert_eq!(rt.app(bad).unwrap_err().kind, ErrorKind::InvalidArgument, "{bad:?}");
            assert_eq!(rt.permissions(bad).unwrap_err().kind, ErrorKind::InvalidArgument);
        }
        assert_eq!(rt.app("nope").unwrap_err().kind, ErrorKind::NotFound);
        assert_eq!(rt.permissions("nope").unwrap_err().kind, ErrorKind::NotFound);
    }

    #[test]
    fn corrupt_metadata_is_unavailable() {
        let (_d, rt) = rt();
        let env = add(&rt, "x", |_| {});
        std::fs::write(env.metadata_path(), "{nope").unwrap();
        assert_eq!(rt.app("x").unwrap_err().kind, ErrorKind::Unavailable);
    }

    #[test]
    fn every_returned_string_is_cleaned_and_bounded() {
        let (_d, rt) = rt();
        let long = format!("{HOSTILE}{}", "z".repeat(900));
        let env = add(&rt, "h", |m| {
            m.name = HOSTILE.into();
            m.executable = format!("C:\\a\\{HOSTILE_FILE}{}.exe", "e".repeat(200));
            m.version = Some(long.clone());
            m.environment = HOSTILE.into();
            m.subsystem = HOSTILE.into();
            m.backend = BackendInfo {
                id: HOSTILE.into(),
                version: long.clone(),
            };
            m.installer = Some(InstallerMeta {
                family: HOSTILE.into(),
                product_name: Some(long.clone()),
                uninstall_command: Some(format!("{HOSTILE}{}", "u".repeat(2000)).chars().take(1000).collect()),
            });
            m.dependencies = vec![DependencyRecord {
                id: HOSTILE.into(),
                version: long.clone(),
                sha256: "0".repeat(64),
                installed_at: 7,
                consent: None,
            }];
        });
        let d = rt.app("h").unwrap();
        let mut all = vec![
            d.name,
            d.architecture,
            d.executable.clone(),
            d.environment,
            d.backend.id,
            d.backend.version,
            d.subsystem,
            d.version.clone().unwrap(),
        ];
        let i = d.installer.unwrap();
        all.extend([i.family, i.product_name.unwrap(), i.uninstall_command.unwrap()]);
        all.extend([d.dependencies[0].id.clone(), d.dependencies[0].version.clone()]);
        for s in &all {
            assert!(clean(s), "{s:?}");
            assert!(s.len() <= LONG_MAX, "{} bytes", s.len());
        }

        assert!(d.version.unwrap().len() <= TEXT_MAX);
        assert!(d.dependencies[0].version.len() <= TEXT_MAX);
        assert!(
            d.executable.starts_with(r"C:\a\xyz") && !d.executable.contains('\u{202e}'),
            "{}",
            d.executable
        );
        assert!(i_product_name_is_cleaned(&rt));
        let s = &rt.apps().apps[0];
        assert!(clean(&s.name) && s.version.as_deref().is_some_and(clean));
        // the bare (non-hostile) case is untouched
        std::fs::remove_dir_all(env.root()).unwrap();
        add(&rt, "p", |_| {});
        let p = rt.app("p").unwrap();
        assert_eq!((p.name.as_str(), p.version.as_deref()), ("App", Some("1.0")));
        assert_eq!(p.executable, r"C:\app\a.exe");
    }

    fn i_product_name_is_cleaned(rt: &Runtime) -> bool {
        let i = rt.app("h").unwrap().installer.unwrap();
        clean(&i.product_name.unwrap())
    }

    #[test]
    fn app_reports_dependencies_installer_and_prefix_state() {
        let (_d, rt) = rt();
        let env = add(&rt, "a", |m| {
            m.dependencies = vec![DependencyRecord {
                id: "vcrun2022".into(),
                version: "14.3".into(),
                sha256: "0".repeat(64),
                installed_at: 5,
                consent: None,
            }];
        });
        let d = rt.app("a").unwrap();
        assert_eq!(
            d.dependencies,
            vec![DependencyView {
                id: "vcrun2022".into(),
                version: "14.3".into(),
                installed_at: 5
            }]
        );
        assert!(d.installer.is_none());
        assert_eq!(
            d.prefix,
            PrefixState {
                exists: false,
                has_drive_c: false
            }
        );
        std::fs::create_dir_all(env.drive_c()).unwrap();
        assert_eq!(
            rt.app("a").unwrap().prefix,
            PrefixState {
                exists: true,
                has_drive_c: true
            }
        );
    }

    #[test]
    fn a_symlink_never_counts_as_the_prefix_or_drive_c() {
        let (_d, rt) = rt();
        let env = add(&rt, "a", |_| {});
        let none = PrefixState {
            exists: false,
            has_drive_c: false,
        };
        // prefix -> a directory that DOES hold a drive_c: absent, and the target is not probed
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(outside.path().join("drive_c")).unwrap();
        std::os::unix::fs::symlink(outside.path(), env.prefix()).unwrap();
        assert_eq!(rt.app("a").unwrap().prefix, none);
        // prefix -> a directory without drive_c
        std::fs::remove_file(env.prefix()).unwrap();
        std::os::unix::fs::symlink("/tmp", env.prefix()).unwrap();
        assert_eq!(rt.app("a").unwrap().prefix, none);
        // a real prefix whose drive_c is a symlink to a real directory
        std::fs::remove_file(env.prefix()).unwrap();
        std::fs::create_dir(env.prefix()).unwrap();
        std::os::unix::fs::symlink(outside.path().join("drive_c"), env.drive_c()).unwrap();
        assert_eq!(
            rt.app("a").unwrap().prefix,
            PrefixState {
                exists: true,
                has_drive_c: false
            }
        );
    }

    #[test]
    fn permissions_matrix() {
        let (d, rt) = rt();
        let env = add(&rt, "p", |_| {});
        let ctx = ctx(d.path());
        let file = env.root().join("permissions.toml");
        let view = |rt: &Runtime| rt.permissions_with(&env, &ctx);

        let v = view(&rt).unwrap(); // no file
        assert_eq!(v.source, PermSource::Default);
        assert_eq!(v.network, NetworkView::Deny);
        assert!(v.display && v.audio && v.gpu && v.filesystem.is_empty());
        assert_eq!(
            v.limits,
            LimitsView {
                memory_mb: None,
                cpu_percent: None,
                tasks: Some(4096),
                tasks_default: true,
                explicit: false
            }
        );

        std::fs::write(
            &file,
            "version = 1\nnetwork = \"allow\"\ngpu = false\n[limits]\nmemory_mb = 512\ntasks = 100\n",
        )
        .unwrap();
        let v = view(&rt).unwrap(); // valid file
        assert_eq!(
            (v.source, v.network, v.gpu),
            (PermSource::File, NetworkView::Allow, false)
        );
        assert_eq!(
            v.limits,
            LimitsView {
                memory_mb: Some(512),
                cpu_percent: None,
                tasks: Some(100),
                tasks_default: false,
                explicit: true
            }
        );

        std::fs::write(&file, "version = 1\nbogus = 1\n").unwrap(); // invalid
        assert_eq!(view(&rt).unwrap_err().kind, ErrorKind::Unavailable);

        std::fs::write(&file, format!("version = 1\n# {}\n", "x".repeat(70_000))).unwrap(); // oversized
        assert_eq!(view(&rt).unwrap_err().kind, ErrorKind::Unavailable);

        std::fs::remove_file(&file).unwrap(); // symlinked
        let real = d.path().join("real.toml");
        std::fs::write(&real, "version = 1\n").unwrap();
        std::os::unix::fs::symlink(&real, &file).unwrap();
        assert_eq!(view(&rt).unwrap_err().kind, ErrorKind::Unavailable);
    }

    #[test]
    fn permissions_lists_grants() {
        let (d, rt) = rt();
        let env = add(&rt, "g", |_| {});
        // /tmp is never grantable; /var/tmp is.
        let Ok(vt) = tempfile::tempdir_in("/var/tmp") else {
            eprintln!("SKIPPED permissions_lists_grants: /var/tmp is not a writable directory");
            return;
        };
        let saves = vt.path().join("saves");
        std::fs::create_dir(&saves).unwrap();
        std::fs::write(
            env.root().join("permissions.toml"),
            format!(
                "version = 1\n[[filesystem]]\npath = {:?}\naccess = \"rw\"\n",
                saves.to_str().unwrap()
            ),
        )
        .unwrap();
        let v = rt.permissions_with(&env, &ctx(d.path())).unwrap();
        assert_eq!(v.filesystem.len(), 1);
        assert_eq!(v.filesystem[0].access, AccessView::Rw);
        assert!(v.filesystem[0].path.ends_with("saves"));
    }

    #[test]
    fn compat_equals_the_bundled_records() {
        let (_d, rt) = rt();
        let c = rt.compat();
        let b = crate::compat::bundled();
        assert_eq!(c.records.len(), b.records.len());
        assert!(!c.records.is_empty());
        assert_eq!(c.records[0].app, b.records[0].app);
        assert_eq!(c.records[0].status, b.records[0].status);
        // Whole, as `runtime compat --json` prints them (notes may be up to 300 bytes long).
        assert_eq!(
            c.records.iter().map(|r| &r.notes).collect::<Vec<_>>(),
            b.records.iter().map(|r| &r.notes).collect::<Vec<_>>()
        );
    }

    #[test]
    fn version_values() {
        let (_d, rt) = rt();
        let v = rt.version();
        assert_eq!(
            v,
            VersionInfo {
                api: "0.2.0".into(),
                runtime: env!("CARGO_PKG_VERSION").into(),
                protocol: "jsonrpc-2.0-ndjson".into(),
                write: false
            }
        );
    }

    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
        v: T,
    ) -> serde_json::Value {
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(serde_json::from_value::<T>(j.clone()).unwrap(), v);
        j
    }

    #[test]
    fn a_request_is_listed_until_the_profile_grants_it() {
        let all: Vec<String> = rt_core::REQUESTABLE_PERMISSIONS
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        // The default profile: network deny, display/audio/gpu on.
        assert_eq!(
            requests_not_granted(&Permissions::default(), &all),
            ["network=allow", "display=off", "audio=off", "gpu=off"]
        );
        let p = Permissions {
            network: rt_sandbox::Network::Allow,
            display: false,
            audio: false,
            gpu: false,
            ..Permissions::default()
        };
        assert_eq!(
            requests_not_granted(&p, &all),
            ["network=deny", "display=on", "audio=on", "gpu=on"]
        );
        assert_eq!(
            requests_not_granted(&p, &["bogus".into()]),
            ["bogus"],
            "an unknown EXPR is never granted"
        );
        assert!(requests_not_granted(&p, &[]).is_empty());
    }

    #[test]
    fn every_wire_type_round_trips_in_camel_case() {
        let (_d, rt) = rt();
        add(&rt, "r", |m| {
            m.installer = Some(InstallerMeta {
                family: "msi".into(),
                product_name: Some("P".into()),
                uninstall_command: None,
            });
            m.dependencies = vec![DependencyRecord {
                id: "d".into(),
                version: "1".into(),
                sha256: "0".repeat(64),
                installed_at: 1,
                consent: None,
            }];
            m.package = Some(rt_core::PackageMeta {
                id: "r".into(),
                version: "1.0".into(),
                digest: "ab".repeat(32),
                requested_dependencies: vec!["vcrun2022".into()],
                requested_permissions: vec!["network=allow".into()],
            });
        });
        round_trip(rt.version());
        let list = rt.apps();
        round_trip(list.apps[0].clone());
        round_trip(list.clone());
        let d = round_trip(rt.app("r").unwrap());
        assert!(d["installer"]["productName"].is_string() && d["prefix"]["hasDriveC"].is_boolean());
        assert!(d["dependencies"][0]["installedAt"].is_number());
        assert_eq!(d["package"]["requestedPermissions"][0], "network=allow");
        assert_eq!(d["package"]["requestedDependencies"][0], "vcrun2022");
        assert_eq!(d["package"]["digest"], "ab".repeat(32));
        let env = rt.env("r").unwrap();
        let p = rt.permissions_with(&env, &ctx(_d.path())).unwrap();
        let j = round_trip(p);
        assert_eq!(
            (j["source"].as_str(), j["network"].as_str()),
            (Some("default"), Some("deny"))
        );
        assert!(j["limits"]["tasksDefault"].is_boolean());
        assert_eq!(
            j["requested"],
            serde_json::json!(["network=allow"]),
            "requested, not granted"
        );
        round_trip(GrantView {
            path: "/x".into(),
            access: AccessView::Ro,
        });
        round_trip(rt.compat());
        round_trip(rt.compat().records[0].clone());
        for k in [
            ErrorKind::NotFound,
            ErrorKind::InvalidArgument,
            ErrorKind::Unavailable,
            ErrorKind::Internal,
            ErrorKind::ReadOnly,
            ErrorKind::ConsentMismatch,
            ErrorKind::Busy,
            ErrorKind::AppBusy,
        ] {
            let j = round_trip(ApiError::new(k, "m"));
            assert!(matches!(
                j["kind"].as_str(),
                Some(
                    "not_found"
                        | "invalid_argument"
                        | "unavailable"
                        | "internal"
                        | "read_only"
                        | "consent_mismatch"
                        | "busy"
                        | "app_busy"
                )
            ));
        }
        // A 0.1 daemon's version has no `write`: read as a read-only daemon.
        let old: VersionInfo = serde_json::from_str(r#"{"api":"0.1.0","runtime":"0","protocol":"p"}"#).unwrap();
        assert!(!old.write);
    }

    #[test]
    fn error_messages_are_cleaned_and_bounded() {
        let e = ApiError::new(ErrorKind::Internal, format!("{HOSTILE}{}", "m".repeat(2000)));
        assert!(clean(&e.message) && e.message.len() <= 512);
    }

    #[test]
    fn an_unknown_error_kind_still_deserialises() {
        let e: ApiError = serde_json::from_str(r#"{"kind":"some_future_kind","message":"x"}"#).unwrap();
        assert_eq!((e.kind, e.message.as_str()), (ErrorKind::Unknown, "x"));
    }

    #[test]
    fn grant_paths_are_cleaned() {
        let p = rt_sandbox::Permissions {
            filesystem: vec![rt_sandbox::FsGrant {
                path: format!("/a/b{HOSTILE}c").into(),
                access: rt_sandbox::Access::Rw,
            }],
            ..Default::default()
        };
        let v = PermissionsView::from_profile(&p, PermSource::File);
        assert_eq!(v.filesystem[0].path, "/a/ba[31mbcde".to_owned() + "c");
    }

    #[test]
    fn path_bound_shows_a_maximal_grant_path_whole() {
        let p = format!("/{}", "d".repeat(PATH_MAX - 1));
        let v = PermissionsView::from_profile(
            &rt_sandbox::Permissions {
                filesystem: vec![rt_sandbox::FsGrant {
                    path: p.clone().into(),
                    access: rt_sandbox::Access::Ro,
                }],
                ..Default::default()
            },
            PermSource::File,
        );
        assert_eq!(v.filesystem[0].path, p);
    }

    /// Every string of every result (keys too) is free of control and format characters. A string field added
    /// to a wire type must be filled with hostile text here, or this guard proves nothing about it.
    fn walk(v: &serde_json::Value, at: &str) {
        match v {
            serde_json::Value::String(s) => assert!(clean(s), "{at}: {s:?}"),
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, at)),
            serde_json::Value::Object(o) => o.iter().for_each(|(k, x)| {
                assert!(clean(k), "{at}: key {k:?}");
                walk(x, k);
            }),
            _ => {}
        }
    }

    #[test]
    fn no_string_anywhere_holds_an_invisible_character() {
        let (d, mut rt) = rt();
        // A hostile GPU: names from `vulkaninfo` are host text we do not control.
        rt.vulkan_probe = || rt_core::HostVulkan {
            tool_found: true,
            loader_found: true,
            devices: vec![rt_core::VulkanDevice {
                name: HOSTILE.into(),
                device_type: HOSTILE.into(),
                api: (1, 3),
                driver: HOSTILE.into(),
            }],
        };
        let hostile_installer = InstallerMeta {
            family: HOSTILE.into(),
            product_name: Some(HOSTILE.into()),
            uninstall_command: Some(format!("C:\\{HOSTILE_FILE}\\u.exe {HOSTILE}")),
        };
        let dep = |id: &str| DependencyRecord {
            id: id.into(),
            version: HOSTILE.into(),
            sha256: "0".repeat(64),
            installed_at: 1,
            consent: None,
        };
        add(&rt, "h1", |m| {
            m.name = HOSTILE.into();
            m.version = Some(HOSTILE.into());
            m.executable = format!("C:\\{HOSTILE_FILE}\\{HOSTILE_FILE}.exe");
            m.environment = HOSTILE.into();
            m.subsystem = HOSTILE.into();
            m.backend = BackendInfo {
                id: HOSTILE.into(),
                version: HOSTILE.into(),
            };
            m.installer = Some(hostile_installer.clone());
            m.dependencies = vec![dep(HOSTILE)];
        });
        add(&rt, "plain", |_| {});
        // A grant whose directory name carries a format character is refused by the validator (it rejects
        // control and format characters in any grant path, so a hostile-but-VALID grant cannot exist: the view's
        // path cleaning is exercised in `grant_paths_are_cleaned` instead). The refusal message quotes the path.
        let env = add(&rt, "g", |_| {});
        let ctx = ctx(d.path());
        if let Ok(vt) = tempfile::tempdir_in("/var/tmp") {
            let odd = vt.path().join("od\u{202e}d");
            std::fs::create_dir(&odd).unwrap();
            let toml_path = format!("{}/od\\u202ed", vt.path().to_str().unwrap());
            std::fs::write(
                env.root().join("permissions.toml"),
                format!("version = 1\n[[filesystem]]\npath = \"{toml_path}\"\naccess = \"ro\"\n"),
            )
            .unwrap();
            let err = rt.permissions_with(&env, &ctx).unwrap_err();
            assert_eq!(err.kind, ErrorKind::Unavailable);
            assert!(
                err.message.contains("invisible characters"),
                "the validator's reason: {}",
                err.message
            );
            assert!(
                err.message.contains("/od") && err.message.contains("d"),
                "path reached the text: {}",
                err.message
            );
            walk(&serde_json::to_value(&err).unwrap(), "grant error");
        } else {
            eprintln!("SKIPPED: /var/tmp not writable (hostile grant check)");
        }
        std::fs::remove_file(env.root().join("permissions.toml")).ok();
        walk(&serde_json::to_value(rt.version()).unwrap(), "version");
        walk(&serde_json::to_value(rt.apps()).unwrap(), "apps");
        for id in ["h1", "plain", "g"] {
            walk(&serde_json::to_value(rt.app(id).unwrap()).unwrap(), id);
            let env = rt.env(id).unwrap();
            walk(
                &serde_json::to_value(rt.permissions_with(&env, &ctx).unwrap()).unwrap(),
                id,
            );
        }
        walk(&serde_json::to_value(rt.compat()).unwrap(), "compat");
        walk(&serde_json::to_value(rt.graphics_info()).unwrap(), "graphics");
        // h1's executable path is hostile and missing: the plan's warning quotes it.
        let plan = rt.deps_plan("h1").unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("cannot read")), "{plan:?}");
        for id in ["h1", "plain", "g"] {
            walk(&serde_json::to_value(rt.deps_plan(id).unwrap()).unwrap(), id);
        }
        // `consentText` and `sha256` come from the manifest: a hostile one (the bundled one is validated).
        let mut m = rt_deps::Manifest::bundled().clone();
        let p = m.packages.iter_mut().find(|p| p.requires_consent).unwrap();
        (p.licence, p.url, p.sha256, p.version) = (HOSTILE.into(), HOSTILE.into(), HOSTILE.into(), HOSTILE.into());
        let plan = rt_deps::AppPlan {
            facts: rt_deps::Facts {
                imports: vec![],
                extra_capabilities: vec![],
                requested: vec![],
            },
            plan: rt_deps::Plan {
                entries: vec![rt_deps::PlanEntry {
                    package: p.id.clone(),
                    action: rt_deps::Action::Install,
                    consent: rt_deps::ConsentState::Needed,
                }],
                unsatisfied: vec![],
            },
            warnings: vec![],
        };
        let v = DepsPlanView::from_plan(&AppId::parse("h1").unwrap(), &plan, &m);
        assert!(v.entries[0].consent_text.is_some());
        walk(&serde_json::to_value(v).unwrap(), "hostile manifest");
        // doctor and sandbox_info probe the host (Wine, bwrap, systemd-run): their guard runs in the CLI's rig
        // (`crates/cli/tests/apps.rs`, `api_*`), in a child process with the rig's environment.
        for e in [
            rt.app(HOSTILE).unwrap_err(),
            rt.app("nope").unwrap_err(),
            ApiError::new(ErrorKind::Internal, HOSTILE),
        ] {
            walk(&serde_json::to_value(e).unwrap(), "error");
        }
    }
}
