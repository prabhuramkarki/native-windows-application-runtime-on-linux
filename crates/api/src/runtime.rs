//! [`Runtime`]: the read-only methods. Nothing here writes, locks or spawns; everything read is untrusted.
use crate::error::{ApiError, ErrorKind};
use crate::types::*;
use crate::{API_VERSION, PROTOCOL};
use rt_core::{AppEnv, AppId, Store, StoreError};
use rt_sandbox::{GrantCtx, load_opt};

pub struct Runtime {
    store: Store,
}

fn unavailable(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(ErrorKind::Unavailable, e.to_string())
}

impl Runtime {
    /// The store at the user's apps directory (`rt_core::apps_dir`).
    pub fn open() -> Result<Runtime, ApiError> {
        let dir = rt_core::apps_dir().map_err(unavailable)?;
        Ok(Runtime::with_store(Store::new(dir).map_err(unavailable)?))
    }

    pub fn with_store(store: Store) -> Runtime {
        Runtime { store }
    }

    pub fn version(&self) -> VersionInfo {
        VersionInfo {
            api: API_VERSION.to_owned(),
            runtime: env!("CARGO_PKG_VERSION").to_owned(),
            protocol: PROTOCOL.to_owned(),
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
    fn env(&self, id: &str) -> Result<AppEnv, ApiError> {
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
        Ok(PermissionsView::from_profile(&loaded.unwrap_or_default(), source))
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
            d.executable,
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
        let s = &rt.apps().apps[0];
        assert!(clean(&s.name) && s.version.as_deref().is_some_and(clean));
        // the bare (non-hostile) case is untouched
        std::fs::remove_dir_all(env.root()).unwrap();
        add(&rt, "p", |_| {});
        let p = rt.app("p").unwrap();
        assert_eq!((p.name.as_str(), p.version.as_deref()), ("App", Some("1.0")));
        assert_eq!(p.executable, r"C:\app\a.exe");
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
        // a symlinked prefix does not count
        std::fs::remove_dir_all(env.prefix()).unwrap();
        std::os::unix::fs::symlink("/tmp", env.prefix()).unwrap();
        assert_eq!(
            rt.app("a").unwrap().prefix,
            PrefixState {
                exists: false,
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
        let vt = tempfile::tempdir_in("/var/tmp").unwrap();
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
    }

    #[test]
    fn version_values() {
        let (_d, rt) = rt();
        let v = rt.version();
        assert_eq!(
            v,
            VersionInfo {
                api: "0.1.0".into(),
                runtime: env!("CARGO_PKG_VERSION").into(),
                protocol: "jsonrpc-2.0-ndjson".into()
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
        });
        round_trip(rt.version());
        let list = rt.apps();
        round_trip(list.apps[0].clone());
        round_trip(list.clone());
        let d = round_trip(rt.app("r").unwrap());
        assert!(d["installer"]["productName"].is_string() && d["prefix"]["hasDriveC"].is_boolean());
        assert!(d["dependencies"][0]["installedAt"].is_number());
        let env = rt.env("r").unwrap();
        let p = rt.permissions_with(&env, &ctx(_d.path())).unwrap();
        let j = round_trip(p);
        assert_eq!(
            (j["source"].as_str(), j["network"].as_str()),
            (Some("default"), Some("deny"))
        );
        assert!(j["limits"]["tasksDefault"].is_boolean());
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
        ] {
            let j = round_trip(ApiError::new(k, "m"));
            assert!(matches!(
                j["kind"].as_str(),
                Some("not_found" | "invalid_argument" | "unavailable" | "internal")
            ));
        }
    }

    #[test]
    fn error_messages_are_cleaned_and_bounded() {
        let e = ApiError::new(ErrorKind::Internal, format!("{HOSTILE}{}", "m".repeat(2000)));
        assert!(clean(&e.message) && e.message.len() <= 512);
    }
}
