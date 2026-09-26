//! `runtimed`: the read-only [`rt_api::Runtime`] served as JSON-RPC 2.0 over an owner-only Unix socket.
//! [`protocol`] is the wire format and its limits, [`dispatch`] the method table, [`server`] the socket, the
//! peer check, the connection limits and shutdown, [`client`] the client that `runtime rpc` uses (it checks the
//! socket before it sends and treats replies as untrusted).
pub mod client;
pub mod dispatch;
pub mod protocol;
pub mod server;

#[cfg(test)]
pub(crate) mod testutil {
    use rt_api::Runtime;
    use rt_core::{AppId, BackendInfo, Metadata, Store, WinPath};

    /// A `Runtime` over a scratch store (never the user's).
    pub fn rt() -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("apps")).unwrap();
        (dir, Runtime::with_store(store))
    }

    /// Installs app `id` named `name` with a (non-PE) `C:\app\a.exe`.
    pub fn plant(rt_dir: &std::path::Path, id: &str, name: &str) {
        let store = Store::new(rt_dir.join("apps")).unwrap();
        let id = AppId::parse(id).unwrap();
        let env = store.create(&id).unwrap();
        std::fs::create_dir_all(env.drive_c().join("app")).unwrap();
        // The per-app HOME `runtime run` prepares (the sandbox command binds it).
        std::fs::create_dir_all(env.root().join("runtime/home")).unwrap();
        std::fs::write(env.drive_c().join("app/a.exe"), b"MZ").unwrap();
        let exe = WinPath::parse(r"C:\app\a.exe").unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: name.into(),
        };
        let md = Metadata::new(id, name.into(), Some(name.into()), "x86_64", &exe, backend, "gui");
        store.write_metadata(&env, &md).unwrap();
    }
}
