use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use std::ffi::OsString;
use std::path::PathBuf;

/// Spec D5: valid reverse-DNS that owns no real domain, until the project is named.
const APP_ID: &str = "local.runtime.Gui";

/// `--socket PATH` (same meaning as the CLI's): the daemon's socket instead of the default. Nothing else.
fn parse_args(mut args: impl Iterator<Item = OsString>) -> Result<Option<PathBuf>, String> {
    let mut socket = None;
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--socket") => socket = Some(PathBuf::from(args.next().ok_or("--socket needs a PATH")?)),
            _ => return Err(format!("unknown argument {:?} (usage: runtime-gui [--socket PATH])", a)),
        }
    }
    Ok(socket)
}

fn main() -> glib::ExitCode {
    let _socket = match parse_args(std::env::args_os().skip(1)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("runtime-gui: {e}");
            return glib::ExitCode::from(2);
        }
    };
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(|app| {
        let w = rt_gui::ui::window();
        w.set_application(Some(app));
        w.present();
    });
    // Our own arguments are parsed above; GApplication gets none of them.
    app.run_with_args::<&str>(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<Option<PathBuf>, String> {
        parse_args(a.iter().map(OsString::from))
    }

    #[test]
    fn only_socket_is_accepted() {
        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&["--socket", "/r/s.sock"]), Ok(Some("/r/s.sock".into())));
        assert!(parse(&["--socket"]).is_err());
        assert!(parse(&["--gapplication-service"]).is_err());
    }
}
