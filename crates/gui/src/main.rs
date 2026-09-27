use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use std::cell::RefCell;
use std::ffi::OsString;
use std::path::PathBuf;
use std::rc::Rc;

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
    let socket = match parse_args(std::env::args_os().skip(1)) {
        // No --socket and no runtime dir: an empty path, which the backend reports as "no runtime directory".
        Ok(s) => s
            .or_else(|| rt_daemon::client::default_socket_path().ok())
            .unwrap_or_default(),
        Err(e) => {
            eprintln!("runtime-gui: {e}");
            return glib::ExitCode::from(2);
        }
    };
    let app = adw::Application::builder().application_id(APP_ID).build();
    // The window's UI lives as long as the application (a second launch only raises it).
    let held: RefCell<Option<Rc<rt_gui::ui::Ui>>> = RefCell::default();
    app.connect_activate(move |app| {
        if let Some(w) = app.active_window() {
            w.present();
            return;
        }
        let ui = rt_gui::ui::start(socket.clone());
        ui.window().set_application(Some(app));
        ui.window().present();
        *held.borrow_mut() = Some(ui);
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
