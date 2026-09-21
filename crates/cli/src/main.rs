mod analyze;

use clap::{Parser, Subcommand};
use std::{io::IsTerminal, path::PathBuf, process::ExitCode};

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
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    let result = match Cli::parse().cmd {
        Cmd::Analyze { file, json } => analyze::run(&file, json),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let safe_err = analyze::safe(&e.to_string());
            eprintln!("error: {}", safe_err);
            ExitCode::FAILURE
        }
    }
}
