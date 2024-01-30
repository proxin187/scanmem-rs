mod mem;
mod cli;
mod log;

use cli::Cli;
use mem::*;

use std::process;

fn main() {
    let mut cli = Cli::new();

    if let Err(err) = cli.run() {
        log::error(&format!("failed to run cli: {}", err.to_string()));
        process::exit(1);
    }
}

