//! Wolfence executable entrypoint.
//!
//! The binary is intentionally small. Its job is to hand control to the
//! application layer, which owns argument parsing, command dispatch, and
//! error translation.

mod app;
mod cli;
mod commands;
mod core;
#[cfg(test)]
mod test_support;

use std::process::ExitCode;

fn main() -> ExitCode {
    match app::run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("wolf: {error}");
            ExitCode::FAILURE
        }
    }
}
