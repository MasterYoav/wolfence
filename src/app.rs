//! Application bootstrap and shared error types.
//!
//! This module is the narrow seam between the operating system and the rest of
//! the codebase. It converts process arguments into a parsed command, dispatches
//! the request, and exposes one crate-wide error type so the early-stage code
//! stays simple and consistent.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::process::ExitCode;

use crate::cli::Cli;
use crate::commands;

/// Crate-wide result alias used by command handlers and core modules.
pub type AppResult<T> = Result<T, AppError>;

/// Minimal application error model for the early scaffold.
///
/// The enum is intentionally conservative: we keep error categories broad until
/// the product's integration surfaces stabilize. This avoids premature
/// complexity while still allowing each layer to preserve useful context.
#[derive(Debug)]
pub enum AppError {
    /// Standard input/output or filesystem failure.
    Io(io::Error),
    /// The local `git` executable failed or returned unexpected output.
    Git(String),
    /// The user invoked the CLI with unsupported or incomplete arguments.
    Cli(String),
    /// A configuration file was invalid or inconsistent.
    Config(String),
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "io error: {error}"),
            Self::Git(message) => write!(f, "git error: {message}"),
            Self::Cli(message) => write!(f, "cli error: {message}"),
            Self::Config(message) => write!(f, "config error: {message}"),
        }
    }
}

impl Error for AppError {}

impl From<io::Error> for AppError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Runs the application from process startup to command completion.
pub fn run() -> AppResult<ExitCode> {
    let cli = Cli::parse(std::env::args().skip(1)).map_err(AppError::Cli)?;
    commands::execute(cli.command)
}
