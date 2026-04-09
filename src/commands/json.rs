use std::path::PathBuf;

use serde::Serialize;

use crate::app::{AppError, AppResult};

#[derive(Serialize)]
pub struct JsonErrorResponse<'a> {
    pub command: &'a str,
    pub status: &'static str,
    pub error: JsonErrorBody,
}

#[derive(Serialize)]
pub struct JsonErrorBody {
    pub kind: &'static str,
    pub message: String,
}

pub fn print_json<T: Serialize>(value: &T) -> AppResult<()> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| AppError::Config(format!("failed to serialize json output: {error}")))?;
    println!("{rendered}");
    Ok(())
}

pub fn print_json_error(command: &str, error: &AppError) -> AppResult<()> {
    print_json(&JsonErrorResponse {
        command,
        status: "error",
        error: JsonErrorBody {
            kind: error_kind(error),
            message: error.to_string(),
        },
    })
}

pub fn path_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

fn error_kind(error: &AppError) -> &'static str {
    match error {
        AppError::Io(_) => "io",
        AppError::Git(_) => "git",
        AppError::Cli(_) => "cli",
        AppError::Config(_) => "config",
    }
}
