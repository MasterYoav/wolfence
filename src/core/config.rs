//! Repository-local configuration loading.
//!
//! The first real configuration surface in Wolfence is deliberately narrow:
//! repo-local policy mode plus explicit resolution metadata. The file format is
//! TOML-shaped so the project can later move to a full parser without forcing a
//! format migration.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use crate::app::{AppError, AppResult};

use super::policy::EnforcementMode;

/// Default repo-local config file path relative to the repository root.
pub const REPO_CONFIG_RELATIVE_PATH: &str = ".wolfence/config.toml";

/// Explains how the effective configuration value was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Default,
    RepoFile,
    EnvironmentOverride,
}

impl Display for ConfigSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::RepoFile => write!(f, "repo-file"),
            Self::EnvironmentOverride => write!(f, "environment"),
        }
    }
}

/// Effective configuration for one Wolfence invocation.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub mode: EnforcementMode,
    pub mode_source: ConfigSource,
    pub repo_config_path: PathBuf,
    pub repo_config_exists: bool,
}

impl ResolvedConfig {
    /// Loads the effective configuration for one repository.
    pub fn load_for_repo(repo_root: &Path) -> AppResult<Self> {
        let repo_config_path = repo_root.join(REPO_CONFIG_RELATIVE_PATH);
        let repo_config_exists = repo_config_path.exists();

        let mut mode = EnforcementMode::Standard;
        let mut mode_source = ConfigSource::Default;

        if repo_config_exists {
            let contents = fs::read_to_string(&repo_config_path)?;
            if let Some(parsed_mode) = parse_mode_from_config(&contents)? {
                mode = parsed_mode;
                mode_source = ConfigSource::RepoFile;
            }
        }

        if let Some(env_mode) = std::env::var("WOLFENCE_MODE").ok() {
            mode = EnforcementMode::parse(&env_mode).map_err(|message| {
                AppError::Config(format!(
                    "invalid WOLFENCE_MODE override `{env_mode}`: {message}"
                ))
            })?;
            mode_source = ConfigSource::EnvironmentOverride;
        }

        Ok(Self {
            mode,
            mode_source,
            repo_config_path,
            repo_config_exists,
        })
    }
}

/// Returns the default initial repo-local config template.
pub fn default_repo_config() -> &'static str {
    r#"# Wolfence repository configuration
#
# This file defines the local default security posture for this repository.
# The current scaffold intentionally keeps the surface small while the core
# decision engine hardens.

[policy]

# Available values:
# - "advisory": never block, but warn on meaningful findings
# - "standard": block high/critical findings
# - "strict": block medium/high/critical findings
mode = "standard"
"#
}

fn parse_mode_from_config(contents: &str) -> AppResult<Option<EnforcementMode>> {
    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();

        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if key.trim() != "mode" {
            continue;
        }

        let normalized = value.trim().trim_matches('"');
        let mode = EnforcementMode::parse(normalized).map_err(|message| {
            AppError::Config(format!(
                "invalid `mode` value in {}: {message}",
                REPO_CONFIG_RELATIVE_PATH
            ))
        })?;

        return Ok(Some(mode));
    }

    Ok(None)
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;

    for (index, character) in line.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..index],
            _ => {}
        }
    }

    line
}

#[cfg(test)]
mod tests {
    use super::parse_mode_from_config;
    use crate::core::policy::EnforcementMode;

    #[test]
    fn parses_mode_from_policy_section() {
        let config = r#"
[policy]
mode = "strict"
"#;

        let mode = parse_mode_from_config(config)
            .expect("config parse should succeed")
            .expect("mode should exist");

        assert_eq!(mode, EnforcementMode::Strict);
    }

    #[test]
    fn ignores_comments_after_mode() {
        let config = r#"mode = "advisory" # local onboarding mode"#;

        let mode = parse_mode_from_config(config)
            .expect("config parse should succeed")
            .expect("mode should exist");

        assert_eq!(mode, EnforcementMode::Advisory);
    }
}
