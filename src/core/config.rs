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
    pub scan_ignore_paths: Vec<String>,
}

impl ResolvedConfig {
    /// Loads the effective configuration for one repository.
    pub fn load_for_repo(repo_root: &Path) -> AppResult<Self> {
        let repo_config_path = repo_root.join(REPO_CONFIG_RELATIVE_PATH);
        let repo_config_exists = repo_config_path.exists();

        let mut mode = EnforcementMode::Standard;
        let mut mode_source = ConfigSource::Default;
        let mut scan_ignore_paths = Vec::new();

        if repo_config_exists {
            let contents = fs::read_to_string(&repo_config_path)?;
            if let Some(parsed_mode) = parse_mode_from_config(&contents)? {
                mode = parsed_mode;
                mode_source = ConfigSource::RepoFile;
            }
            scan_ignore_paths = parse_scan_ignore_paths(&contents)?;
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
            scan_ignore_paths,
        })
    }

    /// Returns whether one repository-relative path should be excluded from scanning.
    pub fn should_ignore_path(&self, relative_path: &Path) -> bool {
        let normalized = relative_path.to_string_lossy().replace('\\', "/");

        self.scan_ignore_paths
            .iter()
            .any(|pattern| path_matches_ignore_pattern(&normalized, pattern))
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

[scan]

# Repository-relative paths or path prefixes to exclude from scanning.
# Supported shapes:
# - "docs/" for a directory prefix
# - "docs/examples.md" for one exact path
# - "fixtures/**" for a recursive prefix
ignore_paths = []
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

fn parse_scan_ignore_paths(contents: &str) -> AppResult<Vec<String>> {
    let mut ignore_paths = Vec::new();

    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();

        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        if key.trim() != "ignore_paths" {
            continue;
        }

        let trimmed = value.trim();
        if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
            return Err(AppError::Config(format!(
                "invalid `ignore_paths` value in {}: expected an array of quoted strings",
                REPO_CONFIG_RELATIVE_PATH
            )));
        }

        let inner = &trimmed[1..trimmed.len() - 1];
        if inner.trim().is_empty() {
            return Ok(Vec::new());
        }

        for item in inner.split(',') {
            let pattern = item.trim().trim_matches('"').trim();
            if pattern.is_empty() {
                continue;
            }
            ignore_paths.push(validate_scan_ignore_pattern(pattern)?);
        }

        return Ok(ignore_paths);
    }

    Ok(ignore_paths)
}

fn validate_scan_ignore_pattern(pattern: &str) -> AppResult<String> {
    let normalized = pattern.replace('\\', "/");

    if normalized.is_empty() {
        return Err(AppError::Config(format!(
            "invalid `ignore_paths` value in {}: exclusion patterns cannot be empty",
            REPO_CONFIG_RELATIVE_PATH
        )));
    }

    if matches!(normalized.as_str(), "." | "./" | "/" | "*" | "**") {
        return Err(AppError::Config(format!(
            "invalid `ignore_paths` value in {}: `{normalized}` would exclude the entire repository",
            REPO_CONFIG_RELATIVE_PATH
        )));
    }

    if normalized.starts_with('/') {
        return Err(AppError::Config(format!(
            "invalid `ignore_paths` value in {}: `{normalized}` must be repository-relative",
            REPO_CONFIG_RELATIVE_PATH
        )));
    }

    if normalized.contains("//") || normalized.split('/').any(|component| component == "..") {
        return Err(AppError::Config(format!(
            "invalid `ignore_paths` value in {}: `{normalized}` must not escape or contain invalid path traversal components",
            REPO_CONFIG_RELATIVE_PATH
        )));
    }

    if normalized.contains('*') && !normalized.ends_with("/**") {
        return Err(AppError::Config(format!(
            "invalid `ignore_paths` value in {}: `{normalized}` uses an unsupported wildcard pattern",
            REPO_CONFIG_RELATIVE_PATH
        )));
    }

    Ok(normalized)
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

fn path_matches_ignore_pattern(path: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }

    if let Some(prefix) = pattern.strip_suffix('/') {
        return path == prefix || path.starts_with(&format!("{prefix}/"));
    }

    path == pattern
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        parse_mode_from_config, parse_scan_ignore_paths, path_matches_ignore_pattern,
        validate_scan_ignore_pattern, ResolvedConfig,
    };
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

    #[test]
    fn parses_scan_ignore_paths() {
        let config = r#"
[scan]
ignore_paths = ["docs/", "fixtures/**", "README.md"]
"#;

        let ignore_paths = parse_scan_ignore_paths(config).expect("ignore paths should parse");

        assert_eq!(ignore_paths, vec!["docs/", "fixtures/**", "README.md"]);
    }

    #[test]
    fn matches_ignore_patterns_for_exact_paths_and_prefixes() {
        assert!(path_matches_ignore_pattern("docs/guide.md", "docs/"));
        assert!(path_matches_ignore_pattern(
            "fixtures/secret/example.txt",
            "fixtures/**"
        ));
        assert!(path_matches_ignore_pattern("README.md", "README.md"));
        assert!(!path_matches_ignore_pattern("src/main.rs", "docs/"));
    }

    #[test]
    fn resolved_config_can_ignore_candidate_paths() {
        let config = ResolvedConfig {
            mode: EnforcementMode::Standard,
            mode_source: super::ConfigSource::RepoFile,
            repo_config_path: Path::new(".wolfence/config.toml").to_path_buf(),
            repo_config_exists: true,
            scan_ignore_paths: vec!["docs/".to_string(), "fixtures/**".to_string()],
        };

        assert!(config.should_ignore_path(Path::new("docs/guide.md")));
        assert!(config.should_ignore_path(Path::new("fixtures/generated/example.txt")));
        assert!(!config.should_ignore_path(Path::new("src/main.rs")));
    }

    #[test]
    fn rejects_broad_or_non_repo_relative_ignore_patterns() {
        for pattern in [".", "./", "/", "*", "**", "/tmp", "../fixtures", "docs/*"] {
            let error = validate_scan_ignore_pattern(pattern)
                .expect_err("invalid ignore pattern should fail");
            let message = error.to_string();
            assert!(
                message.contains("invalid `ignore_paths` value"),
                "unexpected error for {pattern}: {message}"
            );
        }
    }
}
