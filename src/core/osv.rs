//! OSV-backed live advisory intelligence.
//!
//! Wolfence stays local-first by treating live advisory lookups as an optional
//! augmentation layer. The core push gate still works without network access,
//! but this module can add current vulnerability intelligence when enabled.

use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::app::{AppError, AppResult};

use super::context::ProtectedAction;
use super::findings::{Confidence, Finding, FindingCategory, Severity};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/querybatch";
const OSV_QUERY_TIMEOUT_SECONDS: &str = "6";
const MAX_BATCH_DEPENDENCIES: usize = 25;

/// Runtime mode for live OSV advisory lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsvMode {
    Off,
    Auto,
    Require,
}

impl Display for OsvMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Auto => write!(f, "auto"),
            Self::Require => write!(f, "require"),
        }
    }
}

impl OsvMode {
    /// Resolves the OSV advisory mode from the environment.
    pub fn resolve() -> AppResult<Self> {
        match std::env::var("WOLFENCE_OSV").ok().as_deref() {
            None | Some("") | Some("auto") | Some("AUTO") => Ok(Self::Auto),
            Some("off" | "OFF" | "0" | "false" | "FALSE") => Ok(Self::Off),
            Some("require" | "REQUIRE" | "1" | "true" | "TRUE") => Ok(Self::Require),
            Some(other) => Err(AppError::Config(format!(
                "invalid WOLFENCE_OSV override `{other}`: expected off, auto, or require"
            ))),
        }
    }
}

/// One exact-version dependency candidate suitable for OSV lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedDependency {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub file: PathBuf,
}

/// Outcome of a live OSV advisory query.
#[derive(Debug, Clone)]
pub struct OsvScanOutcome {
    pub findings: Vec<Finding>,
    pub queried_dependencies: usize,
    pub skipped_dependencies: usize,
    pub mode: OsvMode,
    pub attempted: bool,
}

/// Queries OSV for exact-version dependencies when the current mode requires it.
pub fn scan_dependencies(
    action: ProtectedAction,
    dependencies: Vec<ResolvedDependency>,
) -> AppResult<OsvScanOutcome> {
    let mode = OsvMode::resolve()?;

    if mode == OsvMode::Off || action != ProtectedAction::Push || dependencies.is_empty() {
        return Ok(OsvScanOutcome {
            findings: Vec::new(),
            queried_dependencies: 0,
            skipped_dependencies: dependencies.len(),
            mode,
            attempted: false,
        });
    }

    let mut unique_dependencies = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dependency in dependencies {
        let key = (
            dependency.ecosystem,
            dependency.name.clone(),
            dependency.version.clone(),
        );
        if seen.insert(key) {
            unique_dependencies.push(dependency);
        }
    }

    let skipped_dependencies = unique_dependencies
        .len()
        .saturating_sub(MAX_BATCH_DEPENDENCIES);
    unique_dependencies.truncate(MAX_BATCH_DEPENDENCIES);

    match query_batch(&unique_dependencies) {
        Ok(findings) => Ok(OsvScanOutcome {
            findings,
            queried_dependencies: unique_dependencies.len(),
            skipped_dependencies,
            mode,
            attempted: true,
        }),
        Err(_error) if mode == OsvMode::Auto => Ok(OsvScanOutcome {
            findings: Vec::new(),
            queried_dependencies: unique_dependencies.len(),
            skipped_dependencies,
            mode,
            attempted: true,
        }),
        Err(error) => Ok(OsvScanOutcome {
            findings: vec![Finding::new(
                "dependency.osv.unavailable",
                "osv-advisory-scanner",
                Severity::High,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Live OSV advisory check was required but unavailable",
                format!(
                    "Wolfence was configured to require live OSV advisories, but the query failed: {error}"
                ),
                "Restore access to `curl` and `https://api.osv.dev`, or set `WOLFENCE_OSV=auto` if you want OSV to remain best-effort.",
                "dependency-osv-unavailable",
            )],
            queried_dependencies: unique_dependencies.len(),
            skipped_dependencies,
            mode,
            attempted: true,
        }),
    }
}

#[derive(Serialize)]
struct QueryBatchRequest {
    queries: Vec<Query>,
}

#[derive(Serialize)]
struct Query {
    package: Package,
    version: String,
}

#[derive(Serialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct QueryBatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Deserialize)]
struct QueryResult {
    vulns: Option<Vec<VulnRef>>,
}

#[derive(Deserialize)]
struct VulnRef {
    id: String,
}

fn query_batch(dependencies: &[ResolvedDependency]) -> AppResult<Vec<Finding>> {
    let payload = QueryBatchRequest {
        queries: dependencies
            .iter()
            .map(|dependency| Query {
                package: Package {
                    name: dependency.name.clone(),
                    ecosystem: dependency.ecosystem.to_string(),
                },
                version: dependency.version.clone(),
            })
            .collect(),
    };

    let payload = serde_json::to_string(&payload)
        .map_err(|error| AppError::Config(format!("failed to serialize OSV request: {error}")))?;

    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            OSV_QUERY_TIMEOUT_SECONDS,
            "-H",
            "content-type: application/json",
            "-d",
            &payload,
            OSV_QUERY_URL,
        ])
        .output()?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let response: QueryBatchResponse = serde_json::from_slice(&output.stdout).map_err(|error| {
        AppError::Config(format!("failed to parse OSV response payload: {error}"))
    })?;

    let mut findings = Vec::new();
    for (dependency, result) in dependencies.iter().zip(response.results.iter()) {
        let Some(vulns) = &result.vulns else {
            continue;
        };
        if vulns.is_empty() {
            continue;
        }

        let advisory_ids = vulns
            .iter()
            .map(|vulnerability| vulnerability.id.as_str())
            .collect::<Vec<_>>();
        let severity = if advisory_ids.len() >= 3 {
            Severity::Critical
        } else {
            Severity::High
        };

        findings.push(Finding::new(
            "dependency.osv.advisory",
            "osv-advisory-scanner",
            severity,
            Confidence::High,
            FindingCategory::Dependency,
            Some(dependency.file.clone()),
            "Known OSV advisories affect an exact dependency version",
            format!(
                "OSV reports that `{}` {} in `{}` is affected by: {}.",
                dependency.name,
                dependency.version,
                dependency.ecosystem,
                advisory_ids.join(", ")
            ),
            "Upgrade or replace the affected dependency version before pushing, or add a short-lived reviewed override receipt if the risk is understood and temporarily accepted.",
            format!(
                "dependency-osv:{}:{}:{}",
                dependency.ecosystem, dependency.name, dependency.version
            ),
        ));
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::OsvMode;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn defaults_osv_mode_to_auto() {
        let _guard = env_lock().lock().expect("lock should succeed");
        let previous = std::env::var("WOLFENCE_OSV").ok();
        std::env::remove_var("WOLFENCE_OSV");
        let mode = OsvMode::resolve().expect("mode should resolve");
        restore_osv_env(previous);
        assert_eq!(mode, OsvMode::Auto);
    }

    #[test]
    fn parses_require_osv_mode() {
        let _guard = env_lock().lock().expect("lock should succeed");
        let previous = std::env::var("WOLFENCE_OSV").ok();
        std::env::set_var("WOLFENCE_OSV", "require");
        let mode = OsvMode::resolve().expect("mode should resolve");
        restore_osv_env(previous);
        assert_eq!(mode, OsvMode::Require);
    }

    fn restore_osv_env(previous: Option<String>) {
        if let Some(value) = previous {
            std::env::set_var("WOLFENCE_OSV", value);
        } else {
            std::env::remove_var("WOLFENCE_OSV");
        }
    }
}
