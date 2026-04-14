//! Repo-local accepted baseline for findings.
//!
//! A finding baseline is an operator-declared starting set of accepted
//! fingerprints. It helps Wolfence focus attention on newly introduced risk,
//! but it never suppresses policy by itself. Override receipts remain the only
//! mechanism that can intentionally bypass a specific finding.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::app::{AppError, AppResult};

use super::findings::Finding;

pub const FINDING_BASELINE_FILE_RELATIVE_PATH: &str = ".wolfence/history/baseline.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingBaselineState {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_on_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingBaselineSummary {
    pub accepted_findings: usize,
    pub unaccepted_findings: usize,
    pub baseline_exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_on_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingBaselineSnapshot {
    pub path: PathBuf,
    pub scope: String,
    pub captured_on_unix: u64,
    pub fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingBaselineFile {
    version: u8,
    scope: String,
    captured_on_unix: u64,
    fingerprints: Vec<String>,
}

pub fn annotate_findings(repo_root: &Path, findings: &mut [Finding]) -> FindingBaselineSummary {
    let snapshot = match load_baseline(repo_root) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let mut summary = FindingBaselineSummary::default();
            summary.unaccepted_findings = findings.len();
            summary.issue = Some(error.to_string());
            for finding in findings {
                finding.baseline = FindingBaselineState::default();
            }
            return summary;
        }
    };

    let accepted = snapshot.as_ref().map_or_else(BTreeSet::new, |value| {
        value.fingerprints.iter().cloned().collect::<BTreeSet<_>>()
    });

    let mut summary = FindingBaselineSummary {
        baseline_exists: snapshot.is_some(),
        captured_on_unix: snapshot.as_ref().map(|value| value.captured_on_unix),
        ..FindingBaselineSummary::default()
    };

    for finding in findings {
        let accepted_fingerprint = accepted.contains(&finding.fingerprint);
        if accepted_fingerprint {
            summary.accepted_findings += 1;
        } else {
            summary.unaccepted_findings += 1;
        }
        finding.baseline = FindingBaselineState {
            accepted: accepted_fingerprint,
            captured_on_unix: summary.captured_on_unix,
        };
    }

    summary
}

pub fn capture_baseline(
    repo_root: &Path,
    scope: &str,
    findings: &[Finding],
) -> AppResult<FindingBaselineSnapshot> {
    let path = repo_root.join(FINDING_BASELINE_FILE_RELATIVE_PATH);
    let parent = path.parent().ok_or_else(|| {
        AppError::Config("finding baseline path has no parent directory.".to_string())
    })?;
    fs::create_dir_all(parent)?;

    let mut fingerprints = findings
        .iter()
        .map(|finding| finding.fingerprint.clone())
        .collect::<Vec<_>>();
    fingerprints.sort();
    fingerprints.dedup();

    let captured_on_unix = current_unix_seconds();
    let file = FindingBaselineFile {
        version: 1,
        scope: scope.to_string(),
        captured_on_unix,
        fingerprints: fingerprints.clone(),
    };
    let contents = serde_json::to_string_pretty(&file).map_err(|error| {
        AppError::Config(format!("failed to serialize finding baseline: {error}"))
    })?;
    fs::write(&path, format!("{contents}\n"))?;

    Ok(FindingBaselineSnapshot {
        path,
        scope: scope.to_string(),
        captured_on_unix,
        fingerprints,
    })
}

pub fn load_baseline(repo_root: &Path) -> AppResult<Option<FindingBaselineSnapshot>> {
    let path = repo_root.join(FINDING_BASELINE_FILE_RELATIVE_PATH);
    if !path.exists() {
        return Ok(None);
    }

    let contents = fs::read_to_string(&path)?;
    let file: FindingBaselineFile = serde_json::from_str(&contents).map_err(|error| {
        AppError::Config(format!(
            "failed to parse finding baseline {}: {error}",
            path.display()
        ))
    })?;

    if file.version != 1 {
        return Err(AppError::Config(format!(
            "unsupported finding baseline version `{}` in {}",
            file.version,
            path.display()
        )));
    }

    Ok(Some(FindingBaselineSnapshot {
        path,
        scope: file.scope,
        captured_on_unix: file.captured_on_unix,
        fingerprints: file.fingerprints,
    }))
}

pub fn clear_baseline(repo_root: &Path) -> AppResult<bool> {
    let path = repo_root.join(FINDING_BASELINE_FILE_RELATIVE_PATH);
    if !path.exists() {
        return Ok(false);
    }

    fs::remove_file(path)?;
    Ok(true)
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        annotate_findings, capture_baseline, clear_baseline, load_baseline,
        FINDING_BASELINE_FILE_RELATIVE_PATH,
    };
    use crate::core::findings::{Confidence, Finding, FindingCategory, Severity};

    #[test]
    fn captured_baseline_marks_matching_findings_as_accepted() {
        let repo_root = temp_repo_root("baseline-accepted");
        let findings = vec![Finding::new(
            "secret.inline-token",
            "secret-scanner",
            Severity::High,
            Confidence::High,
            FindingCategory::Secret,
            Some(PathBuf::from(".env")),
            "Inline credential detected",
            "detail",
            "remediation",
            "secret:inline-token",
        )];
        capture_baseline(&repo_root, "push", &findings).expect("baseline should capture");

        let mut current = findings.clone();
        let summary = annotate_findings(&repo_root, &mut current);

        assert!(current[0].baseline.accepted);
        assert_eq!(summary.accepted_findings, 1);
        assert_eq!(summary.unaccepted_findings, 0);
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    #[test]
    fn clearing_baseline_removes_file() {
        let repo_root = temp_repo_root("baseline-clear");
        let findings = vec![Finding::new(
            "secret.inline-token",
            "secret-scanner",
            Severity::High,
            Confidence::High,
            FindingCategory::Secret,
            Some(PathBuf::from(".env")),
            "Inline credential detected",
            "detail",
            "remediation",
            "secret:inline-token",
        )];
        capture_baseline(&repo_root, "push", &findings).expect("baseline should capture");

        assert!(clear_baseline(&repo_root).expect("baseline should clear"));
        assert!(!repo_root.join(FINDING_BASELINE_FILE_RELATIVE_PATH).exists());
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    #[test]
    fn loads_captured_baseline_metadata() {
        let repo_root = temp_repo_root("baseline-load");
        let findings = vec![Finding::new(
            "secret.inline-token",
            "secret-scanner",
            Severity::High,
            Confidence::High,
            FindingCategory::Secret,
            Some(PathBuf::from(".env")),
            "Inline credential detected",
            "detail",
            "remediation",
            "secret:inline-token",
        )];
        let captured =
            capture_baseline(&repo_root, "push", &findings).expect("baseline should capture");
        let loaded = load_baseline(&repo_root)
            .expect("baseline should load")
            .expect("baseline should exist");

        assert_eq!(loaded.scope, "push");
        assert_eq!(loaded.fingerprints, captured.fingerprints);
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    fn temp_repo_root(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-finding-baseline-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let root = env::temp_dir().join(unique);
        fs::create_dir_all(&root).expect("temp repo root should create");
        root
    }
}
