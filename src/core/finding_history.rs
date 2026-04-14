//! Repo-local finding history.
//!
//! Stable finding fingerprints are useful only if Wolfence remembers what it
//! has already seen. This module persists a bounded local index of prior
//! findings so every new run can distinguish newly introduced risk from
//! recurring known risk without changing the underlying finding identity.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::findings::Finding;

pub const FINDING_HISTORY_FILE_RELATIVE_PATH: &str = ".wolfence/history/findings.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FindingHistoryStatus {
    #[default]
    New,
    Recurring,
}

impl Display for FindingHistoryStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Recurring => write!(f, "recurring"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingHistoryState {
    pub status: FindingHistoryStatus,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub times_seen: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FindingHistorySummary {
    pub new_findings: usize,
    pub recurring_findings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct FindingHistoryFile {
    version: u8,
    records: Vec<FindingHistoryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FindingHistoryRecord {
    fingerprint: String,
    first_seen_unix: u64,
    last_seen_unix: u64,
    times_seen: u32,
}

pub fn annotate_findings(repo_root: &Path, findings: &mut [Finding]) -> FindingHistorySummary {
    let history_path = repo_root.join(FINDING_HISTORY_FILE_RELATIVE_PATH);
    let now = current_unix_seconds();
    let (mut records, mut issue, should_save) = match load_history_records(&history_path) {
        Ok(records) => (records, None, true),
        Err(error) => (
            BTreeMap::new(),
            Some(format!(
                "finding history could not be loaded from {}: {error}",
                history_path.display()
            )),
            false,
        ),
    };

    let mut summary = FindingHistorySummary::default();

    for finding in findings {
        let state = if let Some(existing) = records.get_mut(&finding.fingerprint) {
            existing.last_seen_unix = now;
            existing.times_seen = existing.times_seen.saturating_add(1);
            summary.recurring_findings += 1;
            FindingHistoryState {
                status: FindingHistoryStatus::Recurring,
                first_seen_unix: existing.first_seen_unix,
                last_seen_unix: now,
                times_seen: existing.times_seen,
            }
        } else {
            records.insert(
                finding.fingerprint.clone(),
                FindingHistoryRecord {
                    fingerprint: finding.fingerprint.clone(),
                    first_seen_unix: now,
                    last_seen_unix: now,
                    times_seen: 1,
                },
            );
            summary.new_findings += 1;
            FindingHistoryState {
                status: FindingHistoryStatus::New,
                first_seen_unix: now,
                last_seen_unix: now,
                times_seen: 1,
            }
        };

        finding.history = state;
    }

    if should_save {
        if let Err(error) = save_history_records(&history_path, records) {
            summary.issue = Some(format!(
                "finding history could not be saved to {}: {error}",
                history_path.display()
            ));
            return summary;
        }
    } else {
        summary.issue = issue.take();
    }

    summary
}

fn load_history_records(path: &Path) -> Result<BTreeMap<String, FindingHistoryRecord>, String> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let file: FindingHistoryFile =
        serde_json::from_str(&contents).map_err(|error| error.to_string())?;

    if file.version != 1 {
        return Err(format!(
            "unsupported finding history version `{}`",
            file.version
        ));
    }

    let mut records = BTreeMap::new();
    for record in file.records {
        records.insert(record.fingerprint.clone(), record);
    }
    Ok(records)
}

fn save_history_records(
    path: &Path,
    records: BTreeMap<String, FindingHistoryRecord>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "finding history path has no parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;

    let file = FindingHistoryFile {
        version: 1,
        records: records.into_values().collect(),
    };
    let contents = serde_json::to_string_pretty(&file).map_err(|error| error.to_string())?;
    fs::write(path, format!("{contents}\n")).map_err(|error| error.to_string())
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

    use super::{annotate_findings, FindingHistoryStatus, FINDING_HISTORY_FILE_RELATIVE_PATH};
    use crate::core::findings::{Confidence, Finding, FindingCategory, Severity};

    #[test]
    fn first_observation_marks_findings_as_new_and_persists_state() {
        let repo_root = temp_repo_root("history-new");
        let mut findings = vec![Finding::new(
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

        let summary = annotate_findings(&repo_root, &mut findings);

        assert_eq!(summary.new_findings, 1);
        assert_eq!(summary.recurring_findings, 0);
        assert!(summary.issue.is_none());
        assert_eq!(findings[0].history.status, FindingHistoryStatus::New);
        assert!(repo_root.join(FINDING_HISTORY_FILE_RELATIVE_PATH).exists());
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    #[test]
    fn repeat_observation_marks_findings_as_recurring() {
        let repo_root = temp_repo_root("history-recurring");
        let mut first = vec![Finding::new(
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
        annotate_findings(&repo_root, &mut first);

        let mut second = vec![Finding::new(
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
        let summary = annotate_findings(&repo_root, &mut second);

        assert_eq!(summary.new_findings, 0);
        assert_eq!(summary.recurring_findings, 1);
        assert_eq!(second[0].history.status, FindingHistoryStatus::Recurring);
        assert_eq!(second[0].history.times_seen, 2);
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    #[test]
    fn invalid_history_file_does_not_block_annotation() {
        let repo_root = temp_repo_root("history-invalid");
        let history_path = repo_root.join(FINDING_HISTORY_FILE_RELATIVE_PATH);
        fs::create_dir_all(history_path.parent().expect("history dir"))
            .expect("history dir should create");
        fs::write(&history_path, "{not-json").expect("invalid history file should write");

        let mut findings = vec![Finding::new(
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
        let summary = annotate_findings(&repo_root, &mut findings);

        assert_eq!(findings[0].history.status, FindingHistoryStatus::New);
        assert!(summary.issue.is_some());
        fs::remove_dir_all(repo_root).expect("temp repo should clean up");
    }

    fn temp_repo_root(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-finding-history-{name}-{}-{}",
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
