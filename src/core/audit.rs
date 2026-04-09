//! Tamper-evident local audit logging.
//!
//! Wolfence is a security gate, so protected push decisions should leave a
//! reviewable local trail. This module writes append-only JSONL audit entries
//! chained by content hash and can verify the chain later through diagnostics.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::app::{AppError, AppResult};

use super::context::ProtectedAction;
use super::git;
use super::policy::Verdict;

pub const AUDIT_DIR_RELATIVE_PATH: &str = ".wolfence/audit";
pub const AUDIT_LOG_RELATIVE_PATH: &str = ".wolfence/audit/decisions.jsonl";

/// High-level source that triggered a protected push decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSource {
    PushCommand,
    PrePushHook,
}

impl AuditSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::PushCommand => "push-command",
            Self::PrePushHook => "pre-push-hook",
        }
    }
}

/// Push decision metadata recorded in the local audit chain.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub source: AuditSource,
    pub action: ProtectedAction,
    pub status: &'static str,
    pub outcome: &'static str,
    pub detail: Option<String>,
    pub verdict: Option<Verdict>,
    pub discovered_files: usize,
    pub candidate_files: usize,
    pub ignored_files: usize,
    pub findings: usize,
    pub warnings: usize,
    pub blocks: usize,
    pub overrides_applied: usize,
    pub receipt_issues: usize,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub commits_ahead: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditRecord {
    version: u8,
    sequence: usize,
    timestamp_unix: u64,
    source: String,
    action: String,
    status: String,
    outcome: String,
    detail: Option<String>,
    verdict: Option<String>,
    #[serde(default)]
    discovered_files: usize,
    candidate_files: usize,
    #[serde(default)]
    ignored_files: usize,
    findings: usize,
    warnings: usize,
    blocks: usize,
    overrides_applied: usize,
    receipt_issues: usize,
    branch: Option<String>,
    upstream: Option<String>,
    commits_ahead: Option<usize>,
    prev_hash: String,
    entry_hash: String,
}

/// Verification result for the local audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditVerification {
    pub log_path: PathBuf,
    pub entries: usize,
    pub healthy: bool,
    pub issue: Option<String>,
}

/// Public audit entry shape for operator inspection.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub sequence: usize,
    pub timestamp_unix: u64,
    pub source: String,
    pub action: String,
    pub status: String,
    pub outcome: String,
    pub detail: Option<String>,
    pub verdict: Option<String>,
    pub discovered_files: usize,
    pub candidate_files: usize,
    pub ignored_files: usize,
    pub findings: usize,
    pub warnings: usize,
    pub blocks: usize,
    pub overrides_applied: usize,
    pub receipt_issues: usize,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub commits_ahead: Option<usize>,
}

/// Appends one chained audit record for a protected push decision.
pub fn append_audit_event(repo_root: &Path, event: AuditEvent) -> AppResult<PathBuf> {
    let audit_dir = repo_root.join(AUDIT_DIR_RELATIVE_PATH);
    let log_path = repo_root.join(AUDIT_LOG_RELATIVE_PATH);
    fs::create_dir_all(&audit_dir)?;

    let (sequence, prev_hash) = last_sequence_and_hash(&log_path)?;
    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let base = AuditRecord {
        version: 3,
        sequence: sequence + 1,
        timestamp_unix,
        source: event.source.as_str().to_string(),
        action: event.action.to_string(),
        status: event.status.to_string(),
        outcome: event.outcome.to_string(),
        detail: event.detail,
        verdict: event.verdict.map(|value| value.to_string()),
        discovered_files: event.discovered_files,
        candidate_files: event.candidate_files,
        ignored_files: event.ignored_files,
        findings: event.findings,
        warnings: event.warnings,
        blocks: event.blocks,
        overrides_applied: event.overrides_applied,
        receipt_issues: event.receipt_issues,
        branch: event.branch,
        upstream: event.upstream,
        commits_ahead: event.commits_ahead,
        prev_hash,
        entry_hash: String::new(),
    };

    let entry_hash = git::hash_text(&canonical_record_payload(&base, true)?)?;
    let record = AuditRecord { entry_hash, ..base };

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    serde_json::to_writer(&mut file, &record)
        .map_err(|error| AppError::Config(format!("failed to serialize audit record: {error}")))?;
    file.write_all(b"\n")?;

    Ok(log_path)
}

/// Reads the current audit log for operator inspection.
pub fn read_audit_log(repo_root: &Path) -> AppResult<Vec<AuditEntry>> {
    let log_path = repo_root.join(AUDIT_LOG_RELATIVE_PATH);
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&log_path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let (record, _) = parse_record_line(&line)?;
        entries.push(AuditEntry {
            sequence: record.sequence,
            timestamp_unix: record.timestamp_unix,
            source: record.source,
            action: record.action,
            status: record.status,
            outcome: record.outcome,
            detail: record.detail,
            verdict: record.verdict,
            discovered_files: record.discovered_files,
            candidate_files: record.candidate_files,
            ignored_files: record.ignored_files,
            findings: record.findings,
            warnings: record.warnings,
            blocks: record.blocks,
            overrides_applied: record.overrides_applied,
            receipt_issues: record.receipt_issues,
            branch: record.branch,
            upstream: record.upstream,
            commits_ahead: record.commits_ahead,
        });
    }

    Ok(entries)
}

/// Verifies the local audit log hash chain.
pub fn verify_audit_log(repo_root: &Path) -> AppResult<AuditVerification> {
    let log_path = repo_root.join(AUDIT_LOG_RELATIVE_PATH);
    if !log_path.exists() {
        return Ok(AuditVerification {
            log_path,
            entries: 0,
            healthy: true,
            issue: None,
        });
    }

    let file = fs::File::open(&log_path)?;
    let reader = BufReader::new(file);
    let mut entries = 0usize;
    let mut expected_prev_hash = String::from("genesis");
    let mut expected_sequence = 1usize;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let (record, includes_detail) = parse_record_line(&line)?;
        entries += 1;

        if record.sequence != expected_sequence {
            return Ok(AuditVerification {
                log_path,
                entries,
                healthy: false,
                issue: Some(format!(
                    "audit sequence is broken at entry {}: expected {}, found {}",
                    entries, expected_sequence, record.sequence
                )),
            });
        }

        if record.prev_hash != expected_prev_hash {
            return Ok(AuditVerification {
                log_path,
                entries,
                healthy: false,
                issue: Some(format!("audit previous hash mismatch at entry {}", entries)),
            });
        }

        let expected_hash = git::hash_text(&canonical_record_payload(
            &AuditRecord {
                entry_hash: String::new(),
                ..record.clone()
            },
            includes_detail || record.version >= 2,
        )?)?;

        if record.entry_hash != expected_hash {
            return Ok(AuditVerification {
                log_path,
                entries,
                healthy: false,
                issue: Some(format!("audit entry hash mismatch at entry {}", entries)),
            });
        }

        expected_prev_hash = record.entry_hash;
        expected_sequence += 1;
    }

    Ok(AuditVerification {
        log_path,
        entries,
        healthy: true,
        issue: None,
    })
}

fn last_sequence_and_hash(log_path: &Path) -> AppResult<(usize, String)> {
    if !log_path.exists() {
        return Ok((0, String::from("genesis")));
    }

    let file = fs::File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut last: Option<AuditRecord> = None;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let (record, _) = parse_record_line(&line)?;
        last = Some(record);
    }

    Ok(match last {
        Some(record) => (record.sequence, record.entry_hash),
        None => (0, String::from("genesis")),
    })
}

fn canonical_record_payload(record: &AuditRecord, include_detail: bool) -> AppResult<String> {
    let mut payload = serde_json::json!({
        "version": record.version,
        "sequence": record.sequence,
        "timestamp_unix": record.timestamp_unix,
        "source": record.source,
        "action": record.action,
        "status": record.status,
        "outcome": record.outcome,
        "verdict": record.verdict,
        "findings": record.findings,
        "warnings": record.warnings,
        "blocks": record.blocks,
        "overrides_applied": record.overrides_applied,
        "receipt_issues": record.receipt_issues,
        "branch": record.branch,
        "upstream": record.upstream,
        "commits_ahead": record.commits_ahead,
        "prev_hash": record.prev_hash,
    });

    if record.version >= 3 {
        payload["discovered_files"] = serde_json::json!(record.discovered_files);
        payload["candidate_files"] = serde_json::json!(record.candidate_files);
        payload["ignored_files"] = serde_json::json!(record.ignored_files);
    } else {
        payload["candidate_files"] = serde_json::json!(record.candidate_files);
    }

    if include_detail {
        payload["detail"] = serde_json::to_value(&record.detail).map_err(|error| {
            AppError::Config(format!("failed to serialize audit detail: {error}"))
        })?;
    }

    serde_json::to_string(&payload)
        .map_err(|error| AppError::Config(format!("failed to serialize audit payload: {error}")))
}

fn parse_record_line(line: &str) -> AppResult<(AuditRecord, bool)> {
    let value: Value = serde_json::from_str(line)
        .map_err(|error| AppError::Config(format!("failed to parse audit log entry: {error}")))?;
    let includes_detail = value
        .as_object()
        .map(|object| object.contains_key("detail"))
        .unwrap_or(false);
    let record: AuditRecord = serde_json::from_value(value)
        .map_err(|error| AppError::Config(format!("failed to decode audit log entry: {error}")))?;
    Ok((record, includes_detail))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        append_audit_event, read_audit_log, verify_audit_log, AuditEvent, AuditSource,
        AUDIT_LOG_RELATIVE_PATH,
    };
    use crate::core::context::ProtectedAction;
    use crate::core::git;
    use crate::core::policy::Verdict;

    #[test]
    fn appends_and_verifies_audit_chain() {
        let root = temp_repo("audit-chain");

        append_audit_event(
            &root,
            AuditEvent {
                source: AuditSource::PushCommand,
                action: ProtectedAction::Push,
                status: "ready",
                outcome: "policy-allowed",
                detail: None,
                verdict: Some(Verdict::Allow),
                discovered_files: 5,
                candidate_files: 3,
                ignored_files: 2,
                findings: 1,
                warnings: 1,
                blocks: 0,
                overrides_applied: 0,
                receipt_issues: 0,
                branch: Some("main".to_string()),
                upstream: Some("origin/main".to_string()),
                commits_ahead: Some(1),
            },
        )
        .expect("first append should succeed");

        append_audit_event(
            &root,
            AuditEvent {
                source: AuditSource::PrePushHook,
                action: ProtectedAction::Push,
                status: "ready",
                outcome: "blocked",
                detail: None,
                verdict: Some(Verdict::Block),
                discovered_files: 2,
                candidate_files: 2,
                ignored_files: 0,
                findings: 2,
                warnings: 0,
                blocks: 1,
                overrides_applied: 0,
                receipt_issues: 0,
                branch: Some("main".to_string()),
                upstream: Some("origin/main".to_string()),
                commits_ahead: Some(1),
            },
        )
        .expect("second append should succeed");

        let verification = verify_audit_log(&root).expect("verification should succeed");
        assert!(verification.healthy);
        assert_eq!(verification.entries, 2);

        let entries = read_audit_log(&root).expect("audit log should be readable");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, "policy-allowed");
        assert_eq!(entries[0].discovered_files, 5);
        assert_eq!(entries[0].ignored_files, 2);
        assert_eq!(entries[1].outcome, "blocked");
    }

    #[test]
    fn verifies_legacy_v1_entry_without_detail_field() {
        let root = temp_repo("audit-legacy");
        let log_path = root.join(AUDIT_LOG_RELATIVE_PATH);
        fs::create_dir_all(log_path.parent().expect("audit log should have parent"))
            .expect("audit dir should exist");
        let legacy_entry = serde_json::json!({
            "version": 1,
            "sequence": 1,
            "timestamp_unix": 1775748508u64,
            "source": "push-command",
            "action": "push",
            "status": "no-commits",
            "outcome": "no-op",
            "verdict": serde_json::Value::Null,
            "candidate_files": 0,
            "findings": 0,
            "warnings": 0,
            "blocks": 0,
            "overrides_applied": 0,
            "receipt_issues": 0,
            "branch": serde_json::Value::Null,
            "upstream": serde_json::Value::Null,
            "commits_ahead": serde_json::Value::Null,
            "prev_hash": "genesis",
        });
        let entry_hash =
            git::hash_text(&serde_json::to_string(&legacy_entry).expect("json should serialize"))
                .expect("hash should compute");
        let mut record = legacy_entry
            .as_object()
            .expect("legacy entry should be object")
            .clone();
        record.insert(
            "entry_hash".to_string(),
            serde_json::Value::String(entry_hash),
        );
        let line = serde_json::to_string(&record).expect("record should serialize");
        fs::write(&log_path, format!("{line}\n")).expect("legacy log should write");

        let verification = verify_audit_log(&root).expect("verification should succeed");
        assert!(verification.healthy);
        assert_eq!(verification.entries, 1);
    }

    fn temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-audit-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("should create temp repo");
        path
    }
}
