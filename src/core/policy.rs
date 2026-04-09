//! Policy evaluation.
//!
//! The policy layer turns raw findings into operator-facing decisions. This is
//! where Wolfence eventually becomes opinionated: org policy, exception models,
//! signed rule bundles, and mode presets should all collapse into this
//! deterministic gate.

use std::fmt::{self, Display, Formatter};

use serde::Serialize;

use super::context::ProtectedAction;
use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::orchestrator::ScanReport;
use super::receipts::{OverrideReceipt, ReceiptIndex};

/// High-level enforcement presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Advisory,
    Standard,
    Strict,
}

impl Display for EnforcementMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advisory => write!(f, "advisory"),
            Self::Standard => write!(f, "standard"),
            Self::Strict => write!(f, "strict"),
        }
    }
}

impl EnforcementMode {
    /// Parses one textual mode name.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value.trim() {
            "advisory" => Ok(Self::Advisory),
            "standard" => Ok(Self::Standard),
            "strict" => Ok(Self::Strict),
            _ => Err("expected advisory, standard, or strict"),
        }
    }
}

/// Final outcome returned to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

impl Display for Verdict {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Warn => write!(f, "warn"),
            Self::Block => write!(f, "block"),
        }
    }
}

/// Explanation bundle emitted alongside a verdict.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub verdict: Verdict,
    pub blocking_findings: Vec<PolicyFinding>,
    pub warning_findings: Vec<PolicyFinding>,
    pub overridden_findings: Vec<OverriddenFinding>,
}

/// One finding plus the policy rationale behind its classification.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyFinding {
    pub finding: Finding,
    pub rationale: &'static str,
}

/// One finding that was suppressed by an active override receipt.
#[derive(Debug, Clone, Serialize)]
pub struct OverriddenFinding {
    pub finding: Finding,
    pub receipt: OverrideReceipt,
}

impl PolicyDecision {
    /// Returns whether the decision contains any non-blocking warnings.
    pub fn has_warnings(&self) -> bool {
        !self.warning_findings.is_empty()
    }
}

impl ScanReport {
    /// Evaluates the report against one enforcement mode.
    pub fn evaluate(
        &self,
        mode: EnforcementMode,
        receipts: &ReceiptIndex,
        action: ProtectedAction,
    ) -> PolicyDecision {
        let mut blocking_findings = Vec::new();
        let mut warning_findings = Vec::new();
        let mut overridden_findings = Vec::new();

        for finding in &self.findings {
            let disposition = classify_finding(mode, finding);
            let should_allow = matches!(disposition, FindingDisposition::Allow);

            if !should_allow {
                if let Some(receipt) =
                    receipts.matching_override(action, finding.category, &finding.fingerprint)
                {
                    overridden_findings.push(OverriddenFinding {
                        finding: finding.clone(),
                        receipt: receipt.clone(),
                    });
                    continue;
                }
            }

            match disposition {
                FindingDisposition::Allow => {}
                FindingDisposition::Warn(rationale) => warning_findings.push(PolicyFinding {
                    finding: finding.clone(),
                    rationale,
                }),
                FindingDisposition::Block(rationale) => blocking_findings.push(PolicyFinding {
                    finding: finding.clone(),
                    rationale,
                }),
            }
        }

        let verdict = if !blocking_findings.is_empty() {
            Verdict::Block
        } else if !warning_findings.is_empty() {
            Verdict::Warn
        } else {
            Verdict::Allow
        };

        PolicyDecision {
            verdict,
            blocking_findings,
            warning_findings,
            overridden_findings,
        }
    }
}

enum FindingDisposition {
    Allow,
    Warn(&'static str),
    Block(&'static str),
}

fn classify_finding(mode: EnforcementMode, finding: &Finding) -> FindingDisposition {
    match mode {
        EnforcementMode::Advisory => classify_advisory(finding),
        EnforcementMode::Standard => classify_standard(finding),
        EnforcementMode::Strict => classify_strict(finding),
    }
}

fn classify_advisory(finding: &Finding) -> FindingDisposition {
    if finding.severity >= Severity::Medium {
        return FindingDisposition::Warn(
            "advisory mode never blocks, but medium-and-above findings still require review.",
        );
    }

    if is_high_signal_non_heuristic(finding) {
        return FindingDisposition::Warn(
            "advisory mode still surfaces high-confidence non-vulnerability findings for review.",
        );
    }

    FindingDisposition::Allow
}

fn classify_standard(finding: &Finding) -> FindingDisposition {
    if finding.severity >= Severity::High {
        return FindingDisposition::Block("standard mode blocks high and critical findings.");
    }

    if finding.severity >= Severity::Medium && is_high_signal_non_heuristic(finding) {
        return FindingDisposition::Block(
            "standard mode blocks medium findings when the signal is high-confidence and not a heuristic vulnerability guess.",
        );
    }

    if finding.severity >= Severity::Medium {
        return FindingDisposition::Warn(
            "standard mode warns on remaining medium findings for operator review.",
        );
    }

    if is_high_signal_non_heuristic(finding) {
        return FindingDisposition::Warn(
            "standard mode surfaces high-confidence non-vulnerability findings even when they are not severe enough to block.",
        );
    }

    FindingDisposition::Allow
}

fn classify_strict(finding: &Finding) -> FindingDisposition {
    if finding.severity >= Severity::Medium {
        return FindingDisposition::Block(
            "strict mode blocks medium, high, and critical findings.",
        );
    }

    if finding.severity >= Severity::Low && is_high_signal_non_heuristic(finding) {
        return FindingDisposition::Block(
            "strict mode also blocks low-severity high-confidence non-vulnerability findings.",
        );
    }

    if finding.severity >= Severity::Low {
        return FindingDisposition::Warn("strict mode warns on remaining low-severity findings.");
    }

    if is_high_signal_non_heuristic(finding) {
        return FindingDisposition::Warn(
            "strict mode surfaces high-confidence informational findings for operator review.",
        );
    }

    FindingDisposition::Allow
}

fn is_high_signal_non_heuristic(finding: &Finding) -> bool {
    finding.confidence == Confidence::High && finding.category != FindingCategory::Vulnerability
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{EnforcementMode, Verdict};
    use crate::core::context::ProtectedAction;
    use crate::core::findings::{Confidence, Finding, FindingCategory, Severity};
    use crate::core::orchestrator::ScanReport;
    use crate::core::receipts::OverrideReceipt;
    use crate::core::receipts::{ReceiptIndex, RECEIPTS_DIR_RELATIVE_PATH};

    #[test]
    fn standard_mode_blocks_high_findings() {
        let report = ScanReport {
            findings: vec![Finding::new(
                "secret.aws_key",
                "secret-scanner",
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(PathBuf::from(".env")),
                "AWS access key pattern detected",
                "A staged file appears to contain a production credential.",
                "Remove the secret and rotate the credential.",
                "abc123",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Standard,
            &ReceiptIndex::default(),
            ProtectedAction::Push,
        );
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(decision.blocking_findings.len(), 1);
    }

    #[test]
    fn advisory_mode_warns_instead_of_blocking() {
        let report = ScanReport {
            findings: vec![Finding::new(
                "sast.eval",
                "basic-sast",
                Severity::Medium,
                Confidence::Medium,
                FindingCategory::Vulnerability,
                Some(PathBuf::from("app.js")),
                "Dynamic code execution pattern detected",
                "The staged code references eval-like behavior.",
                "Replace dynamic execution with a fixed dispatch table.",
                "def456",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Advisory,
            &ReceiptIndex::default(),
            ProtectedAction::Push,
        );
        assert_eq!(decision.verdict, Verdict::Warn);
        assert_eq!(decision.warning_findings.len(), 1);
    }

    #[test]
    fn standard_mode_blocks_medium_high_confidence_non_vulnerability_findings() {
        let report = ScanReport {
            findings: vec![Finding::new(
                "dependency.lock.missing-integrity",
                "dependency-scanner",
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(PathBuf::from("package-lock.json")),
                "Lockfile entry is missing integrity metadata",
                "The dependency lockfile includes a package without integrity verification metadata.",
                "Regenerate the lockfile with integrity hashes intact.",
                "lock:missing-integrity",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Standard,
            &ReceiptIndex::default(),
            ProtectedAction::Push,
        );
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(decision.blocking_findings.len(), 1);
    }

    #[test]
    fn standard_mode_only_warns_on_medium_vulnerability_heuristics() {
        let report = ScanReport {
            findings: vec![Finding::new(
                "sast.template-injection",
                "basic-sast",
                Severity::Medium,
                Confidence::High,
                FindingCategory::Vulnerability,
                Some(PathBuf::from("server.js")),
                "Potential injection sink detected",
                "The code routes untrusted data into a sensitive sink.",
                "Validate the data flow before allowing the push.",
                "sast:template-injection",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Standard,
            &ReceiptIndex::default(),
            ProtectedAction::Push,
        );
        assert_eq!(decision.verdict, Verdict::Warn);
        assert_eq!(decision.warning_findings.len(), 1);
    }

    #[test]
    fn strict_mode_blocks_low_severity_high_confidence_dependency_findings() {
        let report = ScanReport {
            findings: vec![Finding::new(
                "dependency.cargo.path-source",
                "dependency-scanner",
                Severity::Low,
                Confidence::High,
                FindingCategory::Dependency,
                Some(PathBuf::from("Cargo.toml")),
                "Cargo dependency uses a local path source",
                "A Cargo dependency is sourced from a local path.",
                "Confirm the path dependency is intentional.",
                "dependency-cargo-path:Cargo.toml:12",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Strict,
            &ReceiptIndex::default(),
            ProtectedAction::Push,
        );
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(decision.blocking_findings.len(), 1);
    }

    #[test]
    fn valid_override_receipt_suppresses_blocking_finding() {
        let repo_root = make_temp_repo("policy-override");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        let receipt = OverrideReceipt {
            path: receipts_dir.join("allow.toml"),
            receipt_id: "wr_policyoverride".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            category_bound: true,
            fingerprint: "abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            approver: None,
            key_id: None,
            reason: "temporary override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            checksum: "irrelevant-for-policy-test".to_string(),
        };

        let report = ScanReport {
            findings: vec![Finding::new(
                "secret.aws_key",
                "secret-scanner",
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(PathBuf::from(".env")),
                "AWS access key pattern detected",
                "A staged file appears to contain a production credential.",
                "Remove the secret and rotate the credential.",
                "abc123",
            )],
            discovered_files: 1,
            scanned_files: 1,
            ignored_files: 0,
            scanners_run: 1,
        };

        let decision = report.evaluate(
            EnforcementMode::Standard,
            &ReceiptIndex {
                active: vec![receipt],
                issues: Vec::new(),
                trusted_keys: 0,
                published_trusted_keys: 0,
                expired_trusted_keys: 0,
                trust_metadata_files: 0,
                trust_metadata_missing: 0,
                trust_metadata_incomplete: 0,
                scoped_trusted_keys: 0,
                unrestricted_trusted_keys: 0,
                signed_receipts_required: false,
                signed_receipts_required_by_policy: false,
                approval_policy_exists: false,
                require_explicit_category: false,
                require_signed_receipts: false,
                require_reviewer_metadata: false,
                max_lifetime_days: None,
                allowed_reviewers: 0,
                allowed_approvers: 0,
                allowed_key_ids: 0,
                category_policy_overrides: 0,
                signed_category_policy_overrides: 0,
                legacy_active_receipts: 0,
            },
            ProtectedAction::Push,
        );

        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.overridden_findings.len(), 1);
        assert!(decision.blocking_findings.is_empty());
    }

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-policy-{name}-{}-{}",
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
