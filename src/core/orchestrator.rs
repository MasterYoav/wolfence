//! Scan orchestration.
//!
//! The orchestrator is the control plane for one command execution. It decides
//! which scanners run, collects their normalized findings, and returns a single
//! report for downstream policy evaluation.

use std::cmp::Reverse;

use crate::app::AppResult;

use super::context::ExecutionContext;
use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::scanners::{
    BasicSastScanner, ConfigScanner, DependencyScanner, PolicyScanner, Scanner, SecretScanner,
};

/// Final scan output for one invocation.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub discovered_files: usize,
    pub scanned_files: usize,
    pub ignored_files: usize,
    pub scanners_run: usize,
}

/// Coordinates scanner execution.
pub struct Orchestrator {
    scanners: Vec<Box<dyn Scanner>>,
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self {
            scanners: vec![
                Box::new(SecretScanner),
                Box::new(BasicSastScanner),
                Box::new(DependencyScanner),
                Box::new(ConfigScanner),
                Box::new(PolicyScanner),
            ],
        }
    }
}

impl Orchestrator {
    /// Runs every configured scanner against one execution context.
    pub fn run(&self, context: &ExecutionContext) -> AppResult<ScanReport> {
        let mut findings = Vec::new();

        for scanner in &self.scanners {
            findings.extend(scanner.scan(context)?);
        }

        normalize_findings(&mut findings);

        Ok(ScanReport {
            findings,
            discovered_files: context.discovered_candidate_files,
            scanned_files: context.candidate_files.len(),
            ignored_files: context
                .discovered_candidate_files
                .saturating_sub(context.candidate_files.len()),
            scanners_run: self.scanners.len(),
        })
    }
}

fn normalize_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|left, right| {
        Reverse(severity_rank(left.severity))
            .cmp(&Reverse(severity_rank(right.severity)))
            .then_with(|| {
                Reverse(confidence_rank(left.confidence))
                    .cmp(&Reverse(confidence_rank(right.confidence)))
            })
            .then_with(|| {
                Reverse(category_rank(left.category)).cmp(&Reverse(category_rank(right.category)))
            })
            .then_with(|| left.scanner.cmp(right.scanner))
            .then_with(|| left.location().cmp(&right.location()))
            .then_with(|| left.id.cmp(&right.id))
    });
    findings.dedup_by(|left, right| left.fingerprint == right.fingerprint);
}

fn severity_rank(value: Severity) -> u8 {
    match value {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn confidence_rank(value: Confidence) -> u8 {
    match value {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn category_rank(value: FindingCategory) -> u8 {
    match value {
        FindingCategory::Policy => 0,
        FindingCategory::Configuration => 1,
        FindingCategory::Dependency => 2,
        FindingCategory::Vulnerability => 3,
        FindingCategory::Secret => 4,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{normalize_findings, Orchestrator};
    use crate::core::config::{ConfigSource, ResolvedConfig};
    use crate::core::context::{ExecutionContext, ProtectedAction};
    use crate::core::findings::{Confidence, Finding, FindingCategory, Severity};
    use crate::core::policy::EnforcementMode;
    use crate::core::receipts::ReceiptIndex;

    #[test]
    fn normalization_sorts_stronger_findings_first_and_deduplicates_fingerprints() {
        let mut findings = vec![
            Finding::new(
                "dependency.medium",
                "dependency-scanner",
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(PathBuf::from("Cargo.toml")),
                "Medium dependency risk",
                "detail",
                "fix",
                "shared-fingerprint",
            ),
            Finding::new(
                "secret.critical",
                "secret-scanner",
                Severity::Critical,
                Confidence::High,
                FindingCategory::Secret,
                Some(PathBuf::from(".env")),
                "Critical secret",
                "detail",
                "fix",
                "critical-secret",
            ),
            Finding::new(
                "dependency.medium.duplicate",
                "dependency-scanner",
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(PathBuf::from("Cargo.toml")),
                "Duplicate dependency risk",
                "detail",
                "fix",
                "shared-fingerprint",
            ),
        ];

        normalize_findings(&mut findings);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].id, "secret.critical");
        assert_eq!(findings[1].id, "dependency.medium");
    }

    #[test]
    fn report_tracks_discovered_scanned_and_ignored_file_counts() {
        let context = ExecutionContext {
            action: ProtectedAction::Scan,
            repo_root: std::env::temp_dir(),
            discovered_candidate_files: 3,
            candidate_files: vec![PathBuf::from("README.md")],
            ignored_candidate_files: vec![
                PathBuf::from("docs/guide.md"),
                PathBuf::from("docs/api.md"),
            ],
            config: ResolvedConfig {
                mode: EnforcementMode::Standard,
                mode_source: ConfigSource::Default,
                repo_config_path: PathBuf::from(".wolfence/config.toml"),
                repo_config_exists: true,
                scan_ignore_paths: vec!["docs/".to_string()],
            },
            receipts: ReceiptIndex::default(),
            push_status: None,
        };

        let report = Orchestrator::default()
            .run(&context)
            .expect("orchestrator should succeed");

        assert_eq!(report.discovered_files, 3);
        assert_eq!(report.scanned_files, 1);
        assert_eq!(report.ignored_files, 2);
    }
}
