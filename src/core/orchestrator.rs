//! Scan orchestration.
//!
//! The orchestrator is the control plane for one command execution. It decides
//! which scanners run, collects their normalized findings, and returns a single
//! report for downstream policy evaluation.

use std::cmp::Reverse;

use crate::app::AppResult;
use serde::Serialize;

use super::context::ExecutionContext;
use super::finding_baseline::FindingBaselineSummary;
use super::finding_history::FindingHistorySummary;
use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::scanners::{
    ArtifactScanner, BasicSastScanner, ConfigScanner, DependencyScanner, PolicyScanner,
    Scanner, ScannerProgress as ScannerFileProgress, SecretScanner,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanProgress {
    ScannerStarted {
        name: &'static str,
        index: usize,
        total: usize,
    },
    ScannerFinished {
        name: &'static str,
        index: usize,
        total: usize,
        findings: usize,
    },
    FileStarted {
        scanner: &'static str,
        file: std::path::PathBuf,
        current: usize,
        total: usize,
    },
}

/// Final scan output for one invocation.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub discovered_files: usize,
    pub scanned_files: usize,
    pub ignored_files: usize,
    pub scanners_run: usize,
    pub finding_history: FindingHistorySummary,
    pub finding_baseline: FindingBaselineSummary,
}

impl ScanReport {
    /// Adds findings after orchestration and keeps the report normalized.
    pub fn include_findings(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
        normalize_findings(&mut self.findings);
    }

    pub fn set_finding_history(&mut self, summary: FindingHistorySummary) {
        self.finding_history = summary;
    }

    pub fn set_finding_baseline(&mut self, summary: FindingBaselineSummary) {
        self.finding_baseline = summary;
    }
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
                Box::new(ArtifactScanner),
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
        self.run_with_progress(context, |_| {})
    }

    /// Runs every configured scanner against one execution context and emits
    /// progress events before and after each scanner.
    pub fn run_with_progress<F>(
        &self,
        context: &ExecutionContext,
        mut on_progress: F,
    ) -> AppResult<ScanReport>
    where
        F: FnMut(ScanProgress),
    {
        let mut findings = Vec::new();
        let total = self.scanners.len();

        for (index, scanner) in self.scanners.iter().enumerate() {
            let index = index + 1;
            on_progress(ScanProgress::ScannerStarted {
                name: scanner.name(),
                index,
                total,
            });
            let findings_before = findings.len();
            findings.extend(scanner.scan_with_progress(context, &mut |event| match event {
                ScannerFileProgress::FileStarted {
                    scanner,
                    file,
                    current,
                    total,
                } => on_progress(ScanProgress::FileStarted {
                    scanner,
                    file,
                    current,
                    total,
                }),
            })?);
            on_progress(ScanProgress::ScannerFinished {
                name: scanner.name(),
                index,
                total,
                findings: findings.len().saturating_sub(findings_before),
            });
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
            finding_history: FindingHistorySummary::default(),
            finding_baseline: FindingBaselineSummary::default(),
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
                node_internal_packages: Vec::new(),
                node_internal_package_prefixes: Vec::new(),
                node_registry_ownership: Vec::new(),
                ruby_source_ownership: Vec::new(),
                python_internal_packages: Vec::new(),
                python_internal_package_prefixes: Vec::new(),
                python_index_ownership: Vec::new(),
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
        assert_eq!(report.scanners_run, 6);
        assert_eq!(report.finding_history.new_findings, 0);
        assert_eq!(report.finding_history.recurring_findings, 0);
        assert_eq!(report.finding_baseline.accepted_findings, 0);
        assert_eq!(report.finding_baseline.unaccepted_findings, 0);
    }
}
