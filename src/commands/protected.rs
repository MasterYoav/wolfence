//! Shared protected-action evaluation helpers.
//!
//! Git hooks and user-facing commands must not drift apart. This module keeps
//! the common evaluation logic in one place so every enforcement path sees the
//! same execution context, scan report, and policy result.

use crate::app::AppResult;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::findings::{Finding, FindingCategory, Severity};
use crate::core::git::PushStatus;
use crate::core::orchestrator::{Orchestrator, ScanReport};
use crate::core::policy::{OverriddenFinding, PolicyDecision, PolicyFinding};
use crate::core::receipts::ReceiptIssue;

const FILE_SAMPLE_LIMIT: usize = 8;

/// Evaluation result for a protected push.
#[derive(Debug, Clone)]
pub enum PushEvaluation {
    NoCommits {
        context: ExecutionContext,
    },
    UpToDate {
        context: ExecutionContext,
    },
    Ready {
        context: ExecutionContext,
        report: ScanReport,
        decision: PolicyDecision,
        current_branch: String,
        upstream_branch: Option<String>,
        commits_ahead: usize,
    },
}

/// Evaluates the real outbound content of a protected push.
pub fn evaluate_push_action() -> AppResult<PushEvaluation> {
    let context = ExecutionContext::load(ProtectedAction::Push)?;
    let Some(push_status) = context.push_status.clone() else {
        return Ok(PushEvaluation::UpToDate { context });
    };

    match push_status {
        PushStatus::NoCommits => Ok(PushEvaluation::NoCommits { context }),
        PushStatus::UpToDate => Ok(PushEvaluation::UpToDate { context }),
        PushStatus::Ready {
            current_branch,
            upstream_branch,
            commits_ahead,
            ..
        } => {
            let report = Orchestrator::default().run(&context)?;
            let decision = report.evaluate(context.config.mode, &context.receipts, context.action);

            Ok(PushEvaluation::Ready {
                context,
                report,
                decision,
                current_branch: current_branch.clone(),
                upstream_branch: upstream_branch.clone(),
                commits_ahead,
            })
        }
    }
}

/// Prints a consistent finding breakdown for protected push decisions.
pub fn print_decision_findings(decision: &PolicyDecision) {
    if !decision.blocking_findings.is_empty() {
        println!("  blocking findings:");
        print_finding_group(&decision.blocking_findings);
    }

    if decision.has_warnings() {
        println!("  warnings:");
        print_finding_group(&decision.warning_findings);
    }

    if !decision.overridden_findings.is_empty() {
        println!("  applied overrides:");
        print_overridden_group(&decision.overridden_findings);
    }
}

/// Prints the effective scan scope, including repo-local exclusions.
pub fn print_scan_scope(report: &ScanReport, context: &ExecutionContext) {
    println!("  candidate files discovered: {}", report.discovered_files);
    println!("  candidate files scanned: {}", report.scanned_files);
    print_file_sample("scanned file sample", &context.candidate_files);

    if report.ignored_files == 0 {
        return;
    }

    println!(
        "  candidate files ignored by config: {}",
        report.ignored_files
    );
    println!(
        "  ignore patterns: {}",
        context.config.scan_ignore_paths.join(", ")
    );
    print_file_sample("ignored file sample", &context.ignored_candidate_files);
}

/// Prints high-level finding counts before detailed output.
pub fn print_finding_summary(findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }

    println!(
        "  severity summary: critical {}, high {}, medium {}, low {}, info {}",
        count_by_severity(findings, Severity::Critical),
        count_by_severity(findings, Severity::High),
        count_by_severity(findings, Severity::Medium),
        count_by_severity(findings, Severity::Low),
        count_by_severity(findings, Severity::Info),
    );
    println!(
        "  category summary: secret {}, vulnerability {}, dependency {}, configuration {}, policy {}",
        count_by_category(findings, FindingCategory::Secret),
        count_by_category(findings, FindingCategory::Vulnerability),
        count_by_category(findings, FindingCategory::Dependency),
        count_by_category(findings, FindingCategory::Configuration),
        count_by_category(findings, FindingCategory::Policy),
    );
}

/// Prints ignored receipt issues so the operator can see why an override did not apply.
pub fn print_receipt_issues(issues: &[ReceiptIssue]) {
    if issues.is_empty() {
        return;
    }

    println!("  ignored receipt issues:");
    for issue in issues {
        println!("    - {}", issue.path.display());
        println!("      detail: {}", issue.detail);
        println!("      remediation: {}", issue.remediation);
    }
}

fn print_finding_group(findings: &[PolicyFinding]) {
    for policy_finding in findings {
        let finding = &policy_finding.finding;
        println!(
            "    - [{}|{}|{}] {}",
            finding.severity, finding.confidence, finding.category, finding.title
        );
        println!("      scanner: {}", finding.scanner);
        println!("      location: {}", finding.location());
        println!("      detail: {}", finding.detail);
        println!("      remediation: {}", finding.remediation);
        println!("      policy: {}", policy_finding.rationale);
    }
}

fn print_overridden_group(findings: &[OverriddenFinding]) {
    for overridden in findings {
        println!(
            "    - [{}|{}|{}] {}",
            overridden.finding.severity,
            overridden.finding.confidence,
            overridden.finding.category,
            overridden.finding.title
        );
        println!("      scanner: {}", overridden.finding.scanner);
        println!("      location: {}", overridden.finding.location());
        println!("      receipt: {}", overridden.receipt.path.display());
        println!("      owner: {}", overridden.receipt.owner);
        if let Some(approver) = &overridden.receipt.approver {
            println!("      approver: {}", approver);
        }
        if let Some(key_id) = &overridden.receipt.key_id {
            println!("      key_id: {}", key_id);
        }
        println!("      expires_on: {}", overridden.receipt.expires_on);
        println!("      reason: {}", overridden.receipt.reason);
    }
}

fn print_file_sample(label: &str, files: &[std::path::PathBuf]) {
    if files.is_empty() {
        return;
    }

    println!("  {label}:");
    for path in files.iter().take(FILE_SAMPLE_LIMIT) {
        println!("    - {}", path.display());
    }

    let remaining = files.len().saturating_sub(FILE_SAMPLE_LIMIT);
    if remaining > 0 {
        println!("    - ... and {remaining} more");
    }
}

fn count_by_severity(findings: &[Finding], target: Severity) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity == target)
        .count()
}

fn count_by_category(findings: &[Finding], target: FindingCategory) -> usize {
    findings
        .iter()
        .filter(|finding| finding.category == target)
        .count()
}
