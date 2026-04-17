//! Shared protected-action evaluation helpers.
//!
//! Git hooks and user-facing commands must not drift apart. This module keeps
//! the common evaluation logic in one place so every enforcement path sees the
//! same execution context, scan report, and policy result.

use crate::app::AppResult;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::finding_baseline;
use crate::core::finding_history;
use crate::core::findings::{Finding, FindingCategory, Severity};
use crate::core::git::{self, PushStatus};
use crate::core::github_governance;
use crate::core::orchestrator::{Orchestrator, ScanProgress, ScanReport};
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
        push_status: PushStatus,
        current_branch: String,
        upstream_branch: Option<String>,
        commits_ahead: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushEvaluationProgress {
    SnapshotLoaded {
        current_branch: String,
        upstream_branch: Option<String>,
        commits_ahead: usize,
        discovered_files: usize,
        scanned_files: usize,
        ignored_files: usize,
    },
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
    GovernanceCheck,
    FindingHistory,
    FindingBaseline,
    PolicyEvaluation,
}

/// Evaluates the real outbound content of a protected push.
pub fn evaluate_push_action() -> AppResult<PushEvaluation> {
    evaluate_push_action_with_progress(|_| {})
}

/// Evaluates the real outbound content of a protected push for one explicit
/// repository root and emits progress events.
pub fn evaluate_push_action_for_repo_with_progress<F>(
    repo_root: &std::path::Path,
    on_progress: F,
) -> AppResult<PushEvaluation>
where
    F: FnMut(PushEvaluationProgress),
{
    evaluate_push_action_from_context(ExecutionContext::load_for_repo(
        repo_root,
        ProtectedAction::Push,
    )?, on_progress)
}

/// Evaluates the real outbound content of a protected push and emits progress
/// events that terminal UIs can render in real time.
pub fn evaluate_push_action_with_progress<F>(mut on_progress: F) -> AppResult<PushEvaluation>
where
    F: FnMut(PushEvaluationProgress),
{
    let context = ExecutionContext::load(ProtectedAction::Push)?;
    evaluate_push_action_from_context(context, |event| on_progress(event))
}

fn evaluate_push_action_from_context<F>(
    context: ExecutionContext,
    mut on_progress: F,
) -> AppResult<PushEvaluation>
where
    F: FnMut(PushEvaluationProgress),
{
    let Some(push_status) = context.push_status.clone() else {
        return Ok(PushEvaluation::UpToDate { context });
    };

    match &push_status {
        PushStatus::NoCommits => Ok(PushEvaluation::NoCommits { context }),
        PushStatus::UpToDate => Ok(PushEvaluation::UpToDate { context }),
        PushStatus::Ready {
            current_branch,
            upstream_branch,
            commits_ahead,
            ..
        } => {
            on_progress(PushEvaluationProgress::SnapshotLoaded {
                current_branch: current_branch.clone(),
                upstream_branch: upstream_branch.clone(),
                commits_ahead: *commits_ahead,
                discovered_files: context.discovered_candidate_files,
                scanned_files: context.candidate_files.len(),
                ignored_files: context.ignored_candidate_files.len(),
            });

            let mut report = Orchestrator::default().run_with_progress(&context, |event| {
                match event {
                    ScanProgress::ScannerStarted { name, index, total } => {
                        on_progress(PushEvaluationProgress::ScannerStarted { name, index, total });
                    }
                    ScanProgress::ScannerFinished {
                        name,
                        index,
                        total,
                        findings,
                    } => {
                        on_progress(PushEvaluationProgress::ScannerFinished {
                            name,
                            index,
                            total,
                            findings,
                        });
                    }
                    ScanProgress::FileStarted {
                        scanner,
                        file,
                        current,
                        total,
                    } => {
                        on_progress(PushEvaluationProgress::FileStarted {
                            scanner,
                            file,
                            current,
                            total,
                        });
                    }
                }
            })?;
            on_progress(PushEvaluationProgress::GovernanceCheck);
            inject_live_github_governance(&context, &mut report)?;
            on_progress(PushEvaluationProgress::FindingHistory);
            let history =
                finding_history::annotate_findings(&context.repo_root, &mut report.findings);
            report.set_finding_history(history);
            on_progress(PushEvaluationProgress::FindingBaseline);
            let baseline =
                finding_baseline::annotate_findings(&context.repo_root, &mut report.findings);
            report.set_finding_baseline(baseline);
            on_progress(PushEvaluationProgress::PolicyEvaluation);
            let decision = report.evaluate(context.config.mode, &context.receipts, context.action);

            Ok(PushEvaluation::Ready {
                context,
                report,
                decision,
                push_status: push_status.clone(),
                current_branch: current_branch.clone(),
                upstream_branch: upstream_branch.clone(),
                commits_ahead: *commits_ahead,
            })
        }
    }
}

/// Rechecks the outbound push snapshot before the final transport side effect.
pub fn verify_ready_push_snapshot(
    context: &ExecutionContext,
    expected: &PushStatus,
) -> AppResult<()> {
    git::verify_push_status_unchanged(&context.repo_root, expected)
}

fn inject_live_github_governance(
    context: &ExecutionContext,
    report: &mut ScanReport,
) -> AppResult<()> {
    let Some(finding) = github_governance::push_blocking_finding(&context.repo_root)? else {
        return Ok(());
    };

    report.include_findings([finding]);
    Ok(())
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

pub fn print_finding_history(report: &ScanReport) {
    if report.findings.is_empty() {
        return;
    }

    println!(
        "  finding history: {} new, {} recurring",
        report.finding_history.new_findings, report.finding_history.recurring_findings
    );
    if let Some(issue) = &report.finding_history.issue {
        println!("  finding history issue: {issue}");
    }
}

pub fn print_finding_baseline(report: &ScanReport) {
    if report.findings.is_empty() {
        return;
    }

    println!(
        "  finding baseline: {} accepted, {} not accepted",
        report.finding_baseline.accepted_findings, report.finding_baseline.unaccepted_findings
    );
    if let Some(issue) = &report.finding_baseline.issue {
        println!("  finding baseline issue: {issue}");
    }
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
        let remediation = &finding.remediation_advice;
        println!(
            "    - [{}|{}|{}] {}",
            finding.severity, finding.confidence, finding.category, finding.title
        );
        println!("      scanner: {}", finding.scanner);
        println!("      location: {}", finding.location());
        println!("      detail: {}", finding.detail);
        println!("      fingerprint: {}", finding.fingerprint);
        println!(
            "      baseline: {}",
            if finding.baseline.accepted {
                "accepted-starting-state"
            } else {
                "not-in-baseline"
            }
        );
        println!("      action: {}", remediation.primary_action);
        println!(
            "      urgency: {}, owner: {}",
            remediation.urgency, remediation.owner_surface
        );
        if let Some(command) = &remediation.primary_command {
            println!("      command: {command}");
        }
        if let Some(docs_ref) = &remediation.docs_ref {
            println!("      docs: {docs_ref}");
        }
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
        println!("      fingerprint: {}", overridden.finding.fingerprint);
        println!(
            "      baseline: {}",
            if overridden.finding.baseline.accepted {
                "accepted-starting-state"
            } else {
                "not-in-baseline"
            }
        );
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
