//! Shared protected-action evaluation helpers.
//!
//! Git hooks and user-facing commands must not drift apart. This module keeps
//! the common evaluation logic in one place so every enforcement path sees the
//! same execution context, scan report, and policy result.

use crate::app::AppResult;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::git::PushStatus;
use crate::core::orchestrator::{Orchestrator, ScanReport};
use crate::core::policy::{OverriddenFinding, PolicyDecision, PolicyFinding};
use crate::core::receipts::ReceiptIssue;

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
