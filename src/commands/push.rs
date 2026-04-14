//! `wolf push`
//!
//! This is the highest-value workflow in the product. Even in scaffold form,
//! the command executes the same sequence the final system will need:
//! repository context -> scan orchestration -> policy evaluation -> operator
//! explanation -> git side effect.
//!
//! This command now protects the actual `git push` path. It still has important
//! limitations, but it no longer pretends that staged files are equivalent to
//! outbound branch content.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use serde::Serialize;

use crate::app::AppResult;
use crate::core::audit::{self, AuditEvent, AuditSource};
use crate::core::policy::{OverriddenFinding, PolicyDecision, PolicyFinding};
use crate::core::git;
use crate::core::policy::Verdict;

use super::json::{path_strings, print_json, print_json_error};
use super::protected::{self, PushEvaluation, PushEvaluationProgress};

pub fn run(json: bool) -> AppResult<ExitCode> {
    let result = run_internal(json);
    if json {
        if let Err(error) = &result {
            print_json_error("push", error)?;
            return Ok(ExitCode::FAILURE);
        }
    }
    result
}

#[derive(Serialize)]
struct JsonPushScope {
    discovered_files: usize,
    scanned_files: usize,
    ignored_files: usize,
    scanned_paths: Vec<String>,
    ignored_paths: Vec<String>,
    ignore_patterns: Vec<String>,
}

#[derive(Serialize)]
struct JsonPushResponse {
    command: &'static str,
    action: &'static str,
    repo_root: String,
    mode: Option<String>,
    mode_source: Option<String>,
    status: &'static str,
    branch: Option<String>,
    upstream: Option<String>,
    commits_ahead: Option<usize>,
    report: Option<crate::core::orchestrator::ScanReport>,
    decision: Option<crate::core::policy::PolicyDecision>,
    scan_scope: Option<JsonPushScope>,
    receipt_issues: Vec<crate::core::receipts::ReceiptIssue>,
    outcome: &'static str,
    git_error: Option<String>,
}

fn run_internal(json: bool) -> AppResult<ExitCode> {
    let interactive = interactive_output_enabled(json);
    let mut tty = interactive.then(TtyPushUi::new);
    let evaluation = if let Some(tty) = tty.as_mut() {
        protected::evaluate_push_action_with_progress(|event| tty.handle_progress(event))?
    } else {
        protected::evaluate_push_action()?
    };

    match evaluation {
        PushEvaluation::NoCommits { context } => {
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PushCommand,
                    action: context.action,
                    status: "no-commits",
                    outcome: "no-op",
                    detail: None,
                    verdict: None,
                    discovered_files: 0,
                    candidate_files: 0,
                    ignored_files: 0,
                    findings: 0,
                    warnings: 0,
                    blocks: 0,
                    overrides_applied: 0,
                    receipt_issues: context.receipts.issues.len(),
                    branch: None,
                    upstream: None,
                    commits_ahead: None,
                },
            )?;
            if json {
                print_json(&JsonPushResponse {
                    command: "push",
                    action: "push",
                    repo_root: context.repo_root.display().to_string(),
                    mode: None,
                    mode_source: None,
                    status: "no-commits",
                    branch: None,
                    upstream: None,
                    commits_ahead: None,
                    report: None,
                    decision: None,
                    scan_scope: None,
                    receipt_issues: context.receipts.issues.clone(),
                    outcome: "no-op",
                    git_error: None,
                })?;
                return Ok(ExitCode::FAILURE);
            }
            if let Some(tty) = tty.as_mut() {
                tty.finish_scan_line("No commits exist on the current branch.");
                println!("  result: nothing to push");
            } else {
                println!("Wolfence push");
                println!("  action: {}", context.action);
                println!("  repo root: {}", context.repo_root.display());
                println!("  status: no commits exist on the current branch");
                println!("  result: nothing to push");
            }
            Ok(ExitCode::FAILURE)
        }
        PushEvaluation::UpToDate { context } => {
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PushCommand,
                    action: context.action,
                    status: "up-to-date",
                    outcome: "no-op",
                    detail: None,
                    verdict: None,
                    discovered_files: 0,
                    candidate_files: 0,
                    ignored_files: 0,
                    findings: 0,
                    warnings: 0,
                    blocks: 0,
                    overrides_applied: 0,
                    receipt_issues: context.receipts.issues.len(),
                    branch: None,
                    upstream: None,
                    commits_ahead: Some(0),
                },
            )?;
            if json {
                print_json(&JsonPushResponse {
                    command: "push",
                    action: "push",
                    repo_root: context.repo_root.display().to_string(),
                    mode: None,
                    mode_source: None,
                    status: "up-to-date",
                    branch: None,
                    upstream: None,
                    commits_ahead: Some(0),
                    report: None,
                    decision: None,
                    scan_scope: None,
                    receipt_issues: context.receipts.issues.clone(),
                    outcome: "no-op",
                    git_error: None,
                })?;
                return Ok(ExitCode::SUCCESS);
            }
            if let Some(tty) = tty.as_mut() {
                tty.finish_scan_line("Branch is already up to date.");
                println!("  result: nothing to push");
            } else {
                println!("Wolfence push");
                println!("  action: {}", context.action);
                println!("  repo root: {}", context.repo_root.display());
                println!("  status: branch is not ahead of its upstream");
                println!("  result: nothing to push");
            }
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::Ready {
            context,
            report,
            decision,
            push_status,
            current_branch,
            upstream_branch,
            commits_ahead,
        } => {
            let scan_scope = JsonPushScope {
                discovered_files: report.discovered_files,
                scanned_files: report.scanned_files,
                ignored_files: report.ignored_files,
                scanned_paths: path_strings(&context.candidate_files),
                ignored_paths: path_strings(&context.ignored_candidate_files),
                ignore_patterns: context.config.scan_ignore_paths.clone(),
            };

            let outcome = match decision.verdict {
                Verdict::Allow | Verdict::Warn if dry_run_enabled() => "allowed-dry-run",
                Verdict::Allow | Verdict::Warn => "policy-allowed",
                Verdict::Block => "blocked",
            };

            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PushCommand,
                    action: context.action,
                    status: "ready",
                    outcome,
                    detail: None,
                    verdict: Some(decision.verdict),
                    discovered_files: report.discovered_files,
                    candidate_files: report.scanned_files,
                    ignored_files: report.ignored_files,
                    findings: report.findings.len(),
                    warnings: decision.warning_findings.len(),
                    blocks: decision.blocking_findings.len(),
                    overrides_applied: decision.overridden_findings.len(),
                    receipt_issues: context.receipts.issues.len(),
                    branch: Some(current_branch.clone()),
                    upstream: upstream_branch.clone(),
                    commits_ahead: Some(commits_ahead),
                },
            )?;

            if json {
                match decision.verdict {
                    Verdict::Block => {
                        print_json(&JsonPushResponse {
                            command: "push",
                            action: "push",
                            repo_root: context.repo_root.display().to_string(),
                            mode: Some(context.config.mode.to_string()),
                            mode_source: Some(context.config.mode_source.to_string()),
                            status: "ready",
                            branch: Some(current_branch),
                            upstream: upstream_branch,
                            commits_ahead: Some(commits_ahead),
                            report: Some(report),
                            decision: Some(decision),
                            scan_scope: Some(scan_scope),
                            receipt_issues: context.receipts.issues.clone(),
                            outcome,
                            git_error: None,
                        })?;
                        return Ok(ExitCode::FAILURE);
                    }
                    Verdict::Allow | Verdict::Warn if dry_run_enabled() => {
                        print_json(&JsonPushResponse {
                            command: "push",
                            action: "push",
                            repo_root: context.repo_root.display().to_string(),
                            mode: Some(context.config.mode.to_string()),
                            mode_source: Some(context.config.mode_source.to_string()),
                            status: "ready",
                            branch: Some(current_branch),
                            upstream: upstream_branch,
                            commits_ahead: Some(commits_ahead),
                            report: Some(report),
                            decision: Some(decision),
                            scan_scope: Some(scan_scope),
                            receipt_issues: context.receipts.issues.clone(),
                            outcome,
                            git_error: None,
                        })?;
                        return Ok(ExitCode::SUCCESS);
                    }
                    Verdict::Allow | Verdict::Warn => {
                        if let Err(error) =
                            protected::verify_ready_push_snapshot(&context, &push_status)
                        {
                            let detail = error.to_string();
                            audit::append_audit_event(
                                &context.repo_root,
                                AuditEvent {
                                    source: AuditSource::PushCommand,
                                    action: context.action,
                                    status: "ready",
                                    outcome: "push-failed",
                                    detail: Some(detail.clone()),
                                    verdict: Some(decision.verdict),
                                    discovered_files: report.discovered_files,
                                    candidate_files: report.scanned_files,
                                    ignored_files: report.ignored_files,
                                    findings: report.findings.len(),
                                    warnings: decision.warning_findings.len(),
                                    blocks: decision.blocking_findings.len(),
                                    overrides_applied: decision.overridden_findings.len(),
                                    receipt_issues: context.receipts.issues.len(),
                                    branch: Some(current_branch.clone()),
                                    upstream: upstream_branch.clone(),
                                    commits_ahead: Some(commits_ahead),
                                },
                            )?;
                            print_json(&JsonPushResponse {
                                command: "push",
                                action: "push",
                                repo_root: context.repo_root.display().to_string(),
                                mode: Some(context.config.mode.to_string()),
                                mode_source: Some(context.config.mode_source.to_string()),
                                status: "ready",
                                branch: Some(current_branch),
                                upstream: upstream_branch,
                                commits_ahead: Some(commits_ahead),
                                report: Some(report),
                                decision: Some(decision),
                                scan_scope: Some(scan_scope),
                                receipt_issues: context.receipts.issues.clone(),
                                outcome: "push-failed",
                                git_error: Some(detail),
                            })?;
                            return Ok(ExitCode::FAILURE);
                        }

                        match git::push(
                            &context.repo_root,
                            &current_branch,
                            upstream_branch.as_deref(),
                        ) {
                            Ok(()) => {
                                audit::append_audit_event(
                                    &context.repo_root,
                                    AuditEvent {
                                        source: AuditSource::PushCommand,
                                        action: context.action,
                                        status: "completed",
                                        outcome: "push-completed",
                                        detail: None,
                                        verdict: Some(decision.verdict),
                                        discovered_files: report.discovered_files,
                                        candidate_files: report.scanned_files,
                                        ignored_files: report.ignored_files,
                                        findings: report.findings.len(),
                                        warnings: decision.warning_findings.len(),
                                        blocks: decision.blocking_findings.len(),
                                        overrides_applied: decision.overridden_findings.len(),
                                        receipt_issues: context.receipts.issues.len(),
                                        branch: Some(current_branch.clone()),
                                        upstream: upstream_branch.clone(),
                                        commits_ahead: Some(commits_ahead),
                                    },
                                )?;
                                print_json(&JsonPushResponse {
                                    command: "push",
                                    action: "push",
                                    repo_root: context.repo_root.display().to_string(),
                                    mode: Some(context.config.mode.to_string()),
                                    mode_source: Some(context.config.mode_source.to_string()),
                                    status: "completed",
                                    branch: Some(current_branch),
                                    upstream: upstream_branch,
                                    commits_ahead: Some(commits_ahead),
                                    report: Some(report),
                                    decision: Some(decision),
                                    scan_scope: Some(scan_scope),
                                    receipt_issues: context.receipts.issues.clone(),
                                    outcome: "push-completed",
                                    git_error: None,
                                })?;
                                return Ok(ExitCode::SUCCESS);
                            }
                            Err(error) => {
                                let detail = error.to_string();
                                audit::append_audit_event(
                                    &context.repo_root,
                                    AuditEvent {
                                        source: AuditSource::PushCommand,
                                        action: context.action,
                                        status: "ready",
                                        outcome: "push-failed",
                                        detail: Some(detail.clone()),
                                        verdict: Some(decision.verdict),
                                        discovered_files: report.discovered_files,
                                        candidate_files: report.scanned_files,
                                        ignored_files: report.ignored_files,
                                        findings: report.findings.len(),
                                        warnings: decision.warning_findings.len(),
                                        blocks: decision.blocking_findings.len(),
                                        overrides_applied: decision.overridden_findings.len(),
                                        receipt_issues: context.receipts.issues.len(),
                                        branch: Some(current_branch.clone()),
                                        upstream: upstream_branch.clone(),
                                        commits_ahead: Some(commits_ahead),
                                    },
                                )?;
                                print_json(&JsonPushResponse {
                                    command: "push",
                                    action: "push",
                                    repo_root: context.repo_root.display().to_string(),
                                    mode: Some(context.config.mode.to_string()),
                                    mode_source: Some(context.config.mode_source.to_string()),
                                    status: "ready",
                                    branch: Some(current_branch),
                                    upstream: upstream_branch,
                                    commits_ahead: Some(commits_ahead),
                                    report: Some(report),
                                    decision: Some(decision),
                                    scan_scope: Some(scan_scope),
                                    receipt_issues: context.receipts.issues.clone(),
                                    outcome: "push-failed",
                                    git_error: Some(detail),
                                })?;
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                    }
                }
            }

            if let Some(tty) = tty.as_mut() {
                tty.finish_scan_summary(
                    &context,
                    &report,
                    &decision,
                    &current_branch,
                    upstream_branch.as_deref(),
                    commits_ahead,
                );
                if matches!(decision.verdict, Verdict::Allow | Verdict::Warn)
                    && (decision.has_warnings() || !decision.overridden_findings.is_empty())
                {
                    print_tty_decision_findings(&decision);
                }
            } else {
                println!("Wolfence push");
                println!("  action: {}", context.action);
                println!("  repo root: {}", context.repo_root.display());
                println!(
                    "  mode: {} ({})",
                    context.config.mode, context.config.mode_source
                );
                println!("  branch: {}", current_branch);
                println!(
                    "  upstream: {}",
                    upstream_branch
                        .as_deref()
                        .unwrap_or("<none: initial push mode>")
                );
                println!("  commits ahead: {}", commits_ahead);
                protected::print_scan_scope(&report, &context);
                println!("  findings: {}", report.findings.len());
                protected::print_finding_summary(&report.findings);
                protected::print_finding_history(&report);
                protected::print_finding_baseline(&report);
                println!("  warnings: {}", decision.warning_findings.len());
                println!("  blocks: {}", decision.blocking_findings.len());
                println!(
                    "  overrides applied: {}",
                    decision.overridden_findings.len()
                );
                println!("  receipt issues: {}", context.receipts.issues.len());
                println!("  verdict: {}", decision.verdict);
                protected::print_receipt_issues(&context.receipts.issues);
                protected::print_decision_findings(&decision);
            }

            match decision.verdict {
                Verdict::Allow | Verdict::Warn => {
                    if dry_run_enabled() {
                        if tty.is_some() {
                            print_tty_result_line("dry run", true);
                        } else {
                            println!("  result: policy allowed the push, but git push was skipped because WOLFENCE_DRY_RUN=1");
                        }
                        return Ok(ExitCode::SUCCESS);
                    }

                    if let Some(tty) = tty.as_mut() {
                        tty.start_transport("Verifying outbound snapshot");
                    }
                    if let Err(error) =
                        protected::verify_ready_push_snapshot(&context, &push_status)
                    {
                        let detail = error.to_string();
                        audit::append_audit_event(
                            &context.repo_root,
                            AuditEvent {
                                source: AuditSource::PushCommand,
                                action: context.action,
                                status: "ready",
                                outcome: "push-failed",
                                detail: Some(detail.clone()),
                                verdict: Some(decision.verdict),
                                discovered_files: report.discovered_files,
                                candidate_files: report.scanned_files,
                                ignored_files: report.ignored_files,
                                findings: report.findings.len(),
                                warnings: decision.warning_findings.len(),
                                blocks: decision.blocking_findings.len(),
                                overrides_applied: decision.overridden_findings.len(),
                                receipt_issues: context.receipts.issues.len(),
                                branch: Some(current_branch.clone()),
                                upstream: upstream_branch.clone(),
                                commits_ahead: Some(commits_ahead),
                            },
                        )?;
                        if let Some(tty) = tty.as_mut() {
                            tty.finish_transport_line("snapshot changed");
                            println!("  git: {detail}");
                        } else {
                            println!("  result: policy allowed the push, but the outbound snapshot changed before transport");
                            println!("  git: {detail}");
                        }
                        return Ok(ExitCode::FAILURE);
                    }

                    if let Some(tty) = tty.as_mut() {
                        tty.start_transport(&format!(
                            "Pushing {} -> {}",
                            current_branch,
                            upstream_branch
                                .as_deref()
                                .unwrap_or("<initial push>")
                        ));
                    }
                    match git::push(
                        &context.repo_root,
                        &current_branch,
                        upstream_branch.as_deref(),
                    ) {
                        Ok(()) => {
                            audit::append_audit_event(
                                &context.repo_root,
                                AuditEvent {
                                    source: AuditSource::PushCommand,
                                    action: context.action,
                                    status: "completed",
                                    outcome: "push-completed",
                                    detail: None,
                                    verdict: Some(decision.verdict),
                                    discovered_files: report.discovered_files,
                                    candidate_files: report.scanned_files,
                                    ignored_files: report.ignored_files,
                                    findings: report.findings.len(),
                                    warnings: decision.warning_findings.len(),
                                    blocks: decision.blocking_findings.len(),
                                    overrides_applied: decision.overridden_findings.len(),
                                    receipt_issues: context.receipts.issues.len(),
                                    branch: Some(current_branch.clone()),
                                    upstream: upstream_branch.clone(),
                                    commits_ahead: Some(commits_ahead),
                                },
                            )?;
                            if let Some(tty) = tty.as_mut() {
                                tty.finish_transport_line("push completed");
                            } else {
                                println!("  result: git push completed");
                            }
                            Ok(ExitCode::SUCCESS)
                        }
                        Err(error) => {
                            let detail = error.to_string();
                            audit::append_audit_event(
                                &context.repo_root,
                                AuditEvent {
                                    source: AuditSource::PushCommand,
                                    action: context.action,
                                    status: "ready",
                                    outcome: "push-failed",
                                    detail: Some(detail.clone()),
                                    verdict: Some(decision.verdict),
                                    discovered_files: report.discovered_files,
                                    candidate_files: report.scanned_files,
                                    ignored_files: report.ignored_files,
                                    findings: report.findings.len(),
                                    warnings: decision.warning_findings.len(),
                                    blocks: decision.blocking_findings.len(),
                                    overrides_applied: decision.overridden_findings.len(),
                                    receipt_issues: context.receipts.issues.len(),
                                    branch: Some(current_branch.clone()),
                                    upstream: upstream_branch.clone(),
                                    commits_ahead: Some(commits_ahead),
                                },
                            )?;
                            if let Some(tty) = tty.as_mut() {
                                tty.finish_transport_line("push failed");
                                println!("  git: {detail}");
                            } else {
                                println!("  result: policy allowed the push, but git push failed");
                                println!("  git: {detail}");
                            }
                            Ok(ExitCode::FAILURE)
                        }
                    }
                }
                Verdict::Block => {
                    if let Some(_tty) = tty.as_mut() {
                        protected::print_receipt_issues(&context.receipts.issues);
                        print_tty_decision_findings(&decision);
                        print_tty_result_line("blocked", false);
                    } else {
                        println!("  push blocked by current policy");
                    }
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn interactive_output_enabled(json: bool) -> bool {
    !json && io::stdout().is_terminal()
}

fn dry_run_enabled() -> bool {
    matches!(
        std::env::var("WOLFENCE_DRY_RUN").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

struct SpinnerState {
    message: String,
}

struct SpinnerHandle {
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<SpinnerState>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SpinnerHandle {
    fn start(initial_message: impl Into<String>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(SpinnerState {
            message: initial_message.into(),
        }));
        let thread_stop = Arc::clone(&stop);
        let thread_state = Arc::clone(&state);

        let thread = thread::spawn(move || {
            let frames = ['-', '\\', '|', '/'];
            let mut frame_index = 0usize;
            let mut last_width = 0usize;

            while !thread_stop.load(Ordering::Relaxed) {
                let message = thread_state
                    .lock()
                    .map(|state| state.message.clone())
                    .unwrap_or_else(|_| "Working".to_string());
                let rendered = format!("  {} {}", frames[frame_index], message);
                let padding = " ".repeat(last_width.saturating_sub(rendered.len()));
                print!("\r{rendered}{padding}");
                let _ = io::stdout().flush();
                last_width = rendered.len();
                frame_index = (frame_index + 1) % frames.len();
                thread::sleep(Duration::from_millis(90));
            }

            let clear = " ".repeat(last_width);
            print!("\r{clear}\r");
            let _ = io::stdout().flush();
        });

        Self {
            stop,
            state,
            thread: Some(thread),
        }
    }

    fn update(&self, message: impl Into<String>) {
        if let Ok(mut state) = self.state.lock() {
            state.message = message.into();
        }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for SpinnerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct TtyPushUi {
    spinner: Option<SpinnerHandle>,
}

impl TtyPushUi {
    fn new() -> Self {
        println!("Wolfence push");
        Self {
            spinner: Some(SpinnerHandle::start("Preparing outbound push snapshot")),
        }
    }

    fn handle_progress(&mut self, progress: PushEvaluationProgress) {
        let Some(spinner) = self.spinner.as_ref() else {
            return;
        };

        match progress {
            PushEvaluationProgress::SnapshotLoaded {
                discovered_files,
                scanned_files,
                ignored_files,
                ..
            } => {
                spinner.update(format!(
                    "Found {discovered_files} outbound files, checking {scanned_files} in scope, ignoring {ignored_files}"
                ));
            }
            PushEvaluationProgress::ScannerStarted { name, index, total } => {
                spinner.update(format!(
                    "{} ({index}/{total})",
                    scanner_progress_label(name)
                ));
            }
            PushEvaluationProgress::ScannerFinished {
                name,
                index,
                total,
                findings,
            } => {
                let finding_note = if findings == 0 {
                    "no new findings".to_string()
                } else if findings == 1 {
                    "1 finding".to_string()
                } else {
                    format!("{findings} findings")
                };
                spinner.update(format!(
                    "{} ({index}/{total}, {finding_note})",
                    scanner_progress_label(name)
                ));
            }
            PushEvaluationProgress::FileStarted {
                scanner,
                file,
                current,
                total,
            } => {
                let message = format!(
                    "{} ({}/{})  {}",
                    scanner_progress_label(scanner),
                    current,
                    total,
                    display_scan_file(&file)
                );
                if total <= 8 {
                    self.echo_progress_line(message);
                } else {
                    spinner.update(message);
                }
            }
            PushEvaluationProgress::GovernanceCheck => {
                spinner.update("Checking live repository governance");
            }
            PushEvaluationProgress::FindingHistory => {
                spinner.update("Comparing findings against recent history");
            }
            PushEvaluationProgress::FindingBaseline => {
                spinner.update("Comparing findings against the accepted baseline");
            }
            PushEvaluationProgress::PolicyEvaluation => {
                spinner.update("Applying local push policy");
            }
        }
    }

    fn finish_scan_line(&mut self, message: &str) {
        if let Some(mut spinner) = self.spinner.take() {
            spinner.stop();
        }
        println!("  {message}");
    }

    fn finish_scan_summary(
        &mut self,
        context: &crate::core::context::ExecutionContext,
        report: &crate::core::orchestrator::ScanReport,
        decision: &crate::core::policy::PolicyDecision,
        current_branch: &str,
        upstream_branch: Option<&str>,
        commits_ahead: usize,
    ) {
        if let Some(mut spinner) = self.spinner.take() {
            spinner.stop();
        }

        println!(
            "  branch: {} -> {}",
            current_branch,
            upstream_branch.unwrap_or("<initial push>")
        );
        println!(
            "  mode: {} ({})",
            context.config.mode, context.config.mode_source
        );
        println!(
            "  scope: {} commits ahead, {} files checked, {} ignored, {} discovered",
            commits_ahead, report.scanned_files, report.ignored_files, report.discovered_files
        );
        if !context.config.scan_ignore_paths.is_empty() {
            println!(
                "  repo exclusions: {}",
                context.config.scan_ignore_paths.join(", ")
            );
        }
        println!(
            "  checks: {} scanners, {} findings, {} warnings, {} blocks",
            report.scanners_run,
            report.findings.len(),
            decision.warning_findings.len(),
            decision.blocking_findings.len()
        );
        if !report.findings.is_empty() {
            protected::print_finding_summary(&report.findings);
        }
        println!(
            "  history: {} new, {} recurring",
            report.finding_history.new_findings, report.finding_history.recurring_findings
        );
        println!(
            "  baseline: {} accepted, {} not accepted",
            report.finding_baseline.accepted_findings,
            report.finding_baseline.unaccepted_findings
        );
    }

    fn start_transport(&mut self, message: &str) {
        if let Some(mut spinner) = self.spinner.take() {
            spinner.stop();
        }
        self.spinner = Some(SpinnerHandle::start(message.to_string()));
    }

    fn finish_transport_line(&mut self, message: &str) {
        if let Some(mut spinner) = self.spinner.take() {
            spinner.stop();
        }
        let success = message.eq("push completed");
        print_tty_result_line(message, success);
    }

    fn echo_progress_line(&mut self, message: String) {
        if let Some(mut spinner) = self.spinner.take() {
            spinner.stop();
        }
        println!("  {message}");
        self.spinner = Some(SpinnerHandle::start(message));
    }
}

fn scanner_progress_label(name: &str) -> &'static str {
    match name {
        "secret-scanner" => "Checking secrets",
        "basic-sast" => "Checking risky code patterns",
        "artifact-scanner" => "Inspecting generated and packaged artifacts",
        "dependency-scanner" => "Checking dependency and provenance risks",
        "config-scanner" => "Checking infrastructure and workflow config",
        "policy-scanner" => "Checking Wolfence policy integrity",
        _ => "Running scanner",
    }
}

fn display_scan_file(path: &Path) -> String {
    let text = path.display().to_string();
    const MAX_LEN: usize = 56;
    if text.len() <= MAX_LEN {
        return text;
    }

    let suffix_len = MAX_LEN.saturating_sub(3);
    format!("...{}", &text[text.len() - suffix_len..])
}

fn print_tty_decision_findings(decision: &PolicyDecision) {
    if !decision.blocking_findings.is_empty() {
        println!("  BLOCKERS:");
        print_tty_policy_finding_group(&decision.blocking_findings);
    }

    if decision.has_warnings() {
        println!("  warnings:");
        print_tty_policy_finding_group(&decision.warning_findings);
    }

    if !decision.overridden_findings.is_empty() {
        println!("  applied overrides:");
        print_tty_overridden_group(&decision.overridden_findings);
    }
}

fn print_tty_policy_finding_group(findings: &[PolicyFinding]) {
    for policy_finding in findings {
        let finding = &policy_finding.finding;
        println!(
            "    {} - {} - {}",
            tty_finding_label(finding.severity),
            finding.location(),
            finding.title
        );
    }
}

fn print_tty_overridden_group(findings: &[OverriddenFinding]) {
    for overridden in findings {
        let finding = &overridden.finding;
        println!(
            "    {} - {} - {}",
            tty_finding_label(finding.severity),
            finding.location(),
            finding.title
        );
    }
}

fn print_tty_result_line(message: &str, success: bool) {
    let rendered = style_token(
        &message.to_ascii_uppercase(),
        if success { "\x1b[32m" } else { "\x1b[31m" },
    );
    println!("  {rendered}");
}

fn tty_finding_label(severity: crate::core::findings::Severity) -> String {
    let token = match severity {
        crate::core::findings::Severity::Info => "info",
        crate::core::findings::Severity::Low => "low risk",
        crate::core::findings::Severity::Medium => "medium risk",
        crate::core::findings::Severity::High => "high risk",
        crate::core::findings::Severity::Critical => "critical",
    };
    let severity = style_token(token, severity_color(severity));
    format!("[{severity}]")
}

fn severity_color(severity: crate::core::findings::Severity) -> &'static str {
    match severity {
        crate::core::findings::Severity::Medium => "\x1b[38;2;3;49;255m",
        crate::core::findings::Severity::High | crate::core::findings::Severity::Critical => {
            "\x1b[31m"
        }
        crate::core::findings::Severity::Low => "\x1b[33m",
        crate::core::findings::Severity::Info => "\x1b[36m",
    }
}

fn style_token(token: &str, color: &str) -> String {
    if tty_colors_enabled() {
        format!("{color}{token}\x1b[0m")
    } else {
        token.to_string()
    }
}

fn tty_colors_enabled() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::run;
    use crate::commands::protected::{self, PushEvaluation};
    use crate::core::audit::{verify_audit_log, AUDIT_LOG_RELATIVE_PATH};
    use crate::core::context::ProtectedAction;
    use crate::core::findings::FindingCategory;
    use crate::core::github_governance;
    use crate::core::receipts::{
        draft_checksum, generate_receipt_id, render_receipt_file, ReceiptDraft,
        RECEIPTS_DIR_RELATIVE_PATH,
    };
    use crate::test_support::{
        activate_live_github_governance_fixture, assert_fixture_audit_expectation,
        assert_fixture_expectation, install_live_github_governance_receipt,
        materialize_repo_fixture, process_lock, restore_live_github_governance_fixture,
    };

    #[test]
    fn push_blocks_high_confidence_secret_candidates() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-block");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join(".env"),
            "DATABASE_URL=postgres://prod.example.internal/app\n",
        )
        .expect("should write .env file");
        commit_all(&repo_root, "add env file");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_eq!(result, std::process::ExitCode::FAILURE);
    }

    #[test]
    fn push_allows_harmless_initial_commit_in_dry_run_mode() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-allow");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless prototype file.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_eq!(result, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn push_respects_repo_scan_exclusions_for_docs_paths() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-ignore-docs");
        initialize_repo(&repo_root);
        write_repo_config(
            &repo_root,
            "[policy]\nmode = \"standard\"\n\n[scan]\nignore_paths = [\"docs/\"]\n",
        );
        fs::create_dir_all(repo_root.join("docs")).expect("should create docs dir");
        fs::write(
            repo_root.join("docs/request.md"),
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\n",
        )
        .expect("should write docs fixture");
        commit_all(&repo_root, "add ignored docs file");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_eq!(result, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn push_audits_transport_failure_when_policy_allows_but_no_remote_exists() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-no-remote");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis initial push has no remote configured.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::remove_var("WOLFENCE_DRY_RUN");

        let result = run(false).expect("push command should handle git failure gracefully");

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_eq!(result, std::process::ExitCode::FAILURE);

        let audit_log = fs::read_to_string(repo_root.join(AUDIT_LOG_RELATIVE_PATH))
            .expect("audit log should exist");
        assert!(audit_log.contains("\"outcome\":\"policy-allowed\""));
        assert!(audit_log.contains("\"outcome\":\"push-failed\""));
        assert!(audit_log.contains("no git remote is configured"));

        let verification = verify_audit_log(&repo_root).expect("audit verification should work");
        assert!(verification.healthy);
        assert_eq!(verification.entries, 2);
    }

    #[test]
    fn push_fixture_captures_policy_allowed_transport_failure_audit_chain() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-transport-failure-no-remote");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::remove_var("WOLFENCE_DRY_RUN");

        let result = run(false).expect("push command should handle transport failure");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_when_live_github_governance_drifts() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-governance-drift-block");
        initialize_repo(&repo_root);
        configure_live_governance_repo(&repo_root);

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        let previous_governance = env::var("WOLFENCE_GITHUB_GOVERNANCE").ok();
        let previous_path = env::var("PATH").ok();
        let fake_bin = install_fake_gh(&repo_root, false);
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        env::set_var("WOLFENCE_GITHUB_GOVERNANCE", "auto");
        set_test_path(&fake_bin, previous_path.as_deref());

        let result = run(false).expect("push command should run");

        restore_process_state(
            &previous_dir,
            previous_dry_run,
            previous_governance,
            previous_path,
        );
        assert_eq!(result, std::process::ExitCode::FAILURE);
    }

    #[test]
    fn push_allows_receipted_live_github_governance_drift() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("push-governance-drift-override");
        initialize_repo(&repo_root);
        configure_live_governance_repo(&repo_root);
        install_governance_override_receipt(&repo_root);

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        let previous_governance = env::var("WOLFENCE_GITHUB_GOVERNANCE").ok();
        let previous_path = env::var("PATH").ok();
        let fake_bin = install_fake_gh(&repo_root, false);
        env::set_current_dir(&repo_root).expect("should enter repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        env::set_var("WOLFENCE_GITHUB_GOVERNANCE", "auto");
        set_test_path(&fake_bin, previous_path.as_deref());

        let result = run(false).expect("push command should run");

        restore_process_state(
            &previous_dir,
            previous_dry_run,
            previous_governance,
            previous_path,
        );
        assert_eq!(result, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn push_blocks_fixture_repo_with_committed_secret_in_dry_run_mode() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-blocking-secret");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_with_harmless_committed_content_in_dry_run_mode() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-allow-readme");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_with_receipted_secret_in_dry_run_mode() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-override-receipt");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_trust_requires_signed_receipts() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-trust-requires-signature");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_with_signed_trusted_secret_receipt() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-trust-valid-signed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_secret_receipt_policy_requires_reviewer_metadata() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-reviewer-required");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_secret_reviewer_is_not_allowlisted() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-reviewer-disallowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_when_secret_reviewer_is_allowlisted() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-reviewer-allowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_secret_policy_requires_signed_receipts() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-signed-required");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_when_signed_receipt_matches_policy_allowlists() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-signed-allowlists-allowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_signed_receipt_key_id_is_not_allowlisted() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-secret-policy-signed-key-disallowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_receipt_change_lacks_codeowners_coverage() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-receipt-change-codeowners-uncovered");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_receipt_change_is_codeowners_covered() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-receipt-change-codeowners-covered");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_release_governance_drift_lacks_codeowners_coverage() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-release-governance-uncovered");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_release_governance_drift_is_codeowners_covered() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-release-governance-covered");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_live_github_governance_drift_is_detected() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-drift-block");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_when_live_github_governance_drift_receipt_matches() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-drift-override-allowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_live_github_governance_receipt_is_stale() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-drift-override-stale");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_allows_fixture_repo_when_live_github_governance_signed_receipt_matches() {
        let _guard = process_lock();
        let fixture =
            materialize_repo_fixture("push-live-governance-drift-signed-override-allowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_live_github_governance_receipt_is_unsigned_under_trust() {
        let _guard = process_lock();
        let fixture =
            materialize_repo_fixture("push-live-governance-drift-signed-required-unsigned");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_live_github_governance_signing_key_is_disallowed() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-drift-signed-key-disallowed");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_live_github_governance_signing_key_is_untrusted() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-drift-signed-key-untrusted");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );
        install_live_github_governance_receipt(
            &repo_root,
            fixture.live_github_governance.as_ref(),
            fixture.live_github_governance_receipt.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    #[test]
    fn push_blocks_fixture_repo_when_required_live_github_governance_is_unavailable() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("push-live-governance-unavailable-require");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        let previous_dry_run = env::var("WOLFENCE_DRY_RUN").ok();
        env::set_current_dir(&repo_root).expect("should enter fixture repo");
        env::set_var("WOLFENCE_DRY_RUN", "1");
        let live_state = activate_live_github_governance_fixture(
            &repo_root,
            fixture.live_github_governance.as_ref(),
        );

        let result = run(false).expect("push command should run");
        let findings = load_push_report_findings();

        restore_process_state(&previous_dir, previous_dry_run, None, None);
        restore_live_github_governance_fixture(live_state);
        assert_fixture_expectation(
            &fixture.name,
            "push",
            result,
            &findings,
            fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations"),
        );
        assert_fixture_audit_expectation(
            &fixture.name,
            "push",
            &repo_root,
            fixture
                .expectations
                .push
                .as_ref()
                .and_then(|expectation| expectation.audit.as_ref())
                .expect("fixture should declare push audit expectations"),
        );
    }

    fn restore_process_state(
        previous_dir: &Path,
        previous_dry_run: Option<String>,
        previous_governance: Option<String>,
        previous_path: Option<String>,
    ) {
        env::set_current_dir(previous_dir).expect("should restore current dir");
        if let Some(value) = previous_dry_run {
            env::set_var("WOLFENCE_DRY_RUN", value);
        } else {
            env::remove_var("WOLFENCE_DRY_RUN");
        }
        if let Some(value) = previous_governance {
            env::set_var("WOLFENCE_GITHUB_GOVERNANCE", value);
        }
        if let Some(value) = previous_path {
            env::set_var("PATH", value);
        }
    }

    fn initialize_repo(repo_root: &Path) {
        fs::create_dir_all(repo_root).expect("should create repo root");
        run_git(repo_root, &["init", "-b", "main"]);
        run_git(repo_root, &["config", "user.name", "Wolfence Test"]);
        run_git(repo_root, &["config", "user.email", "wolfence@example.com"]);
    }

    fn write_repo_config(repo_root: &Path, contents: &str) {
        let config_dir = repo_root.join(".wolfence");
        fs::create_dir_all(&config_dir).expect("should create config dir");
        fs::write(config_dir.join("config.toml"), contents).expect("should write repo config");
    }

    fn configure_live_governance_repo(repo_root: &Path) {
        fs::create_dir_all(repo_root.join(".github")).expect("should create .github dir");
        fs::write(
            repo_root.join(".github/settings.yml"),
            "branches:\n  - name: main\n    protection:\n      enforce_admins: true\n      required_pull_request_reviews:\n        required_approving_review_count: 2\n        dismiss_stale_reviews: true\n        require_code_owner_reviews: true\n      allow_force_pushes: false\n      allow_deletions: false\n",
        )
        .expect("should write settings");
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nRepository with governance-as-code.\n",
        )
        .expect("should write readme");
        run_git(
            repo_root,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/openai/wolfence.git",
            ],
        );
        commit_all(repo_root, "add governance intent");
    }

    fn install_governance_override_receipt(repo_root: &Path) {
        let fake_bin = install_fake_gh(repo_root, false);
        let previous_path = env::var("PATH").ok();
        set_test_path(&fake_bin, previous_path.as_deref());
        let finding = github_governance::push_blocking_finding(repo_root)
            .expect("governance finding should resolve")
            .expect("drift should exist");
        if let Some(value) = previous_path {
            env::set_var("PATH", value);
        } else {
            env::remove_var("PATH");
        }

        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        let mut draft = ReceiptDraft {
            receipt_id: String::new(),
            action: ProtectedAction::Push,
            category: FindingCategory::Policy,
            fingerprint: finding.fingerprint,
            owner: "security-team".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary review of live GitHub governance drift".to_string(),
            created_on: "2026-04-10".to_string(),
            expires_on: "2099-12-31".to_string(),
            category_bound: true,
        };
        draft.receipt_id = generate_receipt_id(&draft).expect("receipt id should generate");
        let checksum = draft_checksum(&draft).expect("checksum should generate");
        let contents = render_receipt_file(&draft, &checksum, None, None, None);
        fs::write(receipts_dir.join("governance-drift.toml"), contents)
            .expect("receipt should write");
    }

    fn commit_all(repo_root: &Path, message: &str) {
        run_git(repo_root, &["add", "."]);
        run_git(repo_root, &["commit", "-m", message]);
    }

    fn run_git(repo_root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(args)
            .output()
            .expect("git command should spawn");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn install_fake_gh(repo_root: &Path, unavailable: bool) -> PathBuf {
        let bin_dir = repo_root.join("test-bin");
        fs::create_dir_all(&bin_dir).expect("should create fake bin dir");
        let script = if unavailable {
            "#!/bin/sh\necho 'gh auth expired' >&2\nexit 1\n".to_string()
        } else {
            "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n  repos/openai/wolfence)\n    printf '{\"default_branch\":\"main\"}'\n    ;;\n  repos/openai/wolfence/branches/main/protection)\n    printf '{\"allow_force_pushes\":{\"enabled\":true},\"allow_deletions\":{\"enabled\":true},\"enforce_admins\":{\"enabled\":false},\"required_pull_request_reviews\":{\"dismiss_stale_reviews\":false,\"require_code_owner_reviews\":false,\"required_approving_review_count\":1}}'\n    ;;\n  'repos/openai/wolfence/rulesets?includes_parents=true&per_page=100')\n    printf '[]'\n    ;;\n  *)\n    echo \"unexpected gh api path: $last\" >&2\n    exit 1\n    ;;\n esac\n"
                .to_string()
        };
        let gh_path = bin_dir.join("gh");
        fs::write(&gh_path, script).expect("should write fake gh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&gh_path)
                .expect("metadata should load")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&gh_path, permissions).expect("permissions should set");
        }
        bin_dir
    }

    fn set_test_path(fake_bin: &Path, previous_path: Option<&str>) {
        let updated = match previous_path {
            Some(value) if !value.is_empty() => format!("{}:{value}", fake_bin.display()),
            _ => fake_bin.display().to_string(),
        };
        env::set_var("PATH", updated);
    }

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-push-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        env::temp_dir().join(unique)
    }

    fn load_push_report_findings() -> Vec<crate::core::findings::Finding> {
        match protected::evaluate_push_action().expect("push evaluation should load") {
            PushEvaluation::Ready { report, .. } => report.findings,
            other => panic!("expected ready push evaluation, got {other:?}"),
        }
    }
}
