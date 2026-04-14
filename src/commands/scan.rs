//! `wolf scan`
//!
//! The standalone scan command is the easiest place to inspect Wolfence
//! decisions without taking Git side effects. It can preview either the staged
//! working set or the real outbound push scope.

use std::process::ExitCode;

use serde::Serialize;
#[cfg(test)]
use serde_json::Value;

use crate::app::AppResult;
use crate::cli::ScanCommand;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::finding_baseline;
use crate::core::finding_history;
use crate::core::orchestrator::{Orchestrator, ScanReport};
use crate::core::policy::{PolicyDecision, Verdict};

use super::json::{path_strings, print_json, print_json_error};
use super::protected::{self, PushEvaluation};

pub fn run(command: ScanCommand) -> AppResult<ExitCode> {
    let json = match &command {
        ScanCommand::Staged { json } | ScanCommand::Push { json } => *json,
        ScanCommand::Help => false,
    };

    let result = match command {
        ScanCommand::Staged { json } => run_staged_scan(json),
        ScanCommand::Push { json } => run_push_scan(json),
        ScanCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    };

    if json {
        if let Err(error) = &result {
            print_json_error("scan", error)?;
            return Ok(ExitCode::FAILURE);
        }
    }

    result
}

#[derive(Serialize)]
struct JsonScanScope {
    discovered_files: usize,
    scanned_files: usize,
    ignored_files: usize,
    scanned_paths: Vec<String>,
    ignored_paths: Vec<String>,
    ignore_patterns: Vec<String>,
}

#[derive(Serialize)]
struct JsonReceiptState {
    issues: Vec<crate::core::receipts::ReceiptIssue>,
    issue_count: usize,
    overrides_applied: usize,
}

#[derive(Serialize)]
struct JsonScanResponse {
    command: &'static str,
    scope: &'static str,
    action: String,
    repo_root: String,
    mode: Option<String>,
    mode_source: Option<String>,
    status: &'static str,
    branch: Option<String>,
    upstream: Option<String>,
    commits_ahead: Option<usize>,
    scanners_run: usize,
    report: Option<ScanReport>,
    decision: Option<PolicyDecision>,
    receipts: JsonReceiptState,
    scan_scope: Option<JsonScanScope>,
    result: &'static str,
}

fn run_staged_scan(json: bool) -> AppResult<ExitCode> {
    let (context, report, decision) = staged_scan_state()?;

    if json {
        let response = build_staged_json_response(&context, &report, &decision);
        print_json(&response)?;
        return Ok(if decision.verdict == Verdict::Block {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        });
    }

    println!("Wolfence scan");
    println!("  scope: staged");
    println!("  action: {}", context.action);
    println!("  repo root: {}", context.repo_root.display());
    println!(
        "  mode: {} ({})",
        context.config.mode, context.config.mode_source
    );
    protected::print_scan_scope(&report, &context);
    println!("  scanners run: {}", report.scanners_run);
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
    println!("  preview verdict: {}", decision.verdict);
    protected::print_receipt_issues(&context.receipts.issues);
    print_findings(&report);
    protected::print_decision_findings(&decision);

    if decision.verdict == Verdict::Block {
        println!("  result: staged scan would block under the current policy");
        return Ok(ExitCode::FAILURE);
    }

    println!("  result: staged scan completed without a blocking verdict");
    Ok(ExitCode::SUCCESS)
}

fn run_push_scan(json: bool) -> AppResult<ExitCode> {
    match protected::evaluate_push_action()? {
        PushEvaluation::NoCommits { context } => {
            if json {
                print_json(&build_push_json_response(&PushEvaluation::NoCommits {
                    context: context.clone(),
                }))?;
                return Ok(ExitCode::SUCCESS);
            }
            println!("Wolfence scan");
            println!("  scope: push");
            println!("  action: push-preview");
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: no commits exist on the current branch");
            println!("  result: no outbound push scope is available yet");
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::UpToDate { context } => {
            if json {
                print_json(&build_push_json_response(&PushEvaluation::UpToDate {
                    context: context.clone(),
                }))?;
                return Ok(ExitCode::SUCCESS);
            }
            println!("Wolfence scan");
            println!("  scope: push");
            println!("  action: push-preview");
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: branch is not ahead of its upstream");
            println!("  result: no outbound push scope is available yet");
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
            if json {
                print_json(&build_push_json_response(&PushEvaluation::Ready {
                    context: context.clone(),
                    report: report.clone(),
                    decision: decision.clone(),
                    push_status: push_status.clone(),
                    current_branch: current_branch.clone(),
                    upstream_branch: upstream_branch.clone(),
                    commits_ahead,
                }))?;
                return Ok(if decision.verdict == Verdict::Block {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                });
            }
            println!("Wolfence scan");
            println!("  scope: push");
            println!("  action: push-preview");
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
            println!("  scanners run: {}", report.scanners_run);
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
            println!("  preview verdict: {}", decision.verdict);
            protected::print_receipt_issues(&context.receipts.issues);
            print_findings(&report);
            protected::print_decision_findings(&decision);
            if decision.verdict == Verdict::Block {
                println!("  result: push preview would block without invoking git push");
                return Ok(ExitCode::FAILURE);
            }

            println!("  result: push preview completed without invoking git push");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn staged_scan_state() -> AppResult<(ExecutionContext, ScanReport, PolicyDecision)> {
    let context = ExecutionContext::load(ProtectedAction::Scan)?;
    let mut report = Orchestrator::default().run(&context)?;
    let history = finding_history::annotate_findings(&context.repo_root, &mut report.findings);
    report.set_finding_history(history);
    let baseline = finding_baseline::annotate_findings(&context.repo_root, &mut report.findings);
    report.set_finding_baseline(baseline);
    let decision = report.evaluate(context.config.mode, &context.receipts, context.action);
    Ok((context, report, decision))
}

fn build_scan_scope(context: &ExecutionContext, report: &ScanReport) -> JsonScanScope {
    JsonScanScope {
        discovered_files: report.discovered_files,
        scanned_files: report.scanned_files,
        ignored_files: report.ignored_files,
        scanned_paths: path_strings(&context.candidate_files),
        ignored_paths: path_strings(&context.ignored_candidate_files),
        ignore_patterns: context.config.scan_ignore_paths.clone(),
    }
}

fn build_receipt_state(context: &ExecutionContext, overrides_applied: usize) -> JsonReceiptState {
    JsonReceiptState {
        issues: context.receipts.issues.clone(),
        issue_count: context.receipts.issues.len(),
        overrides_applied,
    }
}

fn build_staged_json_response(
    context: &ExecutionContext,
    report: &ScanReport,
    decision: &PolicyDecision,
) -> JsonScanResponse {
    JsonScanResponse {
        command: "scan",
        scope: "staged",
        action: context.action.to_string(),
        repo_root: context.repo_root.display().to_string(),
        mode: Some(context.config.mode.to_string()),
        mode_source: Some(context.config.mode_source.to_string()),
        status: "ready",
        branch: None,
        upstream: None,
        commits_ahead: None,
        scanners_run: report.scanners_run,
        report: Some(report.clone()),
        decision: Some(decision.clone()),
        receipts: build_receipt_state(context, decision.overridden_findings.len()),
        scan_scope: Some(build_scan_scope(context, report)),
        result: if decision.verdict == Verdict::Block {
            "blocked"
        } else {
            "completed"
        },
    }
}

fn build_push_json_response(evaluation: &PushEvaluation) -> JsonScanResponse {
    match evaluation {
        PushEvaluation::NoCommits { context } => JsonScanResponse {
            command: "scan",
            scope: "push",
            action: "push-preview".to_string(),
            repo_root: context.repo_root.display().to_string(),
            mode: None,
            mode_source: None,
            status: "no-commits",
            branch: None,
            upstream: None,
            commits_ahead: None,
            scanners_run: 0,
            report: None,
            decision: None,
            receipts: build_receipt_state(context, 0),
            scan_scope: None,
            result: "no-op",
        },
        PushEvaluation::UpToDate { context } => JsonScanResponse {
            command: "scan",
            scope: "push",
            action: "push-preview".to_string(),
            repo_root: context.repo_root.display().to_string(),
            mode: None,
            mode_source: None,
            status: "up-to-date",
            branch: None,
            upstream: None,
            commits_ahead: Some(0),
            scanners_run: 0,
            report: None,
            decision: None,
            receipts: build_receipt_state(context, 0),
            scan_scope: None,
            result: "no-op",
        },
        PushEvaluation::Ready {
            context,
            report,
            decision,
            current_branch,
            upstream_branch,
            commits_ahead,
            ..
        } => JsonScanResponse {
            command: "scan",
            scope: "push",
            action: "push-preview".to_string(),
            repo_root: context.repo_root.display().to_string(),
            mode: Some(context.config.mode.to_string()),
            mode_source: Some(context.config.mode_source.to_string()),
            status: "ready",
            branch: Some(current_branch.clone()),
            upstream: upstream_branch.clone(),
            commits_ahead: Some(*commits_ahead),
            scanners_run: report.scanners_run,
            report: Some(report.clone()),
            decision: Some(decision.clone()),
            receipts: build_receipt_state(context, decision.overridden_findings.len()),
            scan_scope: Some(build_scan_scope(context, report)),
            result: if decision.verdict == Verdict::Block {
                "blocked"
            } else {
                "completed"
            },
        },
    }
}

#[cfg(test)]
fn scan_response_json_value(response: &JsonScanResponse) -> Value {
    serde_json::to_value(response).expect("scan response should serialize")
}

fn print_findings(report: &ScanReport) {
    if report.findings.is_empty() {
        return;
    }

    println!("  findings detail:");
    for finding in &report.findings {
        println!(
            "    - [{}|{}|{}|{}|{}] {} | {} | {}",
            finding.severity,
            finding.confidence,
            finding.category,
            finding.history.status,
            if finding.baseline.accepted {
                "baseline"
            } else {
                "not-baseline"
            },
            finding.scanner,
            finding.location(),
            finding.title
        );
    }
}

fn print_help() {
    println!("Wolfence scan");
    println!("  Preview Wolfence findings without taking Git side effects");
    println!();
    println!("Usage:");
    println!("  wolf scan [--json]");
    println!("  wolf scan staged [--json]");
    println!("  wolf scan push [--json]");
    println!();
    println!("Modes:");
    println!("  staged  Scan the currently staged files (default)");
    println!("  push    Preview the real outbound push scope and fail if the preview would block");
    println!("  help    Show this help text");
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_push_json_response, build_staged_json_response, run, scan_response_json_value,
        staged_scan_state,
    };
    use crate::cli::ScanCommand;
    use crate::commands::protected;
    use crate::core::context::{ExecutionContext, ProtectedAction};
    use crate::core::orchestrator::{Orchestrator, ScanReport};
    use crate::test_support::{
        activate_live_github_governance_fixture, assert_fixture_expectation,
        assert_fixture_json_expectation, install_live_github_governance_receipt,
        materialize_repo_fixture, process_lock, restore_live_github_governance_fixture,
    };
    use serde_json::Value;

    #[test]
    fn push_scope_preview_fails_when_policy_would_block() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("scan-push-block");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join(".env"),
            "DATABASE_URL=postgres://prod.example.internal/app\n",
        )
        .expect("should write .env file");
        commit_all(&repo_root, "add env file");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run(ScanCommand::Push { json: false }).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn staged_scan_fails_when_policy_would_block() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("scan-staged-block");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join(".env"),
            "DATABASE_URL=postgres://prod.example.internal/app\n",
        )
        .expect("should write .env file");
        stage_all(&repo_root);

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn staged_scan_succeeds_for_harmless_staged_changes() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("scan-staged-allow");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless staged prototype file.\n",
        )
        .expect("should write readme");
        stage_all(&repo_root);

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn staged_scan_respects_repo_exclusions_for_docs_paths() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("scan-staged-ignore-docs");
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
        stage_all(&repo_root);

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn push_scope_preview_succeeds_for_harmless_initial_commit() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("scan-push-allow");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless prototype file.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run(ScanCommand::Push { json: false }).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn staged_scan_blocks_fixture_repo_with_real_config_and_ci_risks() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-blocking-config");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_scan_allows_fixture_repo_with_docs_only_ignore_scope() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-ignore-docs");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_scan_blocks_fixture_repo_with_governance_as_code_regressions() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-governance-risk");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_scan_blocks_fixture_repo_with_iac_posture_regressions() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-iac-risk");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_scan_blocks_fixture_repo_with_dependency_provenance_regressions() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-dependency-risk");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_scan_blocks_fixture_repo_with_appsec_code_regressions() {
        let _guard = process_lock();
        let fixture = materialize_repo_fixture("staged-appsec-risk");
        let repo_root = fixture.repo_root.clone();

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter fixture repo");

        let result = run(ScanCommand::Staged { json: false }).expect("scan command should run");
        let report = load_staged_report();

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_fixture_expectation(
            &fixture.name,
            "staged",
            result,
            &report.findings,
            fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations"),
        );
    }

    #[test]
    fn staged_fixture_json_contracts_hold() {
        let _guard = process_lock();

        for name in [
            "staged-ignore-docs",
            "staged-blocking-config",
            "staged-governance-risk",
            "staged-iac-risk",
            "staged-dependency-risk",
            "staged-appsec-risk",
        ] {
            let fixture = materialize_repo_fixture(name);
            let repo_root = fixture.repo_root.clone();
            let previous_dir = env::current_dir().expect("current dir should resolve");
            env::set_current_dir(&repo_root).expect("should enter fixture repo");

            let expectation = fixture
                .expectations
                .staged
                .as_ref()
                .expect("fixture should declare staged expectations");
            let json_expectation = expectation
                .json
                .as_ref()
                .expect("fixture should declare staged json expectations");
            let json = load_staged_json_value();

            env::set_current_dir(previous_dir).expect("should restore current dir");
            assert_fixture_json_expectation(&fixture.name, "staged", &json, json_expectation);
        }
    }

    #[test]
    fn push_fixture_json_contracts_hold() {
        let _guard = process_lock();

        for name in [
            "push-allow-readme",
            "push-blocking-secret",
            "push-secret-override-receipt",
            "push-secret-policy-reviewer-required",
            "push-secret-policy-reviewer-disallowed",
            "push-secret-policy-reviewer-allowed",
            "push-secret-policy-signed-required",
            "push-secret-policy-signed-allowlists-allowed",
            "push-secret-policy-signed-key-disallowed",
            "push-receipt-change-codeowners-uncovered",
            "push-receipt-change-codeowners-covered",
            "push-release-governance-uncovered",
            "push-release-governance-covered",
            "push-live-governance-drift-block",
            "push-live-governance-drift-override-allowed",
            "push-live-governance-drift-override-stale",
            "push-live-governance-drift-signed-override-allowed",
            "push-live-governance-drift-signed-required-unsigned",
            "push-live-governance-drift-signed-key-disallowed",
            "push-live-governance-drift-signed-key-untrusted",
            "push-live-governance-unavailable-require",
            "push-secret-trust-requires-signature",
            "push-secret-trust-valid-signed",
            "push-transport-failure-no-remote",
        ] {
            let fixture = materialize_repo_fixture(name);
            let repo_root = fixture.repo_root.clone();
            let previous_dir = env::current_dir().expect("current dir should resolve");
            env::set_current_dir(&repo_root).expect("should enter fixture repo");
            let live_state = activate_live_github_governance_fixture(
                &repo_root,
                fixture.live_github_governance.as_ref(),
            );
            install_live_github_governance_receipt(
                &repo_root,
                fixture.live_github_governance.as_ref(),
                fixture.live_github_governance_receipt.as_ref(),
            );

            let expectation = fixture
                .expectations
                .push
                .as_ref()
                .expect("fixture should declare push expectations");
            let json_expectation = expectation
                .json
                .as_ref()
                .expect("fixture should declare push json expectations");
            let json = load_push_json_value();

            env::set_current_dir(previous_dir).expect("should restore current dir");
            restore_live_github_governance_fixture(live_state);
            assert_fixture_json_expectation(&fixture.name, "push", &json, json_expectation);
        }
    }

    fn initialize_repo(repo_root: &Path) {
        fs::create_dir_all(repo_root).expect("should create repo root");
        run_git(repo_root, &["init", "-b", "main"]);
        run_git(repo_root, &["config", "user.name", "Wolfence Test"]);
        run_git(repo_root, &["config", "user.email", "wolfence@example.com"]);
    }

    fn commit_all(repo_root: &Path, message: &str) {
        run_git(repo_root, &["add", "."]);
        run_git(repo_root, &["commit", "-m", message]);
    }

    fn stage_all(repo_root: &Path) {
        run_git(repo_root, &["add", "."]);
    }

    fn write_repo_config(repo_root: &Path, contents: &str) {
        let wolfence_dir = repo_root.join(".wolfence");
        fs::create_dir_all(&wolfence_dir).expect("should create wolfence dir");
        fs::write(wolfence_dir.join("config.toml"), contents).expect("should write repo config");
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

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        env::temp_dir().join(unique)
    }

    fn load_staged_report() -> ScanReport {
        let context = ExecutionContext::load(ProtectedAction::Scan)
            .expect("staged execution context should load");
        Orchestrator::default()
            .run(&context)
            .expect("orchestrator should produce report")
    }

    fn load_staged_json_value() -> Value {
        let (context, report, decision) =
            staged_scan_state().expect("staged scan state should load");
        scan_response_json_value(&build_staged_json_response(&context, &report, &decision))
    }

    fn load_push_json_value() -> Value {
        let evaluation = protected::evaluate_push_action().expect("push evaluation should load");
        scan_response_json_value(&build_push_json_response(&evaluation))
    }
}
