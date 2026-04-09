//! `wolf scan`
//!
//! The standalone scan command is the easiest place to inspect Wolfence
//! decisions without taking Git side effects. It can preview either the staged
//! working set or the real outbound push scope.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::cli::ScanCommand;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::orchestrator::{Orchestrator, ScanReport};
use crate::core::policy::Verdict;

use super::protected::{self, PushEvaluation};

pub fn run(command: ScanCommand) -> AppResult<ExitCode> {
    match command {
        ScanCommand::Staged => run_staged_scan(),
        ScanCommand::Push => run_push_scan(),
        ScanCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_staged_scan() -> AppResult<ExitCode> {
    let context = ExecutionContext::load(ProtectedAction::Scan)?;
    let report = Orchestrator::default().run(&context)?;
    let decision = report.evaluate(context.config.mode, &context.receipts, context.action);

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

fn run_push_scan() -> AppResult<ExitCode> {
    match protected::evaluate_push_action()? {
        PushEvaluation::NoCommits { context } => {
            println!("Wolfence scan");
            println!("  scope: push");
            println!("  action: push-preview");
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: no commits exist on the current branch");
            println!("  result: no outbound push scope is available yet");
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::UpToDate { context } => {
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
            current_branch,
            upstream_branch,
            commits_ahead,
        } => {
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

fn print_findings(report: &ScanReport) {
    if report.findings.is_empty() {
        return;
    }

    println!("  findings detail:");
    for finding in &report.findings {
        println!(
            "    - [{}|{}|{}] {} | {} | {}",
            finding.severity,
            finding.confidence,
            finding.category,
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
    println!("  wolf scan");
    println!("  wolf scan staged");
    println!("  wolf scan push");
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

    use super::run;
    use crate::cli::ScanCommand;
    use crate::test_support::process_lock;

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

        let result = run(ScanCommand::Push).expect("scan command should run");

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

        let result = run(ScanCommand::Staged).expect("scan command should run");

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

        let result = run(ScanCommand::Staged).expect("scan command should run");

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

        let result = run(ScanCommand::Staged).expect("scan command should run");

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

        let result = run(ScanCommand::Push).expect("scan command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::SUCCESS);
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
}
