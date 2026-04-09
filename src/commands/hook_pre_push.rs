//! Internal pre-push hook entrypoint.
//!
//! This command is meant to be called by Git hooks, not by end users directly.
//! It reuses the same push-evaluation logic as `wolfence push`, but it never
//! executes `git push` itself.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::core::audit::{self, AuditEvent, AuditSource};
use crate::core::policy::Verdict;

use super::protected::{self, PushEvaluation};

pub fn run() -> AppResult<ExitCode> {
    match protected::evaluate_push_action()? {
        PushEvaluation::NoCommits { context } => {
            println!("Wolfence pre-push hook");
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: no commits exist on the current branch");
            println!("  result: nothing to validate");
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PrePushHook,
                    action: context.action,
                    status: "no-commits",
                    outcome: "no-op",
                    detail: None,
                    verdict: None,
                    candidate_files: 0,
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
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::UpToDate { context } => {
            println!("Wolfence pre-push hook");
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: branch is not ahead of its upstream");
            println!("  result: nothing to validate");
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PrePushHook,
                    action: context.action,
                    status: "up-to-date",
                    outcome: "no-op",
                    detail: None,
                    verdict: None,
                    candidate_files: 0,
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
            println!("Wolfence pre-push hook");
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
            println!("  candidate files: {}", report.scanned_files);
            println!("  findings: {}", report.findings.len());
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

            let outcome = if decision.verdict == Verdict::Block {
                "blocked"
            } else {
                "allowed"
            };
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PrePushHook,
                    action: context.action,
                    status: "ready",
                    outcome,
                    detail: None,
                    verdict: Some(decision.verdict),
                    candidate_files: report.scanned_files,
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

            if decision.verdict == Verdict::Block {
                println!("  result: push blocked by Wolfence pre-push policy");
                return Ok(ExitCode::FAILURE);
            }

            println!("  result: push allowed by Wolfence pre-push policy");
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::run;
    use crate::test_support::process_lock;

    #[test]
    fn pre_push_hook_blocks_high_confidence_secret_candidates() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("hook-block");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join(".env"),
            "DATABASE_URL=postgres://prod.example.internal/app\n",
        )
        .expect("should write .env file");
        commit_all(&repo_root, "add env file");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run().expect("hook command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn pre_push_hook_allows_harmless_initial_commit() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("hook-allow");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless prototype file.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result = run().expect("hook command should run");

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
