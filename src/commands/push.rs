//! `wolfence push`
//!
//! This is the highest-value workflow in the product. Even in scaffold form,
//! the command executes the same sequence the final system will need:
//! repository context -> scan orchestration -> policy evaluation -> operator
//! explanation -> git side effect.
//!
//! This command now protects the actual `git push` path. It still has important
//! limitations, but it no longer pretends that staged files are equivalent to
//! outbound branch content.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::core::audit::{self, AuditEvent, AuditSource};
use crate::core::git;
use crate::core::policy::Verdict;

use super::protected::{self, PushEvaluation};

pub fn run() -> AppResult<ExitCode> {
    match protected::evaluate_push_action()? {
        PushEvaluation::NoCommits { context } => {
            println!("Wolfence push");
            println!("  action: {}", context.action);
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: no commits exist on the current branch");
            println!("  result: nothing to push");
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PushCommand,
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
            Ok(ExitCode::FAILURE)
        }
        PushEvaluation::UpToDate { context } => {
            println!("Wolfence push");
            println!("  action: {}", context.action);
            println!("  repo root: {}", context.repo_root.display());
            println!("  status: branch is not ahead of its upstream");
            println!("  result: nothing to push");
            audit::append_audit_event(
                &context.repo_root,
                AuditEvent {
                    source: AuditSource::PushCommand,
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

            let outcome = match decision.verdict {
                Verdict::Allow | Verdict::Warn if dry_run_enabled() => "allowed-dry-run",
                Verdict::Allow | Verdict::Warn => "policy-allowed",
                Verdict::Block => "blocked",
            };

            match decision.verdict {
                Verdict::Allow | Verdict::Warn => {
                    audit::append_audit_event(
                        &context.repo_root,
                        AuditEvent {
                            source: AuditSource::PushCommand,
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

                    if dry_run_enabled() {
                        println!("  result: policy allowed the push, but git push was skipped because WOLFENCE_DRY_RUN=1");
                        return Ok(ExitCode::SUCCESS);
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
                            println!("  result: git push completed");
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
                            println!("  result: policy allowed the push, but git push failed");
                            println!("  git: {detail}");
                            Ok(ExitCode::FAILURE)
                        }
                    }
                }
                Verdict::Block => {
                    audit::append_audit_event(
                        &context.repo_root,
                        AuditEvent {
                            source: AuditSource::PushCommand,
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
                    println!("  push blocked by current policy");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

fn dry_run_enabled() -> bool {
    matches!(
        std::env::var("WOLFENCE_DRY_RUN").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::run;
    use crate::core::audit::{verify_audit_log, AUDIT_LOG_RELATIVE_PATH};
    use crate::test_support::process_lock;

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

        let result = run().expect("push command should run");

        restore_process_state(&previous_dir, previous_dry_run);
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

        let result = run().expect("push command should run");

        restore_process_state(&previous_dir, previous_dry_run);
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

        let result = run().expect("push command should handle git failure gracefully");

        restore_process_state(&previous_dir, previous_dry_run);
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

    fn restore_process_state(previous_dir: &Path, previous_dry_run: Option<String>) {
        env::set_current_dir(previous_dir).expect("should restore current dir");
        if let Some(value) = previous_dry_run {
            env::set_var("WOLFENCE_DRY_RUN", value);
        } else {
            env::remove_var("WOLFENCE_DRY_RUN");
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
            "wolfence-push-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        env::temp_dir().join(unique)
    }
}
