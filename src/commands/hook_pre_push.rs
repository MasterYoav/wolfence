//! Internal pre-push hook entrypoint.
//!
//! This command is meant to be called by Git hooks, not by end users directly.
//! It reuses the same push-evaluation logic as `wolf push`, but it never
//! executes `git push` itself.

use std::io::{self, BufRead, BufReader};
use std::process::ExitCode;

use crate::app::{AppError, AppResult};
use crate::core::audit::{self, AuditEvent, AuditSource};
use crate::core::policy::Verdict;

use super::protected::{self, PushEvaluation};

const ZERO_GIT_OBJECT_ID: &str = "0000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrePushRefUpdate {
    local_ref: String,
    local_oid: String,
    remote_ref: String,
    remote_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrePushBranchTransport {
    local_ref: String,
    remote_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrePushTransport {
    None,
    Branch(PrePushBranchTransport),
    Unsupported(String),
}

pub fn run() -> AppResult<ExitCode> {
    run_with_pre_push_input(BufReader::new(io::stdin().lock()))
}

fn run_with_pre_push_input<R: BufRead>(reader: R) -> AppResult<ExitCode> {
    let transport = inspect_pre_push_transport(&parse_pre_push_updates(reader)?);

    match protected::evaluate_push_action()? {
        PushEvaluation::NoCommits { context } => {
            if let Some(detail) = blocked_transport_without_ready_snapshot(&transport) {
                println!("Wolfence pre-push hook");
                println!("  repo root: {}", context.repo_root.display());
                println!("  status: no commits exist on the current branch");
                println!("  result: push blocked because the native push transport did not match a reviewable branch snapshot");
                println!("  detail: {detail}");
                audit::append_audit_event(
                    &context.repo_root,
                    AuditEvent {
                        source: AuditSource::PrePushHook,
                        action: context.action,
                        status: "no-commits",
                        outcome: "blocked",
                        detail: Some(detail),
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
                return Ok(ExitCode::FAILURE);
            }

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
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::UpToDate { context } => {
            if let Some(detail) = blocked_transport_without_ready_snapshot(&transport) {
                println!("Wolfence pre-push hook");
                println!("  repo root: {}", context.repo_root.display());
                println!("  status: branch is not ahead of its upstream");
                println!("  result: push blocked because the native push transport did not match the evaluated push window");
                println!("  detail: {detail}");
                audit::append_audit_event(
                    &context.repo_root,
                    AuditEvent {
                        source: AuditSource::PrePushHook,
                        action: context.action,
                        status: "up-to-date",
                        outcome: "blocked",
                        detail: Some(detail),
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
                return Ok(ExitCode::FAILURE);
            }

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
            Ok(ExitCode::SUCCESS)
        }
        PushEvaluation::Ready {
            context,
            report,
            decision,
            push_status: _,
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

            let transport_detail = if decision.verdict == Verdict::Block {
                None
            } else {
                validate_ready_transport(
                    &transport,
                    &current_branch,
                    upstream_branch.as_deref(),
                )
                .err()
            };

            let outcome = if decision.verdict == Verdict::Block || transport_detail.is_some() {
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
                    detail: transport_detail.clone(),
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

            if decision.verdict == Verdict::Block {
                println!("  result: push blocked by Wolfence pre-push policy");
                return Ok(ExitCode::FAILURE);
            }

            if let Some(detail) = transport_detail {
                println!("  result: push blocked because the native push transport did not match the evaluated snapshot");
                println!("  detail: {detail}");
                return Ok(ExitCode::FAILURE);
            }

            println!("  result: push allowed by Wolfence pre-push policy");
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_pre_push_updates<R: BufRead>(reader: R) -> AppResult<Vec<PrePushRefUpdate>> {
    let mut updates = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let fields = trimmed.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(AppError::Cli(format!(
                "pre-push hook received an unexpected transport line: `{trimmed}`"
            )));
        }

        updates.push(PrePushRefUpdate {
            local_ref: fields[0].to_string(),
            local_oid: fields[1].to_string(),
            remote_ref: fields[2].to_string(),
            remote_oid: fields[3].to_string(),
        });
    }

    Ok(updates)
}

fn inspect_pre_push_transport(updates: &[PrePushRefUpdate]) -> PrePushTransport {
    if updates.is_empty() {
        return PrePushTransport::None;
    }

    if updates.len() != 1 {
        return PrePushTransport::Unsupported(
            "Wolfence's managed native pre-push path currently supports one branch ref update at a time. Use `wolf push` or push one branch ref at a time.".to_string(),
        );
    }

    let update = &updates[0];
    if update.local_ref == "(delete)" || update.local_oid == ZERO_GIT_OBJECT_ID {
        return PrePushTransport::Unsupported(
            "Wolfence's managed native pre-push path does not currently verify branch deletion pushes. Use `wolf push` for reviewed branch pushes and handle deletions separately.".to_string(),
        );
    }

    if !update.local_ref.starts_with("refs/heads/") || !update.remote_ref.starts_with("refs/heads/")
    {
        return PrePushTransport::Unsupported(
            "Wolfence's managed native pre-push path currently verifies only branch-to-branch pushes. Tag pushes and other ref updates are not yet covered.".to_string(),
        );
    }

    PrePushTransport::Branch(PrePushBranchTransport {
        local_ref: update.local_ref.clone(),
        remote_ref: update.remote_ref.clone(),
    })
}

fn blocked_transport_without_ready_snapshot(transport: &PrePushTransport) -> Option<String> {
    match transport {
        PrePushTransport::None => None,
        PrePushTransport::Unsupported(detail) => Some(detail.clone()),
        PrePushTransport::Branch(transport) => Some(format!(
            "Git is attempting to push `{}` to `{}`, but Wolfence did not resolve a normal ahead-of-upstream current-branch snapshot for this native push. Use `wolf push` for this transport shape.",
            display_ref(&transport.local_ref),
            display_ref(&transport.remote_ref),
        )),
    }
}

fn validate_ready_transport(
    transport: &PrePushTransport,
    current_branch: &str,
    upstream_branch: Option<&str>,
) -> Result<(), String> {
    let expected_local_ref = format!("refs/heads/{current_branch}");
    let expected_remote_ref = upstream_branch
        .map(normalize_upstream_branch_ref)
        .unwrap_or_else(|| expected_local_ref.clone());

    match transport {
        PrePushTransport::None => Ok(()),
        PrePushTransport::Unsupported(detail) => Err(detail.clone()),
        PrePushTransport::Branch(transport) => {
            if transport.local_ref != expected_local_ref {
                return Err(format!(
                    "Wolfence evaluated branch `{current_branch}`, but Git is pushing `{}`. Use `wolf push` or push the current branch normally so the reviewed snapshot matches transport.",
                    display_ref(&transport.local_ref),
                ));
            }

            if transport.remote_ref != expected_remote_ref {
                return Err(format!(
                    "Wolfence evaluated push transport to `{}`, but Git is pushing to `{}`. Use `wolf push` or establish the normal upstream branch before relying on native `git push`.",
                    display_ref(&expected_remote_ref),
                    display_ref(&transport.remote_ref),
                ));
            }

            Ok(())
        }
    }
}

fn normalize_upstream_branch_ref(upstream_branch: &str) -> String {
    if upstream_branch.starts_with("refs/heads/") {
        return upstream_branch.to_string();
    }

    if let Some((_, branch)) = upstream_branch.split_once('/') {
        return format!("refs/heads/{branch}");
    }

    format!("refs/heads/{upstream_branch}")
}

fn display_ref(reference: &str) -> &str {
    reference
        .strip_prefix("refs/heads/")
        .or_else(|| reference.strip_prefix("refs/tags/"))
        .unwrap_or(reference)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::process::ExitCode;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        inspect_pre_push_transport, run_with_pre_push_input, validate_ready_transport,
        PrePushBranchTransport, PrePushRefUpdate, PrePushTransport, ZERO_GIT_OBJECT_ID,
    };
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

        let result =
            run_with_pre_push_input(Cursor::new(Vec::<u8>::new())).expect("hook command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn pre_push_hook_allows_harmless_initial_commit_on_current_branch_transport() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("hook-allow");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless prototype file.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");
        let head = rev_parse(&repo_root, "HEAD");
        let transport_line = format!(
            "refs/heads/main {head} refs/heads/main {ZERO_GIT_OBJECT_ID}\n"
        );

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result =
            run_with_pre_push_input(Cursor::new(transport_line)).expect("hook command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn pre_push_hook_blocks_tag_transport() {
        let _guard = process_lock();
        let repo_root = make_temp_repo("hook-block-tag");
        initialize_repo(&repo_root);
        fs::write(
            repo_root.join("README.md"),
            "# Demo\n\nThis is a harmless prototype file.\n",
        )
        .expect("should write readme");
        commit_all(&repo_root, "add readme");
        let head = rev_parse(&repo_root, "HEAD");
        let transport_line = format!(
            "refs/tags/v1 {head} refs/tags/v1 {ZERO_GIT_OBJECT_ID}\n"
        );

        let previous_dir = env::current_dir().expect("current dir should resolve");
        env::set_current_dir(&repo_root).expect("should enter repo");

        let result =
            run_with_pre_push_input(Cursor::new(transport_line)).expect("hook command should run");

        env::set_current_dir(previous_dir).expect("should restore current dir");
        assert_eq!(result, ExitCode::FAILURE);
    }

    #[test]
    fn pre_push_transport_rejects_multiple_ref_updates() {
        let transport = inspect_pre_push_transport(&[
            PrePushRefUpdate {
                local_ref: "refs/heads/main".to_string(),
                local_oid: "1111111111111111111111111111111111111111".to_string(),
                remote_ref: "refs/heads/main".to_string(),
                remote_oid: ZERO_GIT_OBJECT_ID.to_string(),
            },
            PrePushRefUpdate {
                local_ref: "refs/heads/release".to_string(),
                local_oid: "2222222222222222222222222222222222222222".to_string(),
                remote_ref: "refs/heads/release".to_string(),
                remote_oid: ZERO_GIT_OBJECT_ID.to_string(),
            },
        ]);

        assert!(matches!(transport, PrePushTransport::Unsupported(_)));
    }

    #[test]
    fn pre_push_transport_rejects_branch_mismatch_from_ready_snapshot() {
        let transport = PrePushTransport::Branch(PrePushBranchTransport {
            local_ref: "refs/heads/release".to_string(),
            remote_ref: "refs/heads/release".to_string(),
        });

        let error =
            validate_ready_transport(&transport, "main", Some("refs/heads/main")).unwrap_err();

        assert!(error.contains("evaluated branch `main`"));
    }

    #[test]
    fn pre_push_transport_accepts_remote_tracking_upstream_names() {
        let transport = PrePushTransport::Branch(PrePushBranchTransport {
            local_ref: "refs/heads/main".to_string(),
            remote_ref: "refs/heads/main".to_string(),
        });

        let result = validate_ready_transport(&transport, "main", Some("origin/main"));

        assert!(result.is_ok(), "expected normal origin/main transport to pass, got: {result:?}");
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

    fn rev_parse(repo_root: &Path, rev: &str) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["rev-parse", rev])
            .output()
            .expect("git rev-parse should spawn");
        assert!(
            output.status.success(),
            "git rev-parse {:?} failed: {}",
            rev,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
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
