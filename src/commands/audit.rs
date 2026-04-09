//! `wolf audit`
//!
//! Operators should not need to open JSONL by hand just to understand what
//! Wolfence decided locally. This command exposes a compact, reviewable view of
//! the audit chain and its health.

use std::process::ExitCode;

use serde::Serialize;

use crate::app::AppResult;
use crate::cli::AuditCommand;
use crate::core::{audit, git};

use super::json::{print_json, print_json_error};

pub fn run(command: AuditCommand) -> AppResult<ExitCode> {
    let json = match &command {
        AuditCommand::List { json } | AuditCommand::Verify { json } => *json,
        AuditCommand::Help => false,
    };

    let result = match command {
        AuditCommand::List { json } => run_list(json),
        AuditCommand::Verify { json } => run_verify(json),
        AuditCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    };

    if json {
        if let Err(error) = &result {
            print_json_error("audit", error)?;
            return Ok(ExitCode::FAILURE);
        }
    }

    result
}

#[derive(Serialize)]
struct AuditListJsonResponse {
    command: &'static str,
    subcommand: &'static str,
    repo_root: String,
    verification: audit::AuditVerification,
    entries: Vec<audit::AuditEntry>,
    result: &'static str,
}

#[derive(Serialize)]
struct AuditVerifyJsonResponse {
    command: &'static str,
    subcommand: &'static str,
    repo_root: String,
    verification: audit::AuditVerification,
    result: &'static str,
}

fn run_list(json: bool) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let entries = audit::read_audit_log(&repo_root)?;
    let verification = audit::verify_audit_log(&repo_root)?;

    if json {
        print_json(&AuditListJsonResponse {
            command: "audit",
            subcommand: "list",
            repo_root: repo_root.display().to_string(),
            result: if entries.is_empty() {
                "no-entries"
            } else if verification.healthy {
                "healthy"
            } else {
                "unhealthy"
            },
            verification: verification.clone(),
            entries,
        })?;
        return Ok(if verification.healthy {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }

    println!("Wolfence audit");
    println!("  repo root: {}", repo_root.display());
    println!("  log path: {}", verification.log_path.display());
    println!("  entries: {}", entries.len());
    println!(
        "  chain health: {}",
        if verification.healthy {
            "healthy"
        } else {
            "unhealthy"
        }
    );

    if let Some(issue) = verification.issue.clone() {
        println!("  issue: {issue}");
    }

    if entries.is_empty() {
        println!("  result: no local audit entries are present yet");
        return Ok(ExitCode::SUCCESS);
    }

    println!("  recent entries:");
    for entry in entries.iter().rev().take(10) {
        println!(
            "    - #{} {} | {} | {} | {}",
            entry.sequence, entry.timestamp_unix, entry.source, entry.status, entry.outcome
        );
        println!("      action: {}", entry.action);
        println!(
            "      verdict: {}",
            entry.verdict.as_deref().unwrap_or("<none>")
        );
        println!(
            "      findings: {} total, {} warnings, {} blocks",
            entry.findings, entry.warnings, entry.blocks
        );
        if entry.discovered_files > 0 || entry.ignored_files > 0 {
            println!(
                "      scope: {} discovered, {} scanned, {} ignored, {} overrides, {} receipt issues",
                entry.discovered_files,
                entry.candidate_files,
                entry.ignored_files,
                entry.overrides_applied,
                entry.receipt_issues
            );
        } else {
            println!(
                "      scope: {} candidate files, {} overrides, {} receipt issues",
                entry.candidate_files, entry.overrides_applied, entry.receipt_issues
            );
        }
        if let Some(branch) = &entry.branch {
            println!("      branch: {branch}");
        }
        if let Some(upstream) = &entry.upstream {
            println!("      upstream: {upstream}");
        }
        if let Some(commits_ahead) = entry.commits_ahead {
            println!("      commits ahead: {commits_ahead}");
        }
        if let Some(detail) = &entry.detail {
            println!("      detail: {detail}");
        }
    }

    Ok(if verification.healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn run_verify(json: bool) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let verification = audit::verify_audit_log(&repo_root)?;

    if json {
        print_json(&AuditVerifyJsonResponse {
            command: "audit",
            subcommand: "verify",
            repo_root: repo_root.display().to_string(),
            result: if verification.healthy {
                "verified"
            } else {
                "verification-failed"
            },
            verification: verification.clone(),
        })?;
        return Ok(if verification.healthy {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }

    println!("Wolfence audit verify");
    println!("  repo root: {}", repo_root.display());
    println!("  log path: {}", verification.log_path.display());
    println!("  entries: {}", verification.entries);

    if verification.healthy {
        println!("  chain health: healthy");
        println!("  result: audit log verification succeeded");
        return Ok(ExitCode::SUCCESS);
    }

    println!("  chain health: unhealthy");
    if let Some(issue) = verification.issue {
        println!("  issue: {issue}");
    }
    println!("  result: audit log verification failed");
    Ok(ExitCode::FAILURE)
}

fn print_help() {
    println!("Wolfence audit");
    println!("  List and verify the local Wolfence audit chain");
    println!();
    println!("Usage:");
    println!("  wolf audit <command> [--json]");
    println!();
    println!("Commands:");
    println!("  list    Show audit log health and the 10 most recent entries");
    println!("  verify  Verify the local audit hash chain");
    println!("  help    Show this help text");
}
