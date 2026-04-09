//! `wolf audit`
//!
//! Operators should not need to open JSONL by hand just to understand what
//! Wolfence decided locally. This command exposes a compact, reviewable view of
//! the audit chain and its health.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::cli::AuditCommand;
use crate::core::{audit, git};

pub fn run(command: AuditCommand) -> AppResult<ExitCode> {
    match command {
        AuditCommand::List => run_list(),
        AuditCommand::Verify => run_verify(),
        AuditCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_list() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let entries = audit::read_audit_log(&repo_root)?;
    let verification = audit::verify_audit_log(&repo_root)?;

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

    if let Some(issue) = verification.issue {
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

fn run_verify() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let verification = audit::verify_audit_log(&repo_root)?;

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
    println!("  wolf audit <command>");
    println!();
    println!("Commands:");
    println!("  list    Show audit log health and the 10 most recent entries");
    println!("  verify  Verify the local audit hash chain");
    println!("  help    Show this help text");
}
