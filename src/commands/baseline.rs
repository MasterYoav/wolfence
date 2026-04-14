//! `wolf baseline`
//!
//! Baselines let an operator declare the currently known finding set as an
//! accepted starting point. This never suppresses policy; it only makes new
//! findings stand out relative to an intentional baseline snapshot.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::cli::{BaselineCommand, BaselineScope};
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::finding_baseline;
use crate::core::git;
use crate::core::orchestrator::Orchestrator;

use super::protected::{self, PushEvaluation};

pub fn run(command: BaselineCommand) -> AppResult<ExitCode> {
    match command {
        BaselineCommand::Capture { scope } => capture(scope),
        BaselineCommand::Show => show(),
        BaselineCommand::Clear => clear(),
        BaselineCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn capture(scope: BaselineScope) -> AppResult<ExitCode> {
    let (repo_root, findings, status_label) = match scope {
        BaselineScope::Push => match protected::evaluate_push_action()? {
            PushEvaluation::NoCommits { context } => {
                (context.repo_root, Vec::new(), "no-commits".to_string())
            }
            PushEvaluation::UpToDate { context } => {
                (context.repo_root, Vec::new(), "up-to-date".to_string())
            }
            PushEvaluation::Ready {
                context, report, ..
            } => (context.repo_root, report.findings, "ready".to_string()),
        },
        BaselineScope::Staged => {
            let context = ExecutionContext::load(ProtectedAction::Scan)?;
            let report = Orchestrator::default().run(&context)?;
            (context.repo_root, report.findings, "ready".to_string())
        }
    };

    let scope_label = match scope {
        BaselineScope::Push => "push",
        BaselineScope::Staged => "staged",
    };
    let snapshot = finding_baseline::capture_baseline(&repo_root, scope_label, &findings)?;

    println!("Wolfence baseline");
    println!("  repo root: {}", repo_root.display());
    println!("  scope: {scope_label}");
    println!("  source status: {status_label}");
    println!("  baseline path: {}", snapshot.path.display());
    println!("  fingerprints captured: {}", snapshot.fingerprints.len());
    println!("  captured_on_unix: {}", snapshot.captured_on_unix);
    println!(
        "  note: baselines do not suppress policy. Use override receipts for explicit, reviewed exceptions."
    );
    Ok(ExitCode::SUCCESS)
}

fn show() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let Some(snapshot) = finding_baseline::load_baseline(&repo_root)? else {
        println!("Wolfence baseline");
        println!("  repo root: {}", repo_root.display());
        println!("  status: no finding baseline has been captured yet");
        println!(
            "  next: run `wolf baseline capture` to record the current accepted starting set."
        );
        return Ok(ExitCode::SUCCESS);
    };

    println!("Wolfence baseline");
    println!("  repo root: {}", repo_root.display());
    println!("  baseline path: {}", snapshot.path.display());
    println!("  scope: {}", snapshot.scope);
    println!("  captured_on_unix: {}", snapshot.captured_on_unix);
    println!("  fingerprints: {}", snapshot.fingerprints.len());
    for fingerprint in snapshot.fingerprints.iter().take(8) {
        println!("    - {fingerprint}");
    }
    let remaining = snapshot.fingerprints.len().saturating_sub(8);
    if remaining > 0 {
        println!("    - ... and {remaining} more");
    }
    println!(
        "  note: the baseline only marks accepted starting state. It does not change push verdicts."
    );
    Ok(ExitCode::SUCCESS)
}

fn clear() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let removed = finding_baseline::clear_baseline(&repo_root)?;

    println!("Wolfence baseline");
    println!("  repo root: {}", repo_root.display());
    if removed {
        println!("  result: removed the current finding baseline");
    } else {
        println!("  result: no finding baseline was present");
    }
    Ok(ExitCode::SUCCESS)
}

fn print_help() {
    println!("Wolfence baseline");
    println!("  Manage repo-local accepted finding baselines");
    println!();
    println!("Usage:");
    println!("  wolf baseline capture [push|staged]");
    println!("  wolf baseline show");
    println!("  wolf baseline clear");
    println!();
    println!("Notes:");
    println!("  capture defaults to `push` scope");
    println!("  baselines do not suppress findings or change push policy");
    println!("  override receipts remain the only reviewed suppression path");
}
