//! `wolfence scan`
//!
//! The standalone scan command is the easiest place to harden the platform
//! before wrapping real Git operations. It produces the same report shape the
//! policy engine and future UI integrations will consume.

use std::process::ExitCode;

use crate::app::AppResult;
use crate::core::context::{ExecutionContext, ProtectedAction};
use crate::core::orchestrator::Orchestrator;

pub fn run() -> AppResult<ExitCode> {
    let context = ExecutionContext::load(ProtectedAction::Scan)?;
    let report = Orchestrator::default().run(&context)?;

    println!("Wolfence scan");
    println!("  action: {}", context.action);
    println!("  repo root: {}", context.repo_root.display());
    println!(
        "  mode: {} ({})",
        context.config.mode, context.config.mode_source
    );
    println!("  candidate files: {}", report.scanned_files);
    println!("  scanners run: {}", report.scanners_run);
    println!("  findings: {}", report.findings.len());

    if report.findings.is_empty() {
        println!("  result: no findings in the current local detection pipeline");
        return Ok(ExitCode::SUCCESS);
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

    Ok(ExitCode::SUCCESS)
}
