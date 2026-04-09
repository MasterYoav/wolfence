//! Top-level command dispatch.
//!
//! The command layer converts parsed CLI intent into use-case execution. It may
//! print operator-facing output, but it should keep business rules in the core
//! modules so the same logic can later back git hooks, editor integrations, or
//! a background daemon.

mod audit;
mod config;
mod doctor;
mod hook_pre_push;
mod init;
mod json;
mod protected;
mod push;
mod receipt;
mod scan;
mod trust;

use std::process::ExitCode;

use crate::app::AppResult;
use crate::cli::Command;

/// Executes the selected top-level command.
pub fn execute(command: Command) -> AppResult<ExitCode> {
    match command {
        Command::Init => init::run(),
        Command::Push { json } => push::run(json),
        Command::HookPrePush => hook_pre_push::run(),
        Command::Scan(command) => scan::run(command),
        Command::Doctor { json } => doctor::run(json),
        Command::Config => config::run(),
        Command::Receipt(command) => receipt::run(command),
        Command::Trust(command) => trust::run(command),
        Command::Audit(command) => audit::run(command),
        Command::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        Command::Version => {
            println!("wolf {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_help() {
    println!("Wolfence");
    println!("  Security-first Git interface for local safety gates");
    println!();
    println!("Usage:");
    println!("  wolf <command>");
    println!();
    println!("Commands:");
    println!("  init     Initialize repo-local Wolfence configuration");
    println!(
        "  push     Run scans and evaluate whether a push should be allowed (`--json` supported)"
    );
    println!("  hook-pre-push    Internal Git hook entrypoint for push enforcement");
    println!("  scan     Run the local scan pipeline without taking Git side effects (`--json` supported)");
    println!("  doctor   Inspect local prerequisites and repository state (`--json` supported)");
    println!("  config   Explain configuration surfaces and intended ownership");
    println!(
        "  receipt  List, create, verify, archive, checksum, and sign reviewable override receipts"
    );
    println!(
        "  trust    Inspect, archive, restore, and initialize repo-local receipt trust material"
    );
    println!("  audit    Inspect and verify the local Wolfence audit chain");
    println!("  help     Show this help text");
    println!("  version  Show the current Wolfence version");
    println!();
    print_receipt_help_summary();
    print_trust_help_summary();
    print_audit_help_summary();
    print_scan_help_summary();
}

fn print_receipt_help_summary() {
    println!("Receipt Commands:");
    println!("  receipt list");
    println!("  receipt new <receipt-path> <action> <category> <fingerprint> <owner> <expires-on> <reason>");
    println!("  receipt checksum <receipt-path>");
    println!("  receipt verify <receipt-path>");
    println!("  receipt archive <receipt-path> <reason>");
    println!("  receipt sign <receipt-path> <approver> <key-id> <private-key-path>");
}

fn print_trust_help_summary() {
    println!("Trust Commands:");
    println!("  trust list");
    println!("  trust verify <key-id>");
    println!("  trust init <key-id> <owner> <expires-on> [categories]");
    println!("  trust archive <key-id> <reason>");
    println!("  trust restore <key-id>");
}

fn print_audit_help_summary() {
    println!("Audit Commands:");
    println!("  audit list [--json]");
    println!("  audit verify [--json]");
}

fn print_scan_help_summary() {
    println!("Scan Commands:");
    println!("  scan [--json]");
    println!("  scan staged [--json]");
    println!("  scan push [--json]");
}
