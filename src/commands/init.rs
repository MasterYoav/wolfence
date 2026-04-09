//! `wolf init`
//!
//! The initialization flow creates the first repo-local Wolfence config file.
//! This makes the local security posture explicit and gives future policy work a
//! stable place to grow.

use std::fs;
use std::process::ExitCode;

use crate::app::AppResult;
use crate::core::audit::AUDIT_DIR_RELATIVE_PATH;
use crate::core::config::{default_repo_config, REPO_CONFIG_RELATIVE_PATH};
use crate::core::git;
use crate::core::hooks::{self, HookInstallStatus};
use crate::core::receipt_policy::{
    default_receipt_policy, RECEIPT_POLICY_DIR_RELATIVE_PATH, RECEIPT_POLICY_FILE_RELATIVE_PATH,
};
use crate::core::receipts::RECEIPTS_DIR_RELATIVE_PATH;
use crate::core::trust::TRUST_DIR_RELATIVE_PATH;

pub fn run() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let config_path = repo_root.join(REPO_CONFIG_RELATIVE_PATH);
    let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
    let audit_dir = repo_root.join(AUDIT_DIR_RELATIVE_PATH);
    let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
    let receipt_policy_dir = repo_root.join(RECEIPT_POLICY_DIR_RELATIVE_PATH);
    let receipt_policy_path = repo_root.join(RECEIPT_POLICY_FILE_RELATIVE_PATH);
    let hooks_dir = git::hooks_dir(&repo_root)?;

    println!("Wolfence repository initialization");
    println!("  repo root: {}", repo_root.display());
    println!("  hooks dir: {}", hooks_dir.display());

    let config_created = if config_path.exists() {
        false
    } else {
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&config_path, default_repo_config())?;
        true
    };

    let receipts_created = if receipts_dir.exists() {
        false
    } else {
        fs::create_dir_all(&receipts_dir)?;
        true
    };

    let audit_created = if audit_dir.exists() {
        false
    } else {
        fs::create_dir_all(&audit_dir)?;
        true
    };

    let trust_created = if trust_dir.exists() {
        false
    } else {
        fs::create_dir_all(&trust_dir)?;
        true
    };

    let receipt_policy_dir_created = if receipt_policy_dir.exists() {
        false
    } else {
        fs::create_dir_all(&receipt_policy_dir)?;
        true
    };

    let receipt_policy_created = if receipt_policy_path.exists() {
        false
    } else {
        fs::write(&receipt_policy_path, default_receipt_policy())?;
        true
    };

    let hook_reports = hooks::install_managed_hooks(&repo_root)?;

    if config_created {
        println!("  config: created {}", config_path.display());
        println!("  mode: standard");
    } else {
        println!("  config: already exists at {}", config_path.display());
    }

    if receipts_created {
        println!("  receipts: created {}", receipts_dir.display());
    } else {
        println!("  receipts: already exists at {}", receipts_dir.display());
    }

    if audit_created {
        println!("  audit: created {}", audit_dir.display());
    } else {
        println!("  audit: already exists at {}", audit_dir.display());
    }

    if trust_created {
        println!("  trust: created {}", trust_dir.display());
    } else {
        println!("  trust: already exists at {}", trust_dir.display());
    }

    if receipt_policy_dir_created || receipt_policy_created {
        println!(
            "  receipt policy: created {}",
            receipt_policy_path.display()
        );
    } else {
        println!(
            "  receipt policy: already exists at {}",
            receipt_policy_path.display()
        );
    }

    println!("  hooks:");
    for report in hook_reports {
        let status = match report.status {
            HookInstallStatus::Installed => "installed",
            HookInstallStatus::Updated => "updated",
            HookInstallStatus::SkippedExisting => "skipped-existing",
            HookInstallStatus::Removed => "removed",
        };

        println!(
            "    - {}: {} ({})",
            report.hook_name,
            report.path.display(),
            status
        );
    }

    println!("  next steps:");
    println!("    - review .wolfence/config.toml");
    println!(
        "    - review .wolfence/policy/receipts.toml before using exceptions in a team workflow"
    );
    println!("    - read docs/security/override-receipts.md before using exceptions");
    println!("    - read docs/security/trust-store.md before adopting signed receipts");
    println!("    - add public keys to .wolfence/trust/ if you want signed receipts");
    println!("    - audit log will be written to .wolfence/audit/decisions.jsonl");
    println!("    - run `wolf scan`");
    println!("    - use `git push` to exercise the installed hook");

    Ok(ExitCode::SUCCESS)
}
