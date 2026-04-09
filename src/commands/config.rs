//! `wolfence config`
//!
//! A security product lives or dies on configuration clarity. This command
//! prints the effective config resolution so an operator can immediately see
//! which mode is active and why.

use std::process::ExitCode;

use super::trust::archived_trust_count;
use crate::app::AppResult;
use crate::core::audit::{self, AUDIT_LOG_RELATIVE_PATH};
use crate::core::config::ResolvedConfig;
use crate::core::context::ProtectedAction;
use crate::core::git;
use crate::core::osv::OsvMode;
use crate::core::receipt_policy::RECEIPT_POLICY_FILE_RELATIVE_PATH;
use crate::core::receipts::ReceiptIndex;
use crate::core::trust::TRUST_DIR_RELATIVE_PATH;
pub fn run() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let config = ResolvedConfig::load_for_repo(&repo_root)?;
    let receipts = ReceiptIndex::load_for_repo(&repo_root)?;
    let osv_mode = OsvMode::resolve()?;
    let archived_trust_keys = archived_trust_count(&repo_root)?;

    println!("Wolfence configuration surfaces");
    println!("  global: ~/.wolfence/config.toml");
    println!("  repo:   .wolfence/config.toml");
    println!("  policy: {RECEIPT_POLICY_FILE_RELATIVE_PATH}");
    println!("  receipts: .wolfence/receipts/*.toml");
    println!(
        "  trust: {TRUST_DIR_RELATIVE_PATH}/*.pem + *.toml (archive in .wolfence/trust/archive/)"
    );
    println!("  audit: {AUDIT_LOG_RELATIVE_PATH}");
    println!("  live advisories: OSV via WOLFENCE_OSV");
    println!("  modes:  advisory | standard | strict");
    println!();
    println!("Effective configuration");
    println!("  repo root: {}", repo_root.display());
    println!("  repo config path: {}", config.repo_config_path.display());
    println!("  repo config exists: {}", config.repo_config_exists);
    println!(
        "  override receipts active for push: {}",
        receipts.active_count_for_action(ProtectedAction::Push)
    );
    println!("  override receipt issues: {}", receipts.issues.len());
    println!("  trusted receipt keys: {}", receipts.trusted_keys);
    println!(
        "  published trust keys: {}",
        receipts.published_trusted_keys
    );
    println!("  expired trust keys: {}", receipts.expired_trusted_keys);
    println!("  trust metadata files: {}", receipts.trust_metadata_files);
    println!(
        "  trust metadata missing: {}",
        receipts.trust_metadata_missing
    );
    println!(
        "  trust metadata incomplete: {}",
        receipts.trust_metadata_incomplete
    );
    println!("  scoped trust keys: {}", receipts.scoped_trusted_keys);
    println!(
        "  unrestricted trust keys: {}",
        receipts.unrestricted_trusted_keys
    );
    println!("  archived trust keys: {}", archived_trust_keys);
    println!(
        "  signed receipts required: {}",
        receipts.signed_receipts_required
    );
    println!(
        "  signed receipts required by policy: {}",
        receipts.signed_receipts_required_by_policy
    );
    println!(
        "  receipt approval policy exists: {}",
        receipts.approval_policy_exists
    );
    println!(
        "  receipt explicit category required: {}",
        receipts.require_explicit_category
    );
    println!(
        "  receipt signed mode required by policy: {}",
        receipts.require_signed_receipts
    );
    println!(
        "  receipt reviewer metadata required: {}",
        receipts.require_reviewer_metadata
    );
    println!(
        "  receipt max lifetime days: {}",
        receipts
            .max_lifetime_days
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unbounded".to_string())
    );
    println!(
        "  allowed receipt reviewers: {}",
        receipts.allowed_reviewers
    );
    println!(
        "  allowed receipt approvers: {}",
        receipts.allowed_approvers
    );
    println!(
        "  allowed receipt signing key ids: {}",
        receipts.allowed_key_ids
    );
    println!(
        "  receipt signed category policy overrides: {}",
        receipts.signed_category_policy_overrides
    );
    println!(
        "  receipt category policy overrides: {}",
        receipts.category_policy_overrides
    );
    println!(
        "  legacy active receipts: {}",
        receipts.legacy_active_receipts
    );
    let audit = audit::verify_audit_log(&repo_root)?;
    println!("  audit entries: {}", audit.entries);
    println!("  audit healthy: {}", audit.healthy);
    println!("  live OSV advisory mode: {}", osv_mode);
    println!("  effective mode: {} ({})", config.mode, config.mode_source);
    println!("  precedence: WOLFENCE_MODE -> repo config -> built-in default");
    println!("  advisory source precedence: WOLFENCE_OSV -> built-in default (`auto`)");

    Ok(ExitCode::SUCCESS)
}
