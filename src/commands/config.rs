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
use crate::core::finding_baseline::{self, FINDING_BASELINE_FILE_RELATIVE_PATH};
use crate::core::git;
use crate::core::github_governance::GithubGovernanceMode;
use crate::core::osv::OsvMode;
use crate::core::receipt_policy::RECEIPT_POLICY_FILE_RELATIVE_PATH;
use crate::core::receipts::ReceiptIndex;
use crate::core::trust::TRUST_DIR_RELATIVE_PATH;
pub fn run() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let config = ResolvedConfig::load_for_repo(&repo_root)?;
    let receipts = ReceiptIndex::load_for_repo(&repo_root)?;
    let osv_mode = OsvMode::resolve()?;
    let github_governance_mode = GithubGovernanceMode::resolve()?;
    let archived_trust_keys = archived_trust_count(&repo_root)?;
    let baseline = finding_baseline::load_baseline(&repo_root)?;

    println!("Wolfence configuration surfaces");
    println!("  global: ~/.wolfence/config.toml");
    println!("  repo:   .wolfence/config.toml");
    println!("  policy: {RECEIPT_POLICY_FILE_RELATIVE_PATH}");
    println!("  receipts: .wolfence/receipts/*.toml");
    println!("  finding baseline: {FINDING_BASELINE_FILE_RELATIVE_PATH}");
    println!(
        "  trust: {TRUST_DIR_RELATIVE_PATH}/*.pem + *.toml (archive in .wolfence/trust/archive/)"
    );
    println!("  audit: {AUDIT_LOG_RELATIVE_PATH}");
    println!("  live advisories: OSV via WOLFENCE_OSV");
    println!("  live GitHub governance verification: WOLFENCE_GITHUB_GOVERNANCE");
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
    println!("  finding baseline captured: {}", baseline.is_some());
    if let Some(snapshot) = baseline {
        println!("  finding baseline scope: {}", snapshot.scope);
        println!(
            "  finding baseline fingerprints: {}",
            snapshot.fingerprints.len()
        );
    }
    println!("  live OSV advisory mode: {}", osv_mode);
    println!("  live GitHub governance mode: {}", github_governance_mode);
    println!(
        "  scan ignore paths: {}",
        if config.scan_ignore_paths.is_empty() {
            "none".to_string()
        } else {
            config.scan_ignore_paths.join(", ")
        }
    );
    println!(
        "  dependency node internal packages: {}",
        if config.node_internal_packages.is_empty() {
            "none".to_string()
        } else {
            config.node_internal_packages.join(", ")
        }
    );
    println!(
        "  dependency node internal package prefixes: {}",
        if config.node_internal_package_prefixes.is_empty() {
            "none".to_string()
        } else {
            config.node_internal_package_prefixes.join(", ")
        }
    );
    println!(
        "  dependency node registry ownership rules: {}",
        if config.node_registry_ownership.is_empty() {
            "none".to_string()
        } else {
            config.node_registry_ownership.join(", ")
        }
    );
    println!(
        "  dependency ruby source ownership rules: {}",
        if config.ruby_source_ownership.is_empty() {
            "none".to_string()
        } else {
            config.ruby_source_ownership.join(", ")
        }
    );
    println!(
        "  dependency python internal packages: {}",
        if config.python_internal_packages.is_empty() {
            "none".to_string()
        } else {
            config.python_internal_packages.join(", ")
        }
    );
    println!(
        "  dependency python internal package prefixes: {}",
        if config.python_internal_package_prefixes.is_empty() {
            "none".to_string()
        } else {
            config.python_internal_package_prefixes.join(", ")
        }
    );
    println!(
        "  dependency python index ownership rules: {}",
        if config.python_index_ownership.is_empty() {
            "none".to_string()
        } else {
            config.python_index_ownership.join(", ")
        }
    );
    println!("  effective mode: {} ({})", config.mode, config.mode_source);
    println!("  precedence: WOLFENCE_MODE -> repo config -> built-in default");
    println!("  advisory source precedence: WOLFENCE_OSV -> built-in default (`auto`)");
    println!(
        "  live GitHub governance precedence: WOLFENCE_GITHUB_GOVERNANCE -> built-in default (`auto`)"
    );

    Ok(ExitCode::SUCCESS)
}
