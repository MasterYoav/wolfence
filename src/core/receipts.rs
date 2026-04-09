//! Reviewable local override receipts.
//!
//! Wolfence should have an exception path, but it must be explicit, bounded,
//! and easy to audit. This module loads repo-local override receipts, validates
//! their integrity metadata, and exposes only active receipts to the policy
//! engine.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::AppResult;

use super::context::ProtectedAction;
use super::findings::FindingCategory;
use super::git;
use super::receipt_policy::{EffectiveReceiptPolicy, ReceiptApprovalPolicy};
use super::trust::TrustStore;

/// Directory that stores repo-local override receipts.
pub const RECEIPTS_DIR_RELATIVE_PATH: &str = ".wolfence/receipts";

/// One validated override receipt that can suppress a finding for one action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideReceipt {
    pub path: PathBuf,
    pub receipt_id: String,
    pub action: ProtectedAction,
    pub category: FindingCategory,
    pub category_bound: bool,
    pub fingerprint: String,
    pub owner: String,
    pub reviewer: Option<String>,
    pub reviewed_on: Option<String>,
    pub approver: Option<String>,
    pub key_id: Option<String>,
    pub reason: String,
    pub created_on: String,
    pub expires_on: String,
    pub checksum: String,
}

/// Non-fatal issue encountered while loading receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptIssue {
    pub path: PathBuf,
    pub detail: String,
    pub remediation: String,
}

/// Loaded receipt state for one repository.
#[derive(Debug, Clone, Default)]
pub struct ReceiptIndex {
    pub active: Vec<OverrideReceipt>,
    pub issues: Vec<ReceiptIssue>,
    pub trusted_keys: usize,
    pub published_trusted_keys: usize,
    pub expired_trusted_keys: usize,
    pub trust_metadata_files: usize,
    pub trust_metadata_missing: usize,
    pub trust_metadata_incomplete: usize,
    pub scoped_trusted_keys: usize,
    pub unrestricted_trusted_keys: usize,
    pub signed_receipts_required: bool,
    pub signed_receipts_required_by_policy: bool,
    pub approval_policy_exists: bool,
    pub require_explicit_category: bool,
    pub require_signed_receipts: bool,
    pub require_reviewer_metadata: bool,
    pub max_lifetime_days: Option<u32>,
    pub allowed_reviewers: usize,
    pub allowed_approvers: usize,
    pub allowed_key_ids: usize,
    pub category_policy_overrides: usize,
    pub signed_category_policy_overrides: usize,
    pub legacy_active_receipts: usize,
}

/// Canonical editable receipt fields before signature material is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptDraft {
    pub receipt_id: String,
    pub action: ProtectedAction,
    pub category: FindingCategory,
    pub fingerprint: String,
    pub owner: String,
    pub reviewer: Option<String>,
    pub reviewed_on: Option<String>,
    pub reason: String,
    pub created_on: String,
    pub expires_on: String,
    pub category_bound: bool,
}

/// Returns the current UTC date in `YYYY-MM-DD` format for receipt creation.
pub fn today_utc_date() -> String {
    current_utc_date()
}

impl ReceiptIndex {
    /// Loads and validates repo-local override receipts.
    pub fn load_for_repo(repo_root: &Path) -> AppResult<Self> {
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let trust = TrustStore::load_for_repo(repo_root)?;
        let approval_policy = ReceiptApprovalPolicy::load_for_repo(repo_root)?;
        let signed_by_policy = approval_policy.any_signed_receipt_requirement();
        let signed_category_policy_overrides = approval_policy
            .category_rules
            .values()
            .filter(|rule| rule.require_signed_receipts == Some(true))
            .count();
        if !receipts_dir.exists() {
            return Ok(Self {
                active: Vec::new(),
                issues: Vec::new(),
                trusted_keys: trust.key_count(),
                published_trusted_keys: trust.published_key_count(),
                expired_trusted_keys: trust.expired_keys,
                trust_metadata_files: trust.metadata_files,
                trust_metadata_missing: trust.metadata_missing,
                trust_metadata_incomplete: trust.metadata_incomplete,
                scoped_trusted_keys: trust.scoped_keys,
                unrestricted_trusted_keys: trust.unrestricted_keys,
                signed_receipts_required: trust.requires_signed_receipts() || signed_by_policy,
                signed_receipts_required_by_policy: signed_by_policy,
                approval_policy_exists: approval_policy.exists,
                require_explicit_category: approval_policy.require_explicit_category,
                require_signed_receipts: approval_policy.require_signed_receipts,
                require_reviewer_metadata: approval_policy.require_reviewer_metadata,
                max_lifetime_days: approval_policy.max_lifetime_days,
                allowed_reviewers: approval_policy.allowed_reviewers.len(),
                allowed_approvers: approval_policy.allowed_approvers.len(),
                allowed_key_ids: approval_policy.allowed_key_ids.len(),
                category_policy_overrides: approval_policy.category_rules.len(),
                signed_category_policy_overrides,
                legacy_active_receipts: 0,
            });
        }

        let mut active = Vec::new();
        let mut issues = Vec::new();
        let today = current_utc_date();

        for entry in fs::read_dir(&receipts_dir)? {
            let entry = entry?;
            let path = entry.path();

            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("toml")
            {
                continue;
            }

            let contents = fs::read_to_string(&path)?;
            match parse_receipt(&path, &contents, &today, &trust, &approval_policy)? {
                ReceiptLoadOutcome::Active(receipt) => active.push(receipt),
                ReceiptLoadOutcome::Issue(issue) => issues.push(issue),
            }
        }

        let duplicate_fingerprints = duplicate_receipt_keys(&active);
        if !duplicate_fingerprints.is_empty() {
            let mut retained = Vec::new();

            for receipt in active {
                let key = duplicate_key(&receipt);
                if duplicate_fingerprints.contains_key(&key) {
                    issues.push(ReceiptIssue {
                        path: receipt.path.clone(),
                        detail: format!(
                            "multiple active override receipts target `{}` for `{}`.",
                            receipt.fingerprint, receipt.action
                        ),
                        remediation:
                            "Keep only one active receipt per finding fingerprint and action."
                                .to_string(),
                    });
                } else {
                    retained.push(receipt);
                }
            }

            active = retained;
        }

        let legacy_active_receipts = active
            .iter()
            .filter(|receipt| !receipt.category_bound)
            .count();

        Ok(Self {
            active,
            issues,
            trusted_keys: trust.key_count(),
            published_trusted_keys: trust.published_key_count(),
            expired_trusted_keys: trust.expired_keys,
            trust_metadata_files: trust.metadata_files,
            trust_metadata_missing: trust.metadata_missing,
            trust_metadata_incomplete: trust.metadata_incomplete,
            scoped_trusted_keys: trust.scoped_keys,
            unrestricted_trusted_keys: trust.unrestricted_keys,
            signed_receipts_required: trust.requires_signed_receipts() || signed_by_policy,
            signed_receipts_required_by_policy: signed_by_policy,
            approval_policy_exists: approval_policy.exists,
            require_explicit_category: approval_policy.require_explicit_category,
            require_signed_receipts: approval_policy.require_signed_receipts,
            require_reviewer_metadata: approval_policy.require_reviewer_metadata,
            max_lifetime_days: approval_policy.max_lifetime_days,
            allowed_reviewers: approval_policy.allowed_reviewers.len(),
            allowed_approvers: approval_policy.allowed_approvers.len(),
            allowed_key_ids: approval_policy.allowed_key_ids.len(),
            category_policy_overrides: approval_policy.category_rules.len(),
            signed_category_policy_overrides,
            legacy_active_receipts,
        })
    }

    /// Returns the active receipt that matches one action and finding fingerprint.
    pub fn matching_override(
        &self,
        action: ProtectedAction,
        category: FindingCategory,
        fingerprint: &str,
    ) -> Option<&OverrideReceipt> {
        self.active.iter().find(|receipt| {
            receipt.action == action
                && receipt.category == category
                && receipt.fingerprint == fingerprint
        })
    }

    /// Counts active receipts for one action.
    pub fn active_count_for_action(&self, action: ProtectedAction) -> usize {
        self.active
            .iter()
            .filter(|receipt| receipt.action == action)
            .count()
    }
}

/// Loads one receipt draft from disk for operator workflows such as checksum
/// generation and signing.
pub fn load_receipt_draft(path: &Path) -> AppResult<ReceiptDraft> {
    let contents = fs::read_to_string(path)?;
    let values = parse_key_value_file(&contents);

    let version = require_draft_value(path, &values, "version")?;
    if version != "1" {
        return Err(crate::app::AppError::Config(format!(
            "{} uses unsupported receipt version `{version}`.",
            path.display()
        )));
    }

    let action_value = require_draft_value(path, &values, "action")?;
    let action = parse_action_value(path, &action_value)?;
    let receipt_id = required_value(&values, "receipt_id")
        .unwrap_or_else(|| legacy_receipt_id(action, &contents));
    let fingerprint = require_draft_value(path, &values, "fingerprint")?;
    let (category, category_bound) = parse_receipt_category(path, &values, &contents)?;
    let owner = require_draft_value(path, &values, "owner")?;
    let reviewer = required_value(&values, "reviewer");
    let reviewed_on = required_value(&values, "reviewed_on");
    let reason = require_draft_value(path, &values, "reason")?;
    let created_on = require_draft_value(path, &values, "created_on")?;
    let expires_on = require_draft_value(path, &values, "expires_on")?;

    if !is_iso_date(&created_on) || !is_iso_date(&expires_on) {
        return Err(crate::app::AppError::Config(format!(
            "{} must use ISO calendar dates for `created_on` and `expires_on`.",
            path.display()
        )));
    }

    if expires_on < created_on {
        return Err(crate::app::AppError::Config(format!(
            "{} expires earlier than it was created.",
            path.display()
        )));
    }

    validate_reviewer_metadata(path, reviewer.as_deref(), reviewed_on.as_deref())?;

    Ok(ReceiptDraft {
        receipt_id,
        action,
        category,
        fingerprint,
        owner,
        reviewer,
        reviewed_on,
        reason,
        created_on,
        expires_on,
        category_bound,
    })
}

/// Computes the canonical checksum for one receipt draft.
pub fn draft_checksum(draft: &ReceiptDraft) -> AppResult<String> {
    receipt_checksum(
        draft.action,
        draft.category,
        &draft.fingerprint,
        &draft.owner,
        &draft.reason,
        &draft.created_on,
        &draft.expires_on,
        draft.category_bound,
    )
}

/// Generates one new receipt id suitable for local operator workflows.
pub fn generate_receipt_id(draft: &ReceiptDraft) -> AppResult<String> {
    let seed = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        draft.action,
        draft.category,
        draft.fingerprint,
        draft.owner,
        draft.created_on,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let hash = git::hash_text(&seed)?;
    Ok(format!("wr_{}", &hash[..12]))
}

/// Returns the canonical signature payload for one draft plus approval fields.
pub fn signed_receipt_payload(
    draft: &ReceiptDraft,
    approver: &str,
    key_id: &str,
    checksum: &str,
) -> String {
    canonical_signed_receipt_payload(
        &draft.receipt_id,
        draft.action,
        draft.category,
        &draft.fingerprint,
        &draft.owner,
        draft.reviewer.as_deref().unwrap_or(""),
        draft.reviewed_on.as_deref().unwrap_or(""),
        approver,
        key_id,
        &draft.reason,
        &draft.created_on,
        &draft.expires_on,
        checksum,
        draft.category_bound,
    )
}

/// Renders one receipt file in canonical field order.
pub fn render_receipt_file(
    draft: &ReceiptDraft,
    checksum: &str,
    approver: Option<&str>,
    key_id: Option<&str>,
    signature: Option<&str>,
) -> String {
    let mut lines = vec![
        r#"version = "1""#.to_string(),
        format!(r#"receipt_id = "{}""#, draft.receipt_id),
        format!(r#"action = "{}""#, draft.action),
        format!(r#"category = "{}""#, draft.category),
        format!(r#"fingerprint = "{}""#, draft.fingerprint),
        format!(r#"owner = "{}""#, draft.owner),
    ];

    if let Some(reviewer) = &draft.reviewer {
        lines.push(format!(r#"reviewer = "{}""#, reviewer));
    }

    if let Some(reviewed_on) = &draft.reviewed_on {
        lines.push(format!(r#"reviewed_on = "{}""#, reviewed_on));
    }

    if let Some(approver) = approver {
        lines.push(format!(r#"approver = "{}""#, approver));
    }

    if let Some(key_id) = key_id {
        lines.push(format!(r#"key_id = "{}""#, key_id));
    }

    lines.push(format!(r#"reason = "{}""#, draft.reason));
    lines.push(format!(r#"created_on = "{}""#, draft.created_on));
    lines.push(format!(r#"expires_on = "{}""#, draft.expires_on));
    lines.push(format!(r#"checksum = "{}""#, checksum));

    if let Some(signature) = signature {
        lines.push(format!(r#"signature = "{}""#, signature));
    }

    lines.join("\n") + "\n"
}

enum ReceiptLoadOutcome {
    Active(OverrideReceipt),
    Issue(ReceiptIssue),
}

fn parse_receipt(
    path: &Path,
    contents: &str,
    today: &str,
    trust: &TrustStore,
    approval_policy: &ReceiptApprovalPolicy,
) -> AppResult<ReceiptLoadOutcome> {
    let values = parse_key_value_file(contents);

    let Some(version) = required_value(&values, "version") else {
        return Ok(missing_key_issue(path, "version"));
    };
    if version != "1" {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: format!("unsupported receipt version `{version}`."),
            remediation: "Set `version = \"1\"` or regenerate the receipt in the current format."
                .to_string(),
        }));
    }

    let Some(action) = required_value(&values, "action") else {
        return Ok(missing_key_issue(path, "action"));
    };
    let action = match parse_action_value(path, &action) {
        Ok(action) => action,
        Err(crate::app::AppError::Config(message)) => {
            return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
                path: path.to_path_buf(),
                detail: message,
                remediation: "Use `push` or `scan` as the receipt action.".to_string(),
            }))
        }
        Err(error) => return Err(error),
    };
    let receipt_id = required_value(&values, "receipt_id")
        .unwrap_or_else(|| legacy_receipt_id(action, contents));
    let Some(fingerprint) = required_value(&values, "fingerprint") else {
        return Ok(missing_key_issue(path, "fingerprint"));
    };
    let (category, category_bound) = match parse_receipt_category(path, &values, contents) {
        Ok(result) => result,
        Err(crate::app::AppError::Config(message)) => {
            return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
                path: path.to_path_buf(),
                detail: message,
                remediation: "Set `category` to one of the supported finding categories."
                    .to_string(),
            }))
        }
        Err(error) => return Err(error),
    };
    let Some(owner) = required_value(&values, "owner") else {
        return Ok(missing_key_issue(path, "owner"));
    };
    let reviewer = required_value(&values, "reviewer");
    let reviewed_on = required_value(&values, "reviewed_on");
    let approver = required_value(&values, "approver");
    let key_id = required_value(&values, "key_id");
    let Some(reason) = required_value(&values, "reason") else {
        return Ok(missing_key_issue(path, "reason"));
    };
    let Some(created_on) = required_value(&values, "created_on") else {
        return Ok(missing_key_issue(path, "created_on"));
    };
    let Some(expires_on) = required_value(&values, "expires_on") else {
        return Ok(missing_key_issue(path, "expires_on"));
    };
    let Some(checksum) = required_value(&values, "checksum") else {
        return Ok(missing_key_issue(path, "checksum"));
    };

    if !is_iso_date(&created_on) || !is_iso_date(&expires_on) {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: "receipt dates must use ISO format `YYYY-MM-DD`.".to_string(),
            remediation: "Set `created_on` and `expires_on` using exact ISO calendar dates."
                .to_string(),
        }));
    }

    if expires_on < created_on {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: "receipt expiry date is earlier than its creation date.".to_string(),
            remediation: "Use an `expires_on` date that is on or after `created_on`.".to_string(),
        }));
    }

    if let Err(crate::app::AppError::Config(message)) =
        validate_reviewer_metadata(path, reviewer.as_deref(), reviewed_on.as_deref())
    {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: message,
            remediation:
                "Set both `reviewer` and `reviewed_on` together using ISO dates, or remove the incomplete metadata.".to_string(),
        }));
    }

    if approval_policy.require_explicit_category && !category_bound {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail:
                "receipt approval policy requires an explicit `category` field; legacy category inference is not allowed."
                    .to_string(),
            remediation:
                "Regenerate or re-sign the receipt so it includes an explicit `category` field."
                    .to_string(),
        }));
    }

    let effective_policy = approval_policy.effective_for(category);

    if let Err(message) = validate_against_approval_policy(
        &effective_policy,
        category,
        reviewer.as_deref(),
        reviewed_on.as_deref(),
        approver.as_deref(),
        key_id.as_deref(),
        &created_on,
        &expires_on,
    ) {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: message,
            remediation:
                "Adjust `.wolfence/policy/receipts.toml` or bring the receipt metadata into policy compliance.".to_string(),
        }));
    }

    let expected_checksum = receipt_checksum(
        action,
        category,
        &fingerprint,
        &owner,
        &reason,
        &created_on,
        &expires_on,
        category_bound,
    )?;

    if checksum != expected_checksum {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: "receipt checksum does not match its contents.".to_string(),
            remediation:
                "Recompute the checksum after editing the receipt or revert unintended changes."
                    .to_string(),
        }));
    }

    if expires_on.as_str() < today {
        return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
            path: path.to_path_buf(),
            detail: format!("receipt expired on {expires_on}."),
            remediation:
                "Remove the receipt or replace it with a newly justified, time-bounded override."
                    .to_string(),
        }));
    }

    let signed_receipts_required =
        trust.requires_signed_receipts() || effective_policy.require_signed_receipts;

    if signed_receipts_required {
        let Some(approver) = approver.clone() else {
            return Ok(missing_signature_issue(
                path,
                "approver",
                "Add the approver identity for this signed override receipt, or relax the repo receipt signature policy.",
            ));
        };
        let Some(key_id) = key_id.clone() else {
            return Ok(missing_signature_issue(
                path,
                "key_id",
                "Add the trusted public key id that should verify this receipt, or relax the repo receipt signature policy.",
            ));
        };
        let Some(signature) = required_value(&values, "signature") else {
            return Ok(missing_signature_issue(
                path,
                "signature",
                "Add a detached hex signature for this receipt, or remove or relax the incomplete override.",
            ));
        };

        if trust.key_path(&key_id).is_none() {
            let detail = if trust.has_key_id(&key_id) && !trust.key_is_active(&key_id) {
                format!("receipt references trusted key id `{key_id}`, but that key is expired and inactive.")
            } else {
                format!("receipt references unknown trusted key id `{key_id}`.")
            };
            return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
                path: path.to_path_buf(),
                detail,
                remediation: "Add or renew the matching public key under `.wolfence/trust/`, correct the receipt key id, or relax the repo signature policy.".to_string(),
            }));
        }

        if !trust.key_allows_category(&key_id, category) {
            return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
                path: path.to_path_buf(),
                detail: format!(
                    "receipt references trusted key id `{key_id}`, but that key is not trusted for `{category}` receipts."
                ),
                remediation: "Use a trust key whose metadata allows this receipt category, or narrow the receipt to a category the key is trusted to approve.".to_string(),
            }));
        }

        let signed_payload = canonical_signed_receipt_payload(
            &receipt_id,
            action,
            category,
            &fingerprint,
            &owner,
            reviewer.as_deref().unwrap_or(""),
            reviewed_on.as_deref().unwrap_or(""),
            &approver,
            &key_id,
            &reason,
            &created_on,
            &expires_on,
            &checksum,
            category_bound,
        );

        let verified = trust.verify_receipt_signature(&key_id, &signed_payload, &signature)?;
        if !verified {
            return Ok(ReceiptLoadOutcome::Issue(ReceiptIssue {
                path: path.to_path_buf(),
                detail: format!(
                    "receipt signature verification failed for trusted key `{key_id}`."
                ),
                remediation: "Re-sign the receipt with the matching private key or remove the invalid receipt.".to_string(),
            }));
        }
    }

    Ok(ReceiptLoadOutcome::Active(OverrideReceipt {
        path: path.to_path_buf(),
        receipt_id,
        action,
        category,
        category_bound,
        fingerprint,
        owner,
        reviewer,
        reviewed_on,
        approver,
        key_id,
        reason,
        created_on,
        expires_on,
        checksum,
    }))
}

fn validate_against_approval_policy(
    policy: &EffectiveReceiptPolicy,
    category: FindingCategory,
    reviewer: Option<&str>,
    reviewed_on: Option<&str>,
    approver: Option<&str>,
    key_id: Option<&str>,
    created_on: &str,
    expires_on: &str,
) -> Result<(), String> {
    if policy.require_reviewer_metadata && (reviewer.is_none() || reviewed_on.is_none()) {
        return Err(
            "receipt approval policy requires `reviewer` and `reviewed_on` metadata.".to_string(),
        );
    }

    if !policy.allowed_reviewers.is_empty() {
        let Some(reviewer) = reviewer else {
            return Err(
                "receipt approval policy requires a reviewer from the allowed reviewer set."
                    .to_string(),
            );
        };
        if !policy
            .allowed_reviewers
            .iter()
            .any(|value| value == reviewer)
        {
            return Err(format!(
                "receipt reviewer `{reviewer}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
            ));
        }
    }

    if !policy.allowed_approvers.is_empty() {
        let Some(approver) = approver else {
            return Err(
                "receipt approval policy requires an approver from the allowed approver set."
                    .to_string(),
            );
        };
        if !policy
            .allowed_approvers
            .iter()
            .any(|value| value == approver)
        {
            return Err(format!(
                "receipt approver `{approver}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
            ));
        }
    }

    if !policy.allowed_key_ids.is_empty() {
        let Some(key_id) = key_id else {
            return Err(
                "receipt approval policy requires a signing key id from the allowed key set."
                    .to_string(),
            );
        };
        if !policy.allowed_key_ids.iter().any(|value| value == key_id) {
            return Err(format!(
                "receipt signing key id `{key_id}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
            ));
        }
    }

    if let Some(max_lifetime_days) = policy.max_lifetime_days {
        let created_days = parse_iso_date_to_days(created_on)
            .ok_or_else(|| "receipt creation date could not be evaluated.".to_string())?;
        let expires_days = parse_iso_date_to_days(expires_on)
            .ok_or_else(|| "receipt expiry date could not be evaluated.".to_string())?;
        let lifetime_days = expires_days.saturating_sub(created_days) as u32;
        if lifetime_days > max_lifetime_days {
            return Err(format!(
                "receipt lifetime of {lifetime_days} day(s) exceeds the policy maximum of {max_lifetime_days}."
            ));
        }
    }

    Ok(())
}

fn validate_reviewer_metadata(
    path: &Path,
    reviewer: Option<&str>,
    reviewed_on: Option<&str>,
) -> AppResult<()> {
    match (reviewer, reviewed_on) {
        (None, None) => Ok(()),
        (Some(_), Some(reviewed_on)) if is_iso_date(reviewed_on) => Ok(()),
        (Some(_), Some(_)) => Err(crate::app::AppError::Config(format!(
            "{} uses malformed `reviewed_on`; expected ISO format `YYYY-MM-DD`.",
            path.display()
        ))),
        (Some(_), None) => Err(crate::app::AppError::Config(format!(
            "{} sets `reviewer` without `reviewed_on`.",
            path.display()
        ))),
        (None, Some(_)) => Err(crate::app::AppError::Config(format!(
            "{} sets `reviewed_on` without `reviewer`.",
            path.display()
        ))),
    }
}

fn missing_key_issue(path: &Path, key: &str) -> ReceiptLoadOutcome {
    ReceiptLoadOutcome::Issue(ReceiptIssue {
        path: path.to_path_buf(),
        detail: format!("missing required receipt key `{key}`."),
        remediation: "Add the missing field or remove the incomplete receipt.".to_string(),
    })
}

fn missing_signature_issue(path: &Path, key: &str, remediation: &str) -> ReceiptLoadOutcome {
    ReceiptLoadOutcome::Issue(ReceiptIssue {
        path: path.to_path_buf(),
        detail: format!(
            "signed receipts are required for this repository, but receipt key `{key}` is missing."
        ),
        remediation: remediation.to_string(),
    })
}

fn require_draft_value(
    path: &Path,
    values: &HashMap<String, String>,
    key: &str,
) -> AppResult<String> {
    required_value(values, key).ok_or_else(|| {
        crate::app::AppError::Config(format!(
            "{} is missing required receipt key `{key}`.",
            path.display()
        ))
    })
}

fn parse_action_value(path: &Path, value: &str) -> AppResult<ProtectedAction> {
    match value {
        "push" => Ok(ProtectedAction::Push),
        "scan" => Ok(ProtectedAction::Scan),
        other => Err(crate::app::AppError::Config(format!(
            "{} uses unsupported receipt action `{other}`.",
            path.display()
        ))),
    }
}

fn parse_receipt_category(
    path: &Path,
    values: &HashMap<String, String>,
    contents: &str,
) -> AppResult<(FindingCategory, bool)> {
    if let Some(category) = required_value(values, "category") {
        let parsed = FindingCategory::parse(&category).map_err(|message| {
            crate::app::AppError::Config(format!(
                "{} uses unsupported receipt category `{category}`: {message}.",
                path.display()
            ))
        })?;
        return Ok((parsed, true));
    }

    infer_category_from_fingerprint(
        path,
        required_value(values, "fingerprint").as_deref(),
        contents,
    )
}

fn infer_category_from_fingerprint(
    path: &Path,
    fingerprint: Option<&str>,
    _contents: &str,
) -> AppResult<(FindingCategory, bool)> {
    let Some(fingerprint) = fingerprint else {
        return Err(crate::app::AppError::Config(format!(
            "{} is missing required receipt key `fingerprint`.",
            path.display()
        )));
    };

    let prefix = fingerprint.split(':').next().unwrap_or_default();
    let category = FindingCategory::parse(prefix).map_err(|_| {
        crate::app::AppError::Config(format!(
            "{} is missing `category`, and the legacy fingerprint `{fingerprint}` does not encode a supported category prefix.",
            path.display()
        ))
    })?;

    Ok((category, false))
}

fn required_value(values: &HashMap<String, String>, key: &str) -> Option<String> {
    values.get(key).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn parse_key_value_file(contents: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();

    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();

        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        values.insert(
            key.trim().to_string(),
            value.trim().trim_matches('"').to_string(),
        );
    }

    values
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;

    for (index, character) in line.char_indices() {
        match character {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..index],
            _ => {}
        }
    }

    line
}

fn duplicate_receipt_keys(
    receipts: &[OverrideReceipt],
) -> HashMap<(ProtectedAction, FindingCategory, String), usize> {
    let mut counts = HashMap::new();
    for receipt in receipts {
        *counts.entry(duplicate_key(receipt)).or_insert(0) += 1;
    }
    counts.retain(|_, count| *count > 1);
    counts
}

fn duplicate_key(receipt: &OverrideReceipt) -> (ProtectedAction, FindingCategory, String) {
    (
        receipt.action,
        receipt.category,
        receipt.fingerprint.clone(),
    )
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn current_utc_date() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let days = (duration.as_secs() / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn parse_iso_date_to_days(value: &str) -> Option<i64> {
    if !is_iso_date(value) {
        return None;
    }

    let year = value[0..4].parse::<i32>().ok()?;
    let month = value[5..7].parse::<u32>().ok()?;
    let day = value[8..10].parse::<u32>().ok()?;
    Some(days_from_civil(year, month, day))
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    (year as i32, month as u32, day as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era as i64) * 146_097 + (day_of_era as i64) - 719_468
}

fn receipt_checksum(
    action: ProtectedAction,
    category: FindingCategory,
    fingerprint: &str,
    owner: &str,
    reason: &str,
    created_on: &str,
    expires_on: &str,
    category_bound: bool,
) -> AppResult<String> {
    let payload = canonical_receipt_payload(
        action,
        category,
        fingerprint,
        owner,
        reason,
        created_on,
        expires_on,
        category_bound,
    );
    git::hash_text(&payload)
}

fn canonical_receipt_payload(
    action: ProtectedAction,
    category: FindingCategory,
    fingerprint: &str,
    owner: &str,
    reason: &str,
    created_on: &str,
    expires_on: &str,
    category_bound: bool,
) -> String {
    if !category_bound {
        return format!(
            "version=1\naction={action}\nfingerprint={fingerprint}\nowner={owner}\nreason={reason}\ncreated_on={created_on}\nexpires_on={expires_on}\n"
        );
    }

    format!(
        "version=1\naction={action}\ncategory={category}\nfingerprint={fingerprint}\nowner={owner}\nreason={reason}\ncreated_on={created_on}\nexpires_on={expires_on}\n"
    )
}

fn legacy_receipt_id(action: ProtectedAction, contents: &str) -> String {
    let seed = format!("{action}:{contents}");
    let hash = git::hash_text(&seed).unwrap_or_else(|_| "legacyreceiptid".to_string());
    format!("legacy-{}", &hash[..12.min(hash.len())])
}

fn canonical_signed_receipt_payload(
    receipt_id: &str,
    action: ProtectedAction,
    category: FindingCategory,
    fingerprint: &str,
    owner: &str,
    reviewer: &str,
    reviewed_on: &str,
    approver: &str,
    key_id: &str,
    reason: &str,
    created_on: &str,
    expires_on: &str,
    checksum: &str,
    category_bound: bool,
) -> String {
    if !category_bound {
        return format!(
            "version=1\nreceipt_id={receipt_id}\naction={action}\nfingerprint={fingerprint}\nowner={owner}\nreviewer={reviewer}\nreviewed_on={reviewed_on}\napprover={approver}\nkey_id={key_id}\nreason={reason}\ncreated_on={created_on}\nexpires_on={expires_on}\nchecksum={checksum}\n"
        );
    }

    format!(
        "version=1\nreceipt_id={receipt_id}\naction={action}\ncategory={category}\nfingerprint={fingerprint}\nowner={owner}\nreviewer={reviewer}\nreviewed_on={reviewed_on}\napprover={approver}\nkey_id={key_id}\nreason={reason}\ncreated_on={created_on}\nexpires_on={expires_on}\nchecksum={checksum}\n"
    )
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        draft_checksum, legacy_receipt_id, render_receipt_file, signed_receipt_payload,
        ReceiptDraft, ReceiptIndex, RECEIPTS_DIR_RELATIVE_PATH,
    };
    use crate::core::context::ProtectedAction;
    use crate::core::findings::FindingCategory;
    use crate::core::trust::{sign_payload_with_private_key, TRUST_DIR_RELATIVE_PATH};

    #[test]
    fn loads_valid_active_receipt() {
        let repo_root = make_temp_repo("valid-receipt");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        let draft = ReceiptDraft {
            receipt_id: "wr_validreceipt".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");

        fs::write(
            receipts_dir.join("allow-secret.toml"),
            render_receipt_file(&draft, &checksum, None, None, None),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(index.active.len(), 1);
        assert!(index.issues.is_empty());
        assert_eq!(index.trusted_keys, 0);
        assert!(!index.signed_receipts_required);
    }

    #[test]
    fn rejects_invalid_checksum_receipt() {
        let repo_root = make_temp_repo("invalid-checksum");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        fs::write(
            receipts_dir.join("broken.toml"),
            "version = \"1\"\naction = \"push\"\nfingerprint = \"secret:abc123\"\nowner = \"yoav\"\nreason = \"temporary internal test override\"\ncreated_on = \"2026-04-01\"\nexpires_on = \"2099-04-30\"\nchecksum = \"wrong\"\n",
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0].detail.contains("checksum"));
    }

    #[test]
    fn rejects_expired_receipt() {
        let repo_root = make_temp_repo("expired-receipt");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        let draft = ReceiptDraft {
            receipt_id: "wr_expiredreceipt".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2020-01-01".to_string(),
            expires_on: "2020-02-01".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");

        fs::write(
            receipts_dir.join("expired.toml"),
            render_receipt_file(&draft, &checksum, None, None, None),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0].detail.contains("expired"));
    }

    #[test]
    fn rejects_duplicate_active_receipts_for_same_fingerprint() {
        let repo_root = make_temp_repo("duplicate-receipts");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

        let draft = ReceiptDraft {
            receipt_id: "wr_duplicatereceipt".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Dependency,
            fingerprint: "dependency:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");

        for name in ["one.toml", "two.toml"] {
            fs::write(
                receipts_dir.join(name),
                render_receipt_file(&draft, &checksum, None, None, None),
            )
            .expect("should write receipt");
        }

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 2);
    }

    #[test]
    fn requires_signed_receipt_fields_when_trust_store_exists() {
        let repo_root = make_temp_repo("signed-receipt-required");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy-public-key")
            .expect("should write trust key");
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2099-12-31\"\n",
        )
        .expect("should write trust metadata");

        let draft = ReceiptDraft {
            receipt_id: "wr_signedrequired".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");

        fs::write(
            receipts_dir.join("unsigned.toml"),
            render_receipt_file(&draft, &checksum, None, None, None),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0]
            .detail
            .contains("signed receipts are required"));
        assert_eq!(index.trusted_keys, 1);
        assert!(index.signed_receipts_required);
    }

    #[test]
    fn loads_valid_signed_receipt_when_trust_store_exists() {
        if !openssl_available() {
            return;
        }

        let repo_root = make_temp_repo("signed-receipt-valid");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&trust_dir).expect("should create trust dir");

        let private_key_path = repo_root.join("security-team-private.pem");
        let public_key_path = trust_dir.join("security-team.pem");
        generate_test_keypair(&private_key_path, &public_key_path);
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2099-12-31\"\n",
        )
        .expect("should write trust metadata");

        let draft = ReceiptDraft {
            receipt_id: "wr_signedvalid".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: Some("security-team".to_string()),
            reviewed_on: Some("2026-04-02".to_string()),
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        let payload = signed_receipt_payload(&draft, "security-team", "security-team", &checksum);
        let signature = sign_payload_with_private_key(&private_key_path, &payload)
            .expect("signature should be created");

        fs::write(
            receipts_dir.join("signed.toml"),
            render_receipt_file(
                &draft,
                &checksum,
                Some("security-team"),
                Some("security-team"),
                Some(&signature),
            ),
        )
        .expect("should write signed receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(index.active.len(), 1);
        assert!(index.issues.is_empty());
        assert_eq!(index.trusted_keys, 1);
        assert!(index.signed_receipts_required);
        assert_eq!(index.active[0].receipt_id, "wr_signedvalid");
        assert_eq!(index.active[0].reviewer.as_deref(), Some("security-team"));
        assert_eq!(index.active[0].reviewed_on.as_deref(), Some("2026-04-02"));
        assert_eq!(index.active[0].approver.as_deref(), Some("security-team"));
        assert_eq!(index.active[0].key_id.as_deref(), Some("security-team"));
    }

    #[test]
    fn rejects_signed_receipt_when_trusted_key_scope_does_not_allow_category() {
        if !openssl_available() {
            return;
        }

        let repo_root = make_temp_repo("signed-receipt-scope");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&trust_dir).expect("should create trust dir");

        let private_key_path = repo_root.join("security-team-private.pem");
        let public_key_path = trust_dir.join("security-team.pem");
        generate_test_keypair(&private_key_path, &public_key_path);
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2099-12-31\"\ncategories = [\"policy\"]\n",
        )
        .expect("should write trust metadata");

        let draft = ReceiptDraft {
            receipt_id: "wr_signedscope".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: Some("security-team".to_string()),
            reviewed_on: Some("2026-04-02".to_string()),
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        let payload = signed_receipt_payload(&draft, "security-team", "security-team", &checksum);
        let signature = sign_payload_with_private_key(&private_key_path, &payload)
            .expect("signature should be created");

        fs::write(
            receipts_dir.join("signed.toml"),
            render_receipt_file(
                &draft,
                &checksum,
                Some("security-team"),
                Some("security-team"),
                Some(&signature),
            ),
        )
        .expect("should write signed receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0]
            .detail
            .contains("not trusted for `secret` receipts"));
        assert_eq!(index.scoped_trusted_keys, 1);
        assert_eq!(index.unrestricted_trusted_keys, 0);
    }

    #[test]
    fn derives_legacy_receipt_id_when_field_is_missing() {
        let repo_root = make_temp_repo("legacy-receipt-id");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        let draft = ReceiptDraft {
            receipt_id: "wr_legacysource".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: false,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        let contents = format!(
            "version = \"1\"\naction = \"push\"\nfingerprint = \"secret:abc123\"\nowner = \"yoav\"\nreason = \"temporary internal test override\"\ncreated_on = \"2026-04-01\"\nexpires_on = \"2099-04-30\"\nchecksum = \"{checksum}\"\n"
        );
        fs::write(receipts_dir.join("legacy.toml"), &contents).expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(index.active.len(), 1);
        assert_eq!(
            index.active[0].receipt_id,
            legacy_receipt_id(ProtectedAction::Push, &contents)
        );
    }

    #[test]
    fn category_specific_policy_rejects_unapproved_secret_reviewer() {
        let repo_root = make_temp_repo("category-approval-policy");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "[categories.secret]\nrequire_reviewer_metadata = true\nallowed_reviewers = [\"security-team\"]\n",
        )
        .expect("should write policy");

        let draft = ReceiptDraft {
            receipt_id: "wr_secretreview".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: Some("repo-owner".to_string()),
            reviewed_on: Some("2026-04-02".to_string()),
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        fs::write(
            receipts_dir.join("allow-secret.toml"),
            render_receipt_file(&draft, &checksum, None, None, None),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0]
            .detail
            .contains("not allowed for `secret` receipts"));
    }

    #[test]
    fn policy_can_reject_legacy_categoryless_receipts() {
        let repo_root = make_temp_repo("require-explicit-category");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "require_explicit_category = true\n",
        )
        .expect("should write policy");

        let draft = ReceiptDraft {
            receipt_id: "wr_legacycategory".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: false,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        fs::write(
            receipts_dir.join("legacy.toml"),
            format!(
                "version = \"1\"\nreceipt_id = \"{}\"\naction = \"push\"\nfingerprint = \"{}\"\nowner = \"{}\"\nreason = \"{}\"\ncreated_on = \"{}\"\nexpires_on = \"{}\"\nchecksum = \"{}\"\n",
                draft.receipt_id,
                draft.fingerprint,
                draft.owner,
                draft.reason,
                draft.created_on,
                draft.expires_on,
                checksum,
            ),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0].detail.contains("explicit `category` field"));
    }

    #[test]
    fn category_specific_policy_rejects_unapproved_signing_key_id() {
        let repo_root = make_temp_repo("category-key-policy");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "[categories.secret]\nallowed_approvers = [\"security-team\"]\nallowed_key_ids = [\"security-team\"]\n",
        )
        .expect("should write policy");

        let draft = ReceiptDraft {
            receipt_id: "wr_secretkeyid".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: Some("security-team".to_string()),
            reviewed_on: Some("2026-04-02".to_string()),
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        fs::write(
            receipts_dir.join("allow-secret.toml"),
            render_receipt_file(
                &draft,
                &checksum,
                Some("security-team"),
                Some("staging-team"),
                Some("deadbeef"),
            ),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0]
            .detail
            .contains("signing key id `staging-team` is not allowed"));
    }

    #[test]
    fn category_policy_can_require_signed_receipts_without_global_trust_flip() {
        let repo_root = make_temp_repo("category-signed-requirement");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "[categories.secret]\nrequire_signed_receipts = true\n",
        )
        .expect("should write policy");

        let draft = ReceiptDraft {
            receipt_id: "wr_secretsigned".to_string(),
            action: ProtectedAction::Push,
            category: FindingCategory::Secret,
            fingerprint: "secret:abc123".to_string(),
            owner: "yoav".to_string(),
            reviewer: None,
            reviewed_on: None,
            reason: "temporary internal test override".to_string(),
            created_on: "2026-04-01".to_string(),
            expires_on: "2099-04-30".to_string(),
            category_bound: true,
        };
        let checksum = draft_checksum(&draft).expect("checksum should compute");
        fs::write(
            receipts_dir.join("allow-secret.toml"),
            render_receipt_file(&draft, &checksum, None, None, None),
        )
        .expect("should write receipt");

        let index = ReceiptIndex::load_for_repo(&repo_root).expect("load should succeed");
        assert!(index.active.is_empty());
        assert_eq!(index.issues.len(), 1);
        assert!(index.issues[0]
            .detail
            .contains("signed receipts are required"));
        assert!(index.signed_receipts_required);
        assert!(index.signed_receipts_required_by_policy);
        assert_eq!(index.trusted_keys, 0);
    }

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-receipts-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let path = env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("should create temp repo");
        path
    }

    fn openssl_available() -> bool {
        Command::new("openssl")
            .arg("version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn generate_test_keypair(private_key_path: &PathBuf, public_key_path: &PathBuf) {
        let private = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                private_key_path.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("private key generation should run");
        assert!(
            private.status.success(),
            "private key generation failed: {}",
            String::from_utf8_lossy(&private.stderr)
        );

        let public = Command::new("openssl")
            .args([
                "pkey",
                "-in",
                private_key_path.to_string_lossy().as_ref(),
                "-pubout",
                "-out",
                public_key_path.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("public key export should run");
        assert!(
            public.status.success(),
            "public key export failed: {}",
            String::from_utf8_lossy(&public.stderr)
        );
    }
}
