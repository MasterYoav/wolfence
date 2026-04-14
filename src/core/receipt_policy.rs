//! Repository-local receipt approval policy.
//!
//! Receipts are only trustworthy if the repository can constrain who is
//! allowed to review and approve them. This module loads a small repo-local
//! policy file that sets lifetime bounds and reviewer/approver allowlists for
//! override receipts.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::app::{AppError, AppResult};
use crate::core::findings::FindingCategory;

pub const RECEIPT_POLICY_DIR_RELATIVE_PATH: &str = ".wolfence/policy";
pub const RECEIPT_POLICY_FILE_RELATIVE_PATH: &str = ".wolfence/policy/receipts.toml";

#[derive(Debug, Clone, Default)]
pub struct ReceiptApprovalPolicy {
    pub exists: bool,
    pub require_explicit_category: bool,
    pub require_signed_receipts: bool,
    pub max_lifetime_days: Option<u32>,
    pub require_reviewer_metadata: bool,
    pub allowed_reviewers: Vec<String>,
    pub allowed_approvers: Vec<String>,
    pub allowed_key_ids: Vec<String>,
    pub category_rules: HashMap<FindingCategory, CategoryReceiptPolicy>,
}

#[derive(Debug, Clone, Default)]
pub struct CategoryReceiptPolicy {
    pub require_signed_receipts: Option<bool>,
    pub max_lifetime_days: Option<u32>,
    pub require_reviewer_metadata: Option<bool>,
    pub allowed_reviewers: Option<Vec<String>>,
    pub allowed_approvers: Option<Vec<String>>,
    pub allowed_key_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct EffectiveReceiptPolicy {
    pub require_signed_receipts: bool,
    pub max_lifetime_days: Option<u32>,
    pub require_reviewer_metadata: bool,
    pub allowed_reviewers: Vec<String>,
    pub allowed_approvers: Vec<String>,
    pub allowed_key_ids: Vec<String>,
}

impl ReceiptApprovalPolicy {
    pub fn load_for_repo(repo_root: &Path) -> AppResult<Self> {
        let path = repo_root.join(RECEIPT_POLICY_FILE_RELATIVE_PATH);
        if !path.exists() {
            return Ok(Self {
                exists: false,
                ..Self::default()
            });
        }

        let contents = fs::read_to_string(&path)?;
        let mut policy = Self {
            exists: true,
            ..Self::default()
        };

        let mut current_category = None;

        for raw_line in contents.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') {
                current_category = parse_category_section(line).map_err(|message| {
                    AppError::Config(format!(
                        "invalid category section in {}: {message}",
                        RECEIPT_POLICY_FILE_RELATIVE_PATH
                    ))
                })?;
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            if let Some(category) = current_category {
                let entry = policy.category_rules.entry(category).or_default();
                match key {
                    "require_signed_receipts" => {
                        entry.require_signed_receipts =
                            Some(parse_bool(value).map_err(|message| {
                                AppError::Config(format!(
                                    "invalid `{key}` in {}: {message}",
                                    RECEIPT_POLICY_FILE_RELATIVE_PATH
                                ))
                            })?);
                    }
                    "max_lifetime_days" => {
                        let parsed = value.parse::<u32>().map_err(|error| {
                            AppError::Config(format!(
                                "invalid `{key}` in {}: {error}",
                                RECEIPT_POLICY_FILE_RELATIVE_PATH
                            ))
                        })?;
                        entry.max_lifetime_days = Some(parsed);
                    }
                    "require_reviewer_metadata" => {
                        entry.require_reviewer_metadata =
                            Some(parse_bool(value).map_err(|message| {
                                AppError::Config(format!(
                                    "invalid `{key}` in {}: {message}",
                                    RECEIPT_POLICY_FILE_RELATIVE_PATH
                                ))
                            })?);
                    }
                    "allowed_reviewers" => {
                        entry.allowed_reviewers =
                            Some(parse_string_list(value).map_err(|message| {
                                AppError::Config(format!(
                                    "invalid `{key}` in {}: {message}",
                                    RECEIPT_POLICY_FILE_RELATIVE_PATH
                                ))
                            })?);
                    }
                    "allowed_approvers" => {
                        entry.allowed_approvers =
                            Some(parse_string_list(value).map_err(|message| {
                                AppError::Config(format!(
                                    "invalid `{key}` in {}: {message}",
                                    RECEIPT_POLICY_FILE_RELATIVE_PATH
                                ))
                            })?);
                    }
                    "allowed_key_ids" => {
                        entry.allowed_key_ids =
                            Some(parse_string_list(value).map_err(|message| {
                                AppError::Config(format!(
                                    "invalid `{key}` in {}: {message}",
                                    RECEIPT_POLICY_FILE_RELATIVE_PATH
                                ))
                            })?);
                    }
                    _ => {}
                }
                continue;
            }

            match key {
                "max_lifetime_days" => {
                    let parsed = value.parse::<u32>().map_err(|error| {
                        AppError::Config(format!(
                            "invalid `max_lifetime_days` in {}: {error}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                    policy.max_lifetime_days = Some(parsed);
                }
                "require_explicit_category" => {
                    policy.require_explicit_category = parse_bool(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `require_explicit_category` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                "require_signed_receipts" => {
                    policy.require_signed_receipts = parse_bool(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `require_signed_receipts` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                "require_reviewer_metadata" => {
                    policy.require_reviewer_metadata = parse_bool(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `require_reviewer_metadata` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                "allowed_reviewers" => {
                    policy.allowed_reviewers = parse_string_list(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `allowed_reviewers` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                "allowed_approvers" => {
                    policy.allowed_approvers = parse_string_list(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `allowed_approvers` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                "allowed_key_ids" => {
                    policy.allowed_key_ids = parse_string_list(value).map_err(|message| {
                        AppError::Config(format!(
                            "invalid `allowed_key_ids` in {}: {message}",
                            RECEIPT_POLICY_FILE_RELATIVE_PATH
                        ))
                    })?;
                }
                _ => {}
            }
        }

        Ok(policy)
    }

    pub fn effective_for(&self, category: FindingCategory) -> EffectiveReceiptPolicy {
        let category_rule = self.category_rules.get(&category);
        EffectiveReceiptPolicy {
            require_signed_receipts: category_rule
                .and_then(|rule| rule.require_signed_receipts)
                .unwrap_or(self.require_signed_receipts),
            max_lifetime_days: category_rule
                .and_then(|rule| rule.max_lifetime_days)
                .or(self.max_lifetime_days),
            require_reviewer_metadata: category_rule
                .and_then(|rule| rule.require_reviewer_metadata)
                .unwrap_or(self.require_reviewer_metadata),
            allowed_reviewers: category_rule
                .and_then(|rule| rule.allowed_reviewers.clone())
                .unwrap_or_else(|| self.allowed_reviewers.clone()),
            allowed_approvers: category_rule
                .and_then(|rule| rule.allowed_approvers.clone())
                .unwrap_or_else(|| self.allowed_approvers.clone()),
            allowed_key_ids: category_rule
                .and_then(|rule| rule.allowed_key_ids.clone())
                .unwrap_or_else(|| self.allowed_key_ids.clone()),
        }
    }

    pub fn any_signed_receipt_requirement(&self) -> bool {
        self.require_signed_receipts
            || self
                .category_rules
                .values()
                .any(|rule| rule.require_signed_receipts == Some(true))
    }
}

pub fn validate_signed_receipt_fields(
    policy: &EffectiveReceiptPolicy,
    category: FindingCategory,
    reviewer: &str,
    approver: &str,
    key_id: &str,
) -> Result<(), String> {
    if policy.require_reviewer_metadata && reviewer.trim().is_empty() {
        return Err(
            "receipt approval policy requires reviewer metadata before signing.".to_string(),
        );
    }

    if !policy.allowed_reviewers.is_empty()
        && !policy
            .allowed_reviewers
            .iter()
            .any(|value| value == reviewer)
    {
        return Err(format!(
            "receipt reviewer `{reviewer}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
        ));
    }

    if !policy.allowed_approvers.is_empty()
        && !policy
            .allowed_approvers
            .iter()
            .any(|value| value == approver)
    {
        return Err(format!(
            "receipt approver `{approver}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
        ));
    }

    if !policy.allowed_key_ids.is_empty()
        && !policy.allowed_key_ids.iter().any(|value| value == key_id)
    {
        return Err(format!(
            "receipt signing key id `{key_id}` is not allowed for `{category}` receipts by `.wolfence/policy/receipts.toml`."
        ));
    }

    Ok(())
}

pub fn default_receipt_policy() -> &'static str {
    r#"# Wolfence receipt approval policy
#
# This file constrains who can review or approve override receipts and how
# long they may stay active.
#
# Recommended production starting posture:
# - set `require_explicit_category = true`
# - set `require_reviewer_metadata = true`
# - set `max_lifetime_days` to a small number such as 7
# - require signed receipts for high-risk categories like `secret` and `policy`

# Maximum number of days between `created_on` and `expires_on`.
# max_lifetime_days = 14

# Require every active receipt to declare an explicit `category` field instead
# of relying on legacy fingerprint-prefix inference.
require_explicit_category = false

# Require signed receipts for all categories, even if the repo has not yet
# adopted a global trust-store-driven signed posture.
require_signed_receipts = false

# Require `reviewer` and `reviewed_on` on every active receipt.
require_reviewer_metadata = false

# Restrict who may review receipts.
allowed_reviewers = []

# Restrict who may appear as the signing approver on signed receipts.
allowed_approvers = []

# Restrict which trusted key ids may sign receipts.
allowed_key_ids = []

# Optional category-specific overrides. These replace the global allowlists for
# the category they target, so use them when high-risk findings need tighter
# governance than the repo-wide default.
#
# [categories.secret]
# require_signed_receipts = true
# require_reviewer_metadata = true
# max_lifetime_days = 7
# allowed_reviewers = ["security-team"]
# allowed_approvers = ["security-team"]
# allowed_key_ids = ["security-team"]
"#
}

fn parse_category_section(line: &str) -> Result<Option<FindingCategory>, String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err("section headers must be wrapped in `[` and `]`.".to_string());
    }

    let name = &trimmed[1..trimmed.len() - 1];
    if name.is_empty() {
        return Ok(None);
    }
    if let Some(category) = name.strip_prefix("categories.") {
        let parsed = FindingCategory::parse(category).map_err(|message| message.to_string())?;
        return Ok(Some(parsed));
    }

    Err(format!(
        "unsupported section `{name}`; only `[categories.<name>]` is allowed."
    ))
}

fn parse_bool(value: &str) -> Result<bool, &'static str> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("expected true or false"),
    }
}

fn parse_string_list(value: &str) -> Result<Vec<String>, &'static str> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err("expected a TOML-style string array");
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    for part in inner.split(',') {
        let normalized = part.trim().trim_matches('"').trim();
        if normalized.is_empty() {
            return Err("string array entries must not be empty");
        }
        values.push(normalized.to_string());
    }
    Ok(values)
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

#[cfg(test)]
mod tests {
    use super::{validate_signed_receipt_fields, ReceiptApprovalPolicy};
    use crate::core::findings::FindingCategory;
    use std::env;
    use std::fs;

    #[test]
    fn loads_receipt_approval_policy() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-receipt-policy-{}", std::process::id()));
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "require_signed_receipts = true\nmax_lifetime_days = 7\nrequire_reviewer_metadata = true\nallowed_reviewers = [\"security-team\"]\nallowed_approvers = [\"security-team\"]\nallowed_key_ids = [\"security-team\"]\n",
        )
        .expect("should write policy");

        let policy = ReceiptApprovalPolicy::load_for_repo(&repo_root).expect("load should work");
        assert!(policy.exists);
        assert!(!policy.require_explicit_category);
        assert!(policy.require_signed_receipts);
        assert_eq!(policy.max_lifetime_days, Some(7));
        assert!(policy.require_reviewer_metadata);
        assert_eq!(policy.allowed_reviewers, vec!["security-team"]);
        assert_eq!(policy.allowed_approvers, vec!["security-team"]);
        assert_eq!(policy.allowed_key_ids, vec!["security-team"]);
    }

    #[test]
    fn loads_category_specific_receipt_policy_overrides() {
        let repo_root = env::temp_dir().join(format!(
            "wolfence-receipt-category-policy-{}",
            std::process::id()
        ));
        let policy_dir = repo_root.join(".wolfence/policy");
        fs::create_dir_all(&policy_dir).expect("should create policy dir");
        fs::write(
            policy_dir.join("receipts.toml"),
            "require_explicit_category = true\nrequire_reviewer_metadata = false\nallowed_reviewers = [\"repo-owner\"]\nallowed_key_ids = [\"repo-owner-key\"]\n\n[categories.secret]\nrequire_signed_receipts = true\nrequire_reviewer_metadata = true\nallowed_reviewers = [\"security-team\"]\nallowed_approvers = [\"security-team\"]\nallowed_key_ids = [\"security-team\"]\n",
        )
        .expect("should write policy");

        let policy = ReceiptApprovalPolicy::load_for_repo(&repo_root).expect("load should work");
        assert!(policy.require_explicit_category);
        let secret = policy.effective_for(FindingCategory::Secret);
        let dependency = policy.effective_for(FindingCategory::Dependency);

        assert!(secret.require_signed_receipts);
        assert!(secret.require_reviewer_metadata);
        assert_eq!(secret.allowed_reviewers, vec!["security-team"]);
        assert_eq!(secret.allowed_approvers, vec!["security-team"]);
        assert_eq!(secret.allowed_key_ids, vec!["security-team"]);
        assert!(!dependency.require_signed_receipts);
        assert!(!dependency.require_reviewer_metadata);
        assert_eq!(dependency.allowed_reviewers, vec!["repo-owner"]);
        assert_eq!(dependency.allowed_key_ids, vec!["repo-owner-key"]);
        assert!(dependency.allowed_approvers.is_empty());
        assert!(policy.any_signed_receipt_requirement());
    }

    #[test]
    fn signed_receipt_validation_rejects_unapproved_key_id() {
        let policy = ReceiptApprovalPolicy {
            allowed_key_ids: vec!["security-team".to_string()],
            ..ReceiptApprovalPolicy::default()
        }
        .effective_for(FindingCategory::Secret);

        let error = validate_signed_receipt_fields(
            &policy,
            FindingCategory::Secret,
            "security-team",
            "security-team",
            "staging-team",
        )
        .expect_err("validation should fail");

        assert!(error.contains("signing key id `staging-team` is not allowed"));
    }
}
