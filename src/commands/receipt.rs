//! `wolfence receipt ...`
//!
//! Signed override receipts are only useful if operators can generate them
//! deterministically. This command surface keeps receipt checksum generation and
//! signature creation inside Wolfence so teams do not have to reimplement the
//! canonical payload rules in shell scripts.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use crate::app::{AppError, AppResult};
use crate::cli::ReceiptCommand;
use crate::core::findings::FindingCategory;
use crate::core::git;
use crate::core::receipt_policy::{validate_signed_receipt_fields, ReceiptApprovalPolicy};
use crate::core::receipts::{
    draft_checksum, generate_receipt_id, load_receipt_draft, render_receipt_file,
    signed_receipt_payload, today_utc_date, ReceiptDraft, ReceiptIndex, RECEIPTS_DIR_RELATIVE_PATH,
};
use crate::core::trust::{sign_payload_with_private_key, TrustStore};

const RECEIPTS_ARCHIVE_DIR_RELATIVE_PATH: &str = ".wolfence/receipts/archive";

pub fn run(command: ReceiptCommand) -> AppResult<ExitCode> {
    match command {
        ReceiptCommand::List => run_list(),
        ReceiptCommand::New {
            receipt_path,
            action,
            category,
            fingerprint,
            owner,
            expires_on,
            reason,
        } => run_new(
            &receipt_path,
            &action,
            &category,
            &fingerprint,
            &owner,
            &expires_on,
            &reason,
        ),
        ReceiptCommand::Checksum { receipt_path } => run_checksum(&receipt_path),
        ReceiptCommand::Verify { receipt_path } => run_verify(&receipt_path),
        ReceiptCommand::Archive {
            receipt_path,
            reason,
        } => run_archive(&receipt_path, &reason),
        ReceiptCommand::Sign {
            receipt_path,
            approver,
            key_id,
            private_key_path,
        } => run_sign(&receipt_path, &approver, &key_id, &private_key_path),
        ReceiptCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_list() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let receipts = ReceiptIndex::load_for_repo(&repo_root)?;
    let archived = list_archived_receipts(&repo_root)?;

    println!("Wolfence receipt list");
    println!("  repo root: {}", repo_root.display());
    println!(
        "  summary: {} active, {} ignored, {} archived",
        receipts.active.len(),
        receipts.issues.len(),
        archived.len()
    );

    if receipts.active.is_empty() {
        println!("  active: none");
    } else {
        println!("  active:");
        let mut active = receipts.active.clone();
        active.sort_by(|left, right| left.path.cmp(&right.path));
        for receipt in active {
            println!("    - {}", display_repo_relative(&repo_root, &receipt.path));
            println!("      receipt_id: {}", receipt.receipt_id);
            println!("      action: {}", receipt.action);
            println!("      category: {}", receipt.category);
            println!(
                "      format: {}",
                if receipt.category_bound {
                    "category-bound"
                } else {
                    "legacy"
                }
            );
            println!("      fingerprint: {}", receipt.fingerprint);
            if let Some(reviewer) = &receipt.reviewer {
                println!(
                    "      reviewer: {} ({})",
                    reviewer,
                    receipt.reviewed_on.as_deref().unwrap_or("unknown")
                );
            }
            println!("      expires_on: {}", receipt.expires_on);
        }
    }

    if receipts.issues.is_empty() {
        println!("  ignored: none");
    } else {
        println!("  ignored:");
        let mut issues = receipts.issues.clone();
        issues.sort_by(|left, right| left.path.cmp(&right.path));
        for issue in issues {
            println!("    - {}", display_repo_relative(&repo_root, &issue.path));
            println!("      detail: {}", issue.detail);
        }
    }

    if archived.is_empty() {
        println!("  archived: none");
    } else {
        println!("  archived:");
        for path in archived {
            println!("    - {}", display_repo_relative(&repo_root, &path));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn run_new(
    receipt_path: &str,
    action: &str,
    category: &str,
    fingerprint: &str,
    owner: &str,
    expires_on: &str,
    reason: &str,
) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let receipt_path = resolve_new_receipt_path(&repo_root, receipt_path)?;
    let action = parse_receipt_action(action)?;
    let category = parse_receipt_category(category)?;
    let created_on = today_utc_date();
    let mut draft = ReceiptDraft {
        receipt_id: String::new(),
        action,
        category,
        fingerprint: fingerprint.trim().to_string(),
        owner: owner.trim().to_string(),
        reviewer: None,
        reviewed_on: None,
        reason: reason.trim().to_string(),
        created_on,
        expires_on: expires_on.trim().to_string(),
        category_bound: true,
    };
    draft.receipt_id = generate_receipt_id(&draft)?;
    validate_new_draft(&draft)?;
    let checksum = draft_checksum(&draft)?;
    let rendered = render_receipt_file(&draft, &checksum, None, None, None);

    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&receipt_path, rendered)?;

    println!("Wolfence receipt new");
    println!("  repo root: {}", repo_root.display());
    println!("  receipt: {}", receipt_path.display());
    println!("  receipt_id: {}", draft.receipt_id);
    println!("  action: {}", draft.action);
    println!("  category: {}", draft.category);
    println!("  fingerprint: {}", draft.fingerprint);
    println!("  owner: {}", draft.owner);
    println!("  created_on: {}", draft.created_on);
    println!("  expires_on: {}", draft.expires_on);
    println!("  checksum: {checksum}");
    println!("  result: canonical unsigned receipt draft created");

    Ok(ExitCode::SUCCESS)
}

fn run_checksum(receipt_path: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let receipt_path = resolve_receipt_path(&repo_root, receipt_path)?;
    let draft = load_receipt_draft(&receipt_path)?;
    let checksum = draft_checksum(&draft)?;

    println!("Wolfence receipt checksum");
    println!("  repo root: {}", repo_root.display());
    println!("  receipt: {}", receipt_path.display());
    println!("  receipt_id: {}", draft.receipt_id);
    println!("  action: {}", draft.action);
    println!("  category: {}", draft.category);
    println!("  fingerprint: {}", draft.fingerprint);
    println!("  checksum: {checksum}");

    Ok(ExitCode::SUCCESS)
}

fn run_verify(receipt_path: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let receipt_path = resolve_receipt_path(&repo_root, receipt_path)?;
    let receipts = ReceiptIndex::load_for_repo(&repo_root)?;

    if let Some(receipt) = receipts
        .active
        .iter()
        .find(|receipt| receipt.path == receipt_path)
    {
        println!("Wolfence receipt verify");
        println!("  repo root: {}", repo_root.display());
        println!("  receipt: {}", receipt.path.display());
        println!("  receipt_id: {}", receipt.receipt_id);
        println!("  status: active");
        println!("  action: {}", receipt.action);
        println!("  category: {}", receipt.category);
        println!(
            "  format: {}",
            if receipt.category_bound {
                "category-bound"
            } else {
                "legacy"
            }
        );
        println!("  fingerprint: {}", receipt.fingerprint);
        println!("  owner: {}", receipt.owner);
        if let Some(reviewer) = &receipt.reviewer {
            println!("  reviewer: {reviewer}");
        }
        if let Some(reviewed_on) = &receipt.reviewed_on {
            println!("  reviewed_on: {reviewed_on}");
        }
        if let Some(approver) = &receipt.approver {
            println!("  approver: {approver}");
        }
        if let Some(key_id) = &receipt.key_id {
            println!("  key_id: {key_id}");
            println!("  trust: signed receipt verified against repo trust material");
        } else {
            println!("  trust: unsigned receipt accepted because no trusted keys are required");
        }
        println!("  expires_on: {}", receipt.expires_on);
        println!("  result: receipt is currently valid");
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(issue) = receipts
        .issues
        .iter()
        .find(|issue| issue.path == receipt_path)
    {
        println!("Wolfence receipt verify");
        println!("  repo root: {}", repo_root.display());
        println!("  receipt: {}", issue.path.display());
        println!("  status: ignored");
        println!("  detail: {}", issue.detail);
        println!("  remediation: {}", issue.remediation);
        println!("  result: receipt is not currently valid");
        return Ok(ExitCode::FAILURE);
    }

    Err(AppError::Config(format!(
        "receipt file `{}` was not found in the current repo receipt index.",
        receipt_path.display()
    )))
}

fn run_archive(receipt_path: &str, reason: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let receipt_path = resolve_receipt_path(&repo_root, receipt_path)?;
    let archive_reason = reason.trim();
    if archive_reason.is_empty() {
        return Err(AppError::Config(
            "archive reason cannot be empty.".to_string(),
        ));
    }

    let archived_on = today_utc_date();
    let archive_path = build_archive_path(&repo_root, &receipt_path, &archived_on)?;
    if let Some(parent) = archive_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let original_contents = fs::read_to_string(&receipt_path)?;
    let archived_contents = format!(
        "# archived_on = \"{archived_on}\"\n# archived_reason = \"{}\"\n# archived_from = \"{}\"\n\n{}",
        escape_comment_value(archive_reason),
        receipt_path
            .strip_prefix(&repo_root)
            .unwrap_or(receipt_path.as_path())
            .display(),
        original_contents
    );
    fs::write(&archive_path, archived_contents)?;
    fs::remove_file(&receipt_path)?;

    println!("Wolfence receipt archive");
    println!("  repo root: {}", repo_root.display());
    println!("  archived_on: {archived_on}");
    println!("  receipt: {}", receipt_path.display());
    println!("  archive: {}", archive_path.display());
    println!("  reason: {archive_reason}");
    println!("  result: receipt moved out of active enforcement scope");

    Ok(ExitCode::SUCCESS)
}

fn run_sign(
    receipt_path: &str,
    approver: &str,
    key_id: &str,
    private_key_path: &str,
) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust = TrustStore::load_for_repo(&repo_root)?;
    if trust.key_count() == 0 {
        let detail = if trust.published_key_count() > 0 {
            "signed receipt creation requires at least one active trusted public key under `.wolfence/trust/`; current published keys are expired or missing required metadata.".to_string()
        } else {
            "signed receipt creation requires at least one trusted public key under `.wolfence/trust/`.".to_string()
        };
        return Err(AppError::Config(detail));
    }

    let Some(public_key_path) = trust.key_path(key_id) else {
        let detail = if trust.has_key_id(key_id) {
            format!(
                "trusted key id `{key_id}` exists under `.wolfence/trust/`, but it is inactive because it is expired or missing required metadata."
            )
        } else {
            format!("trusted key id `{key_id}` was not found under `.wolfence/trust/`.")
        };
        return Err(AppError::Config(detail));
    };

    let receipt_path = resolve_receipt_path(&repo_root, receipt_path)?;
    let draft = load_receipt_draft(&receipt_path)?;
    let approval_policy = ReceiptApprovalPolicy::load_for_repo(&repo_root)?;
    let reviewed_on = today_utc_date();
    let reviewer = approver.trim().to_string();
    let signed_draft = ReceiptDraft {
        category_bound: true,
        reviewer: Some(reviewer.clone()),
        reviewed_on: Some(reviewed_on.clone()),
        ..draft.clone()
    };
    let effective_policy = approval_policy.effective_for(signed_draft.category);
    validate_signed_receipt_fields(
        &effective_policy,
        signed_draft.category,
        &reviewer,
        approver,
        key_id,
    )
    .map_err(AppError::Config)?;
    if !trust.key_allows_category(key_id, signed_draft.category) {
        return Err(AppError::Config(format!(
            "trusted key id `{key_id}` is active, but it is not trusted for `{}` receipts.",
            signed_draft.category
        )));
    }
    let checksum = draft_checksum(&signed_draft)?;
    let payload = signed_receipt_payload(&signed_draft, approver, key_id, &checksum);
    let private_key_path = PathBuf::from(private_key_path);
    let signature = sign_payload_with_private_key(&private_key_path, &payload)?;

    if !trust.verify_receipt_signature(key_id, &payload, &signature)? {
        return Err(AppError::Config(format!(
            "the provided private key did not produce a signature that matches trusted public key `{}`.",
            public_key_path.display()
        )));
    }

    let rendered = render_receipt_file(
        &signed_draft,
        &checksum,
        Some(approver),
        Some(key_id),
        Some(&signature),
    );
    fs::write(&receipt_path, rendered)?;

    println!("Wolfence receipt sign");
    println!("  repo root: {}", repo_root.display());
    println!("  receipt: {}", receipt_path.display());
    println!("  receipt_id: {}", signed_draft.receipt_id);
    println!("  category: {}", signed_draft.category);
    println!("  trusted key: {}", public_key_path.display());
    println!("  reviewer: {}", reviewer);
    println!("  reviewed_on: {}", reviewed_on);
    println!("  approver: {approver}");
    println!("  key_id: {key_id}");
    println!("  checksum: {checksum}");
    println!("  signature: wrote detached hex signature into the receipt file");
    println!("  result: receipt updated in place");

    Ok(ExitCode::SUCCESS)
}

fn resolve_receipt_path(repo_root: &Path, input: &str) -> AppResult<PathBuf> {
    let candidate = PathBuf::from(input);
    let receipt_path = if candidate.is_absolute() {
        candidate
    } else {
        repo_root.join(candidate)
    };

    if !receipt_path.exists() {
        return Err(AppError::Config(format!(
            "receipt file `{}` does not exist.",
            receipt_path.display()
        )));
    }

    let canonical_receipt_path = fs::canonicalize(&receipt_path)?;
    let canonical_receipts_root = fs::canonicalize(repo_root.join(RECEIPTS_DIR_RELATIVE_PATH))?;
    if !canonical_receipt_path.starts_with(&canonical_receipts_root) {
        return Err(AppError::Config(format!(
            "receipt workflows only operate on files under `{}`.",
            canonical_receipts_root.display()
        )));
    }

    Ok(canonical_receipt_path)
}

fn resolve_new_receipt_path(repo_root: &Path, input: &str) -> AppResult<PathBuf> {
    let candidate = PathBuf::from(input);
    if candidate.is_absolute() {
        return Err(AppError::Config(
            "new receipt paths must be repo-relative under `.wolfence/receipts/`.".to_string(),
        ));
    }

    if candidate.extension().and_then(|value| value.to_str()) != Some("toml") {
        return Err(AppError::Config(
            "new receipt files must use the `.toml` extension.".to_string(),
        ));
    }

    let canonical_repo_root = fs::canonicalize(repo_root)?;
    let receipts_root = canonical_repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
    let normalized_receipt_path = normalize_relative_path(&canonical_repo_root, &candidate)?;

    if !normalized_receipt_path.starts_with(&receipts_root) {
        return Err(AppError::Config(format!(
            "new receipts must live under `{}`.",
            receipts_root.display()
        )));
    }

    if normalized_receipt_path.exists() {
        return Err(AppError::Config(format!(
            "receipt file `{}` already exists.",
            normalized_receipt_path.display()
        )));
    }

    Ok(normalized_receipt_path)
}

fn build_archive_path(
    repo_root: &Path,
    receipt_path: &Path,
    archived_on: &str,
) -> AppResult<PathBuf> {
    let canonical_repo_root = fs::canonicalize(repo_root)?;
    let archive_root = canonical_repo_root.join(RECEIPTS_ARCHIVE_DIR_RELATIVE_PATH);
    let canonical_receipt_path = fs::canonicalize(receipt_path)?;

    if canonical_receipt_path.starts_with(&archive_root) {
        return Err(AppError::Config(format!(
            "receipt `{}` is already archived.",
            canonical_receipt_path.display()
        )));
    }

    let file_name = canonical_receipt_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::Config("receipt file name must be valid UTF-8.".to_string()))?;

    let mut candidate = archive_root.join(format!("{archived_on}-{file_name}"));
    let mut suffix = 1usize;
    while candidate.exists() {
        candidate = archive_root.join(format!("{archived_on}-{suffix}-{file_name}"));
        suffix += 1;
    }

    Ok(candidate)
}

fn list_archived_receipts(repo_root: &Path) -> AppResult<Vec<PathBuf>> {
    let archive_root = repo_root.join(RECEIPTS_ARCHIVE_DIR_RELATIVE_PATH);
    if !archive_root.exists() {
        return Ok(Vec::new());
    }

    let mut archived = Vec::new();
    for entry in fs::read_dir(&archive_root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|value| value.to_str()) == Some("toml") {
            archived.push(fs::canonicalize(path)?);
        }
    }

    archived.sort();
    Ok(archived)
}

fn display_repo_relative<'a>(repo_root: &Path, path: &'a Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn normalize_relative_path(base: &Path, relative: &Path) -> AppResult<PathBuf> {
    let mut normalized = PathBuf::from(base);

    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(AppError::Config(
                        "receipt path escapes the repository root.".to_string(),
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::Config(
                    "receipt paths must be relative repository paths.".to_string(),
                ))
            }
        }
    }

    Ok(normalized)
}

fn parse_receipt_action(value: &str) -> AppResult<crate::core::context::ProtectedAction> {
    match value.trim() {
        "push" => Ok(crate::core::context::ProtectedAction::Push),
        "scan" => Ok(crate::core::context::ProtectedAction::Scan),
        other => Err(AppError::Config(format!(
            "unsupported receipt action `{other}`. Use `push` or `scan`."
        ))),
    }
}

fn parse_receipt_category(value: &str) -> AppResult<FindingCategory> {
    FindingCategory::parse(value.trim()).map_err(|message| {
        AppError::Config(format!(
            "unsupported receipt category `{}`. {message}.",
            value.trim()
        ))
    })
}

fn validate_new_draft(draft: &ReceiptDraft) -> AppResult<()> {
    if draft.fingerprint.is_empty() {
        return Err(AppError::Config(
            "receipt fingerprint cannot be empty.".to_string(),
        ));
    }

    if draft.owner.is_empty() {
        return Err(AppError::Config(
            "receipt owner cannot be empty.".to_string(),
        ));
    }

    if draft.reason.is_empty() {
        return Err(AppError::Config(
            "receipt reason cannot be empty.".to_string(),
        ));
    }

    if !is_iso_date(&draft.expires_on) {
        return Err(AppError::Config(
            "receipt expiry must use ISO format `YYYY-MM-DD`.".to_string(),
        ));
    }

    if draft.expires_on < draft.created_on {
        return Err(AppError::Config(
            "receipt expiry cannot be earlier than the creation date.".to_string(),
        ));
    }

    Ok(())
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

fn escape_comment_value(value: &str) -> String {
    value
        .replace('\n', " ")
        .replace('\r', " ")
        .trim()
        .to_string()
}

fn print_help() {
    println!("Wolfence receipt workflows");
    println!("  list");
    println!("      Show active, ignored, and archived receipts for the current repository");
    println!(
        "  new <receipt-path> <action> <category> <fingerprint> <owner> <expires-on> <reason>"
    );
    println!("      Create one canonical unsigned receipt draft inside .wolfence/receipts/");
    println!("      categories: secret | vulnerability | dependency | configuration | policy");
    println!("  checksum <receipt-path>");
    println!("      Compute the canonical checksum for one receipt file");
    println!("  verify <receipt-path>");
    println!("      Evaluate one receipt against the current repo trust model and report whether it is active or ignored");
    println!("  archive <receipt-path> <reason>");
    println!("      Move one receipt into .wolfence/receipts/archive/ so it no longer affects enforcement but stays reviewable");
    println!("  sign <receipt-path> <approver> <key-id> <private-key-path>");
    println!("      Recompute the checksum, sign the canonical payload, verify it against the trusted public key, and update the receipt in place");
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_archive_path, list_archived_receipts, resolve_new_receipt_path, resolve_receipt_path,
        RECEIPTS_ARCHIVE_DIR_RELATIVE_PATH,
    };
    use crate::core::receipts::RECEIPTS_DIR_RELATIVE_PATH;

    #[test]
    fn rejects_paths_outside_receipts_directory() {
        let repo_root = make_temp_repo("path-scope");
        fs::create_dir_all(repo_root.join(RECEIPTS_DIR_RELATIVE_PATH))
            .expect("should create receipts dir");
        fs::write(repo_root.join("other.toml"), "version = \"1\"\n").expect("should write file");

        let error = resolve_receipt_path(&repo_root, "other.toml").expect_err("path should fail");
        assert!(error.to_string().contains("only operate on files under"));
    }

    #[test]
    fn accepts_existing_paths_inside_receipts_directory() {
        let repo_root = make_temp_repo("path-accept");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        let receipt_path = receipts_dir.join("allow.toml");
        fs::write(&receipt_path, "version = \"1\"\n").expect("should write receipt");

        let resolved =
            resolve_receipt_path(&repo_root, ".wolfence/receipts/allow.toml").expect("valid path");
        assert_eq!(
            resolved,
            fs::canonicalize(receipt_path).expect("receipt path should canonicalize")
        );
    }

    #[test]
    fn new_receipt_path_must_stay_under_receipts_directory() {
        let repo_root = make_temp_repo("new-path-scope");
        let error = resolve_new_receipt_path(&repo_root, ".wolfence/outside.toml")
            .expect_err("path should fail");
        assert!(error.to_string().contains("must live under"));
    }

    #[test]
    fn accepts_new_relative_receipt_path_inside_receipts_directory() {
        let repo_root = make_temp_repo("new-path-accept");
        let resolved = resolve_new_receipt_path(&repo_root, ".wolfence/receipts/team/allow.toml")
            .expect("path should be accepted");
        assert!(
            resolved.ends_with(".wolfence/receipts/team/allow.toml"),
            "resolved path should stay under receipts directory"
        );
    }

    #[test]
    fn builds_archive_path_under_archive_directory() {
        let repo_root = make_temp_repo("archive-path");
        let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
        fs::create_dir_all(&receipts_dir).expect("should create receipts dir");
        let receipt_path = receipts_dir.join("allow.toml");
        fs::write(&receipt_path, "version = \"1\"\n").expect("should write receipt");

        let archive_path =
            build_archive_path(&repo_root, &receipt_path, "2026-04-09").expect("archive path");
        assert!(
            archive_path.ends_with(".wolfence/receipts/archive/2026-04-09-allow.toml"),
            "archive path should move into archive directory"
        );
    }

    #[test]
    fn lists_archived_receipts_sorted() {
        let repo_root = make_temp_repo("archive-list");
        let archive_dir = repo_root.join(RECEIPTS_ARCHIVE_DIR_RELATIVE_PATH);
        fs::create_dir_all(&archive_dir).expect("should create archive dir");
        fs::write(archive_dir.join("2026-04-09-b.toml"), "version = \"1\"\n")
            .expect("should write archive receipt");
        fs::write(archive_dir.join("2026-04-09-a.toml"), "version = \"1\"\n")
            .expect("should write archive receipt");

        let archived = list_archived_receipts(&repo_root).expect("listing should succeed");
        assert_eq!(archived.len(), 2);
        assert!(archived[0].ends_with("2026-04-09-a.toml"));
        assert!(archived[1].ends_with("2026-04-09-b.toml"));
    }

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-receipt-command-{name}-{}-{}",
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
}
