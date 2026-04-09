//! `wolf trust ...`
//!
//! Trust material should be reviewable and operationally legible. This command
//! surface lets operators inspect repo-local trust keys and create the metadata
//! files that make a published key active.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::app::{AppError, AppResult};
use crate::cli::TrustCommand;
use crate::core::findings::FindingCategory;
use crate::core::git;
use crate::core::trust::{TrustStore, TrustedKeyStatus, TRUST_DIR_RELATIVE_PATH};

const TRUST_ARCHIVE_DIR_RELATIVE_PATH: &str = ".wolfence/trust/archive";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArchivedTrustEntry {
    note_path: PathBuf,
    key_id: String,
    archived_on: String,
    reason: String,
    public_key: String,
    metadata: String,
    restored_on: Option<String>,
    restored_to: Option<String>,
}

pub fn run(command: TrustCommand) -> AppResult<ExitCode> {
    match command {
        TrustCommand::List => run_list(),
        TrustCommand::Verify { key_id } => run_verify(&key_id),
        TrustCommand::Init {
            key_id,
            owner,
            expires_on,
            categories,
        } => run_init(&key_id, &owner, &expires_on, categories.as_deref()),
        TrustCommand::Archive { key_id, reason } => run_archive(&key_id, &reason),
        TrustCommand::Restore { key_id } => run_restore(&key_id),
        TrustCommand::Help => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_list() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust = TrustStore::load_for_repo(&repo_root)?;
    let archived = list_archived_trust_entries(&repo_root)?;

    println!("Wolfence trust list");
    println!("  repo root: {}", repo_root.display());
    println!(
        "  summary: {} active, {} published, {} expired, {} metadata missing, {} metadata incomplete, {} scoped, {} unrestricted, {} archived",
        trust.key_count(),
        trust.published_key_count(),
        trust.expired_keys,
        trust.metadata_missing,
        trust.metadata_incomplete,
        trust.scoped_keys,
        trust.unrestricted_keys,
        archived.len()
    );

    if trust.keys.is_empty() {
        println!("  keys: none");
    } else {
        println!("  keys:");
        for key in &trust.keys {
            let metadata_path = key
                .metadata_path
                .as_ref()
                .map(|path| display_repo_relative(&repo_root, path.as_path()))
                .unwrap_or_else(|| "<missing>".to_string());
            let status = if key.active { "active" } else { "inactive" };
            println!("    - key_id: {}", key.key_id);
            println!("      status: {status}");
            println!(
                "      public_key: {}",
                display_repo_relative(&repo_root, &key.path)
            );
            println!("      metadata: {metadata_path}");
            println!(
                "      owner: {}",
                key.owner.as_deref().unwrap_or("<missing>")
            );
            println!(
                "      expires_on: {}",
                key.expires_on.as_deref().unwrap_or("<missing>")
            );
            println!("      categories: {}", render_categories(&key.categories));
        }
    }

    if archived.is_empty() {
        println!("  archived: none");
    } else {
        println!("  archived:");
        for entry in archived {
            println!("    - key_id: {}", entry.key_id);
            println!(
                "      status: {}",
                if entry.restored_on.is_some() {
                    "restored-history"
                } else {
                    "archived"
                }
            );
            println!("      archived_on: {}", entry.archived_on);
            println!("      reason: {}", entry.reason);
            println!("      public_key: {}", entry.public_key);
            println!("      metadata: {}", entry.metadata);
            if let Some(restored_on) = &entry.restored_on {
                println!("      restored_on: {restored_on}");
            }
            if let Some(restored_to) = &entry.restored_to {
                println!("      restored_to: {restored_to}");
            }
            println!(
                "      archive_note: {}",
                display_repo_relative(&repo_root, entry.note_path.as_path())
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn run_verify(key_id: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust = TrustStore::load_for_repo(&repo_root)?;
    let key_id = key_id.trim();

    let archived = list_archived_trust_entries(&repo_root)?;

    let Some(key) = trust.key(key_id) else {
        if let Some(entry) = archived.iter().find(|entry| entry.key_id == key_id) {
            println!("Wolfence trust verify");
            println!("  repo root: {}", repo_root.display());
            println!("  key_id: {}", entry.key_id);
            println!("  status: archived");
            println!("  archived_on: {}", entry.archived_on);
            println!("  reason: {}", entry.reason);
            println!("  public_key: {}", entry.public_key);
            println!("  metadata: {}", entry.metadata);
            if let Some(restored_on) = &entry.restored_on {
                println!("  restored_on: {restored_on}");
            }
            if let Some(restored_to) = &entry.restored_to {
                println!("  restored_to: {restored_to}");
            }
            println!(
                "  archive_note: {}",
                display_repo_relative(&repo_root, entry.note_path.as_path())
            );
            println!(
                "  detail: trusted key is not currently part of live trust and does not affect current signed-receipt verification."
            );
            return Ok(ExitCode::FAILURE);
        }

        return Err(AppError::Config(format!(
            "trusted key `{key_id}` was not found under `{}` or `{}`.",
            repo_root.join(TRUST_DIR_RELATIVE_PATH).display(),
            repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH).display()
        )));
    };

    let status = trust.key_status(key_id).expect("key should exist");
    let (status_label, detail, remediation, exit_code) = match status {
        TrustedKeyStatus::Active => (
            "active",
            if key.categories.is_empty() {
                "trusted key is fully described and currently usable for signature verification across all receipt categories.".to_string()
            } else {
                format!(
                    "trusted key is fully described and currently usable for these receipt categories: {}.",
                    render_categories(&key.categories)
                )
            },
            None,
            ExitCode::SUCCESS,
        ),
        TrustedKeyStatus::MissingMetadata => (
            "inactive",
            "trusted key is published, but no companion metadata file exists.".to_string(),
            Some(
                "Run `cargo run -- trust init <key-id> <owner> <expires-on>` to create the metadata file."
                    .to_string(),
            ),
            ExitCode::FAILURE,
        ),
        TrustedKeyStatus::IncompleteMetadata => (
            "inactive",
            "trusted key metadata exists but is missing `owner` or `expires_on`.".to_string(),
            Some(
                "Fill in both `owner` and `expires_on` in the companion trust metadata file."
                    .to_string(),
            ),
            ExitCode::FAILURE,
        ),
        TrustedKeyStatus::Expired => (
            "inactive",
            format!(
                "trusted key expired on {} and is no longer active for verification.",
                key.expires_on.as_deref().unwrap_or("<unknown>")
            ),
            Some(
                "Rotate or renew the key metadata and public key, then remove stale trust material if it is no longer needed."
                    .to_string(),
            ),
            ExitCode::FAILURE,
        ),
    };

    println!("Wolfence trust verify");
    println!("  repo root: {}", repo_root.display());
    println!("  key_id: {}", key.key_id);
    println!(
        "  public_key: {}",
        display_repo_relative(&repo_root, &key.path)
    );
    println!(
        "  metadata: {}",
        key.metadata_path
            .as_ref()
            .map(|path| display_repo_relative(&repo_root, path.as_path()))
            .unwrap_or_else(|| "<missing>".to_string())
    );
    println!("  owner: {}", key.owner.as_deref().unwrap_or("<missing>"));
    println!(
        "  expires_on: {}",
        key.expires_on.as_deref().unwrap_or("<missing>")
    );
    println!("  categories: {}", render_categories(&key.categories));
    println!("  status: {status_label}");
    println!("  detail: {detail}");
    if let Some(remediation) = remediation {
        println!("  remediation: {remediation}");
    }

    Ok(exit_code)
}

fn run_init(
    key_id: &str,
    owner: &str,
    expires_on: &str,
    categories: Option<&str>,
) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
    let key_id = key_id.trim();
    let owner = owner.trim();
    let expires_on = expires_on.trim();
    let categories = parse_categories_argument(categories)?;

    if key_id.is_empty() {
        return Err(AppError::Config(
            "trust key id cannot be empty.".to_string(),
        ));
    }
    if owner.is_empty() {
        return Err(AppError::Config("trust owner cannot be empty.".to_string()));
    }
    if !is_iso_date(expires_on) {
        return Err(AppError::Config(
            "trust key expiry must use ISO format `YYYY-MM-DD`.".to_string(),
        ));
    }

    fs::create_dir_all(&trust_dir)?;
    let public_key_path = trust_dir.join(format!("{key_id}.pem"));
    if !public_key_path.exists() {
        return Err(AppError::Config(format!(
            "trusted key `{}` does not exist under `{}`.",
            key_id,
            trust_dir.display()
        )));
    }

    let metadata_path = trust_dir.join(format!("{key_id}.toml"));
    if metadata_path.exists() {
        return Err(AppError::Config(format!(
            "trust metadata `{}` already exists.",
            metadata_path.display()
        )));
    }

    let mut rendered = format!("owner = \"{owner}\"\nexpires_on = \"{expires_on}\"\n");
    if !categories.is_empty() {
        rendered.push_str("categories = [");
        rendered.push_str(
            &categories
                .iter()
                .map(|category| format!("\"{category}\""))
                .collect::<Vec<_>>()
                .join(", "),
        );
        rendered.push_str("]\n");
    }
    fs::write(&metadata_path, rendered)?;

    println!("Wolfence trust init");
    println!("  repo root: {}", repo_root.display());
    println!("  key_id: {key_id}");
    println!(
        "  public_key: {}",
        display_repo_relative(&repo_root, &public_key_path)
    );
    println!(
        "  metadata: {}",
        display_repo_relative(&repo_root, &metadata_path)
    );
    println!("  owner: {owner}");
    println!("  expires_on: {expires_on}");
    println!("  categories: {}", render_categories(&categories));
    println!("  result: canonical trust metadata created");

    Ok(ExitCode::SUCCESS)
}

fn run_archive(key_id: &str, reason: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
    let archive_dir = repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH);
    let key_id = key_id.trim();
    let reason = reason.trim();

    if key_id.is_empty() {
        return Err(AppError::Config(
            "trust key id cannot be empty.".to_string(),
        ));
    }
    if reason.is_empty() {
        return Err(AppError::Config(
            "trust archive reason cannot be empty.".to_string(),
        ));
    }

    let public_key_path = trust_dir.join(format!("{key_id}.pem"));
    if !public_key_path.exists() {
        return Err(AppError::Config(format!(
            "trusted key `{key_id}` does not exist under `{}`.",
            trust_dir.display()
        )));
    }

    let metadata_path = trust_dir.join(format!("{key_id}.toml"));
    let archived_on = current_utc_date();
    fs::create_dir_all(&archive_dir)?;

    let (archived_public_key_path, archived_metadata_path, archive_note_path) =
        build_archive_paths(&repo_root, key_id, &archived_on)?;

    fs::rename(&public_key_path, &archived_public_key_path)?;
    if metadata_path.exists() {
        fs::rename(&metadata_path, &archived_metadata_path)?;
    }

    let archive_note = format!(
        "key_id = \"{key_id}\"\narchived_on = \"{archived_on}\"\nreason = \"{}\"\npublic_key = \"{}\"\nmetadata = \"{}\"\n",
        escape_toml_string(reason),
        display_repo_relative(&repo_root, &archived_public_key_path),
        if archived_metadata_path.exists() {
            display_repo_relative(&repo_root, &archived_metadata_path)
        } else {
            "<none>".to_string()
        }
    );
    fs::write(&archive_note_path, archive_note)?;

    println!("Wolfence trust archive");
    println!("  repo root: {}", repo_root.display());
    println!("  key_id: {key_id}");
    println!("  archived_on: {archived_on}");
    println!(
        "  public_key: {}",
        display_repo_relative(&repo_root, &archived_public_key_path)
    );
    println!(
        "  metadata: {}",
        if archived_metadata_path.exists() {
            display_repo_relative(&repo_root, &archived_metadata_path)
        } else {
            "<none>".to_string()
        }
    );
    println!(
        "  archive_note: {}",
        display_repo_relative(&repo_root, &archive_note_path)
    );
    println!("  reason: {reason}");
    println!("  result: trust key removed from live trust scope and archived");

    Ok(ExitCode::SUCCESS)
}

fn run_restore(key_id: &str) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
    let key_id = key_id.trim();

    if key_id.is_empty() {
        return Err(AppError::Config(
            "trust key id cannot be empty.".to_string(),
        ));
    }

    let live_public_key_path = trust_dir.join(format!("{key_id}.pem"));
    let live_metadata_path = trust_dir.join(format!("{key_id}.toml"));
    if live_public_key_path.exists() || live_metadata_path.exists() {
        return Err(AppError::Config(format!(
            "live trust material for `{key_id}` already exists under `{}`.",
            trust_dir.display()
        )));
    }

    let archived = list_archived_trust_entries(&repo_root)?;
    let Some(entry) = archived
        .iter()
        .rev()
        .find(|entry| entry.key_id == key_id && entry.restored_on.is_none())
    else {
        return Err(AppError::Config(format!(
            "no restorable archived trust material for `{key_id}` was found under `{}`.",
            repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH).display()
        )));
    };

    let archived_public_key_path = resolve_archived_asset_path(&repo_root, &entry.public_key)?;
    if !archived_public_key_path.exists() {
        return Err(AppError::Config(format!(
            "archived public key for `{key_id}` is missing at `{}`.",
            archived_public_key_path.display()
        )));
    }

    let archived_metadata_path = if entry.metadata != "<none>" {
        let path = resolve_archived_asset_path(&repo_root, &entry.metadata)?;
        if !path.exists() {
            return Err(AppError::Config(format!(
                "archived trust metadata for `{key_id}` is missing at `{}`.",
                path.display()
            )));
        }
        Some(path)
    } else {
        None
    };

    fs::rename(&archived_public_key_path, &live_public_key_path)?;

    let restored_metadata = if let Some(archived_metadata_path) = archived_metadata_path {
        fs::rename(&archived_metadata_path, &live_metadata_path)?;
        Some(live_metadata_path.clone())
    } else {
        None
    };

    let restored_on = current_utc_date();
    let restored_to = display_repo_relative(&repo_root, &live_public_key_path);
    let mut note_contents = fs::read_to_string(&entry.note_path)?;
    if !note_contents.ends_with('\n') {
        note_contents.push('\n');
    }
    note_contents.push_str(&format!(
        "restored_on = \"{restored_on}\"\nrestored_to = \"{}\"\n",
        escape_toml_string(&restored_to)
    ));
    fs::write(&entry.note_path, note_contents)?;

    println!("Wolfence trust restore");
    println!("  repo root: {}", repo_root.display());
    println!("  key_id: {key_id}");
    println!("  archived_on: {}", entry.archived_on);
    println!("  restored_on: {restored_on}");
    println!("  public_key: {}", restored_to);
    println!(
        "  metadata: {}",
        restored_metadata
            .as_ref()
            .map(|path| display_repo_relative(&repo_root, path))
            .unwrap_or_else(|| "<none>".to_string())
    );
    println!(
        "  archive_note: {}",
        display_repo_relative(&repo_root, entry.note_path.as_path())
    );
    println!("  result: archived trust key restored into live trust scope");

    Ok(ExitCode::SUCCESS)
}

fn display_repo_relative(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .display()
        .to_string()
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

fn parse_categories_argument(input: Option<&str>) -> AppResult<Vec<FindingCategory>> {
    let Some(input) = input.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };

    let mut categories = Vec::new();
    for raw_value in input.split(',') {
        let value = raw_value.trim();
        if value.is_empty() {
            return Err(AppError::Config(
                "trust categories must not contain empty values.".to_string(),
            ));
        }
        let parsed = FindingCategory::parse(value).map_err(|message| {
            AppError::Config(format!("unsupported trust category `{value}`. {message}."))
        })?;
        if !categories.contains(&parsed) {
            categories.push(parsed);
        }
    }

    Ok(categories)
}

fn render_categories(categories: &[FindingCategory]) -> String {
    if categories.is_empty() {
        "<any>".to_string()
    } else {
        categories
            .iter()
            .map(|category| category.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn current_utc_date() -> String {
    // Keep trust archival dates aligned with receipt timestamps.
    crate::core::receipts::today_utc_date()
}

fn escape_toml_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn build_archive_paths(
    repo_root: &Path,
    key_id: &str,
    archived_on: &str,
) -> AppResult<(PathBuf, PathBuf, PathBuf)> {
    let archive_root = repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH);
    let mut suffix = 0usize;

    loop {
        let label = if suffix == 0 {
            format!("{archived_on}-{key_id}")
        } else {
            format!("{archived_on}-{suffix}-{key_id}")
        };
        let archived_public_key = archive_root.join(format!("{label}.pem"));
        let archived_metadata = archive_root.join(format!("{label}.toml"));
        let archived_note = archive_root.join(format!("{label}.archive.toml"));
        let metadata_conflict = archived_metadata.exists();

        if !archived_public_key.exists() && !metadata_conflict && !archived_note.exists() {
            return Ok((archived_public_key, archived_metadata, archived_note));
        }

        suffix += 1;
    }
}

#[cfg(test)]
fn list_archived_trust_notes(repo_root: &Path) -> AppResult<Vec<PathBuf>> {
    let entries = list_archived_trust_entries(repo_root)?;
    Ok(entries.into_iter().map(|entry| entry.note_path).collect())
}

pub(super) fn archived_trust_count(repo_root: &Path) -> AppResult<usize> {
    Ok(list_archived_trust_entries(repo_root)?.len())
}

fn list_archived_trust_entries(repo_root: &Path) -> AppResult<Vec<ArchivedTrustEntry>> {
    let archive_root = repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH);
    if !archive_root.exists() {
        return Ok(Vec::new());
    }

    let mut archived = Vec::new();
    for entry in fs::read_dir(&archive_root)? {
        let entry = entry?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if path.is_file() && file_name.ends_with(".archive.toml") {
            let canonical = fs::canonicalize(path)?;
            let contents = fs::read_to_string(&canonical)?;
            archived.push(parse_archived_trust_entry(&canonical, &contents)?);
        }
    }

    archived.sort_by(|left, right| {
        left.archived_on
            .cmp(&right.archived_on)
            .then_with(|| left.key_id.cmp(&right.key_id))
            .then_with(|| left.note_path.cmp(&right.note_path))
    });
    Ok(archived)
}

fn parse_archived_trust_entry(path: &Path, contents: &str) -> AppResult<ArchivedTrustEntry> {
    let mut key_id = None;
    let mut archived_on = None;
    let mut reason = None;
    let mut public_key = None;
    let mut metadata = None;
    let mut restored_on = None;
    let mut restored_to = None;

    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim().to_string();

        match key {
            "key_id" => key_id = Some(value),
            "archived_on" => archived_on = Some(value),
            "reason" => reason = Some(value),
            "public_key" => public_key = Some(value),
            "metadata" => metadata = Some(value),
            "restored_on" => restored_on = Some(value),
            "restored_to" => restored_to = Some(value),
            _ => {}
        }
    }

    let key_id = key_id.ok_or_else(|| {
        AppError::Config(format!(
            "{} is missing required `key_id` archive metadata.",
            path.display()
        ))
    })?;
    let archived_on = archived_on.ok_or_else(|| {
        AppError::Config(format!(
            "{} is missing required `archived_on` archive metadata.",
            path.display()
        ))
    })?;
    let reason = reason.ok_or_else(|| {
        AppError::Config(format!(
            "{} is missing required `reason` archive metadata.",
            path.display()
        ))
    })?;
    let public_key = public_key.ok_or_else(|| {
        AppError::Config(format!(
            "{} is missing required `public_key` archive metadata.",
            path.display()
        ))
    })?;
    let metadata = metadata.ok_or_else(|| {
        AppError::Config(format!(
            "{} is missing required `metadata` archive metadata.",
            path.display()
        ))
    })?;

    if !is_iso_date(&archived_on) {
        return Err(AppError::Config(format!(
            "{} must use ISO format `YYYY-MM-DD` for `archived_on`.",
            path.display()
        )));
    }

    if let Some(restored_on) = &restored_on {
        if !is_iso_date(restored_on) {
            return Err(AppError::Config(format!(
                "{} must use ISO format `YYYY-MM-DD` for `restored_on`.",
                path.display()
            )));
        }
    }

    Ok(ArchivedTrustEntry {
        note_path: path.to_path_buf(),
        key_id,
        archived_on,
        reason,
        public_key,
        metadata,
        restored_on,
        restored_to,
    })
}

fn resolve_archived_asset_path(repo_root: &Path, value: &str) -> AppResult<PathBuf> {
    let candidate = PathBuf::from(value);
    if candidate.is_absolute() {
        return Err(AppError::Config(format!(
            "archived trust asset path `{value}` must stay repository-relative."
        )));
    }

    let path = repo_root.join(candidate);
    let canonical = fs::canonicalize(&path)?;
    let archive_root = fs::canonicalize(repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH))?;
    if !canonical.starts_with(&archive_root) {
        return Err(AppError::Config(format!(
            "archived trust asset `{}` escapes `{}`.",
            canonical.display(),
            archive_root.display()
        )));
    }

    Ok(canonical)
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

fn print_help() {
    println!("Wolfence trust workflows");
    println!("  list");
    println!("      Show active, inactive, expired, and metadata status for repo-local trust keys");
    println!("  verify <key-id>");
    println!("      Evaluate one trust key and explain whether it is active or inactive");
    println!("  init <key-id> <owner> <expires-on> [categories]");
    println!(
        "      Create one canonical metadata file for an existing trust key under .wolfence/trust/"
    );
    println!("      categories: comma-separated secret, vulnerability, dependency, configuration, or policy");
    println!("  archive <key-id> <reason>");
    println!(
        "      Move one live trust key out of .wolfence/trust/ and into .wolfence/trust/archive/"
    );
    println!("  restore <key-id>");
    println!("      Restore the latest un-restored archived trust key back into .wolfence/trust/");
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        build_archive_paths, display_repo_relative, list_archived_trust_notes,
        parse_archived_trust_entry, parse_categories_argument, render_categories,
        TRUST_ARCHIVE_DIR_RELATIVE_PATH,
    };
    use crate::core::findings::FindingCategory;
    use crate::core::trust::TRUST_DIR_RELATIVE_PATH;

    #[test]
    fn display_repo_relative_prefers_repo_paths() {
        let repo_root = make_temp_repo("trust-display");
        let path = repo_root
            .join(TRUST_DIR_RELATIVE_PATH)
            .join("security-team.pem");
        let rendered = display_repo_relative(&repo_root, &path);
        assert_eq!(rendered, ".wolfence/trust/security-team.pem");
    }

    #[test]
    fn parses_scoped_categories_argument() {
        let categories =
            parse_categories_argument(Some("secret, policy, secret")).expect("should parse");
        assert_eq!(
            categories,
            vec![FindingCategory::Secret, FindingCategory::Policy]
        );
    }

    #[test]
    fn render_categories_uses_any_for_unrestricted_keys() {
        assert_eq!(render_categories(&[]), "<any>");
    }

    #[test]
    fn builds_trust_archive_paths_under_archive_directory() {
        let repo_root = make_temp_repo("trust-archive-path");
        let archive_dir = repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH);
        fs::create_dir_all(&archive_dir).expect("should create archive dir");

        let (public_key, metadata, note) =
            build_archive_paths(&repo_root, "security-team", "2026-04-09")
                .expect("archive path should build");

        assert!(public_key.ends_with(".wolfence/trust/archive/2026-04-09-security-team.pem"));
        assert!(metadata.ends_with(".wolfence/trust/archive/2026-04-09-security-team.toml"));
        assert!(note.ends_with(".wolfence/trust/archive/2026-04-09-security-team.archive.toml"));
    }

    #[test]
    fn lists_archived_trust_notes_sorted() {
        let repo_root = make_temp_repo("trust-archive-list");
        let archive_dir = repo_root.join(TRUST_ARCHIVE_DIR_RELATIVE_PATH);
        fs::create_dir_all(&archive_dir).expect("should create archive dir");
        fs::write(
            archive_dir.join("2026-04-09-b.archive.toml"),
            "key_id = \"b\"\narchived_on = \"2026-04-09\"\nreason = \"rotation complete\"\npublic_key = \".wolfence/trust/archive/2026-04-09-b.pem\"\nmetadata = \".wolfence/trust/archive/2026-04-09-b.toml\"\n",
        )
        .expect("should write archive note");
        fs::write(
            archive_dir.join("2026-04-09-a.archive.toml"),
            "key_id = \"a\"\narchived_on = \"2026-04-09\"\nreason = \"rotation complete\"\npublic_key = \".wolfence/trust/archive/2026-04-09-a.pem\"\nmetadata = \".wolfence/trust/archive/2026-04-09-a.toml\"\n",
        )
        .expect("should write archive note");

        let archived = list_archived_trust_notes(&repo_root).expect("listing should succeed");
        assert_eq!(archived.len(), 2);
        assert!(archived[0].ends_with("2026-04-09-a.archive.toml"));
        assert!(archived[1].ends_with("2026-04-09-b.archive.toml"));
    }

    #[test]
    fn parses_archived_trust_entry_fields() {
        let repo_root = make_temp_repo("trust-archive-parse");
        let archive_note_path =
            repo_root.join(".wolfence/trust/archive/2026-04-09-security-team.archive.toml");
        fs::create_dir_all(
            archive_note_path
                .parent()
                .expect("archive note should have parent"),
        )
        .expect("should create archive dir");
        let contents = "key_id = \"security-team\"\narchived_on = \"2026-04-09\"\nreason = \"rotation complete\"\npublic_key = \".wolfence/trust/archive/2026-04-09-security-team.pem\"\nmetadata = \".wolfence/trust/archive/2026-04-09-security-team.toml\"\n";

        let parsed =
            parse_archived_trust_entry(&archive_note_path, contents).expect("should parse");
        assert_eq!(parsed.key_id, "security-team");
        assert_eq!(parsed.archived_on, "2026-04-09");
        assert_eq!(parsed.reason, "rotation complete");
    }

    #[test]
    fn parses_restored_archive_fields() {
        let repo_root = make_temp_repo("trust-archive-restored-parse");
        let archive_note_path =
            repo_root.join(".wolfence/trust/archive/2026-04-09-security-team.archive.toml");
        fs::create_dir_all(
            archive_note_path
                .parent()
                .expect("archive note should have parent"),
        )
        .expect("should create archive dir");
        let contents = "key_id = \"security-team\"\narchived_on = \"2026-04-09\"\nreason = \"rotation complete\"\npublic_key = \".wolfence/trust/archive/2026-04-09-security-team.pem\"\nmetadata = \".wolfence/trust/archive/2026-04-09-security-team.toml\"\nrestored_on = \"2026-04-10\"\nrestored_to = \".wolfence/trust/security-team.pem\"\n";

        let parsed =
            parse_archived_trust_entry(&archive_note_path, contents).expect("should parse");
        assert_eq!(parsed.restored_on.as_deref(), Some("2026-04-10"));
        assert_eq!(
            parsed.restored_to.as_deref(),
            Some(".wolfence/trust/security-team.pem")
        );
    }

    fn make_temp_repo(name: &str) -> PathBuf {
        let unique = format!(
            "wolfence-trust-command-{name}-{}-{}",
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
