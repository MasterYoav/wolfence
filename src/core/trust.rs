//! Repository trust material for signature verification.
//!
//! Wolfence can require signed override receipts when a repository publishes
//! trusted public keys. This module loads that trust store and verifies receipt
//! signatures with the system `openssl` executable.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::{AppError, AppResult};
use crate::core::findings::FindingCategory;

pub const TRUST_DIR_RELATIVE_PATH: &str = ".wolfence/trust";

/// One trusted public key used to verify receipt signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub path: PathBuf,
    pub metadata_path: Option<PathBuf>,
    pub owner: Option<String>,
    pub expires_on: Option<String>,
    pub categories: Vec<FindingCategory>,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeyStatus {
    Active,
    MissingMetadata,
    IncompleteMetadata,
    Expired,
}

/// Repo-local trust store for signed receipts.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
    pub published_keys: usize,
    pub expired_keys: usize,
    pub metadata_files: usize,
    pub metadata_missing: usize,
    pub metadata_incomplete: usize,
    pub scoped_keys: usize,
    pub unrestricted_keys: usize,
}

impl TrustStore {
    /// Loads trusted public keys from the repository.
    pub fn load_for_repo(repo_root: &Path) -> AppResult<Self> {
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        if !trust_dir.exists() {
            return Ok(Self::default());
        }

        let mut keys = Vec::new();
        let mut published_keys = 0usize;
        let mut expired_keys = 0usize;
        let mut metadata_files = 0usize;
        let mut metadata_missing = 0usize;
        let mut metadata_incomplete = 0usize;
        let mut scoped_keys = 0usize;
        let mut unrestricted_keys = 0usize;
        let today = current_utc_date();

        for entry in fs::read_dir(&trust_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|value| value.to_str()) != Some("pem") {
                continue;
            }
            published_keys += 1;

            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };

            let metadata_path = trust_dir.join(format!("{stem}.toml"));
            let (owner, expires_on, categories, metadata_exists) = if metadata_path.exists() {
                metadata_files += 1;
                let metadata = load_key_metadata(&metadata_path)?;
                (
                    metadata.owner,
                    metadata.expires_on,
                    metadata.categories,
                    true,
                )
            } else {
                metadata_missing += 1;
                (None, None, Vec::new(), false)
            };

            let metadata_complete = owner.is_some() && expires_on.is_some();
            if metadata_exists && !metadata_complete {
                metadata_incomplete += 1;
            }

            let active = match expires_on.as_deref() {
                Some(expires_on) if metadata_complete && expires_on < today.as_str() => {
                    expired_keys += 1;
                    false
                }
                Some(_) if metadata_complete => true,
                _ => false,
            };

            if active {
                if categories.is_empty() {
                    unrestricted_keys += 1;
                } else {
                    scoped_keys += 1;
                }
            }

            keys.push(TrustedKey {
                key_id: stem.to_string(),
                path,
                metadata_path: metadata_exists.then_some(metadata_path),
                owner,
                expires_on,
                categories,
                active,
            });
        }

        keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
        Ok(Self {
            keys,
            published_keys,
            expired_keys,
            metadata_files,
            metadata_missing,
            metadata_incomplete,
            scoped_keys,
            unrestricted_keys,
        })
    }

    /// Returns whether signed receipts are required for this repository.
    pub fn requires_signed_receipts(&self) -> bool {
        self.published_key_count() > 0
    }

    /// Returns the count of active trusted public keys.
    pub fn key_count(&self) -> usize {
        self.keys.iter().filter(|key| key.active).count()
    }

    /// Returns the count of published trusted public keys, including expired ones.
    pub fn published_key_count(&self) -> usize {
        self.published_keys
    }

    /// Returns whether one trusted key id exists, even if inactive.
    pub fn has_key_id(&self, key_id: &str) -> bool {
        self.keys.iter().any(|key| key.key_id == key_id)
    }

    /// Returns whether one trusted key id is currently active.
    pub fn key_is_active(&self, key_id: &str) -> bool {
        self.keys
            .iter()
            .any(|key| key.key_id == key_id && key.active)
    }

    /// Returns the path for one trusted key id.
    pub fn key_path(&self, key_id: &str) -> Option<&Path> {
        self.keys
            .iter()
            .find(|key| key.key_id == key_id && key.active)
            .map(|key| key.path.as_path())
    }

    /// Returns one trusted key by id, regardless of active status.
    pub fn key(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// Explains the current trust status for one key.
    pub fn key_status(&self, key_id: &str) -> Option<TrustedKeyStatus> {
        self.key(key_id).map(trusted_key_status)
    }

    /// Returns whether one active trusted key may sign receipts for one category.
    pub fn key_allows_category(&self, key_id: &str, category: FindingCategory) -> bool {
        let Some(key) = self.key(key_id) else {
            return false;
        };
        if !key.active {
            return false;
        }
        key.categories.is_empty() || key.categories.contains(&category)
    }

    /// Verifies one hex-encoded receipt signature against a trusted key.
    pub fn verify_receipt_signature(
        &self,
        key_id: &str,
        payload: &str,
        signature_hex: &str,
    ) -> AppResult<bool> {
        let Some(key_path) = self.key_path(key_id) else {
            return Ok(false);
        };

        let signature_bytes = decode_hex(signature_hex).map_err(|message| {
            AppError::Config(format!(
                "invalid receipt signature hex for key `{key_id}`: {message}"
            ))
        })?;

        let temp_root = std::env::temp_dir().join(format!(
            "wolfence-trust-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_root)?;
        let payload_path = temp_root.join("payload.txt");
        let signature_path = temp_root.join("signature.bin");
        fs::write(&payload_path, payload)?;
        fs::write(&signature_path, signature_bytes)?;

        let output = Command::new("openssl")
            .args([
                "dgst",
                "-sha256",
                "-verify",
                key_path.to_string_lossy().as_ref(),
                "-signature",
                signature_path.to_string_lossy().as_ref(),
                payload_path.to_string_lossy().as_ref(),
            ])
            .output()?;

        let _ = fs::remove_file(&payload_path);
        let _ = fs::remove_file(&signature_path);
        let _ = fs::remove_dir(&temp_root);

        Ok(output.status.success())
    }
}

pub fn trusted_key_status(key: &TrustedKey) -> TrustedKeyStatus {
    if key.active {
        return TrustedKeyStatus::Active;
    }

    if key.metadata_path.is_none() {
        return TrustedKeyStatus::MissingMetadata;
    }

    if key.owner.is_none() || key.expires_on.is_none() {
        return TrustedKeyStatus::IncompleteMetadata;
    }

    TrustedKeyStatus::Expired
}

#[derive(Debug, Clone, Default)]
struct TrustedKeyMetadata {
    owner: Option<String>,
    expires_on: Option<String>,
    categories: Vec<FindingCategory>,
}

/// Signs one canonical receipt payload with a private key and returns a hex
/// detached signature suitable for receipt files.
pub fn sign_payload_with_private_key(private_key_path: &Path, payload: &str) -> AppResult<String> {
    let temp_root = std::env::temp_dir().join(format!(
        "wolfence-sign-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_root)?;
    let payload_path = temp_root.join("payload.txt");
    let signature_path = temp_root.join("signature.bin");
    fs::write(&payload_path, payload)?;

    let output = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-sign",
            private_key_path.to_string_lossy().as_ref(),
            "-out",
            signature_path.to_string_lossy().as_ref(),
            payload_path.to_string_lossy().as_ref(),
        ])
        .output()?;

    if !output.status.success() {
        let _ = fs::remove_file(&payload_path);
        let _ = fs::remove_file(&signature_path);
        let _ = fs::remove_dir(&temp_root);

        return Err(AppError::Config(format!(
            "openssl failed to sign the receipt payload: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let signature_bytes = fs::read(&signature_path)?;

    let _ = fs::remove_file(&payload_path);
    let _ = fs::remove_file(&signature_path);
    let _ = fs::remove_dir(&temp_root);

    Ok(encode_hex(&signature_bytes))
}

fn load_key_metadata(path: &Path) -> AppResult<TrustedKeyMetadata> {
    let contents = fs::read_to_string(path)?;
    let mut metadata = TrustedKeyMetadata::default();

    for raw_line in contents.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"').trim();

        match key {
            "owner" => {
                if !value.is_empty() {
                    metadata.owner = Some(value.to_string());
                }
            }
            "expires_on" => {
                if !is_iso_date(value) {
                    return Err(AppError::Config(format!(
                        "{} must use ISO format `YYYY-MM-DD` for `expires_on`.",
                        path.display()
                    )));
                }
                metadata.expires_on = Some(value.to_string());
            }
            "categories" => {
                let parsed = parse_category_list(value)
                    .map_err(|message| AppError::Config(format!("{} {message}", path.display())))?;
                metadata.categories = parsed;
            }
            _ => {}
        }
    }

    Ok(metadata)
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

fn parse_category_list(value: &str) -> Result<Vec<FindingCategory>, String> {
    let trimmed = value.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err("must use a TOML-style string list for `categories`.".to_string());
    }

    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.trim().is_empty() {
        return Err("must not use an empty `categories` list.".to_string());
    }

    let mut categories = Vec::new();
    for raw_item in inner.split(',') {
        let item = raw_item.trim().trim_matches('"').trim();
        if item.is_empty() {
            return Err("must not contain empty category values.".to_string());
        }
        let parsed = FindingCategory::parse(item)
            .map_err(|message| format!("uses unsupported category `{item}`: {message}"))?;
        if !categories.contains(&parsed) {
            categories.push(parsed);
        }
    }

    Ok(categories)
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

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    let trimmed = value.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("expected an even number of hex characters");
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let chars = trimmed.as_bytes().chunks_exact(2);
    for pair in chars {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(nibble_to_hex(byte >> 4));
        output.push(nibble_to_hex(byte & 0x0f));
    }
    output
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble should always be within hex range"),
    }
}

fn decode_hex_nibble(value: u8) -> Result<u8, &'static str> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("found a non-hex character"),
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;

    use crate::core::findings::FindingCategory;

    use super::{TrustStore, TrustedKeyStatus, TRUST_DIR_RELATIVE_PATH};

    #[test]
    fn loads_repo_trust_keys_by_pem_file_name() {
        let repo_root = env::temp_dir().join(format!("wolfence-trust-load-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");

        let trust = TrustStore::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(trust.key_count(), 0);
        assert_eq!(trust.published_key_count(), 1);
        assert_eq!(trust.metadata_missing, 1);
        assert_eq!(trust.metadata_incomplete, 0);
        assert!(trust.requires_signed_receipts());
    }

    #[test]
    fn expired_trust_keys_become_inactive_when_metadata_is_present() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-trust-expired-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2020-01-01\"\n",
        )
        .expect("should write metadata");

        let trust = TrustStore::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(trust.published_key_count(), 1);
        assert_eq!(trust.key_count(), 0);
        assert_eq!(trust.expired_keys, 1);
        assert_eq!(trust.metadata_files, 1);
        assert!(trust.requires_signed_receipts());
        assert!(trust.has_key_id("security-team"));
        assert!(!trust.key_is_active("security-team"));
        assert!(trust.key_path("security-team").is_none());
    }

    #[test]
    fn trust_keys_with_incomplete_metadata_stay_inactive() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-trust-incomplete-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\n",
        )
        .expect("should write metadata");

        let trust = TrustStore::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(trust.published_key_count(), 1);
        assert_eq!(trust.key_count(), 0);
        assert_eq!(trust.metadata_files, 1);
        assert_eq!(trust.metadata_incomplete, 1);
        assert!(trust.requires_signed_receipts());
        assert!(trust.has_key_id("security-team"));
        assert!(!trust.key_is_active("security-team"));
    }

    #[test]
    fn key_status_reports_missing_metadata() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-trust-status-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");

        let trust = TrustStore::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(
            trust.key_status("security-team"),
            Some(TrustedKeyStatus::MissingMetadata)
        );
    }

    #[test]
    fn scoped_trust_keys_only_allow_configured_categories() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-trust-scope-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2099-12-31\"\ncategories = [\"secret\", \"policy\"]\n",
        )
        .expect("should write metadata");

        let trust = TrustStore::load_for_repo(&repo_root).expect("load should succeed");
        assert_eq!(trust.key_count(), 1);
        assert_eq!(trust.scoped_keys, 1);
        assert_eq!(trust.unrestricted_keys, 0);
        assert!(trust.key_allows_category("security-team", FindingCategory::Secret));
        assert!(trust.key_allows_category("security-team", FindingCategory::Policy));
        assert!(!trust.key_allows_category("security-team", FindingCategory::Dependency));
    }

    #[test]
    fn invalid_empty_category_list_is_rejected() {
        let repo_root =
            env::temp_dir().join(format!("wolfence-trust-empty-scope-{}", std::process::id()));
        let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
        fs::create_dir_all(&trust_dir).expect("should create trust dir");
        fs::write(trust_dir.join("security-team.pem"), "dummy").expect("should write pem");
        fs::write(
            trust_dir.join("security-team.toml"),
            "owner = \"security-team\"\nexpires_on = \"2099-12-31\"\ncategories = []\n",
        )
        .expect("should write metadata");

        let error = TrustStore::load_for_repo(&repo_root).expect_err("load should fail");
        assert!(
            error
                .to_string()
                .contains("must not use an empty `categories` list"),
            "unexpected error: {error}"
        );
    }
}
