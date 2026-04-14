//! `wolf doctor`
//!
//! A local security gate needs an operator-facing audit path, not just scans.
//! This command checks whether the repository is configured in a way that makes
//! Wolfence trustworthy in day-to-day use.

use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::process::{Command, ExitCode};

use serde::Serialize;

use crate::app::AppResult;
use crate::core::audit;
use crate::core::config::{ConfigSource, ResolvedConfig, REPO_CONFIG_RELATIVE_PATH};
use crate::core::git;
use crate::core::git::PushStatus;
use crate::core::github_governance::{self, GithubGovernanceMode};
use crate::core::hooks::{self, HookLauncherKind, HookState};
use crate::core::osv::OsvMode;
use crate::core::policy::EnforcementMode;
use crate::core::receipt_policy::{ReceiptApprovalPolicy, RECEIPT_POLICY_FILE_RELATIVE_PATH};
use crate::core::receipts::{ReceiptIndex, RECEIPTS_DIR_RELATIVE_PATH};
use crate::core::trust::{TrustStore, TRUST_DIR_RELATIVE_PATH};

use super::json::{print_json, print_json_error};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

impl Display for DoctorStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Warn => write!(f, "warn"),
            Self::Fail => write!(f, "fail"),
            Self::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    name: &'static str,
    status: DoctorStatus,
    detail: String,
    remediation: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
struct DoctorSummary {
    pass: usize,
    warn: usize,
    fail: usize,
    info: usize,
}

#[derive(Serialize)]
struct DoctorJsonResponse {
    command: &'static str,
    repo_root: String,
    effective_mode: String,
    mode_source: String,
    summary: DoctorSummary,
    checks: Vec<DoctorCheck>,
    result: &'static str,
}

pub fn run(json: bool) -> AppResult<ExitCode> {
    let result = run_internal(json);
    if json {
        if let Err(error) = &result {
            print_json_error("doctor", error)?;
            return Ok(ExitCode::FAILURE);
        }
    }
    result
}

fn run_internal(json: bool) -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let config = ResolvedConfig::load_for_repo(&repo_root)?;
    let checks = build_checks(&repo_root, &config)?;
    let summary = summarize_checks(&checks);

    if json {
        print_json(&DoctorJsonResponse {
            command: "doctor",
            repo_root: repo_root.display().to_string(),
            effective_mode: config.mode.to_string(),
            mode_source: config.mode_source.to_string(),
            summary,
            checks,
            result: if summary.fail > 0 { "failed" } else { "ok" },
        })?;
        return Ok(if summary.fail > 0 {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        });
    }

    println!("Wolfence doctor");
    println!("  repo root: {}", repo_root.display());
    println!("  effective mode: {} ({})", config.mode, config.mode_source);
    println!(
        "  summary: {} pass, {} warn, {} fail, {} info",
        summary.pass, summary.warn, summary.fail, summary.info
    );
    println!("  checks:");

    for check in &checks {
        println!("    - [{}] {}: {}", check.status, check.name, check.detail);
        if let Some(remediation) = &check.remediation {
            println!("      remediation: {remediation}");
        }
    }

    if summary.fail > 0 {
        println!("  result: blocking environment failures are present");
        return Ok(ExitCode::FAILURE);
    }

    println!("  result: no blocking environment failures detected");
    Ok(ExitCode::SUCCESS)
}

fn build_checks(repo_root: &Path, config: &ResolvedConfig) -> AppResult<Vec<DoctorCheck>> {
    let mut checks = Vec::new();

    checks.push(check_repo_config(config));
    checks.push(check_repo_config_trackability(repo_root, config)?);
    checks.push(check_receipt_policy_trackability(repo_root)?);
    checks.push(check_receipts_trackability(repo_root)?);
    checks.push(check_trust_trackability(repo_root)?);
    checks.push(check_trust_metadata(repo_root)?);
    checks.push(check_receipt_signature_policy(repo_root)?);
    checks.push(check_policy_posture(config));
    checks.push(check_scan_ignore_paths(config));
    checks.push(check_osv_mode()?);
    checks.push(check_github_governance_mode()?);

    if let Some(check) = check_environment_override(config) {
        checks.push(check);
    }

    if let Some(check) = check_dry_run_override() {
        checks.push(check);
    }

    checks.push(check_wolf_runtime());
    checks.push(check_git_identity(repo_root)?);
    checks.push(check_push_remote(repo_root)?);
    checks.push(check_curl_runtime());
    checks.push(check_gh_runtime());
    checks.push(check_openssl_runtime(repo_root)?);
    checks.push(check_pre_push_hook(repo_root)?);
    checks.push(check_audit_log(repo_root)?);
    checks.push(check_receipt_posture(repo_root)?);
    checks.push(check_push_window(repo_root, config)?);
    checks.push(check_live_github_governance(repo_root)?);

    Ok(checks)
}

fn check_repo_config(config: &ResolvedConfig) -> DoctorCheck {
    let detail = if config.repo_config_exists {
        format!(
            "{} exists and resolves to {} mode.",
            config.repo_config_path.display(),
            config.mode
        )
    } else {
        format!(
            "{} is missing, so Wolfence is relying on the built-in {} default.",
            config.repo_config_path.display(),
            config.mode
        )
    };

    let remediation = if config.repo_config_exists {
        None
    } else {
        Some("Run `wolf init` so the repository policy is explicit and reviewable.".to_string())
    };

    DoctorCheck {
        name: "repo config",
        status: if config.repo_config_exists {
            DoctorStatus::Pass
        } else {
            DoctorStatus::Warn
        },
        detail,
        remediation,
    }
}

fn check_repo_config_trackability(
    repo_root: &Path,
    config: &ResolvedConfig,
) -> AppResult<DoctorCheck> {
    if !config.repo_config_exists {
        return Ok(DoctorCheck {
            name: "config trackability",
            status: DoctorStatus::Info,
            detail:
                "repo config does not exist yet, so there is nothing to validate for Git tracking."
                    .to_string(),
            remediation: None,
        });
    }

    let ignored = git::is_path_ignored(repo_root, Path::new(REPO_CONFIG_RELATIVE_PATH))?;
    let (status, detail, remediation) = if ignored {
        (
            DoctorStatus::Fail,
            format!(
                "{} is ignored by Git, so repository policy cannot be shared or reviewed normally.",
                REPO_CONFIG_RELATIVE_PATH
            ),
            Some("Adjust `.gitignore` so `.wolfence/config.toml` is trackable.".to_string()),
        )
    } else {
        (
            DoctorStatus::Pass,
            format!(
                "{} is not ignored by Git and can be committed with the repository.",
                REPO_CONFIG_RELATIVE_PATH
            ),
            None,
        )
    };

    Ok(DoctorCheck {
        name: "config trackability",
        status,
        detail,
        remediation,
    })
}

fn check_policy_posture(config: &ResolvedConfig) -> DoctorCheck {
    let (status, detail, remediation) = match config.mode {
        EnforcementMode::Advisory => (
            DoctorStatus::Warn,
            "advisory mode never blocks pushes, so Wolfence is currently operating as a review surface rather than a hard gate.".to_string(),
            Some("Use `standard` or `strict` in `.wolfence/config.toml` for real enforcement.".to_string()),
        ),
        EnforcementMode::Standard => (
            DoctorStatus::Pass,
            "standard mode is active: high and critical findings block, and medium high-confidence non-vulnerability findings also block.".to_string(),
            None,
        ),
        EnforcementMode::Strict => (
            DoctorStatus::Pass,
            "strict mode is active: medium-and-above findings block, and low high-confidence non-vulnerability findings also block.".to_string(),
            None,
        ),
    };

    DoctorCheck {
        name: "policy posture",
        status,
        detail,
        remediation,
    }
}

fn check_scan_ignore_paths(config: &ResolvedConfig) -> DoctorCheck {
    if config.scan_ignore_paths.is_empty() {
        return DoctorCheck {
            name: "scan exclusions",
            status: DoctorStatus::Info,
            detail: "no repo-local scan exclusions are configured.".to_string(),
            remediation: None,
        };
    }

    let risky_paths = risky_scan_ignore_paths(&config.scan_ignore_paths);
    if !risky_paths.is_empty() {
        return DoctorCheck {
            name: "scan exclusions",
            status: DoctorStatus::Warn,
            detail: format!(
                "{} repo-local scan exclusion pattern(s) are active, including higher-risk paths: {}",
                config.scan_ignore_paths.len(),
                risky_paths.join(", ")
            ),
            remediation: Some(
                "Avoid excluding source, CI, manifest, lockfile, or Wolfence policy paths. Keep exclusions limited to docs, fixtures, or generated artifacts."
                    .to_string(),
            ),
        };
    }

    DoctorCheck {
        name: "scan exclusions",
        status: DoctorStatus::Pass,
        detail: format!(
            "{} repo-local scan exclusion pattern(s) are active: {}",
            config.scan_ignore_paths.len(),
            config.scan_ignore_paths.join(", ")
        ),
        remediation: Some(
            "Keep exclusions narrowly scoped to docs, fixtures, or generated artifacts so the protected push surface does not silently shrink."
                .to_string(),
        ),
    }
}

fn risky_scan_ignore_paths(patterns: &[String]) -> Vec<String> {
    patterns
        .iter()
        .filter(|pattern| is_risky_scan_ignore_path(pattern))
        .cloned()
        .collect()
}

fn is_risky_scan_ignore_path(pattern: &str) -> bool {
    const RISKY_PREFIXES: &[&str] = &["src/", ".github/", ".wolfence/"];
    const RISKY_EXACT_PATHS: &[&str] = &[
        "Cargo.toml",
        "Cargo.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "poetry.lock",
        "Dockerfile",
        ".env",
    ];

    let normalized = pattern.trim();
    RISKY_PREFIXES
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(prefix))
        || RISKY_EXACT_PATHS.contains(&normalized)
}

fn check_receipts_trackability(repo_root: &Path) -> AppResult<DoctorCheck> {
    let ignored = git::is_path_ignored(repo_root, Path::new(".wolfence/receipts/example.toml"))?;
    let (status, detail, remediation) = if ignored {
        (
            DoctorStatus::Warn,
            format!(
                "{} is ignored by Git, so override receipts would not be reviewable by default.",
                RECEIPTS_DIR_RELATIVE_PATH
            ),
            Some(
                "Adjust `.gitignore` so `.wolfence/receipts/*.toml` can be committed when needed."
                    .to_string(),
            ),
        )
    } else {
        (
            DoctorStatus::Pass,
            format!(
                "{} is trackable by Git for reviewable override receipts.",
                RECEIPTS_DIR_RELATIVE_PATH
            ),
            None,
        )
    };

    Ok(DoctorCheck {
        name: "receipt trackability",
        status,
        detail,
        remediation,
    })
}

fn check_receipt_policy_trackability(repo_root: &Path) -> AppResult<DoctorCheck> {
    let policy = ReceiptApprovalPolicy::load_for_repo(repo_root)?;
    if !policy.exists {
        return Ok(DoctorCheck {
            name: "receipt approval policy",
            status: DoctorStatus::Info,
            detail: format!(
                "{} does not exist yet, so receipt governance is relying on defaults.",
                RECEIPT_POLICY_FILE_RELATIVE_PATH
            ),
            remediation: Some(
                "Run `wolf init` or commit `.wolfence/policy/receipts.toml` if you want explicit reviewer governance."
                    .to_string(),
            ),
        });
    }

    let ignored = git::is_path_ignored(repo_root, Path::new(RECEIPT_POLICY_FILE_RELATIVE_PATH))?;
    let (status, detail, remediation) = if ignored {
        (
            DoctorStatus::Fail,
            format!(
                "{} is ignored by Git, so receipt approval policy cannot be shared or reviewed normally.",
                RECEIPT_POLICY_FILE_RELATIVE_PATH
            ),
            Some(
                "Adjust `.gitignore` so `.wolfence/policy/receipts.toml` is trackable."
                    .to_string(),
            ),
        )
    } else {
        (
            DoctorStatus::Pass,
            format!(
                "{} is present and trackable by Git for explicit receipt governance.",
                RECEIPT_POLICY_FILE_RELATIVE_PATH
            ),
            None,
        )
    };

    Ok(DoctorCheck {
        name: "receipt approval policy",
        status,
        detail,
        remediation,
    })
}

fn check_osv_mode() -> AppResult<DoctorCheck> {
    let mode = OsvMode::resolve()?;
    let (status, detail, remediation) = match mode {
        OsvMode::Off => (
            DoctorStatus::Warn,
            "live OSV advisories are disabled via WOLFENCE_OSV=off.".to_string(),
            Some("Use the default `auto` mode or `require` if you want current advisory intelligence during protected pushes.".to_string()),
        ),
        OsvMode::Auto => (
            DoctorStatus::Pass,
            "live OSV advisories are enabled in best-effort mode for protected pushes.".to_string(),
            None,
        ),
        OsvMode::Require => (
            DoctorStatus::Pass,
            "live OSV advisories are required for protected pushes. Advisory lookup failures will become findings.".to_string(),
            None,
        ),
    };

    Ok(DoctorCheck {
        name: "OSV advisory mode",
        status,
        detail,
        remediation,
    })
}

fn check_github_governance_mode() -> AppResult<DoctorCheck> {
    let mode = GithubGovernanceMode::resolve()?;
    let (status, detail, remediation) = match mode {
        GithubGovernanceMode::Off => (
            DoctorStatus::Warn,
            "live GitHub governance verification is disabled via WOLFENCE_GITHUB_GOVERNANCE=off.".to_string(),
            Some("Use the default `auto` mode or `require` if you want Wolfence doctor to compare repo-as-code governance intent against live GitHub state.".to_string()),
        ),
        GithubGovernanceMode::Auto => (
            DoctorStatus::Pass,
            "live GitHub governance verification is enabled in best-effort mode for doctor.".to_string(),
            None,
        ),
        GithubGovernanceMode::Require => (
            DoctorStatus::Pass,
            "live GitHub governance verification is required for doctor. Verification failures will become blocking doctor failures.".to_string(),
            None,
        ),
    };

    Ok(DoctorCheck {
        name: "GitHub governance mode",
        status,
        detail,
        remediation,
    })
}

fn check_trust_trackability(repo_root: &Path) -> AppResult<DoctorCheck> {
    let ignored = git::is_path_ignored(repo_root, Path::new(".wolfence/trust/example.pem"))?;
    let (status, detail, remediation) = if ignored {
        (
            DoctorStatus::Warn,
            format!(
                "{} is ignored by Git, so signed-receipt trust material would not be reviewable by default.",
                TRUST_DIR_RELATIVE_PATH
            ),
            Some(
                "Adjust `.gitignore` so `.wolfence/trust/*.pem` can be committed when the repository adopts signed receipts."
                    .to_string(),
            ),
        )
    } else {
        (
            DoctorStatus::Pass,
            format!(
                "{} is trackable by Git for reviewable receipt trust material.",
                TRUST_DIR_RELATIVE_PATH
            ),
            None,
        )
    };

    Ok(DoctorCheck {
        name: "trust trackability",
        status,
        detail,
        remediation,
    })
}

fn check_receipt_signature_policy(repo_root: &Path) -> AppResult<DoctorCheck> {
    let trust = TrustStore::load_for_repo(repo_root)?;
    let policy = ReceiptApprovalPolicy::load_for_repo(repo_root)?;

    if trust.published_key_count() > 0 && trust.key_count() == 0 {
        return Ok(DoctorCheck {
            name: "receipt signature policy",
            status: DoctorStatus::Fail,
            detail: format!(
                "the repository publishes {} trust key file(s), but all of them are currently inactive or expired.",
                trust.published_key_count()
            ),
            remediation: Some(
                "Renew or replace the expired trust keys under `.wolfence/trust/`, or remove stale trust material if signed receipts should no longer be required."
                    .to_string(),
            ),
        });
    }

    if trust.requires_signed_receipts() {
        return Ok(DoctorCheck {
            name: "receipt signature policy",
            status: DoctorStatus::Pass,
            detail: format!(
                "the repository publishes {} active trusted receipt key(s), so signed receipts are globally required.",
                trust.key_count()
            ),
            remediation: None,
        });
    }

    if policy.any_signed_receipt_requirement() {
        if trust.key_count() == 0 {
            return Ok(DoctorCheck {
                name: "receipt signature policy",
                status: DoctorStatus::Fail,
                detail: "receipt policy requires signed receipts for at least one category, but `.wolfence/trust/` does not currently publish any trusted public keys.".to_string(),
                remediation: Some(
                    "Add at least one trusted public key under `.wolfence/trust/`, or relax `require_signed_receipts` in `.wolfence/policy/receipts.toml`."
                        .to_string(),
                ),
            });
        }

        return Ok(DoctorCheck {
            name: "receipt signature policy",
            status: DoctorStatus::Pass,
            detail: format!(
                "receipt policy requires signed receipts for at least one category, and {} trusted key(s) are available for verification.",
                trust.key_count()
            ),
            remediation: None,
        });
    }

    Ok(DoctorCheck {
        name: "receipt signature policy",
        status: DoctorStatus::Info,
        detail: "signed receipts are not currently required by repo policy or trust-store posture."
            .to_string(),
        remediation: None,
    })
}

fn check_trust_metadata(repo_root: &Path) -> AppResult<DoctorCheck> {
    let trust = TrustStore::load_for_repo(repo_root)?;

    if trust.published_key_count() == 0 {
        return Ok(DoctorCheck {
            name: "trust metadata",
            status: DoctorStatus::Info,
            detail: "no published trust keys are present, so trust metadata is not yet in use."
                .to_string(),
            remediation: None,
        });
    }

    if trust.metadata_missing > 0 {
        return Ok(DoctorCheck {
            name: "trust metadata",
            status: DoctorStatus::Warn,
            detail: format!(
                "{} published trust key(s) do not have companion metadata files under `.wolfence/trust/*.toml`.",
                trust.metadata_missing
            ),
            remediation: Some(
                "Add metadata files with `owner` and `expires_on` for each trusted key so signer rotation and expiry stay reviewable."
                    .to_string(),
            ),
        });
    }

    if trust.metadata_incomplete > 0 {
        return Ok(DoctorCheck {
            name: "trust metadata",
            status: DoctorStatus::Warn,
            detail: format!(
                "{} trust metadata file(s) are present but missing required `owner` or `expires_on` fields.",
                trust.metadata_incomplete
            ),
            remediation: Some(
                "Fill in `owner` and `expires_on` for every trusted key metadata file so trust activation stays explicit and reviewable."
                    .to_string(),
            ),
        });
    }

    if trust.expired_keys > 0 {
        return Ok(DoctorCheck {
            name: "trust metadata",
            status: DoctorStatus::Warn,
            detail: format!("{} trust key(s) are expired and inactive.", trust.expired_keys),
            remediation: Some(
                "Renew or replace expired trust keys, then remove stale metadata and public keys from `.wolfence/trust/`."
                    .to_string(),
            ),
        });
    }

    if trust.unrestricted_keys > 0 {
        return Ok(DoctorCheck {
            name: "trust metadata",
            status: DoctorStatus::Warn,
            detail: format!(
                "{} active trust key(s) do not declare category scope and can approve receipts for any category.",
                trust.unrestricted_keys
            ),
            remediation: Some(
                "Add `categories = [\"...\"]` to each trust metadata file so receipt signing keys are scoped by purpose."
                    .to_string(),
            ),
        });
    }

    Ok(DoctorCheck {
        name: "trust metadata",
        status: DoctorStatus::Pass,
        detail: format!(
            "all {} published trust key(s) have metadata, are currently active, and are category-scoped.",
            trust.published_key_count()
        ),
        remediation: None,
    })
}

fn check_environment_override(config: &ResolvedConfig) -> Option<DoctorCheck> {
    if config.mode_source != ConfigSource::EnvironmentOverride {
        return None;
    }

    Some(DoctorCheck {
        name: "mode override",
        status: DoctorStatus::Warn,
        detail: "WOLFENCE_MODE is overriding repository policy for this shell session.".to_string(),
        remediation: Some(
            "Unset `WOLFENCE_MODE` before relying on the repository's shared enforcement posture."
                .to_string(),
        ),
    })
}

fn check_dry_run_override() -> Option<DoctorCheck> {
    if !dry_run_enabled() {
        return None;
    }

    Some(DoctorCheck {
        name: "dry-run override",
        status: DoctorStatus::Warn,
        detail: "WOLFENCE_DRY_RUN is enabled, so `wolf push` will skip the final `git push` side effect.".to_string(),
        remediation: Some("Unset `WOLFENCE_DRY_RUN` before validating the full protected push path.".to_string()),
    })
}

fn check_wolf_runtime() -> DoctorCheck {
    let binary_path = match hooks::runtime_binary_path() {
        Ok(path) => path,
        Err(error) => {
            return DoctorCheck {
                name: "wolf runtime",
                status: DoctorStatus::Fail,
                detail: format!("failed to resolve the running Wolf executable: {error}"),
                remediation: Some(
                    "Reinstall Wolfence so native Git hooks can call a stable `wolf` binary."
                        .to_string(),
                ),
            };
        }
    };

    if binary_path.exists() {
        return DoctorCheck {
            name: "wolf runtime",
            status: DoctorStatus::Pass,
            detail: format!(
                "the running Wolf executable is available at `{}` and can be pinned into managed hooks.",
                binary_path.display()
            ),
            remediation: None,
        };
    }

    let cargo_output = Command::new("cargo").arg("--version").output();
    match cargo_output {
        Ok(command) if command.status.success() => DoctorCheck {
            name: "wolf runtime",
            status: DoctorStatus::Warn,
            detail: format!(
                "the current Wolf executable path `{}` does not exist, but cargo is available as a development fallback: {}",
                binary_path.display(),
                String::from_utf8_lossy(&command.stdout).trim()
            ),
            remediation: Some(
                "Reinstall Wolfence so managed hooks can pin a stable binary instead of relying on Cargo fallback."
                    .to_string(),
            ),
        },
        Ok(command) => DoctorCheck {
            name: "wolf runtime",
            status: DoctorStatus::Fail,
            detail: format!(
                "the current Wolf executable path `{}` does not exist, and cargo fallback also failed: {}",
                binary_path.display(),
                String::from_utf8_lossy(&command.stderr).trim()
            ),
            remediation: Some(
                "Reinstall Wolfence or repair the local Rust toolchain before relying on managed Git hooks."
                    .to_string(),
            ),
        },
        Err(error) => DoctorCheck {
            name: "wolf runtime",
            status: DoctorStatus::Fail,
            detail: format!(
                "the current Wolf executable path `{}` does not exist, and cargo fallback is unavailable: {error}",
                binary_path.display()
            ),
            remediation: Some(
                "Reinstall Wolfence so managed hooks can invoke a stable binary directly."
                    .to_string(),
            ),
        },
    }
}

fn check_git_identity(repo_root: &Path) -> AppResult<DoctorCheck> {
    let user_name = git::config_value(repo_root, "user.name")?;
    let user_email = git::config_value(repo_root, "user.email")?;

    match (user_name, user_email) {
        (Some(name), Some(email)) => Ok(DoctorCheck {
            name: "git identity",
            status: DoctorStatus::Pass,
            detail: format!("git commits will use `{name} <{email}>`."),
            remediation: None,
        }),
        (None, None) => Ok(DoctorCheck {
            name: "git identity",
            status: DoctorStatus::Warn,
            detail: "Git user.name and user.email are not configured for this repository context."
                .to_string(),
            remediation: Some(
                "Set `git config user.name \"Your Name\"` and `git config user.email \"you@example.com\"` before trying the prototype commit and push flows."
                    .to_string(),
            ),
        }),
        (Some(name), None) => Ok(DoctorCheck {
            name: "git identity",
            status: DoctorStatus::Warn,
            detail: format!(
                "Git user.name is configured as `{name}`, but user.email is still missing."
            ),
            remediation: Some(
                "Set `git config user.email \"you@example.com\"` before creating prototype commits."
                    .to_string(),
            ),
        }),
        (None, Some(email)) => Ok(DoctorCheck {
            name: "git identity",
            status: DoctorStatus::Warn,
            detail: format!(
                "Git user.email is configured as `{email}`, but user.name is still missing."
            ),
            remediation: Some(
                "Set `git config user.name \"Your Name\"` before creating prototype commits."
                    .to_string(),
            ),
        }),
    }
}

fn check_push_remote(repo_root: &Path) -> AppResult<DoctorCheck> {
    match git::preferred_remote(repo_root)? {
        Some(remote) => Ok(DoctorCheck {
            name: "push remote",
            status: DoctorStatus::Pass,
            detail: format!(
                "initial protected pushes can use remote `{remote}` if no upstream is configured yet."
            ),
            remediation: None,
        }),
        None => Ok(DoctorCheck {
            name: "push remote",
            status: DoctorStatus::Warn,
            detail: "no Git remote is configured, so an initial protected push will fail after policy evaluation allows it.".to_string(),
            remediation: Some(
                "Add a remote such as `git remote add origin <url>` before trying a real initial push."
                    .to_string(),
            ),
        }),
    }
}

fn check_curl_runtime() -> DoctorCheck {
    let output = Command::new("curl").arg("--version").output();
    match output {
        Ok(command) if command.status.success() => DoctorCheck {
            name: "curl runtime",
            status: DoctorStatus::Pass,
            detail: String::from_utf8_lossy(&command.stdout)
                .lines()
                .next()
                .unwrap_or("curl available")
                .to_string(),
            remediation: None,
        },
        Ok(command) => DoctorCheck {
            name: "curl runtime",
            status: DoctorStatus::Warn,
            detail: format!(
                "curl returned a non-success status: {}",
                String::from_utf8_lossy(&command.stderr).trim()
            ),
            remediation: Some(
                "Install or repair `curl` if you want live OSV advisory lookups to succeed."
                    .to_string(),
            ),
        },
        Err(error) => DoctorCheck {
            name: "curl runtime",
            status: DoctorStatus::Warn,
            detail: format!("failed to execute `curl --version`: {error}"),
            remediation: Some(
                "Install `curl` if you want live OSV advisory lookups to succeed.".to_string(),
            ),
        },
    }
}

fn check_gh_runtime() -> DoctorCheck {
    let output = Command::new("gh").arg("--version").output();
    match output {
        Ok(command) if command.status.success() => DoctorCheck {
            name: "gh runtime",
            status: DoctorStatus::Pass,
            detail: String::from_utf8_lossy(&command.stdout)
                .lines()
                .next()
                .unwrap_or("gh available")
                .to_string(),
            remediation: None,
        },
        Ok(command) => DoctorCheck {
            name: "gh runtime",
            status: DoctorStatus::Warn,
            detail: format!(
                "gh returned a non-success status: {}",
                String::from_utf8_lossy(&command.stderr).trim()
            ),
            remediation: Some(
                "Install or repair GitHub CLI if you want live GitHub governance verification to succeed."
                    .to_string(),
            ),
        },
        Err(error) => DoctorCheck {
            name: "gh runtime",
            status: DoctorStatus::Warn,
            detail: format!("failed to execute `gh --version`: {error}"),
            remediation: Some(
                "Install GitHub CLI if you want live GitHub governance verification to succeed."
                    .to_string(),
            ),
        },
    }
}

fn check_openssl_runtime(repo_root: &Path) -> AppResult<DoctorCheck> {
    let trust = TrustStore::load_for_repo(repo_root)?;
    let output = Command::new("openssl").arg("version").output();

    let check = match output {
        Ok(command) if command.status.success() => DoctorCheck {
            name: "openssl runtime",
            status: DoctorStatus::Pass,
            detail: String::from_utf8_lossy(&command.stdout).trim().to_string(),
            remediation: None,
        },
        Ok(command) => DoctorCheck {
            name: "openssl runtime",
            status: if trust.requires_signed_receipts() {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            },
            detail: format!(
                "openssl returned a non-success status: {}",
                String::from_utf8_lossy(&command.stderr).trim()
            ),
            remediation: Some(if trust.requires_signed_receipts() {
                "Install or repair `openssl` because this repository publishes trusted receipt keys and signed receipts cannot be verified without it.".to_string()
            } else {
                "Install `openssl` before adopting signed override receipts in this repository."
                    .to_string()
            }),
        },
        Err(error) => DoctorCheck {
            name: "openssl runtime",
            status: if trust.requires_signed_receipts() {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Warn
            },
            detail: format!("failed to execute `openssl version`: {error}"),
            remediation: Some(if trust.requires_signed_receipts() {
                "Install `openssl` because this repository requires signed receipt verification."
                    .to_string()
            } else {
                "Install `openssl` before adopting signed override receipts in this repository."
                    .to_string()
            }),
        },
    };

    Ok(check)
}

fn check_pre_push_hook(repo_root: &Path) -> AppResult<DoctorCheck> {
    let inspection = hooks::inspect_hook(repo_root, "pre-push")?;

    let launcher_detail = inspection
        .launcher
        .map(HookLauncherKind::description)
        .unwrap_or("unknown launcher");

    let (status, detail, remediation) = match inspection.state {
        HookState::Missing => (
            DoctorStatus::Warn,
            format!(
                "{} is missing, so native `git push` is currently unguarded. Only `wolf push` enforces policy.",
                inspection.path.display()
            ),
            Some("Run `wolf init` to install the managed pre-push hook.".to_string()),
        ),
        HookState::Unmanaged => (
            DoctorStatus::Warn,
            format!(
                "{} exists but is not managed by Wolfence, so native `git push` may bypass or diverge from Wolfence policy.",
                inspection.path.display()
            ),
            Some("Review the existing hook and either integrate Wolfence into it or replace it with the managed hook.".to_string()),
        ),
        HookState::Managed if !inspection.executable => (
            DoctorStatus::Fail,
            format!(
                "{} is managed by Wolfence but is not executable, so Git will not run it.",
                inspection.path.display()
            ),
            Some("Re-run `wolf init` to restore executable hook permissions.".to_string()),
        ),
        HookState::Managed => (
            DoctorStatus::Pass,
            format!(
                "{} is managed by Wolfence, executable, and uses {}.",
                inspection.path.display(),
                launcher_detail
            ),
            None,
        ),
    };

    Ok(DoctorCheck {
        name: inspection.hook_name,
        status,
        detail,
        remediation,
    })
}

fn check_audit_log(repo_root: &Path) -> AppResult<DoctorCheck> {
    let audit = audit::verify_audit_log(repo_root)?;
    let (status, detail, remediation) = if !audit.healthy {
        (
            DoctorStatus::Fail,
            format!(
                "{} is unhealthy: {}",
                audit.log_path.display(),
                audit
                    .issue
                    .unwrap_or_else(|| "unknown audit chain issue".to_string())
            ),
            Some(
                "Investigate local tampering or log corruption before trusting recent protected push history."
                    .to_string(),
            ),
        )
    } else if audit.entries == 0 {
        (
            DoctorStatus::Info,
            format!(
                "{} does not exist yet because no protected push decisions have been recorded.",
                audit.log_path.display()
            ),
            None,
        )
    } else {
        (
            DoctorStatus::Pass,
            format!(
                "{} contains {} verified chained audit entr{}.",
                audit.log_path.display(),
                audit.entries,
                if audit.entries == 1 { "y" } else { "ies" }
            ),
            None,
        )
    };

    Ok(DoctorCheck {
        name: "audit log",
        status,
        detail,
        remediation,
    })
}

fn check_receipt_posture(repo_root: &Path) -> AppResult<DoctorCheck> {
    let receipts = ReceiptIndex::load_for_repo(repo_root)?;
    let (status, detail, remediation) = if !receipts.issues.is_empty() {
        (
            DoctorStatus::Warn,
            if receipts.signed_receipts_required || receipts.approval_policy_exists {
                format!(
                    "{} active receipt issue(s) were found while receipt governance is active, so some intended overrides are being ignored.",
                    receipts.issues.len(),
                )
            } else {
                format!(
                    "{} active receipt issue(s) were found, so some intended overrides are being ignored.",
                    receipts.issues.len()
                )
            },
            Some("Review the ignored receipt issues in `wolf push` or fix the files under `.wolfence/receipts/`.".to_string()),
        )
    } else if receipts.legacy_active_receipts > 0 {
        (
            DoctorStatus::Warn,
            format!(
                "{} active override receipt(s) still use legacy category inference instead of an explicit `category` field.",
                receipts.legacy_active_receipts
            ),
            Some(
                "Re-sign or regenerate legacy receipts so they become category-bound, or enable `require_explicit_category = true` in `.wolfence/policy/receipts.toml` once migration is complete."
                    .to_string(),
            ),
        )
    } else if receipts.active.is_empty() {
        (
            DoctorStatus::Info,
            if receipts.signed_receipts_required {
                format!(
                    "no active override receipts are present. Signed receipts are required because the repository publishes {} trusted key(s), which is the safest default posture.",
                    receipts.trusted_keys
                )
            } else if receipts.approval_policy_exists {
                "no active override receipts are present. Receipt approval policy exists, so future exceptions will be constrained by explicit reviewer governance.".to_string()
            } else {
                "no active override receipts are present, which is the safest default posture."
                    .to_string()
            },
            None,
        )
    } else {
        (
            DoctorStatus::Pass,
            if receipts.signed_receipts_required || receipts.approval_policy_exists {
                format!(
                    "{} active override receipt(s) are currently loaded under explicit receipt governance.",
                    receipts.active.len(),
                )
            } else {
                format!(
                    "{} active override receipt(s) are currently loaded.",
                    receipts.active.len()
                )
            },
            None,
        )
    };

    Ok(DoctorCheck {
        name: "override receipts",
        status,
        detail,
        remediation,
    })
}

fn check_push_window(repo_root: &Path, config: &ResolvedConfig) -> AppResult<DoctorCheck> {
    let push_status = git::push_status(repo_root)?;
    Ok(describe_push_window(push_status, config))
}

fn check_live_github_governance(repo_root: &Path) -> AppResult<DoctorCheck> {
    let mode = GithubGovernanceMode::resolve()?;
    if mode == GithubGovernanceMode::Off {
        return Ok(DoctorCheck {
            name: "live GitHub governance",
            status: DoctorStatus::Info,
            detail: "live GitHub governance verification is disabled, so doctor is not comparing repo-as-code governance intent against GitHub's live server-side state.".to_string(),
            remediation: Some(
                "Use the default `auto` mode or `require` if you want Wolfence to compare live GitHub enforcement during doctor and protected push."
                    .to_string(),
            ),
        });
    }

    match github_governance::verify_live_governance(repo_root) {
        Ok(verification) => {
            if verification.repository.is_none() {
                return Ok(DoctorCheck {
                    name: "live GitHub governance",
                    status: DoctorStatus::Info,
                    detail: "the preferred Git remote is not a GitHub repository, so live GitHub governance verification does not apply.".to_string(),
                    remediation: None,
                });
            }

            if !verification.local_intent_present {
                return Ok(DoctorCheck {
                    name: "live GitHub governance",
                    status: DoctorStatus::Info,
                    detail: format!(
                        "no local repo-admin governance intent was detected for `{}`, so there is nothing to compare against live GitHub state.",
                        verification.repository.as_deref().unwrap_or("<unknown repo>")
                    ),
                    remediation: None,
                });
            }

            if let Some(reason) = verification.unavailable_reason {
                return Ok(DoctorCheck {
                    name: "live GitHub governance",
                    status: if mode == GithubGovernanceMode::Require {
                        DoctorStatus::Fail
                    } else {
                        DoctorStatus::Warn
                    },
                    detail: format!(
                        "live GitHub governance verification for `{}` could not complete: {reason}",
                        verification.repository.as_deref().unwrap_or("<unknown repo>")
                    ),
                    remediation: Some(
                        "Authenticate GitHub CLI with `gh auth login`, confirm the repository is reachable, or set WOLFENCE_GITHUB_GOVERNANCE=off if this verification should remain disabled."
                            .to_string(),
                    ),
                });
            }

            if verification.drifts.is_empty() {
                return Ok(DoctorCheck {
                    name: "live GitHub governance",
                    status: DoctorStatus::Pass,
                    detail: format!(
                        "repo-as-code governance intent for `{}` matches live GitHub protection across checked branches ({}) and live rulesets. Default branch: `{}`.",
                        verification.repository.as_deref().unwrap_or("<unknown repo>"),
                        verification.checked_branches.join(", "),
                        verification
                            .default_branch
                            .as_deref()
                            .unwrap_or("<unknown branch>")
                    ),
                    remediation: None,
                });
            }

            Ok(DoctorCheck {
                name: "live GitHub governance",
                status: DoctorStatus::Warn,
                detail: format!(
                    "repo-as-code governance intent for `{}` differs from live GitHub state across checked branches ({}): {}",
                    verification.repository.as_deref().unwrap_or("<unknown repo>"),
                    verification.checked_branches.join(", "),
                    verification.drifts.join(" ")
                ),
                remediation: Some(
                    "Align the live GitHub branch protection and rulesets with the repository's governance-as-code intent, or update the repo files so the intended posture is explicit."
                        .to_string(),
                ),
            })
        }
        Err(error) => Ok(DoctorCheck {
            name: "live GitHub governance",
            status: DoctorStatus::Fail,
            detail: format!("live GitHub governance verification failed: {error}"),
            remediation: Some(
                "Repair GitHub CLI authentication or set WOLFENCE_GITHUB_GOVERNANCE=off if live verification should not be required."
                    .to_string(),
            ),
        }),
    }
}

fn describe_push_window(push_status: PushStatus, config: &ResolvedConfig) -> DoctorCheck {
    let (status, detail, remediation) = match push_status {
        PushStatus::NoCommits => (
            DoctorStatus::Info,
            "the current branch has no commits yet, so there is no outbound history to protect."
                .to_string(),
            None,
        ),
        PushStatus::UpToDate => (
            DoctorStatus::Info,
            "the current branch is not ahead of its upstream, so a push would currently be a no-op."
                .to_string(),
            None,
        ),
        PushStatus::Ready {
            current_branch,
            upstream_branch,
            commits_ahead,
            candidate_files,
        } => {
            let ignored_files = candidate_files
                .iter()
                .filter(|path| config.should_ignore_path(path))
                .count();
            let scanned_files = candidate_files.len().saturating_sub(ignored_files);

            if ignored_files > 0 {
                (
                    DoctorStatus::Warn,
                    format!(
                        "branch `{}` is {} commits ahead of {} with {} outbound candidate files: {} scanned and {} ignored by repo-local exclusions.",
                        current_branch,
                        commits_ahead,
                        upstream_branch
                            .as_deref()
                            .unwrap_or("<no upstream: initial push mode>"),
                        candidate_files.len(),
                        scanned_files,
                        ignored_files
                    ),
                    Some(
                        "Review `.wolfence/config.toml` exclusion patterns and confirm the ignored outbound files are limited to low-risk docs, fixtures, or generated artifacts."
                            .to_string(),
                    ),
                )
            } else {
                (
                    DoctorStatus::Info,
                    format!(
                        "branch `{}` is {} commits ahead of {} with {} candidate files in scope.",
                        current_branch,
                        commits_ahead,
                        upstream_branch
                            .as_deref()
                            .unwrap_or("<no upstream: initial push mode>"),
                        candidate_files.len()
                    ),
                    None,
                )
            }
        }
    };

    DoctorCheck {
        name: "push window",
        status,
        detail,
        remediation,
    }
}

fn summarize_checks(checks: &[DoctorCheck]) -> DoctorSummary {
    let mut summary = DoctorSummary::default();

    for check in checks {
        match check.status {
            DoctorStatus::Pass => summary.pass += 1,
            DoctorStatus::Warn => summary.warn += 1,
            DoctorStatus::Fail => summary.fail += 1,
            DoctorStatus::Info => summary.info += 1,
        }
    }

    summary
}

fn dry_run_enabled() -> bool {
    matches!(
        std::env::var("WOLFENCE_DRY_RUN").ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        check_scan_ignore_paths, describe_push_window, is_risky_scan_ignore_path, summarize_checks,
        DoctorCheck, DoctorStatus,
    };
    use crate::core::config::{ConfigSource, ResolvedConfig};
    use crate::core::git::PushStatus;
    use crate::core::policy::EnforcementMode;

    #[test]
    fn summarize_counts_each_status_class() {
        let checks = vec![
            DoctorCheck {
                name: "one",
                status: DoctorStatus::Pass,
                detail: String::new(),
                remediation: None,
            },
            DoctorCheck {
                name: "two",
                status: DoctorStatus::Warn,
                detail: String::new(),
                remediation: None,
            },
            DoctorCheck {
                name: "three",
                status: DoctorStatus::Fail,
                detail: String::new(),
                remediation: None,
            },
            DoctorCheck {
                name: "four",
                status: DoctorStatus::Info,
                detail: String::new(),
                remediation: None,
            },
        ];

        let summary = summarize_checks(&checks);
        assert_eq!(summary.pass, 1);
        assert_eq!(summary.warn, 1);
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.info, 1);
    }

    #[test]
    fn flags_high_risk_scan_exclusions() {
        assert!(is_risky_scan_ignore_path("src/"));
        assert!(is_risky_scan_ignore_path(".github/workflows/"));
        assert!(is_risky_scan_ignore_path("Cargo.toml"));
        assert!(!is_risky_scan_ignore_path("docs/"));
        assert!(!is_risky_scan_ignore_path("fixtures/**"));
    }

    #[test]
    fn warns_when_scan_exclusions_cover_core_project_paths() {
        let config = ResolvedConfig {
            mode: EnforcementMode::Standard,
            mode_source: ConfigSource::RepoFile,
            repo_config_path: Path::new(".wolfence/config.toml").to_path_buf(),
            repo_config_exists: true,
            scan_ignore_paths: vec!["docs/".to_string(), "src/".to_string()],
            node_internal_packages: Vec::new(),
            node_internal_package_prefixes: Vec::new(),
            node_registry_ownership: Vec::new(),
            ruby_source_ownership: Vec::new(),
            python_internal_packages: Vec::new(),
            python_internal_package_prefixes: Vec::new(),
            python_index_ownership: Vec::new(),
        };

        let check = check_scan_ignore_paths(&config);

        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(check.detail.contains("src/"));
    }

    #[test]
    fn warns_when_push_window_contains_ignored_outbound_files() {
        let config = ResolvedConfig {
            mode: EnforcementMode::Standard,
            mode_source: ConfigSource::RepoFile,
            repo_config_path: Path::new(".wolfence/config.toml").to_path_buf(),
            repo_config_exists: true,
            scan_ignore_paths: vec!["docs/".to_string()],
            node_internal_packages: Vec::new(),
            node_internal_package_prefixes: Vec::new(),
            node_registry_ownership: Vec::new(),
            ruby_source_ownership: Vec::new(),
            python_internal_packages: Vec::new(),
            python_internal_package_prefixes: Vec::new(),
            python_index_ownership: Vec::new(),
        };

        let check = describe_push_window(
            PushStatus::Ready {
                current_branch: "main".to_string(),
                upstream_branch: Some("origin/main".to_string()),
                commits_ahead: 2,
                candidate_files: vec![
                    Path::new("src/main.rs").to_path_buf(),
                    Path::new("docs/request.md").to_path_buf(),
                ],
            },
            &config,
        );

        assert_eq!(check.status, DoctorStatus::Warn);
        assert!(check.detail.contains("1 scanned and 1 ignored"));
    }
}
