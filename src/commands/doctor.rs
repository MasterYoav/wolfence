//! `wolfence doctor`
//!
//! A local security gate needs an operator-facing audit path, not just scans.
//! This command checks whether the repository is configured in a way that makes
//! Wolfence trustworthy in day-to-day use.

use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::process::{Command, ExitCode};

use crate::app::AppResult;
use crate::core::audit;
use crate::core::config::{ConfigSource, ResolvedConfig, REPO_CONFIG_RELATIVE_PATH};
use crate::core::git;
use crate::core::git::PushStatus;
use crate::core::hooks::{self, HookState};
use crate::core::osv::OsvMode;
use crate::core::policy::EnforcementMode;
use crate::core::receipt_policy::{ReceiptApprovalPolicy, RECEIPT_POLICY_FILE_RELATIVE_PATH};
use crate::core::receipts::{ReceiptIndex, RECEIPTS_DIR_RELATIVE_PATH};
use crate::core::trust::{TrustStore, TRUST_DIR_RELATIVE_PATH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
struct DoctorCheck {
    name: &'static str,
    status: DoctorStatus,
    detail: String,
    remediation: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
struct DoctorSummary {
    pass: usize,
    warn: usize,
    fail: usize,
    info: usize,
}

pub fn run() -> AppResult<ExitCode> {
    let repo_root = git::discover_repo_root()?;
    let config = ResolvedConfig::load_for_repo(&repo_root)?;
    let checks = build_checks(&repo_root, &config)?;
    let summary = summarize_checks(&checks);

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
    checks.push(check_osv_mode()?);

    if let Some(check) = check_environment_override(config) {
        checks.push(check);
    }

    if let Some(check) = check_dry_run_override() {
        checks.push(check);
    }

    checks.push(check_cargo_runtime());
    checks.push(check_git_identity(repo_root)?);
    checks.push(check_push_remote(repo_root)?);
    checks.push(check_curl_runtime());
    checks.push(check_openssl_runtime(repo_root)?);
    checks.push(check_pre_push_hook(repo_root)?);
    checks.push(check_audit_log(repo_root)?);
    checks.push(check_receipt_posture(repo_root)?);
    checks.push(check_push_window(repo_root)?);

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
        Some(
            "Run `cargo run -- init` so the repository policy is explicit and reviewable."
                .to_string(),
        )
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
                "Run `cargo run -- init` or commit `.wolfence/policy/receipts.toml` if you want explicit reviewer governance."
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
        detail: "WOLFENCE_DRY_RUN is enabled, so `wolfence push` will skip the final `git push` side effect.".to_string(),
        remediation: Some("Unset `WOLFENCE_DRY_RUN` before validating the full protected push path.".to_string()),
    })
}

fn check_cargo_runtime() -> DoctorCheck {
    let output = Command::new("cargo").arg("--version").output();
    match output {
        Ok(command) if command.status.success() => DoctorCheck {
            name: "cargo runtime",
            status: DoctorStatus::Pass,
            detail: String::from_utf8_lossy(&command.stdout).trim().to_string(),
            remediation: None,
        },
        Ok(command) => DoctorCheck {
            name: "cargo runtime",
            status: DoctorStatus::Fail,
            detail: format!(
                "cargo returned a non-success status: {}",
                String::from_utf8_lossy(&command.stderr).trim()
            ),
            remediation: Some("Install or repair the local Rust toolchain because the managed Git hook executes Wolfence through `cargo run` during development.".to_string()),
        },
        Err(error) => DoctorCheck {
            name: "cargo runtime",
            status: DoctorStatus::Fail,
            detail: format!("failed to execute `cargo --version`: {error}"),
            remediation: Some("Install the Rust toolchain so the managed pre-push hook can execute Wolfence.".to_string()),
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

    let (status, detail, remediation) = match inspection.state {
        HookState::Missing => (
            DoctorStatus::Warn,
            format!(
                "{} is missing, so native `git push` is currently unguarded. Only `wolfence push` enforces policy.",
                inspection.path.display()
            ),
            Some("Run `cargo run -- init` to install the managed pre-push hook.".to_string()),
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
            Some("Re-run `cargo run -- init` to restore executable hook permissions.".to_string()),
        ),
        HookState::Managed => (
            DoctorStatus::Pass,
            format!(
                "{} is managed by Wolfence and executable.",
                inspection.path.display()
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
            Some("Review the ignored receipt issues in `wolfence push` or fix the files under `.wolfence/receipts/`.".to_string()),
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

fn check_push_window(repo_root: &Path) -> AppResult<DoctorCheck> {
    let push_status = git::push_status(repo_root)?;
    let detail = match push_status {
        PushStatus::NoCommits => {
            "the current branch has no commits yet, so there is no outbound history to protect."
                .to_string()
        }
        PushStatus::UpToDate => {
            "the current branch is not ahead of its upstream, so a push would currently be a no-op."
                .to_string()
        }
        PushStatus::Ready {
            current_branch,
            upstream_branch,
            commits_ahead,
            candidate_files,
        } => format!(
            "branch `{}` is {} commits ahead of {} with {} candidate files in scope.",
            current_branch,
            commits_ahead,
            upstream_branch
                .as_deref()
                .unwrap_or("<no upstream: initial push mode>"),
            candidate_files.len()
        ),
    };

    Ok(DoctorCheck {
        name: "push window",
        status: DoctorStatus::Info,
        detail,
        remediation: None,
    })
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
    use super::{summarize_checks, DoctorCheck, DoctorStatus};

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
}
