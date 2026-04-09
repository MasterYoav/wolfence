//! Command-line parsing for Wolfence.
//!
//! The first scaffold intentionally avoids external crates so the repository can
//! compile in a constrained environment without network access. Once the CLI
//! surface stabilizes, migrating to `clap` is reasonable.

/// Parsed application invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// The top-level subcommand the user selected.
    pub command: Command,
}

/// Parsed receipt-specific operator workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptCommand {
    New {
        receipt_path: String,
        action: String,
        category: String,
        fingerprint: String,
        owner: String,
        expires_on: String,
        reason: String,
    },
    Checksum {
        receipt_path: String,
    },
    Verify {
        receipt_path: String,
    },
    List,
    Archive {
        receipt_path: String,
        reason: String,
    },
    Sign {
        receipt_path: String,
        approver: String,
        key_id: String,
        private_key_path: String,
    },
    Help,
}

/// Parsed trust-specific operator workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustCommand {
    List,
    Verify {
        key_id: String,
    },
    Init {
        key_id: String,
        owner: String,
        expires_on: String,
        categories: Option<String>,
    },
    Archive {
        key_id: String,
        reason: String,
    },
    Restore {
        key_id: String,
    },
    Help,
}

/// Parsed audit-specific operator workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditCommand {
    List { json: bool },
    Verify { json: bool },
    Help,
}

/// Parsed scan-specific operator workflows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanCommand {
    Staged { json: bool },
    Push { json: bool },
    Help,
}

/// Parsed top-level command plus any validated arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Init,
    Push { json: bool },
    HookPrePush,
    Scan(ScanCommand),
    Doctor { json: bool },
    Config,
    Receipt(ReceiptCommand),
    Trust(TrustCommand),
    Audit(AuditCommand),
    Help,
    Version,
}

impl Cli {
    /// Parses the command from raw process arguments.
    pub fn parse<I>(mut args: I) -> Result<Self, String>
    where
        I: Iterator<Item = String>,
    {
        let command = match args.next().as_deref() {
            None => Command::Help,
            Some("init") => {
                ensure_no_extra_args(args)?;
                Command::Init
            }
            Some("push") => Command::Push {
                json: parse_json_flag(args)?,
            },
            Some("hook-pre-push") => {
                ensure_no_extra_args(args)?;
                Command::HookPrePush
            }
            Some("scan") => Command::Scan(parse_scan_command(args)?),
            Some("doctor") => Command::Doctor {
                json: parse_json_flag(args)?,
            },
            Some("config") => {
                ensure_no_extra_args(args)?;
                Command::Config
            }
            Some("receipt") => Command::Receipt(parse_receipt_command(args)?),
            Some("trust") => Command::Trust(parse_trust_command(args)?),
            Some("audit") => Command::Audit(parse_audit_command(args)?),
            Some("-h" | "--help" | "help") => {
                ensure_no_extra_args(args)?;
                Command::Help
            }
            Some("-V" | "--version" | "version") => {
                ensure_no_extra_args(args)?;
                Command::Version
            }
            Some(other) => {
                return Err(format!(
                    "unknown command `{other}`. Run `wolf help` to see the supported interface."
                ))
            }
        };

        Ok(Self { command })
    }
}

fn parse_receipt_command<I>(mut args: I) -> Result<ReceiptCommand, String>
where
    I: Iterator<Item = String>,
{
    let subcommand = match args.next().as_deref() {
        Some("new") => {
            let receipt_path = require_arg(&mut args, "receipt path")?;
            let action = require_arg(&mut args, "action")?;
            let category = require_arg(&mut args, "category")?;
            let fingerprint = require_arg(&mut args, "fingerprint")?;
            let owner = require_arg(&mut args, "owner")?;
            let expires_on = require_arg(&mut args, "expires_on")?;
            let reason = require_arg(&mut args, "reason")?;
            ensure_no_extra_args(args)?;
            ReceiptCommand::New {
                receipt_path,
                action,
                category,
                fingerprint,
                owner,
                expires_on,
                reason,
            }
        }
        Some("checksum") => {
            let receipt_path = require_arg(&mut args, "receipt path")?;
            ensure_no_extra_args(args)?;
            ReceiptCommand::Checksum { receipt_path }
        }
        Some("verify") => {
            let receipt_path = require_arg(&mut args, "receipt path")?;
            ensure_no_extra_args(args)?;
            ReceiptCommand::Verify { receipt_path }
        }
        Some("list") => {
            ensure_no_extra_args(args)?;
            ReceiptCommand::List
        }
        Some("archive") => {
            let receipt_path = require_arg(&mut args, "receipt path")?;
            let reason = require_arg(&mut args, "reason")?;
            ensure_no_extra_args(args)?;
            ReceiptCommand::Archive { receipt_path, reason }
        }
        Some("sign") => {
            let receipt_path = require_arg(&mut args, "receipt path")?;
            let approver = require_arg(&mut args, "approver")?;
            let key_id = require_arg(&mut args, "key id")?;
            let private_key_path = require_arg(&mut args, "private key path")?;
            ensure_no_extra_args(args)?;
            ReceiptCommand::Sign {
                receipt_path,
                approver,
                key_id,
                private_key_path,
            }
        }
        None | Some("-h" | "--help" | "help") => {
            ensure_no_extra_args(args)?;
            ReceiptCommand::Help
        }
        Some(other) => {
            return Err(format!(
                "unknown receipt command `{other}`. Run `wolf receipt help` to see the supported receipt workflows."
            ))
        }
    };

    Ok(subcommand)
}

fn parse_trust_command<I>(mut args: I) -> Result<TrustCommand, String>
where
    I: Iterator<Item = String>,
{
    let subcommand = match args.next().as_deref() {
        Some("list") => {
            ensure_no_extra_args(args)?;
            TrustCommand::List
        }
        Some("verify") => {
            let key_id = require_arg(&mut args, "key id")?;
            ensure_no_extra_args(args)?;
            TrustCommand::Verify { key_id }
        }
        Some("init") => {
            let key_id = require_arg(&mut args, "key id")?;
            let owner = require_arg(&mut args, "owner")?;
            let expires_on = require_arg(&mut args, "expires_on")?;
            let categories = args.next();
            ensure_no_extra_args(args)?;
            TrustCommand::Init {
                key_id,
                owner,
                expires_on,
                categories,
            }
        }
        Some("archive") => {
            let key_id = require_arg(&mut args, "key id")?;
            let reason = require_arg(&mut args, "reason")?;
            ensure_no_extra_args(args)?;
            TrustCommand::Archive { key_id, reason }
        }
        Some("restore") => {
            let key_id = require_arg(&mut args, "key id")?;
            ensure_no_extra_args(args)?;
            TrustCommand::Restore { key_id }
        }
        None | Some("-h" | "--help" | "help") => {
            ensure_no_extra_args(args)?;
            TrustCommand::Help
        }
        Some(other) => {
            return Err(format!(
                "unknown trust command `{other}`. Run `wolf trust help` to see the supported trust workflows."
            ))
        }
    };

    Ok(subcommand)
}

fn parse_audit_command<I>(mut args: I) -> Result<AuditCommand, String>
where
    I: Iterator<Item = String>,
{
    let mut args = collect_args(&mut args);
    let subcommand = match args.next().as_deref() {
        Some("list") => {
            AuditCommand::List {
                json: parse_json_flag(args)?,
            }
        }
        Some("verify") => {
            AuditCommand::Verify {
                json: parse_json_flag(args)?,
            }
        }
        None | Some("-h" | "--help" | "help") => {
            ensure_no_extra_args(args)?;
            AuditCommand::Help
        }
        Some(other) => {
            return Err(format!(
                "unknown audit command `{other}`. Run `wolf audit help` to see the supported audit workflows."
            ))
        }
    };

    Ok(subcommand)
}

fn parse_scan_command<I>(mut args: I) -> Result<ScanCommand, String>
where
    I: Iterator<Item = String>,
{
    let mut args = collect_args(&mut args);
    let subcommand = match args.next().as_deref() {
        None => ScanCommand::Staged { json: false },
        Some("push" | "--push") => {
            ScanCommand::Push {
                json: parse_json_flag(args)?,
            }
        }
        Some("staged" | "--staged") => {
            ScanCommand::Staged {
                json: parse_json_flag(args)?,
            }
        }
        Some("--json") => {
            ensure_no_extra_args(args)?;
            ScanCommand::Staged { json: true }
        }
        Some("-h" | "--help" | "help") => {
            ensure_no_extra_args(args)?;
            ScanCommand::Help
        }
        Some(other) => {
            return Err(format!(
                "unknown scan command `{other}`. Run `wolf scan help` to see the supported scan workflows."
            ))
        }
    };

    Ok(subcommand)
}

fn parse_json_flag<I>(args: I) -> Result<bool, String>
where
    I: Iterator<Item = String>,
{
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            other => {
                return Err(format!(
                    "unexpected extra argument `{other}`. The current scaffold accepts only the documented arguments."
                ))
            }
        }
    }

    Ok(json)
}

fn collect_args<I>(args: &mut I) -> std::vec::IntoIter<String>
where
    I: Iterator<Item = String>,
{
    args.collect::<Vec<_>>().into_iter()
}

fn ensure_no_extra_args<I>(mut args: I) -> Result<(), String>
where
    I: Iterator<Item = String>,
{
    if let Some(unexpected) = args.next() {
        return Err(format!(
            "unexpected extra argument `{unexpected}`. The current scaffold accepts only the documented arguments."
        ));
    }

    Ok(())
}

fn require_arg<I>(args: &mut I, label: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| format!("missing required {label}."))
}

#[cfg(test)]
mod tests {
    use super::{AuditCommand, Cli, Command, ReceiptCommand, ScanCommand, TrustCommand};

    #[test]
    fn defaults_to_help_when_no_arguments_are_provided() {
        let cli = Cli::parse(std::iter::empty()).expect("parse should succeed");
        assert_eq!(cli.command, Command::Help);
    }

    #[test]
    fn parses_push_command() {
        let cli = Cli::parse(vec!["push".to_string()].into_iter()).expect("parse should succeed");
        assert_eq!(cli.command, Command::Push { json: false });
    }

    #[test]
    fn parses_push_command_with_json() {
        let cli = Cli::parse(vec!["push".to_string(), "--json".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(cli.command, Command::Push { json: true });
    }

    #[test]
    fn parses_staged_scan_by_default() {
        let cli = Cli::parse(vec!["scan".to_string()].into_iter()).expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Scan(ScanCommand::Staged { json: false })
        );
    }

    #[test]
    fn parses_push_scope_scan_command() {
        let cli = Cli::parse(vec!["scan".to_string(), "push".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Scan(ScanCommand::Push { json: false })
        );
    }

    #[test]
    fn parses_staged_scan_json_flag_without_explicit_subcommand() {
        let cli = Cli::parse(vec!["scan".to_string(), "--json".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Scan(ScanCommand::Staged { json: true })
        );
    }

    #[test]
    fn parses_push_scope_scan_command_with_json() {
        let cli = Cli::parse(
            vec!["scan".to_string(), "push".to_string(), "--json".to_string()].into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(cli.command, Command::Scan(ScanCommand::Push { json: true }));
    }

    #[test]
    fn parses_hook_command() {
        let cli = Cli::parse(vec!["hook-pre-push".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(cli.command, Command::HookPrePush);
    }

    #[test]
    fn parses_receipt_sign_command() {
        let cli = Cli::parse(
            vec![
                "receipt".to_string(),
                "sign".to_string(),
                ".wolfence/receipts/allow.toml".to_string(),
                "security-team".to_string(),
                "security-team".to_string(),
                "/tmp/security-team-private.pem".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Receipt(ReceiptCommand::Sign {
                receipt_path: ".wolfence/receipts/allow.toml".to_string(),
                approver: "security-team".to_string(),
                key_id: "security-team".to_string(),
                private_key_path: "/tmp/security-team-private.pem".to_string(),
            })
        );
    }

    #[test]
    fn parses_receipt_new_command() {
        let cli = Cli::parse(
            vec![
                "receipt".to_string(),
                "new".to_string(),
                ".wolfence/receipts/allow.toml".to_string(),
                "push".to_string(),
                "secret".to_string(),
                "secret:abc123".to_string(),
                "yoav".to_string(),
                "2099-04-30".to_string(),
                "temporary override".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Receipt(ReceiptCommand::New {
                receipt_path: ".wolfence/receipts/allow.toml".to_string(),
                action: "push".to_string(),
                category: "secret".to_string(),
                fingerprint: "secret:abc123".to_string(),
                owner: "yoav".to_string(),
                expires_on: "2099-04-30".to_string(),
                reason: "temporary override".to_string(),
            })
        );
    }

    #[test]
    fn parses_receipt_verify_command() {
        let cli = Cli::parse(
            vec![
                "receipt".to_string(),
                "verify".to_string(),
                ".wolfence/receipts/allow.toml".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Receipt(ReceiptCommand::Verify {
                receipt_path: ".wolfence/receipts/allow.toml".to_string(),
            })
        );
    }

    #[test]
    fn parses_receipt_archive_command() {
        let cli = Cli::parse(
            vec![
                "receipt".to_string(),
                "archive".to_string(),
                ".wolfence/receipts/allow.toml".to_string(),
                "issue resolved".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Receipt(ReceiptCommand::Archive {
                receipt_path: ".wolfence/receipts/allow.toml".to_string(),
                reason: "issue resolved".to_string(),
            })
        );
    }

    #[test]
    fn parses_receipt_list_command() {
        let cli = Cli::parse(vec!["receipt".to_string(), "list".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(cli.command, Command::Receipt(ReceiptCommand::List));
    }

    #[test]
    fn parses_trust_list_command() {
        let cli = Cli::parse(vec!["trust".to_string(), "list".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(cli.command, Command::Trust(TrustCommand::List));
    }

    #[test]
    fn parses_trust_init_command() {
        let cli = Cli::parse(
            vec![
                "trust".to_string(),
                "init".to_string(),
                "security-team".to_string(),
                "security-team".to_string(),
                "2099-12-31".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Trust(TrustCommand::Init {
                key_id: "security-team".to_string(),
                owner: "security-team".to_string(),
                expires_on: "2099-12-31".to_string(),
                categories: None,
            })
        );
    }

    #[test]
    fn parses_scoped_trust_init_command() {
        let cli = Cli::parse(
            vec![
                "trust".to_string(),
                "init".to_string(),
                "security-team".to_string(),
                "security-team".to_string(),
                "2099-12-31".to_string(),
                "secret,policy".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Trust(TrustCommand::Init {
                key_id: "security-team".to_string(),
                owner: "security-team".to_string(),
                expires_on: "2099-12-31".to_string(),
                categories: Some("secret,policy".to_string()),
            })
        );
    }

    #[test]
    fn parses_trust_archive_command() {
        let cli = Cli::parse(
            vec![
                "trust".to_string(),
                "archive".to_string(),
                "security-team".to_string(),
                "rotation complete".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Trust(TrustCommand::Archive {
                key_id: "security-team".to_string(),
                reason: "rotation complete".to_string(),
            })
        );
    }

    #[test]
    fn parses_trust_restore_command() {
        let cli = Cli::parse(
            vec![
                "trust".to_string(),
                "restore".to_string(),
                "security-team".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Trust(TrustCommand::Restore {
                key_id: "security-team".to_string(),
            })
        );
    }

    #[test]
    fn parses_trust_verify_command() {
        let cli = Cli::parse(
            vec![
                "trust".to_string(),
                "verify".to_string(),
                "security-team".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Trust(TrustCommand::Verify {
                key_id: "security-team".to_string(),
            })
        );
    }

    #[test]
    fn parses_audit_list_command() {
        let cli = Cli::parse(vec!["audit".to_string(), "list".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Audit(AuditCommand::List { json: false })
        );
    }

    #[test]
    fn parses_audit_verify_command() {
        let cli = Cli::parse(vec!["audit".to_string(), "verify".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Audit(AuditCommand::Verify { json: false })
        );
    }

    #[test]
    fn parses_audit_verify_command_with_json() {
        let cli = Cli::parse(
            vec![
                "audit".to_string(),
                "verify".to_string(),
                "--json".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse should succeed");
        assert_eq!(
            cli.command,
            Command::Audit(AuditCommand::Verify { json: true })
        );
    }

    #[test]
    fn parses_doctor_command_with_json() {
        let cli = Cli::parse(vec!["doctor".to_string(), "--json".to_string()].into_iter())
            .expect("parse should succeed");
        assert_eq!(cli.command, Command::Doctor { json: true });
    }

    #[test]
    fn rejects_unknown_commands() {
        let error =
            Cli::parse(vec!["ship-it".to_string()].into_iter()).expect_err("parse should fail");
        assert!(error.contains("unknown command"));
    }
}
