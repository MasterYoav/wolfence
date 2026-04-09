//! Built-in scanner interfaces and hardened local detector implementations.
//!
//! The scanner layer is the core of Wolfence's local-first judgment path. These
//! detectors are still heuristic, but they are intentionally structured:
//!
//! - path-aware file classification for obviously sensitive artifacts
//! - high-confidence secret signatures for known token families
//! - generic secret assignment heuristics with placeholder allowlists
//! - dependency intelligence focused on provenance, pinning quality, and lockfile posture
//!
//! The goal is not "match everything". The goal is "block the riskiest outbound
//! mistakes with explainable logic and acceptable false-positive rates."

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::app::AppResult;

use super::context::{ExecutionContext, ProtectedAction};
use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::osv::{self, ResolvedDependency};

const MAX_TEXT_SCAN_BYTES: u64 = 512 * 1024;

/// Shared behavior every scanner must provide.
pub trait Scanner {
    /// Stable scanner identifier for logs, policy, and finding attribution.
    fn name(&self) -> &'static str;
    /// Runs the scanner against the current execution context.
    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>>;
}

/// Secret detection using layered file and content heuristics.
pub struct SecretScanner;

/// Lightweight source pattern detection for obviously dangerous constructs.
pub struct BasicSastScanner;

/// Dependency and lockfile posture analysis.
pub struct DependencyScanner;

/// Configuration and infrastructure checks for unsafe defaults.
pub struct ConfigScanner;

/// Local Wolfence policy posture checks.
pub struct PolicyScanner;

impl Scanner for SecretScanner {
    fn name(&self) -> &'static str {
        "secret-scanner"
    }

    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();

        for file in &context.candidate_files {
            let full_path = context.repo_root.join(file);

            if let Some(finding) = classify_sensitive_path(self.name(), file) {
                record_finding(&mut findings, &mut seen, finding);
            }

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            for (line_number, line) in contents.lines().enumerate() {
                let line_number = line_number + 1;

                if let Some(finding) =
                    scan_private_key_headers(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                for finding in scan_prefixed_secret_tokens(self.name(), file, line_number, line) {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) = scan_secret_assignment(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) = scan_credential_url(self.name(), file, line_number, line) {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_inline_authorization_credential(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_inline_secret_header(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_cookie_header_secret(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }
            }
        }

        Ok(findings)
    }
}

impl Scanner for BasicSastScanner {
    fn name(&self) -> &'static str {
        "basic-sast"
    }

    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();

        for file in &context.candidate_files {
            let full_path = context.repo_root.join(file);

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            for (needle, title, detail, confidence) in [
                (
                    "eval(",
                    "Dynamic code execution pattern detected",
                    "The candidate file references `eval(`, which is a common source of code-injection risk.",
                    Confidence::Medium,
                ),
                (
                    "Runtime.getRuntime().exec",
                    "Command execution sink detected",
                    "The candidate file references a command-execution sink that often needs strict input validation.",
                    Confidence::Medium,
                ),
                (
                    "innerHTML",
                    "Raw HTML sink detected",
                    "The candidate file references `innerHTML`, which can create XSS risk when data is not sanitized.",
                    Confidence::Low,
                ),
            ] {
                if contents.contains(needle) {
                    findings.push(Finding::new(
                        format!("sast.pattern.{needle}"),
                        self.name(),
                        Severity::Medium,
                        confidence,
                        FindingCategory::Vulnerability,
                        Some(file.clone()),
                        title,
                        detail,
                        "Confirm the input path is trusted or replace the construct with a safer pattern.",
                        format!("sast:{}:{needle}", file.display()),
                    ));
                }
            }
        }

        Ok(findings)
    }
}

impl Scanner for DependencyScanner {
    fn name(&self) -> &'static str {
        "dependency-scanner"
    }

    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        let mut findings = dependency_relationship_findings(self.name(), &context.candidate_files);
        let mut seen = findings
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<HashSet<_>>();
        let mut resolved_dependencies = Vec::new();

        for file in &context.candidate_files {
            let full_path = context.repo_root.join(file);
            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            let path_text = file.to_string_lossy();
            let file_name = file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();

            match file_name {
                "Cargo.toml" => {
                    for finding in scan_cargo_manifest(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "Cargo.lock" => {
                    for finding in scan_cargo_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies.extend(extract_cargo_lock_dependencies(file, &contents));
                }
                "package.json" => {
                    for finding in scan_package_json_manifest(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "package-lock.json" | "npm-shrinkwrap.json" => {
                    for finding in scan_package_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies.extend(extract_node_lock_dependencies(file, &contents));
                }
                "pnpm-lock.yaml" => {
                    for finding in scan_pnpm_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "pyproject.toml" => {
                    for finding in scan_pyproject(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "poetry.lock" => {
                    for finding in scan_poetry_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies.extend(extract_poetry_lock_dependencies(file, &contents));
                }
                _ => {
                    if file_name.starts_with("requirements") && path_text.ends_with(".txt") {
                        for finding in scan_requirements(self.name(), file, &contents) {
                            record_finding(&mut findings, &mut seen, finding);
                        }
                        resolved_dependencies
                            .extend(extract_requirements_dependencies(file, &contents));
                    }
                }
            }
        }

        let osv_outcome = osv::scan_dependencies(context.action, resolved_dependencies)?;
        for finding in osv_outcome.findings {
            record_finding(&mut findings, &mut seen, finding);
        }

        if matches!(context.action, ProtectedAction::Push)
            && osv_outcome.mode != osv::OsvMode::Off
            && osv_outcome.attempted
            && osv_outcome.skipped_dependencies > 0
        {
            record_finding(
                &mut findings,
                &mut seen,
                Finding::new(
                    "dependency.osv.truncated-batch",
                    "osv-advisory-scanner",
                    Severity::Low,
                    Confidence::High,
                    FindingCategory::Policy,
                    None,
                    "OSV advisory batch was truncated",
                    format!(
                        "Wolfence queried {} exact-version dependencies against OSV and skipped {} additional dependencies to keep the live request bounded.",
                        osv_outcome.queried_dependencies, osv_outcome.skipped_dependencies
                    ),
                    "Reduce the dependency delta size or run additional scans after the current review cycle if you need broader live advisory coverage.",
                    "dependency-osv-truncated-batch",
                ),
            );
        }

        Ok(findings)
    }
}

impl Scanner for ConfigScanner {
    fn name(&self) -> &'static str {
        "config-scanner"
    }

    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();

        for file in &context.candidate_files {
            let full_path = context.repo_root.join(file);
            let file_name = file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let path_text = file.to_string_lossy();

            let is_config_like = file_name == "Dockerfile"
                || path_text.ends_with(".tf")
                || path_text.contains(".github/workflows")
                || path_text.ends_with(".yaml")
                || path_text.ends_with(".yml");

            if !is_config_like {
                continue;
            }

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            for (needle, title) in [
                (
                    "privileged: true",
                    "Privileged container configuration detected",
                ),
                ("0.0.0.0/0", "Wide-open network exposure detected"),
                (
                    "sudo: required",
                    "Elevated CI runner configuration detected",
                ),
            ] {
                if contents.contains(needle) {
                    findings.push(Finding::new(
                        format!("config.pattern.{needle}"),
                        self.name(),
                        Severity::High,
                        Confidence::Medium,
                        FindingCategory::Configuration,
                        Some(file.clone()),
                        title,
                        format!("The candidate configuration contains `{needle}`."),
                        "Confirm the exposure is intentional and add a narrowly scoped justification or safer configuration.",
                        format!("config:{}:{needle}", file.display()),
                    ));
                }
            }

            if path_text.contains(".github/workflows") {
                if let Some(finding) = scan_github_actions_workflow(self.name(), file, &contents) {
                    findings.push(finding);
                }
            }

            if let Some(finding) = scan_kubernetes_secret_manifest(self.name(), file, &contents) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

fn scan_github_actions_workflow(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Option<Finding> {
    let lower = contents.to_ascii_lowercase();

    if lower.contains("permissions: write-all") || lower.contains("\"permissions\": \"write-all\"")
    {
        return Some(Finding::new(
            "config.github-actions.permissions-write-all",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Configuration,
            Some(file.to_path_buf()),
            "GitHub Actions workflow grants write-all token permissions",
            "The candidate workflow sets `permissions: write-all`, which broadly expands `GITHUB_TOKEN` write access across scopes.",
            "Reduce workflow permissions to the minimum required scopes and prefer explicit per-scope permissions instead of `write-all`.",
            format!("config-github-actions-write-all:{}", file.display()),
        ));
    }

    if lower.contains("pull_request_target") {
        let (severity, confidence, detail, remediation, fingerprint_suffix) =
            if lower.contains("github.event.pull_request.head") {
                (
                    Severity::High,
                    Confidence::High,
                    "The candidate workflow uses `pull_request_target` and also references pull-request head content, which can create a privileged path for untrusted code or artifacts.",
                    "Avoid checking out or using untrusted pull-request head content in a `pull_request_target` workflow. Split privileged operations into a safer workflow design if needed.",
                    "head-reference",
                )
            } else {
                (
                    Severity::Medium,
                    Confidence::Medium,
                    "The candidate workflow uses `pull_request_target`, which runs in the base-repository context and needs careful privilege separation.",
                    "Review whether `pull_request_target` is necessary. If the workflow does not need privileged base-repo context, prefer `pull_request` instead.",
                    "trigger",
                )
            };

        return Some(Finding::new(
            "config.github-actions.pull-request-target",
            scanner,
            severity,
            confidence,
            FindingCategory::Configuration,
            Some(file.to_path_buf()),
            "GitHub Actions pull_request_target workflow detected",
            detail,
            remediation,
            format!(
                "config-github-actions-pull-request-target:{}:{}",
                file.display(),
                fingerprint_suffix
            ),
        ));
    }

    None
}

fn scan_kubernetes_secret_manifest(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Option<Finding> {
    let lower = contents.to_ascii_lowercase();
    let is_kubernetes_secret = lower.contains("kind: secret")
        || (lower.contains("\"kind\"") && lower.contains("\"secret\""));
    if !is_kubernetes_secret {
        return None;
    }

    let has_inline_secret_data = lower.contains("stringdata:")
        || lower.contains("data:")
        || lower.contains("\"stringdata\"")
        || lower.contains("\"data\"");
    if !has_inline_secret_data {
        return None;
    }

    Some(Finding::new(
        "config.kubernetes.secret-manifest",
        scanner,
        Severity::High,
        Confidence::High,
        FindingCategory::Secret,
        Some(file.to_path_buf()),
        "Kubernetes Secret manifest with inline data detected",
        "The candidate configuration appears to define a Kubernetes Secret resource with inline `data` or `stringData`, which often means secret material is being pushed directly into version control.",
        "Move the secret payload to a secure secret-management workflow or encrypted manifest path instead of committing inline Kubernetes Secret data.",
        format!("config-kubernetes-secret:{}", file.display()),
    ))
}

impl Scanner for PolicyScanner {
    fn name(&self) -> &'static str {
        "policy-scanner"
    }

    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        let config_path = context.repo_root.join(".wolfence/config.toml");

        if config_path.exists() {
            return Ok(Vec::new());
        }

        Ok(vec![Finding::new(
            "policy.repo-config.missing",
            self.name(),
            Severity::Info,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Repo-local Wolfence config is not initialized yet",
            "The repository does not have a `.wolfence/config.toml` file yet, so policy is currently running on built-in defaults.",
            "Add repo-local Wolfence configuration so the enforcement posture is explicit and reviewable.",
            "policy:repo-config:missing",
        )])
    }
}

fn classify_sensitive_path(scanner: &'static str, file: &Path) -> Option<Finding> {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    let file_name = file
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let (title, detail, severity, id) = if matches!(
        file_name.as_str(),
        ".env" | ".env.local" | ".env.production" | ".env.staging" | ".envrc"
    ) {
        (
            "Environment file included in outbound change set",
            "Environment files frequently contain live credentials, private endpoints, or deployment-only configuration.",
            Severity::High,
            "secret.file.env",
        )
    } else if file_name == "terraform.tfvars"
        || lower.ends_with(".auto.tfvars")
        || lower.ends_with(".tfvars")
        || lower.ends_with(".tfvars.json")
    {
        (
            "Infrastructure variable file included in outbound change set",
            "Terraform variable files frequently contain cloud credentials, secrets, or environment-specific infrastructure values.",
            Severity::High,
            "secret.file.tfvars",
        )
    } else if matches!(
        file_name.as_str(),
        ".npmrc" | ".pypirc" | ".netrc" | "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa"
    ) || lower.contains(".aws/credentials")
        || lower.contains(".ssh/")
        || lower.contains(".docker/config.json")
        || lower.ends_with(".kube/config")
    {
        (
            "Credential-bearing file path detected",
            "The candidate file path strongly suggests credential, key, or infrastructure access material.",
            Severity::Critical,
            "secret.file.credentials",
        )
    } else if lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".jks")
        || lower.ends_with(".keystore")
    {
        (
            "Key material file extension detected",
            "The candidate file extension is commonly used for private key or keystore material.",
            Severity::Critical,
            "secret.file.key-material",
        )
    } else {
        return None;
    };

    Some(Finding::new(
        id,
        scanner,
        severity,
        Confidence::High,
        FindingCategory::Secret,
        Some(file.to_path_buf()),
        title,
        detail,
        "Remove the file from version control and rotate any credentials or key material if exposure is possible.",
        format!("secret-path:{}", file.display()),
    ))
}

fn scan_private_key_headers(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let trimmed = line.trim();
    if !trimmed.starts_with("-----BEGIN ") {
        return None;
    }

    let is_private_key = [
        "PRIVATE KEY-----",
        "RSA PRIVATE KEY-----",
        "DSA PRIVATE KEY-----",
        "EC PRIVATE KEY-----",
        "OPENSSH PRIVATE KEY-----",
    ]
    .iter()
    .any(|needle| trimmed.ends_with(needle));

    if !is_private_key {
        return None;
    }

    Some(
        Finding::new(
            "secret.pattern.private-key-header",
            scanner,
            Severity::Critical,
            Confidence::High,
            FindingCategory::Secret,
            Some(file.to_path_buf()),
            "Private key material detected",
            "The candidate file contains a private key PEM header, which is almost always sensitive.",
            "Remove the key from version control immediately and rotate any associated credentials.",
            format!("secret-private-key:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_prefixed_secret_tokens(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in [
        PrefixedSecretRule {
            id: "secret.pattern.aws-access-key",
            title: "AWS access key identifier detected",
            detail: "The candidate file contains a token matching the shape of an AWS access key identifier.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "AKIA",
            min_length: 20,
            max_length: Some(20),
            allowed_characters: CharacterClass::UpperAlphaNumeric,
        },
        PrefixedSecretRule {
            id: "secret.pattern.aws-session-key",
            title: "AWS temporary access key identifier detected",
            detail: "The candidate file contains a token matching the shape of an AWS temporary access key identifier.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "ASIA",
            min_length: 20,
            max_length: Some(20),
            allowed_characters: CharacterClass::UpperAlphaNumeric,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub personal or installation token detected",
            detail: "The candidate file contains a token with a GitHub secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "ghp_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub token detected",
            detail: "The candidate file contains a token with a GitHub secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "gho_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub token detected",
            detail: "The candidate file contains a token with a GitHub secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "ghu_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub token detected",
            detail: "The candidate file contains a token with a GitHub secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "ghs_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub token detected",
            detail: "The candidate file contains a token with a GitHub secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "ghr_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.github-pat",
            title: "GitHub fine-grained token detected",
            detail: "The candidate file contains a token matching GitHub's fine-grained personal access token prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "github_pat_",
            min_length: 30,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.slack-token",
            title: "Slack token detected",
            detail: "The candidate file contains a token with a Slack secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "xoxb-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::Slack,
        },
        PrefixedSecretRule {
            id: "secret.pattern.slack-token",
            title: "Slack token detected",
            detail: "The candidate file contains a token with a Slack secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "xoxp-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::Slack,
        },
        PrefixedSecretRule {
            id: "secret.pattern.slack-token",
            title: "Slack token detected",
            detail: "The candidate file contains a token with a Slack secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "xoxa-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::Slack,
        },
        PrefixedSecretRule {
            id: "secret.pattern.slack-token",
            title: "Slack token detected",
            detail: "The candidate file contains a token with a Slack secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "xoxr-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::Slack,
        },
        PrefixedSecretRule {
            id: "secret.pattern.slack-token",
            title: "Slack app-level token detected",
            detail: "The candidate file contains a token with a Slack app-level secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "xapp-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::Slack,
        },
        PrefixedSecretRule {
            id: "secret.pattern.stripe-live-key",
            title: "Stripe live secret key detected",
            detail: "The candidate file contains a token with a Stripe live key prefix.",
            severity: Severity::Critical,
            confidence: Confidence::High,
            prefix: "sk_live_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.stripe-live-key",
            title: "Stripe restricted live key detected",
            detail: "The candidate file contains a token with a Stripe restricted live key prefix.",
            severity: Severity::Critical,
            confidence: Confidence::High,
            prefix: "rk_live_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.npm-token",
            title: "npm token detected",
            detail: "The candidate file contains a token with an npm auth token prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "npm_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
    ] {
        for token in extract_prefixed_tokens(
            line,
            rule.prefix,
            rule.min_length,
            rule.max_length,
            rule.allowed_characters,
        ) {
            if looks_like_placeholder(&token) {
                continue;
            }

            findings.push(
                Finding::new(
                    rule.id,
                    scanner,
                    rule.severity,
                    rule.confidence,
                    FindingCategory::Secret,
                    Some(file.to_path_buf()),
                    rule.title,
                    rule.detail,
                    "Remove the secret from the repository, rotate it if it is real, and replace it with a secure runtime injection path.",
                    format!("secret-token:{}:{}:{}", rule.prefix, file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_secret_assignment(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let (key, value) = extract_assignment(line)?;
    let normalized_key = normalize_identifier(&key);

    if !is_sensitive_identifier(&normalized_key) {
        return None;
    }

    let normalized_value = trim_wrapping_quotes(value.trim_matches(',').trim());
    if normalized_value.len() < 16 {
        return None;
    }

    if looks_like_placeholder(normalized_value) || looks_like_template_expression(normalized_value)
    {
        return None;
    }

    let entropy = shannon_entropy(normalized_value);
    let structured = looks_structured_secret(normalized_value);
    if entropy < 3.5 && !structured {
        return None;
    }

    let severity = if entropy >= 4.3 || normalized_value.len() >= 32 {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(
        Finding::new(
            "secret.assignment.suspicious-value",
            scanner,
            severity,
            Confidence::Medium,
            FindingCategory::Secret,
            Some(file.to_path_buf()),
            "Suspicious secret-like assignment detected",
            format!(
                "The candidate file assigns a high-entropy value to the sensitive identifier `{key}`."
            ),
            "Move the secret to a secure runtime secret store or environment injection path and keep only a reference in source control.",
            format!(
                "secret-assignment:{}:{}:{}",
                file.display(),
                line_number,
                normalized_key
            ),
        )
        .with_line(line_number),
    )
}

fn scan_credential_url(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    let scheme_index = lowered.find("://")?;
    let after_scheme = &line[scheme_index + 3..];
    let at_index = after_scheme.find('@')?;
    let credentials = &after_scheme[..at_index];

    if !credentials.contains(':') {
        return None;
    }

    if looks_like_placeholder(credentials) {
        return None;
    }

    Some(
        Finding::new(
            "secret.url.embedded-credentials",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Secret,
            Some(file.to_path_buf()),
            "Embedded credentials in URL detected",
            "The candidate file appears to contain a URL with inline credentials, which is a common source of credential leakage.",
            "Move credentials out of the URL and into a secure runtime configuration path.",
            format!("secret-url:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_inline_authorization_credential(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    if !lowered.contains("authorization") {
        return None;
    }

    for (scheme, min_length, title, detail) in [
        (
            "bearer ",
            16usize,
            "Inline bearer token detected",
            "The candidate file appears to embed an Authorization bearer credential directly in content.",
        ),
        (
            "basic ",
            12usize,
            "Inline basic authorization credential detected",
            "The candidate file appears to embed an Authorization basic credential directly in content.",
        ),
    ] {
        let Some(marker_index) = lowered.find(scheme) else {
            continue;
        };

        let token = extract_inline_secret_token(&line[marker_index + scheme.len()..]);
        if token.len() < min_length || looks_like_placeholder(&token) {
            continue;
        }

        return Some(
            Finding::new(
                "secret.authorization.inline",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(file.to_path_buf()),
                title,
                detail,
                "Move the credential out of source-controlled content and inject it at runtime through a secure secret path.",
                format!("secret-authorization:{}:{}:{}", file.display(), line_number, scheme.trim()),
            )
            .with_line(line_number),
        );
    }

    None
}

fn scan_inline_secret_header(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let (header_name, value) = extract_http_header(line)?;
    let normalized_header = normalize_identifier(&header_name);
    if ![
        "xapikey",
        "apikey",
        "xauthtoken",
        "authtoken",
        "xaccesstoken",
        "accesstoken",
    ]
    .iter()
    .any(|needle| normalized_header == *needle)
    {
        return None;
    }

    let token = extract_inline_secret_token(value);
    if token.len() < 16 || looks_like_placeholder(&token) {
        return None;
    }

    Some(
        Finding::new(
            "secret.header.inline",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Secret,
            Some(file.to_path_buf()),
            "Inline HTTP secret header detected",
            format!(
                "The candidate file appears to embed a secret-bearing HTTP header `{header_name}` directly in content."
            ),
            "Move the secret value out of source-controlled request fixtures and inject it at runtime through a secure secret path.",
            format!(
                "secret-header:{}:{}:{}",
                file.display(),
                line_number,
                normalized_header
            ),
        )
        .with_line(line_number),
    )
}

fn scan_cookie_header_secret(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let (header_name, value) = extract_http_header(line)?;
    let normalized_header = normalize_identifier(&header_name);
    if normalized_header != "cookie" && normalized_header != "setcookie" {
        return None;
    }

    for segment in value.split(';') {
        let Some((name, raw_value)) = segment.trim().split_once('=') else {
            continue;
        };

        let normalized_name = normalize_identifier(name);
        if !looks_sensitive_cookie_name(&normalized_name) {
            continue;
        }

        let token = extract_inline_secret_token(raw_value);
        if token.len() < 16 || looks_like_placeholder(&token) {
            continue;
        }

        let structured = looks_structured_secret(&token);
        let entropy = shannon_entropy(&token);
        if !structured && entropy < 3.5 {
            continue;
        }

        return Some(
            Finding::new(
                "secret.header.cookie",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(file.to_path_buf()),
                "Inline cookie or session secret detected",
                format!(
                    "The candidate file appears to embed a sensitive cookie or session header `{header_name}` with secret-bearing cookie name `{name}`."
                ),
                "Remove the live cookie or session value from source-controlled content and replace it with a redacted example or runtime injection path.",
                format!(
                    "secret-cookie:{}:{}:{}",
                    file.display(),
                    line_number,
                    normalized_name
                ),
            )
            .with_line(line_number),
        );
    }

    None
}

fn dependency_relationship_findings(
    scanner: &'static str,
    candidate_files: &[PathBuf],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let rust_manifest = changed_file(candidate_files, "Cargo.toml");
    let rust_lockfile = changed_file(candidate_files, "Cargo.lock");
    let node_manifest = changed_file(candidate_files, "package.json");
    let node_lockfile = changed_any_file(
        candidate_files,
        &["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"],
    );
    let python_manifest = changed_any_path_suffix(
        candidate_files,
        &["pyproject.toml", "requirements.txt", "requirements-dev.txt"],
    );
    let python_lockfile = changed_any_file(candidate_files, &["poetry.lock"]);

    if rust_manifest.is_some() && rust_lockfile.is_none() {
        findings.push(Finding::new(
            "dependency.lockfile.missing.rust",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Dependency,
            rust_manifest.cloned(),
            "Cargo manifest changed without a lockfile update",
            "A Rust dependency manifest is part of the outbound change set, but `Cargo.lock` is not.",
            "Review whether the change should also update `Cargo.lock` to preserve a reviewable dependency snapshot.",
            "dependency-lockfile-missing:rust",
        ));
    }

    if node_manifest.is_some() && node_lockfile.is_none() {
        findings.push(Finding::new(
            "dependency.lockfile.missing.node",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Dependency,
            node_manifest.cloned(),
            "Node manifest changed without a lockfile update",
            "A Node package manifest is part of the outbound change set, but no recognized Node lockfile changed alongside it.",
            "Review whether the change should also update `package-lock.json` or `pnpm-lock.yaml` to keep dependency resolution reviewable.",
            "dependency-lockfile-missing:node",
        ));
    }

    if python_manifest.is_some() && python_lockfile.is_none() {
        findings.push(Finding::new(
            "dependency.lockfile.missing.python",
            scanner,
            Severity::Low,
            Confidence::Medium,
            FindingCategory::Dependency,
            python_manifest.cloned(),
            "Python dependency manifest changed without a lockfile update",
            "A Python dependency manifest changed, but no Python lockfile changed alongside it.",
            "If this repository relies on Poetry or another lockfile mechanism, update the lockfile as part of the dependency change.",
            "dependency-lockfile-missing:python",
        ));
    }

    findings
}

fn scan_cargo_manifest(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_section = String::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();

        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed.to_string();

            if trimmed.starts_with("[patch.") || trimmed == "[replace]" {
                findings.push(
                    Finding::new(
                        "dependency.cargo.source-override",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Cargo dependency source override detected",
                        "The Cargo manifest uses `[patch]` or `[replace]`, which can redirect dependency provenance and should receive careful review.",
                        "Confirm the override is intentional, narrowly scoped, and documented.",
                        format!("dependency-cargo-override:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }

            continue;
        }

        let in_dependency_section = current_section.contains("dependencies");
        if !in_dependency_section {
            continue;
        }

        if trimmed.contains("git = ") {
            let severity = if trimmed.contains("branch = ") || trimmed.contains("tag = ") {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(
                Finding::new(
                    "dependency.cargo.git-source",
                    scanner,
                    severity,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Cargo dependency uses a direct Git source",
                    "A Cargo dependency is sourced directly from Git rather than a registry snapshot.",
                    "Prefer reviewed registry releases or pin the Git dependency to an auditable immutable revision with explicit justification.",
                    format!("dependency-cargo-git:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("path = ") {
            findings.push(
                Finding::new(
                    "dependency.cargo.path-source",
                    scanner,
                    Severity::Low,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Cargo dependency uses a local path source",
                    "A Cargo dependency is sourced from a local path. This is often valid in monorepos, but it weakens portability and deserves review in security-sensitive flows.",
                    "Confirm the path dependency is intentional and part of a controlled workspace layout.",
                    format!("dependency-cargo-path:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("http://") {
            findings.push(
                Finding::new(
                    "dependency.cargo.insecure-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Cargo dependency source uses insecure HTTP transport",
                    "The Cargo manifest references dependency metadata over plain HTTP.",
                    "Switch the dependency source to HTTPS or another authenticated, integrity-preserving transport.",
                    format!("dependency-cargo-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("version = \"*\"") || trimmed.ends_with("= \"*\"") {
            findings.push(
                Finding::new(
                    "dependency.cargo.wildcard-version",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Cargo dependency uses a wildcard version",
                    "The Cargo manifest uses `*`, which removes meaningful reviewable pinning constraints for that dependency.",
                    "Replace the wildcard with an explicit semver range that matches the intended update policy.",
                    format!("dependency-cargo-wildcard:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_cargo_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_package = false;
    let mut current_package_name: Option<String> = None;
    let mut registry_source = false;
    let mut has_checksum = false;

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            finalize_cargo_lock_package(
                scanner,
                file,
                &mut findings,
                &current_package_name,
                registry_source,
                has_checksum,
                line_number,
            );
            in_package = true;
            current_package_name = None;
            registry_source = false;
            has_checksum = false;
            continue;
        }

        if !in_package {
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_package_name = Some(name.trim_end_matches('"').to_string());
        }

        if let Some(source) = trimmed.strip_prefix("source = \"") {
            let source = source.trim_end_matches('"');
            if source.starts_with("git+") {
                findings.push(
                    Finding::new(
                        "dependency.cargo-lock.git-source",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Cargo lockfile contains a Git-sourced package",
                        "The lockfile includes a package resolved from Git rather than a registry release.",
                        "Review the package provenance carefully and prefer immutable, reviewable registry releases where possible.",
                        format!("dependency-cargo-lock-git:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }

            if source.starts_with("registry+http://") || source.starts_with("sparse+http://") {
                findings.push(
                    Finding::new(
                        "dependency.cargo-lock.insecure-registry",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Cargo lockfile references an insecure registry source",
                        "The lockfile references a registry over plain HTTP, which weakens dependency transport integrity.",
                        "Use HTTPS-backed registries only.",
                        format!(
                            "dependency-cargo-lock-http:{}:{}",
                            file.display(),
                            line_number
                        ),
                    )
                    .with_line(line_number),
                );
            }

            registry_source = source.starts_with("registry+") || source.starts_with("sparse+");
        }

        if trimmed.starts_with("checksum = ") {
            has_checksum = true;
        }
    }

    finalize_cargo_lock_package(
        scanner,
        file,
        &mut findings,
        &current_package_name,
        registry_source,
        has_checksum,
        contents.lines().count(),
    );

    findings
}

fn finalize_cargo_lock_package(
    scanner: &'static str,
    file: &Path,
    findings: &mut Vec<Finding>,
    current_package_name: &Option<String>,
    registry_source: bool,
    has_checksum: bool,
    line_number: usize,
) {
    if registry_source && !has_checksum {
        findings.push(
            Finding::new(
                "dependency.cargo-lock.missing-checksum",
                scanner,
                Severity::Medium,
                Confidence::Medium,
                FindingCategory::Dependency,
                Some(file.to_path_buf()),
                "Cargo registry package is missing a lockfile checksum",
                format!(
                    "The lockfile package `{}` uses a registry source but does not expose a checksum entry.",
                    current_package_name.as_deref().unwrap_or("<unknown>")
                ),
                "Review the lockfile provenance and ensure the dependency source preserves registry integrity metadata.",
                format!(
                    "dependency-cargo-lock-checksum:{}:{}:{}",
                    file.display(),
                    line_number,
                    current_package_name.as_deref().unwrap_or("<unknown>")
                ),
            )
            .with_line(line_number),
        );
    }
}

fn scan_package_json_manifest(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_section: Option<&str> = None;
    let mut section_depth = 0isize;

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if current_section.is_none() {
            for section in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                let marker = format!("\"{section}\"");
                if trimmed.starts_with(&marker) && trimmed.contains('{') {
                    current_section = Some(section);
                    section_depth = brace_delta(trimmed);
                    break;
                }
            }
        } else {
            section_depth += brace_delta(trimmed);
            if section_depth < 0 {
                section_depth = 0;
            }
            if section_depth == 0 {
                current_section = None;
                continue;
            }

            if let Some((dependency_name, spec)) = parse_json_dependency_entry(trimmed) {
                for finding in scan_dependency_spec(
                    scanner,
                    file,
                    line_number,
                    current_section.unwrap_or("dependencies"),
                    dependency_name,
                    spec,
                ) {
                    findings.push(finding);
                }
            }
        }
    }

    findings
}

fn scan_dependency_spec(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    section: &str,
    dependency_name: &str,
    spec: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let normalized = spec.trim();
    let lower = normalized.to_ascii_lowercase();

    if matches!(lower.as_str(), "*" | "latest")
        || lower == "x"
        || lower.ends_with(".x")
        || lower.contains(": *")
    {
        findings.push(
            Finding::new(
                "dependency.node.unbounded-version",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Dependency,
                Some(file.to_path_buf()),
                "Node dependency uses an unbounded version selector",
                format!(
                    "The `{dependency_name}` dependency in `{section}` uses `{normalized}`, which weakens reviewable version control."
                ),
                "Replace the selector with an explicit semver range or exact version that matches the intended update policy.",
                format!(
                    "dependency-node-unbounded:{}:{}:{}",
                    file.display(),
                    line_number,
                    dependency_name
                ),
            )
            .with_line(line_number),
        );
    }

    let direct_source = if lower.starts_with("git://") {
        Some((
            Severity::High,
            "Node dependency uses insecure Git transport",
        ))
    } else if lower.starts_with("http://") {
        Some((
            Severity::High,
            "Node dependency uses insecure HTTP transport",
        ))
    } else if lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("https://")
    {
        Some((
            Severity::High,
            "Node dependency uses a direct remote source",
        ))
    } else if lower.starts_with("file:") || lower.starts_with("link:") {
        Some((Severity::Medium, "Node dependency uses a local path source"))
    } else {
        None
    };

    if let Some((severity, title)) = direct_source {
        findings.push(
            Finding::new(
                "dependency.node.direct-source",
                scanner,
                severity,
                Confidence::High,
                FindingCategory::Dependency,
                Some(file.to_path_buf()),
                title,
                format!(
                    "The `{dependency_name}` dependency in `{section}` resolves from `{normalized}` rather than a standard registry release."
                ),
                "Prefer reviewed registry releases and lockfiles where possible. If a direct source is required, document and justify it explicitly.",
                format!(
                    "dependency-node-direct-source:{}:{}:{}",
                    file.display(),
                    line_number,
                    dependency_name
                ),
            )
            .with_line(line_number),
        );
    }

    findings
}

fn scan_package_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let has_integrity = contents.contains("\"integrity\"");

    if !has_integrity {
        findings.push(Finding::new(
            "dependency.node.lockfile.missing-integrity",
            scanner,
            Severity::Medium,
            Confidence::Medium,
            FindingCategory::Dependency,
            Some(file.to_path_buf()),
            "Node lockfile does not expose integrity hashes",
            "The lockfile does not appear to contain `integrity` metadata, which weakens package tamper verification.",
            "Regenerate the lockfile with a package manager version that emits integrity metadata, or confirm the ecosystem's equivalent integrity mechanism.",
            format!("dependency-node-lockfile-integrity:{}", file.display()),
        ));
    }

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed.contains("\"resolved\": \"http://") {
            findings.push(
                Finding::new(
                    "dependency.node.lockfile.insecure-resolved-url",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Node lockfile resolves a package over insecure HTTP",
                    "The lockfile contains a package resolution URL using plain HTTP.",
                    "Use HTTPS-backed package sources only.",
                    format!(
                        "dependency-node-lockfile-http:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("\"resolved\": \"git+") || trimmed.contains("\"version\": \"git+") {
            findings.push(
                Finding::new(
                    "dependency.node.lockfile.git-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Node lockfile contains a Git-sourced package",
                    "The lockfile includes a package resolved directly from Git.",
                    "Prefer registry-backed releases or document the provenance and review path for the Git source.",
                    format!("dependency-node-lockfile-git:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_pnpm_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed.contains("tarball: http://") {
            findings.push(
                Finding::new(
                    "dependency.pnpm.insecure-tarball",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "pnpm lockfile resolves a tarball over insecure HTTP",
                    "The lockfile references a tarball URL over plain HTTP.",
                    "Use HTTPS-backed package sources only.",
                    format!("dependency-pnpm-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("tarball: https://") || trimmed.contains("git+") {
            findings.push(
                Finding::new(
                    "dependency.pnpm.direct-remote-source",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "pnpm lockfile contains a direct remote dependency source",
                    "The lockfile references a tarball or Git source directly rather than a normal registry release path.",
                    "Confirm the remote source is intentional and reviewable.",
                    format!("dependency-pnpm-remote:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_pyproject(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.contains("git = ") || trimmed.contains(" @ git+") {
            findings.push(
                Finding::new(
                    "dependency.python.git-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Python dependency uses a direct Git source",
                    "The Python dependency definition references a Git source directly.",
                    "Prefer reviewed package-index releases where possible, or document the justification for the direct source.",
                    format!("dependency-python-git:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("http://") {
            findings.push(
                Finding::new(
                    "dependency.python.insecure-http-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Python dependency uses insecure HTTP transport",
                    "The dependency definition references dependency data over plain HTTP.",
                    "Use HTTPS-backed sources only.",
                    format!("dependency-python-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains(" = \"*\"") || trimmed.contains("@ *") {
            findings.push(
                Finding::new(
                    "dependency.python.wildcard-version",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Python dependency uses a wildcard version",
                    "The dependency definition allows an effectively unbounded version selector.",
                    "Replace the wildcard with an explicit version policy.",
                    format!(
                        "dependency-python-wildcard:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_poetry_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed.contains("url = \"http://") {
            findings.push(
                Finding::new(
                    "dependency.python.lockfile.insecure-url",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Poetry lockfile contains an insecure HTTP source",
                    "The lockfile references a package source over plain HTTP.",
                    "Use HTTPS-backed sources only.",
                    format!("dependency-poetry-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_requirements(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();

        if trimmed.is_empty() || trimmed.starts_with('-') {
            continue;
        }

        if trimmed.contains("git+") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.git-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file uses a direct Git source",
                    "The requirements file references a dependency from Git directly.",
                    "Prefer reviewed package-index releases where possible.",
                    format!(
                        "dependency-requirements-git:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        } else if trimmed.contains("http://") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.insecure-http",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file uses insecure HTTP transport",
                    "The requirements file references a dependency over plain HTTP.",
                    "Use HTTPS-backed sources only.",
                    format!(
                        "dependency-requirements-http:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        } else if !trimmed.contains("==") && !trimmed.contains(" @ ") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.unpinned",
                    scanner,
                    Severity::Low,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements entry is not exactly pinned",
                    "The requirements file contains a package entry that is not pinned to an exact version.",
                    "Consider exact pinning for higher-reproducibility deployment surfaces.",
                    format!("dependency-requirements-unpinned:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn extract_cargo_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            push_resolved_dependency(
                &mut dependencies,
                "crates.io",
                file,
                current_name.take(),
                current_version.take(),
            );
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_name = Some(name.trim_end_matches('"').to_string());
        } else if let Some(version) = trimmed.strip_prefix("version = \"") {
            current_version = Some(version.trim_end_matches('"').to_string());
        }
    }

    push_resolved_dependency(
        &mut dependencies,
        "crates.io",
        file,
        current_name,
        current_version,
    );

    dependencies
}

fn extract_node_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let Ok(value) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };

    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();

    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (path_key, package) in packages {
            if path_key.is_empty() {
                continue;
            }

            let Some(version) = package.get("version").and_then(Value::as_str) else {
                continue;
            };
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| derive_package_name_from_lock_path(path_key));

            let Some(name) = name else {
                continue;
            };

            record_resolved_dependency(
                &mut dependencies,
                &mut seen,
                ResolvedDependency {
                    ecosystem: "npm",
                    name,
                    version: version.to_string(),
                    file: file.to_path_buf(),
                },
            );
        }

        return dependencies;
    }

    if let Some(root_dependencies) = value.get("dependencies").and_then(Value::as_object) {
        collect_legacy_node_dependencies(file, root_dependencies, &mut dependencies, &mut seen);
    }

    dependencies
}

fn collect_legacy_node_dependencies(
    file: &Path,
    entries: &serde_json::Map<String, Value>,
    dependencies: &mut Vec<ResolvedDependency>,
    seen: &mut HashSet<(&'static str, String, String)>,
) {
    for (name, entry) in entries {
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            record_resolved_dependency(
                dependencies,
                seen,
                ResolvedDependency {
                    ecosystem: "npm",
                    name: name.to_string(),
                    version: version.to_string(),
                    file: file.to_path_buf(),
                },
            );
        }

        if let Some(children) = entry.get("dependencies").and_then(Value::as_object) {
            collect_legacy_node_dependencies(file, children, dependencies, seen);
        }
    }
}

fn derive_package_name_from_lock_path(path_key: &str) -> Option<String> {
    let trimmed = path_key.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    trimmed
        .rfind("node_modules/")
        .map(|index| trimmed[index + "node_modules/".len()..].to_string())
}

fn extract_poetry_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            push_resolved_dependency(
                &mut dependencies,
                "PyPI",
                file,
                current_name.take(),
                current_version.take(),
            );
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_name = Some(name.trim_end_matches('"').to_string());
        } else if let Some(version) = trimmed.strip_prefix("version = \"") {
            current_version = Some(version.trim_end_matches('"').to_string());
        }
    }

    push_resolved_dependency(
        &mut dependencies,
        "PyPI",
        file,
        current_name,
        current_version,
    );

    dependencies
}

fn extract_requirements_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() || trimmed.starts_with('-') {
            continue;
        }

        let Some((name, version)) = trimmed.split_once("==") else {
            continue;
        };

        let normalized_name = name
            .trim()
            .split('[')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let normalized_version = version.trim().to_string();
        if normalized_name.is_empty() || normalized_version.is_empty() {
            continue;
        }

        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "PyPI",
                name: normalized_name,
                version: normalized_version,
                file: file.to_path_buf(),
            },
        );
    }

    dependencies
}

fn push_resolved_dependency(
    dependencies: &mut Vec<ResolvedDependency>,
    ecosystem: &'static str,
    file: &Path,
    name: Option<String>,
    version: Option<String>,
) {
    let (Some(name), Some(version)) = (name, version) else {
        return;
    };

    dependencies.push(ResolvedDependency {
        ecosystem,
        name,
        version,
        file: file.to_path_buf(),
    });
}

fn record_resolved_dependency(
    dependencies: &mut Vec<ResolvedDependency>,
    seen: &mut HashSet<(&'static str, String, String)>,
    dependency: ResolvedDependency,
) {
    let key = (
        dependency.ecosystem,
        dependency.name.clone(),
        dependency.version.clone(),
    );
    if seen.insert(key) {
        dependencies.push(dependency);
    }
}

fn changed_file<'a>(candidate_files: &'a [PathBuf], file_name: &str) -> Option<&'a PathBuf> {
    candidate_files.iter().find(|file| {
        file.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value == file_name)
    })
}

fn changed_any_file<'a>(
    candidate_files: &'a [PathBuf],
    file_names: &[&str],
) -> Option<&'a PathBuf> {
    candidate_files.iter().find(|file| {
        file.file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| file_names.contains(&value))
    })
}

fn changed_any_path_suffix<'a>(
    candidate_files: &'a [PathBuf],
    suffixes: &[&str],
) -> Option<&'a PathBuf> {
    candidate_files.iter().find(|file| {
        suffixes
            .iter()
            .any(|suffix| file.to_string_lossy().ends_with(suffix))
    })
}

fn read_text_file(path: &Path) -> AppResult<Option<String>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    if metadata.len() > MAX_TEXT_SCAN_BYTES {
        return Ok(None);
    }

    let bytes = fs::read(path)?;
    if bytes.contains(&0) {
        return Ok(None);
    }

    match String::from_utf8(bytes) {
        Ok(contents) => Ok(Some(contents)),
        Err(_) => Ok(None),
    }
}

fn record_finding(findings: &mut Vec<Finding>, seen: &mut HashSet<String>, finding: Finding) {
    if seen.insert(finding.fingerprint.clone()) {
        findings.push(finding);
    }
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single_quotes = false;
    let mut in_double_quotes = false;

    for (index, character) in line.char_indices() {
        match character {
            '\'' if !in_double_quotes => in_single_quotes = !in_single_quotes,
            '"' if !in_single_quotes => in_double_quotes = !in_double_quotes,
            '#' if !in_single_quotes && !in_double_quotes => return &line[..index],
            _ => {}
        }
    }

    line
}

fn normalize_identifier(identifier: &str) -> String {
    identifier
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
        .flat_map(|character| character.to_lowercase())
        .collect()
}

fn is_sensitive_identifier(identifier: &str) -> bool {
    [
        "secret",
        "token",
        "password",
        "passwd",
        "apikey",
        "api_key",
        "privatekey",
        "private_key",
        "clientsecret",
        "client_secret",
        "accesskey",
        "access_key",
        "auth_token",
        "bearer",
    ]
    .iter()
    .any(|needle| identifier.contains(needle))
}

fn extract_assignment(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim();
    let without_export = trimmed.strip_prefix("export ").unwrap_or(trimmed);

    let (left, right) = without_export
        .split_once('=')
        .or_else(|| without_export.split_once(':'))?;

    let key = left.trim().trim_matches('"').trim_matches('\'').to_string();
    let value = right.trim();

    if key.is_empty() || value.is_empty() {
        return None;
    }

    Some((key, value))
}

fn trim_wrapping_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'').trim()
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();

    if lower.is_empty() {
        return true;
    }

    if [
        "example",
        "sample",
        "test",
        "dummy",
        "placeholder",
        "changeme",
        "replace-me",
        "your_token_here",
        "your-api-key",
        "your_api_key",
        "insert-secret-here",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    if lower.ends_with("example") || lower.ends_with("_example") {
        return true;
    }

    let distinct_characters = lower.chars().collect::<HashSet<_>>().len();
    distinct_characters <= 2 && lower.len() >= 8
}

fn looks_like_template_expression(value: &str) -> bool {
    value.starts_with("${")
        || value.starts_with("{{")
        || value.starts_with('<')
        || value.ends_with('>')
        || value.contains("{{")
        || value.contains("}}")
}

fn looks_structured_secret(value: &str) -> bool {
    looks_base64ish(value) || looks_hexish(value) || looks_jwt(value)
}

fn looks_base64ish(value: &str) -> bool {
    value.len() >= 24
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+/=_-".contains(character))
}

fn looks_hexish(value: &str) -> bool {
    value.len() >= 32 && value.chars().all(|character| character.is_ascii_hexdigit())
}

fn looks_jwt(value: &str) -> bool {
    let mut parts = value.split('.');
    let (Some(first), Some(second), Some(third)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    parts.next().is_none()
        && first.len() >= 8
        && second.len() >= 8
        && third.len() >= 8
        && [first, second, third].iter().all(|part| {
            part.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            })
        })
}

fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = value.as_bytes();

    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn extract_prefixed_tokens(
    line: &str,
    prefix: &str,
    min_length: usize,
    max_length: Option<usize>,
    allowed: CharacterClass,
) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut start = 0usize;

    while let Some(relative_index) = line[start..].find(prefix) {
        let index = start + relative_index;
        let after_prefix = &line[index..];
        let mut end = index;

        for (offset, character) in after_prefix.char_indices() {
            if offset == 0 || allowed.allows(character) {
                end = index + offset + character.len_utf8();
            } else {
                break;
            }
        }

        let candidate = &line[index..end];
        let length_ok = candidate.len() >= min_length
            && max_length.is_none_or(|maximum| candidate.len() <= maximum);
        if length_ok {
            tokens.push(candidate.to_string());
        }

        start = index + prefix.len();
    }

    tokens
}

fn parse_json_dependency_entry(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim().trim_end_matches(',');
    let trimmed = trimmed.strip_prefix('"')?;
    let (name, remainder) = trimmed.split_once('"')?;
    let remainder = remainder.trim_start();
    let remainder = remainder.strip_prefix(':')?.trim_start();
    let remainder = remainder.strip_prefix('"')?;
    let (spec, _) = remainder.split_once('"')?;
    Some((name, spec))
}

fn brace_delta(line: &str) -> isize {
    let opens = line.chars().filter(|character| *character == '{').count() as isize;
    let closes = line.chars().filter(|character| *character == '}').count() as isize;
    opens - closes
}

fn extract_inline_secret_token(value: &str) -> String {
    value
        .trim_start()
        .trim_matches(|character: char| matches!(character, '"' | '\'' | ':' | ' '))
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || "-_.+/=:".contains(*character)
        })
        .collect()
}

fn extract_http_header(line: &str) -> Option<(String, &str)> {
    let trimmed = line.trim();
    let (name, value) = trimmed.split_once(':')?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, value.trim()))
}

fn looks_sensitive_cookie_name(name: &str) -> bool {
    [
        "session",
        "sessionid",
        "sid",
        "auth",
        "authtoken",
        "token",
        "jwt",
        "accesstoken",
        "refreshtoken",
    ]
    .iter()
    .any(|needle| name.contains(needle))
}

#[derive(Clone, Copy)]
struct PrefixedSecretRule {
    id: &'static str,
    title: &'static str,
    detail: &'static str,
    severity: Severity,
    confidence: Confidence,
    prefix: &'static str,
    min_length: usize,
    max_length: Option<usize>,
    allowed_characters: CharacterClass,
}

#[derive(Clone, Copy)]
enum CharacterClass {
    UpperAlphaNumeric,
    UrlSafe,
    Slack,
}

impl CharacterClass {
    fn allows(self, character: char) -> bool {
        match self {
            Self::UpperAlphaNumeric => character.is_ascii_uppercase() || character.is_ascii_digit(),
            Self::UrlSafe => {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            }
            Self::Slack => {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{ConfigScanner, DependencyScanner, Scanner, SecretScanner};
    use crate::core::config::{ConfigSource, ResolvedConfig};
    use crate::core::context::{ExecutionContext, ProtectedAction};
    use crate::core::findings::{Confidence, Severity};
    use crate::core::policy::EnforcementMode;
    use crate::core::receipts::ReceiptIndex;
    use std::fs;
    use std::path::PathBuf;

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn detects_private_key_material_in_text_files() {
        let (context, root) = test_context(&[(
            "keys/deploy.key",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nvery-secret\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Private key")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_docker_client_auth_config_paths() {
        let (context, root) = test_context(&[(
            ".docker/config.json",
            "{\n  \"auths\": {\n    \"registry.example.com\": {\n      \"auth\": \"dXNlcjpzZWNyZXQ=\"\n    }\n  }\n}\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.title.contains("Credential-bearing file path")
                && finding.location().contains(".docker/config.json")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_variable_secret_paths() {
        let (context, root) = test_context(&[(
            "environments/prod.auto.tfvars",
            "db_password = \"super-secret-value\"\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.title.contains("Infrastructure variable file")
                && finding.location().contains("prod.auto.tfvars")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_inline_authorization_credentials_but_ignores_placeholders() {
        let (context, root) = test_context(&[(
            "src/request.txt",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\nAuthorization: Bearer example-token\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Inline bearer token")));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Inline bearer token"))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_inline_http_secret_headers_but_ignores_placeholders() {
        let (context, root) = test_context(&[(
            "requests.http",
            "X-API-Key: sk_test_not_real_example\nX-API-Key: a1b2c3d4e5f6g7h8i9j0k1l2\nX-Auth-Token: example-token\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Inline HTTP secret header"))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_inline_cookie_session_secrets_but_ignores_benign_cookies() {
        let (context, root) = test_context(&[(
            "requests.http",
            "Cookie: theme=dark; sessionid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\nSet-Cookie: auth_token=example-token; Path=/; HttpOnly\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Inline cookie or session secret"))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_high_entropy_secret_assignments_but_ignores_placeholders() {
        let fake_live_key = ["sk", "live", "1234567890abcdefghijklmno"].join("_");
        let (context, root) = test_context(&[(
            "app/.env.template",
            &format!(
                "API_KEY=\"{fake_live_key}\"\nPLACEHOLDER_TOKEN=\"example-token\"\n"
            ),
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Stripe live secret key")));
        assert!(!findings
            .iter()
            .any(|finding| finding.detail.contains("PLACEHOLDER_TOKEN")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_cargo_git_dependencies() {
        let (context, root) = test_context(&[(
            "Cargo.toml",
            "[dependencies]\nserde = \"1\"\nprivate_dep = { git = \"https://github.com/example/private\", branch = \"main\" }\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Cargo dependency uses a direct Git source")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_lockfile_and_version_posture_issues() {
        let (context, root) = test_context(&[
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"left-pad\": \"latest\",\n    \"private-sdk\": \"git+https://github.com/example/private-sdk.git\"\n  }\n}\n",
            ),
            (
                "package-lock.json",
                "{\n  \"name\": \"demo\",\n  \"packages\": {\n    \"\": {\n      \"dependencies\": {\n        \"left-pad\": \"latest\"\n      }\n    }\n  },\n  \"resolved\": \"http://registry.example/pkg.tgz\"\n}\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("unbounded version selector")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("insecure HTTP")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_secret_manifests_with_inline_data() {
        let (context, root) = test_context(&[(
            "k8s/secret.yaml",
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-secret\nstringData:\n  DATABASE_URL: postgres://prod.example.internal/app\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Kubernetes Secret manifest with inline data")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_github_actions_write_all_permissions() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    branches: [main]\npermissions: write-all\njobs:\n  release:\n    runs-on: ubuntu-latest\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("GitHub Actions workflow grants write-all token permissions")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pull_request_target_head_references() {
        let (context, root) = test_context(&[(
            ".github/workflows/pr-target.yml",
            "name: pr-target\non:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("GitHub Actions pull_request_target workflow detected")
                && finding.severity == Severity::High
                && finding.confidence == Confidence::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    fn test_context(files: &[(&str, &str)]) -> (ExecutionContext, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "wolfence-scanner-test-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));

        fs::create_dir_all(&root).expect("temp root should be created");
        let mut candidate_files = Vec::new();

        for (relative_path, contents) in files {
            let full_path = root.join(relative_path);
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent).expect("temp file parent should exist");
            }
            fs::write(&full_path, contents).expect("temp file should be written");
            candidate_files.push(PathBuf::from(relative_path));
        }

        let context = ExecutionContext {
            action: ProtectedAction::Scan,
            repo_root: root.clone(),
            candidate_files,
            config: ResolvedConfig {
                mode: EnforcementMode::Standard,
                mode_source: ConfigSource::Default,
                repo_config_path: root.join(".wolfence/config.toml"),
                repo_config_exists: false,
            },
            receipts: ReceiptIndex::default(),
            push_status: None,
        };

        (context, root)
    }
}
