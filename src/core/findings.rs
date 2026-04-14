//! Normalized finding model.
//!
//! One of the most important architectural choices in Wolfence is that every
//! scanner, no matter how specialized, emits the same core finding shape. That
//! allows policy evaluation, UI rendering, persistence, and later cloud sync to
//! stay independent from scanner-specific quirks.

use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::path::PathBuf;

use serde::Serialize;

use super::finding_baseline::FindingBaselineState;
use super::finding_history::FindingHistoryState;

/// Coarse severity scale used by early policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Display for Severity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Confidence lets policy distinguish between heuristic noise and hard proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Display for Confidence {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// High-level problem category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Secret,
    Vulnerability,
    Dependency,
    Configuration,
    Policy,
}

impl Display for FindingCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret => write!(f, "secret"),
            Self::Vulnerability => write!(f, "vulnerability"),
            Self::Dependency => write!(f, "dependency"),
            Self::Configuration => write!(f, "configuration"),
            Self::Policy => write!(f, "policy"),
        }
    }
}

impl FindingCategory {
    /// Parses one textual finding category name.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value.trim() {
            "secret" => Ok(Self::Secret),
            "vulnerability" => Ok(Self::Vulnerability),
            "dependency" => Ok(Self::Dependency),
            "configuration" => Ok(Self::Configuration),
            "policy" => Ok(Self::Policy),
            _ => Err("expected secret, vulnerability, dependency, configuration, or policy"),
        }
    }
}

/// Coarse remediation family used to group operator actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationKind {
    RotateSecret,
    RestrictScope,
    PinReference,
    AddIntegrity,
    PatchDependency,
    ReviewCode,
    RemoveArtifact,
    RestoreWolfenceGuard,
    TightenGovernance,
    Investigate,
}

impl Display for RemediationKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RotateSecret => write!(f, "rotate-secret"),
            Self::RestrictScope => write!(f, "restrict-scope"),
            Self::PinReference => write!(f, "pin-reference"),
            Self::AddIntegrity => write!(f, "add-integrity"),
            Self::PatchDependency => write!(f, "patch-dependency"),
            Self::ReviewCode => write!(f, "review-code"),
            Self::RemoveArtifact => write!(f, "remove-artifact"),
            Self::RestoreWolfenceGuard => write!(f, "restore-wolfence-guard"),
            Self::TightenGovernance => write!(f, "tighten-governance"),
            Self::Investigate => write!(f, "investigate"),
        }
    }
}

/// Operator urgency bucket for one remediation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationUrgency {
    Immediate,
    BeforePush,
}

impl Display for RemediationUrgency {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate => write!(f, "immediate"),
            Self::BeforePush => write!(f, "before-push"),
        }
    }
}

/// The surface that most likely owns the fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationSurface {
    Secrets,
    Workflow,
    Dependency,
    Registry,
    Code,
    Artifact,
    Governance,
    Wolfence,
    Container,
    Infrastructure,
}

impl Display for RemediationSurface {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secrets => write!(f, "secrets"),
            Self::Workflow => write!(f, "workflow"),
            Self::Dependency => write!(f, "dependency"),
            Self::Registry => write!(f, "registry"),
            Self::Code => write!(f, "code"),
            Self::Artifact => write!(f, "artifact"),
            Self::Governance => write!(f, "governance"),
            Self::Wolfence => write!(f, "wolfence"),
            Self::Container => write!(f, "container"),
            Self::Infrastructure => write!(f, "infrastructure"),
        }
    }
}

/// Stable remediation metadata for UI grouping and operator workflows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemediationAdvice {
    pub kind: RemediationKind,
    pub urgency: RemediationUrgency,
    pub owner_surface: RemediationSurface,
    pub primary_action: String,
    pub primary_command: Option<String>,
    pub docs_ref: Option<String>,
}

/// Canonical finding emitted by a scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub id: String,
    pub scanner: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: FindingCategory,
    pub file: Option<PathBuf>,
    pub line: Option<usize>,
    pub title: String,
    pub detail: String,
    pub remediation: String,
    pub remediation_advice: RemediationAdvice,
    pub fingerprint: String,
    pub history: FindingHistoryState,
    pub baseline: FindingBaselineState,
}

impl Finding {
    /// Helper constructor for the early scaffold.
    pub fn new(
        id: impl Into<String>,
        scanner: &'static str,
        severity: Severity,
        confidence: Confidence,
        category: FindingCategory,
        file: Option<PathBuf>,
        title: impl Into<String>,
        detail: impl Into<String>,
        remediation: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let title = title.into();
        let detail = detail.into();
        let remediation = remediation.into();
        Self {
            remediation_advice: derive_remediation_advice(
                &id,
                scanner,
                category,
                &title,
                &remediation,
            ),
            id,
            scanner,
            severity,
            confidence,
            category,
            file,
            line: None,
            title,
            detail,
            remediation,
            fingerprint: fingerprint.into(),
            history: FindingHistoryState::default(),
            baseline: FindingBaselineState::default(),
        }
    }

    /// Attaches a 1-based line number to a finding.
    pub fn with_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    /// Renders the best available location string for operator-facing output.
    pub fn location(&self) -> String {
        self.file
            .as_ref()
            .map(|file| match self.line {
                Some(line) => format!("{}:{}", file.display(), line),
                None => file.display().to_string(),
            })
            .unwrap_or_else(|| "<no file>".to_string())
    }
}

fn derive_remediation_advice(
    id: &str,
    scanner: &str,
    category: FindingCategory,
    title: &str,
    remediation: &str,
) -> RemediationAdvice {
    if id.starts_with("secret.") {
        return advice(
            RemediationKind::RotateSecret,
            RemediationUrgency::Immediate,
            RemediationSurface::Secrets,
            "Rotate the exposed credential and remove it from repository scope.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.packaged-archive" {
        return advice(
            RemediationKind::RemoveArtifact,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Remove packaged archives from source control or justify them through review.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.archive.path-traversal-entry" {
        return advice(
            RemediationKind::Investigate,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Reject traversal-style archive entries and verify the archive is safe before extraction or distribution.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.archive.embedded-executable" {
        return advice(
            RemediationKind::Investigate,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Review embedded executable payloads inside the archive and verify their provenance before keeping the artifact.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.compiled-binary" {
        return advice(
            RemediationKind::RemoveArtifact,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Remove compiled binaries from the repository or replace them with reproducible sources.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.minified-bundle.remote-loader" {
        return advice(
            RemediationKind::Investigate,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Audit the minified bundle, verify provenance, and replace it with a reviewed build artifact.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.minified-bundle.beaconing" {
        return advice(
            RemediationKind::Investigate,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Audit the beaconing bundle, verify the endpoint and telemetry purpose, and replace it with a reviewed build artifact.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.source-map" {
        return advice(
            RemediationKind::RemoveArtifact,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Remove deployable source maps from the outbound change or restrict how they are distributed.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.generated-asset.embedded-secret" {
        return advice(
            RemediationKind::RotateSecret,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Remove the secret from the generated asset, rotate it, and rebuild the artifact from safe inputs.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id == "artifact.executable-text.new-file" {
        return advice(
            RemediationKind::Investigate,
            RemediationUrgency::BeforePush,
            RemediationSurface::Artifact,
            "Review the new executable launcher, justify its location, and verify its provenance before keeping it executable.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.starts_with("sast.") {
        let primary_action = match id {
            "sast.command-injection.untrusted-input" => {
                "Stop feeding untrusted input into command execution paths."
            }
            "sast.ssrf.untrusted-url" | "sast.ssrf.cloud-metadata-access" => {
                "Constrain outbound requests to trusted destinations and remove attacker-controlled URLs."
            }
            "sast.path-traversal.untrusted-path" => {
                "Constrain filesystem access to trusted paths and normalize user-controlled input."
            }
            "sast.unsafe-deserialization" => {
                "Replace unsafe deserialization with a safe parser or a strict allowlist."
            }
            "sast.sql-injection.untrusted-query" => {
                "Replace string-built SQL with parameterized queries or prepared statements."
            }
            "sast.insecure-randomness.secret-generation" => {
                "Replace non-cryptographic randomness with a cryptographically secure token generator."
            }
            "sast.unsafe-crypto.weak-primitive" => {
                "Replace weak hashes, legacy ciphers, and ECB-mode encryption with modern cryptographic primitives."
            }
            "sast.file-upload.untrusted-write" => {
                "Constrain uploaded-file handling with server-side names, validated content, and fixed destination paths."
            }
            "sast.archive-extraction.untrusted-input" => {
                "Harden archive extraction by validating entries and rejecting traversal paths before unpacking."
            }
            "sast.authz-bypass.untrusted-privilege-assignment" => {
                "Stop trusting caller-supplied role, admin, permission, or ownership fields directly."
            }
            "sast.authz-bypass.privileged-surface-open-access" => {
                "Restore explicit authentication and authorization checks on privileged surfaces."
            }
            "sast.remote-script.execution" => {
                "Stop executing remote scripts directly and replace them with pinned, reviewed assets."
            }
            _ => "Review and harden the flagged code path before push.",
        };
        return advice(
            RemediationKind::ReviewCode,
            RemediationUrgency::BeforePush,
            RemediationSurface::Code,
            primary_action,
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.starts_with("dependency.") {
        return dependency_advice(id);
    }

    if id.starts_with("config.dockerfile.") {
        let (kind, primary_action) = match id {
            "config.dockerfile.unpinned-base-image" => (
                RemediationKind::PinReference,
                "Pin the Docker base image to an immutable digest.",
            ),
            "config.dockerfile.final-stage-root-user" => (
                RemediationKind::RestrictScope,
                "Drop final-stage container privileges to a dedicated non-root user.",
            ),
            "config.dockerfile.remote-pipe-installer" => (
                RemediationKind::ReviewCode,
                "Replace remote shell pipes with pinned or checksum-verified installer inputs.",
            ),
            "config.dockerfile.remote-download-execution" => (
                RemediationKind::ReviewCode,
                "Verify remote downloads explicitly before executing the fetched payload.",
            ),
            "config.dockerfile.remote-add-source" => (
                RemediationKind::ReviewCode,
                "Replace remote ADD sources with verified local build inputs or explicit verified download steps.",
            ),
            _ => (
                RemediationKind::RestrictScope,
                "Review and harden the flagged Dockerfile posture before push.",
            ),
        };
        return advice(
            kind,
            RemediationUrgency::BeforePush,
            RemediationSurface::Container,
            primary_action,
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.starts_with("config.github-actions.") {
        return github_actions_advice(id);
    }

    if id == "config.kubernetes.secret-manifest" {
        return advice(
            RemediationKind::RestrictScope,
            RemediationUrgency::BeforePush,
            RemediationSurface::Infrastructure,
            "Remove inline Kubernetes secrets and move them to a proper secret manager or sealed secret flow.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.starts_with("config.terraform.") {
        return terraform_config_advice(id);
    }

    if id.starts_with("config.kubernetes.") {
        return kubernetes_config_advice(id);
    }

    if id.starts_with("config.github-governance.") || id.starts_with("policy.repo.") {
        return advice(
            RemediationKind::TightenGovernance,
            RemediationUrgency::BeforePush,
            RemediationSurface::Governance,
            "Tighten repository governance so sensitive paths require review and bypasses stay disabled.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.starts_with("policy.wolfence.") {
        return wolfence_policy_advice(id);
    }

    advice(
        default_kind(category, scanner),
        default_urgency(category),
        default_surface(category, scanner),
        first_sentence(remediation).unwrap_or(title).to_string(),
        None,
        Some("docs/security/detection-model.md"),
    )
}

fn dependency_advice(id: &str) -> RemediationAdvice {
    if id.contains("lockfile.missing") {
        return advice(
            RemediationKind::AddIntegrity,
            RemediationUrgency::BeforePush,
            RemediationSurface::Dependency,
            "Commit the matching lockfile before pushing dependency changes.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.contains("missing-integrity") || id.contains("missing-checksum") {
        return advice(
            RemediationKind::AddIntegrity,
            RemediationUrgency::BeforePush,
            RemediationSurface::Dependency,
            "Regenerate the lockfile so dependency integrity data is recorded.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.contains("unpinned")
        || id.contains("wildcard-version")
        || id.contains("unbounded-version")
    {
        return advice(
            RemediationKind::PinReference,
            RemediationUrgency::BeforePush,
            RemediationSurface::Dependency,
            "Pin dependency versions to reviewed, explicit releases.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.contains("insecure")
        || id.contains("trusted-host")
        || id.contains("custom-index")
        || id.contains("extra-index")
        || id.contains("index-url")
        || id.contains("find-links")
    {
        return advice(
            RemediationKind::RestrictScope,
            RemediationUrgency::BeforePush,
            RemediationSurface::Registry,
            "Remove insecure registry overrides and route dependency resolution through trusted registries only.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    if id.contains("git-source")
        || id.contains("direct-source")
        || id.contains("direct-remote-source")
        || id.contains("local-source")
        || id.contains("path-source")
        || id.contains("source-override")
    {
        return advice(
            RemediationKind::PatchDependency,
            RemediationUrgency::BeforePush,
            RemediationSurface::Dependency,
            "Replace ad hoc dependency sources with reviewed registry or vendored releases.",
            None,
            Some("docs/security/detection-model.md"),
        );
    }

    advice(
        RemediationKind::PatchDependency,
        RemediationUrgency::BeforePush,
        RemediationSurface::Dependency,
        "Review the dependency configuration and move it back to a reproducible, integrity-checked state.",
        None,
        Some("docs/security/detection-model.md"),
    )
}

fn github_actions_advice(id: &str) -> RemediationAdvice {
    let (kind, primary_action) = match id {
        "config.github-actions.unpinned-third-party-action"
        | "config.github-actions.unpinned-reusable-workflow" => (
            RemediationKind::PinReference,
            "Pin the referenced action or reusable workflow to an immutable commit SHA.",
        ),
        "config.github-actions.attestation-permissions" => (
            RemediationKind::RestrictScope,
            "Grant the exact attestation permissions required before relying on release provenance.",
        ),
        "config.github-actions.trusted-publishing-permissions" => (
            RemediationKind::RestrictScope,
            "Grant the id-token permission required before relying on trusted publishing.",
        ),
        "config.github-actions.keyless-signing-permissions" => (
            RemediationKind::RestrictScope,
            "Grant the id-token permission required before relying on keyless signing.",
        ),
        "config.github-actions.signing-long-lived-credential" => (
            RemediationKind::RestrictScope,
            "Replace long-lived signing secrets with keyless or otherwise short-lived signing credentials.",
        ),
        "config.github-actions.release-long-lived-credential" => (
            RemediationKind::RestrictScope,
            "Replace long-lived release secrets with the ephemeral repository token or another short-lived release credential flow.",
        ),
        "config.github-actions.oci-long-lived-registry-credential" => (
            RemediationKind::RestrictScope,
            "Replace long-lived OCI registry secrets with short-lived registry authentication where possible.",
        ),
        "config.github-actions.branch-push-publish"
        | "config.github-actions.branch-push-tags"
        | "config.github-actions.publish-without-provenance"
        | "config.github-actions.publish-long-lived-credential"
        | "config.github-actions.oci-publish-without-provenance" => (
            RemediationKind::TightenGovernance,
            "Move publishing behind tag or release-controlled workflows with provenance enabled.",
        ),
        "config.github-actions.dispatch-ref-checkout"
        | "config.github-actions.release-target-checkout"
        | "config.github-actions.release-branch-ref" => (
            RemediationKind::PinReference,
            "Stop checking out mutable refs in release paths and build from the intended immutable target.",
        ),
        "config.github-actions.artifact-execution" => (
            RemediationKind::Investigate,
            "Review downloaded artifacts before execution and remove direct artifact-to-execution chains.",
        ),
        "config.github-actions.permissions-write-all"
        | "config.github-actions.pull-request-target.checkout-credentials"
        | "config.github-actions.secrets-inherit"
        | "config.github-actions.unsecure-commands"
        | "config.github-actions.pull-request-target"
        | "config.github-actions.self-hosted-runner" => (
            RemediationKind::RestrictScope,
            "Reduce workflow privileges so untrusted pull request content cannot inherit secrets, credentials, or runner trust.",
        ),
        "config.github-actions.docker-action" => (
            RemediationKind::Investigate,
            "Review direct docker actions carefully and replace them with pinned, transparent actions when possible.",
        ),
        "config.github-actions.workflow-run" => (
            RemediationKind::Investigate,
            "Review workflow trust bridges so upstream runs cannot smuggle unreviewed content into privileged jobs.",
        ),
        _ => (
            RemediationKind::RestrictScope,
            "Tighten the workflow so it runs with narrower trust and immutable inputs.",
        ),
    };

    advice(
        kind,
        RemediationUrgency::BeforePush,
        RemediationSurface::Workflow,
        primary_action,
        None,
        Some("docs/security/detection-model.md"),
    )
}

fn wolfence_policy_advice(id: &str) -> RemediationAdvice {
    let (primary_action, command) = match id {
        "policy.wolfence.pre-push-hook-missing" => (
            "Reinstall the managed Wolfence pre-push hook before relying on native git push.",
            Some("wolf init"),
        ),
        "policy.wolfence.pre-push-hook-not-executable" => (
            "Restore the managed Wolfence pre-push hook so Git can execute it.",
            Some("wolf init"),
        ),
        "policy.wolfence.pre-push-hook-unmanaged"
        | "policy.wolfence.pre-push-hook-unknown-launcher"
        | "policy.wolfence.pre-push-hook-legacy-launcher"
        | "policy.wolfence.external-hook-helper"
        | "policy.wolfence.external-hook-symlink"
        | "policy.wolfence.external-hooks-path" => (
            "Restore Wolfence as the authoritative pre-push enforcement path.",
            Some("wolf init"),
        ),
        "policy.wolfence.repo-local-hooks-path" => (
            "Review and justify the alternate repo-local hooks authority path before relying on it.",
            None,
        ),
        "policy.wolfence.additional-unmanaged-hooks" => (
            "Review and remove unexpected executable hooks from the effective hooks directory.",
            None,
        ),
        "policy.wolfence.scanner-bundle-changed" => (
            "Review scanner-bundle changes as changes to Wolfence's own trust boundary.",
            None,
        ),
        "policy.wolfence.rule-provenance-missing" => (
            "Update Wolfence's declared rule inventory when scanner-bundle behavior changes.",
            None,
        ),
        "policy.wolfence.mode-advisory" => (
            "Move the repository back to standard or strict mode before production pushes.",
            None,
        ),
        "policy.wolfence.sensitive-ignore-path" => (
            "Remove sensitive paths from Wolfence ignore rules so they stay in enforcement scope.",
            None,
        ),
        "policy.wolfence.receipt-policy-changed"
        | "policy.wolfence.receipt-changed"
        | "policy.wolfence.trust-store-changed"
        | "policy.wolfence.trust-archive-changed"
        | "policy.wolfence.unrestricted-trust-key"
        | "policy.wolfence.config-changed" => (
            "Review the Wolfence governance change and re-approve it under signed exception policy if needed.",
            None,
        ),
        _ => (
            "Review the Wolfence self-protection change before push.",
            None,
        ),
    };

    advice(
        if command.is_some() {
            RemediationKind::RestoreWolfenceGuard
        } else {
            RemediationKind::TightenGovernance
        },
        RemediationUrgency::Immediate,
        RemediationSurface::Wolfence,
        primary_action,
        command.map(str::to_string),
        Some("docs/security/detection-model.md"),
    )
}

fn default_kind(category: FindingCategory, scanner: &str) -> RemediationKind {
    match (category, scanner) {
        (FindingCategory::Secret, _) => RemediationKind::RotateSecret,
        (FindingCategory::Dependency, _) => RemediationKind::PatchDependency,
        (FindingCategory::Vulnerability, _) => RemediationKind::ReviewCode,
        (FindingCategory::Configuration, "policy-scanner") => RemediationKind::TightenGovernance,
        (FindingCategory::Configuration, _) => RemediationKind::RestrictScope,
        (FindingCategory::Policy, _) => RemediationKind::TightenGovernance,
    }
}

fn default_urgency(category: FindingCategory) -> RemediationUrgency {
    match category {
        FindingCategory::Secret | FindingCategory::Policy => RemediationUrgency::Immediate,
        FindingCategory::Vulnerability
        | FindingCategory::Dependency
        | FindingCategory::Configuration => RemediationUrgency::BeforePush,
    }
}

fn default_surface(category: FindingCategory, scanner: &str) -> RemediationSurface {
    match (category, scanner) {
        (FindingCategory::Secret, _) => RemediationSurface::Secrets,
        (FindingCategory::Dependency, _) => RemediationSurface::Dependency,
        (FindingCategory::Vulnerability, _) => RemediationSurface::Code,
        (FindingCategory::Configuration, "config-scanner") => RemediationSurface::Workflow,
        (FindingCategory::Configuration, _) => RemediationSurface::Governance,
        (FindingCategory::Policy, "policy-scanner") => RemediationSurface::Wolfence,
        (FindingCategory::Policy, _) => RemediationSurface::Governance,
    }
}

fn terraform_config_advice(id: &str) -> RemediationAdvice {
    let primary_action = match id {
        "config.terraform.public-storage" => {
            "Disable public object-storage exposure and require explicit private access controls."
        }
        "config.terraform.backend.s3-encryption-disabled" => {
            "Re-enable encryption for the S3 remote state backend."
        }
        "config.terraform.backend.insecure-http" => {
            "Move the remote state backend to HTTPS so state transport remains encrypted and authenticated."
        }
        "config.terraform.output.secret-sensitive-false" => {
            "Mark secret-bearing Terraform outputs as sensitive or remove them from operator-facing output paths."
        }
        "config.terraform.variable.secret-sensitive-false" => {
            "Keep secret-bearing Terraform variables marked sensitive so plans and tooling do not expose them like ordinary values."
        }
        "config.terraform.inline-secret-attribute" => {
            "Replace inline Terraform secrets with sensitive variables, secret-manager references, or another reviewed injection path."
        }
        "config.terraform.iam.wildcard-principal" => {
            "Replace wildcard principals with the narrowest explicit trusted identities."
        }
        "config.terraform.iam.wildcard-actions" => {
            "Replace wildcard IAM actions or resources with a narrowly scoped allowlist."
        }
        "config.terraform.public-admin-ingress" => {
            "Close public administrative ingress and route access through a controlled bastion or private network."
        }
        "config.terraform.public-sensitive-service-ingress" => {
            "Keep database, cache, observability, and control-plane ports off the public internet and route them through private or tightly allowlisted networks only."
        }
        "config.terraform.public-all-ports-ingress" => {
            "Replace broad public ingress with a minimal port set and explicitly allowlisted source ranges."
        }
        _ => "Tighten the Terraform or OpenTofu change before push.",
    };

    advice(
        if id.contains("wildcard") {
            RemediationKind::TightenGovernance
        } else {
            RemediationKind::RestrictScope
        },
        RemediationUrgency::BeforePush,
        RemediationSurface::Infrastructure,
        primary_action,
        None,
        Some("docs/security/detection-model.md"),
    )
}

fn kubernetes_config_advice(id: &str) -> RemediationAdvice {
    let primary_action = match id {
        "config.kubernetes.secret-manifest" => {
            "Remove inline Kubernetes secrets and move them to a proper secret manager or sealed secret flow."
        }
        "config.kubernetes.rbac-wildcard" => {
            "Replace wildcard Kubernetes RBAC permissions with the narrowest required verbs and resources."
        }
        "config.kubernetes.cluster-admin-binding" => {
            "Remove direct cluster-admin bindings and grant the minimum cluster role required."
        }
        "config.kubernetes.privileged-pod" => {
            "Drop privileged container mode and keep the workload within a restricted pod security profile."
        }
        "config.kubernetes.allow-privilege-escalation" => {
            "Disable privilege escalation for the workload unless there is a reviewed hard requirement."
        }
        "config.kubernetes.run-as-root" => {
            "Run the workload as non-root and keep `runAsNonRoot` enabled."
        }
        "config.kubernetes.host-namespace" => {
            "Stop sharing host namespaces unless the workload has an explicit reviewed platform need."
        }
        "config.kubernetes.hostpath-volume" => {
            "Remove hostPath mounts or replace them with a safer storage abstraction."
        }
        "config.kubernetes.ingress-tls-redirect-disabled" => {
            "Re-enable HTTPS redirect for the ingress unless the cleartext path is narrowly reviewed and intentionally constrained."
        }
        "config.kubernetes.ingress-sensitive-path" => {
            "Put sensitive ingress paths behind a source-range allowlist, stronger authentication, or an internal-only ingress surface."
        }
        "config.kubernetes.pod-security-privileged" => {
            "Move namespace Pod Security enforcement to `baseline` or `restricted` unless the namespace has a tightly reviewed privileged workload requirement."
        }
        "config.kubernetes.admission-webhook-failure-ignore" => {
            "Set security-relevant admission webhooks to `failurePolicy: Fail` so enforcement does not silently fail open."
        }
        _ => "Tighten the Kubernetes manifest before push.",
    };

    advice(
        if id.contains("rbac") || id.contains("cluster-admin") {
            RemediationKind::TightenGovernance
        } else {
            RemediationKind::RestrictScope
        },
        RemediationUrgency::BeforePush,
        RemediationSurface::Infrastructure,
        primary_action,
        None,
        Some("docs/security/detection-model.md"),
    )
}

fn advice(
    kind: RemediationKind,
    urgency: RemediationUrgency,
    owner_surface: RemediationSurface,
    primary_action: impl Into<String>,
    primary_command: Option<String>,
    docs_ref: Option<&str>,
) -> RemediationAdvice {
    RemediationAdvice {
        kind,
        urgency,
        owner_surface,
        primary_action: primary_action.into(),
        primary_command,
        docs_ref: docs_ref.map(str::to_string),
    }
}

fn first_sentence(text: &str) -> Option<&str> {
    text.split('.')
        .map(str::trim)
        .find(|segment| !segment.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        Confidence, Finding, FindingCategory, RemediationKind, RemediationSurface,
        RemediationUrgency, Severity,
    };

    #[test]
    fn derives_secret_rotation_guidance() {
        let finding = Finding::new(
            "secret.url.embedded-credentials",
            "secret-scanner",
            Severity::Critical,
            Confidence::High,
            FindingCategory::Secret,
            None,
            "Credential in URL",
            "detail",
            "Remove the secret.",
            "fp",
        );

        assert_eq!(
            finding.remediation_advice.kind,
            RemediationKind::RotateSecret
        );
        assert_eq!(
            finding.remediation_advice.urgency,
            RemediationUrgency::Immediate
        );
        assert_eq!(
            finding.remediation_advice.owner_surface,
            RemediationSurface::Secrets
        );
    }

    #[test]
    fn derives_hook_recovery_command_for_wolfence_policy_findings() {
        let finding = Finding::new(
            "policy.wolfence.pre-push-hook-missing",
            "policy-scanner",
            Severity::High,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Hook missing",
            "detail",
            "Run wolf init.",
            "fp",
        );

        assert_eq!(
            finding.remediation_advice.kind,
            RemediationKind::RestoreWolfenceGuard
        );
        assert_eq!(
            finding.remediation_advice.primary_command.as_deref(),
            Some("wolf init")
        );
    }

    #[test]
    fn derives_lockfile_guidance_for_missing_lockfiles() {
        let finding = Finding::new(
            "dependency.lockfile.missing.python",
            "dependency-scanner",
            Severity::Medium,
            Confidence::High,
            FindingCategory::Dependency,
            None,
            "Missing lockfile",
            "detail",
            "Add a lockfile.",
            "fp",
        );

        assert_eq!(
            finding.remediation_advice.kind,
            RemediationKind::AddIntegrity
        );
        assert_eq!(
            finding.remediation_advice.owner_surface,
            RemediationSurface::Dependency
        );
    }
}
