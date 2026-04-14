//! Optional live GitHub governance verification.
//!
//! Wolfence remains local-first, but repositories that express branch and
//! release controls as code often also need a way to verify that GitHub's live
//! server-side state still matches that intent. This module keeps that check
//! bounded and explicit.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::app::{AppError, AppResult};

use super::findings::{Confidence, Finding, FindingCategory, Severity};
use super::git;

const GITHUB_API_TIMEOUT_SECONDS: &str = "6";
const GITHUB_GOVERNANCE_SCANNER: &str = "github-governance";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubGovernanceMode {
    Off,
    Auto,
    Require,
}

impl Display for GithubGovernanceMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => write!(f, "off"),
            Self::Auto => write!(f, "auto"),
            Self::Require => write!(f, "require"),
        }
    }
}

impl GithubGovernanceMode {
    pub fn resolve() -> AppResult<Self> {
        match std::env::var("WOLFENCE_GITHUB_GOVERNANCE")
            .ok()
            .as_deref()
        {
            None | Some("") | Some("auto") | Some("AUTO") => Ok(Self::Auto),
            Some("off" | "OFF" | "0" | "false" | "FALSE") => Ok(Self::Off),
            Some("require" | "REQUIRE" | "1" | "true" | "TRUE") => Ok(Self::Require),
            Some(other) => Err(AppError::Config(format!(
                "invalid WOLFENCE_GITHUB_GOVERNANCE override `{other}`: expected off, auto, or require"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveGovernanceVerification {
    pub mode: GithubGovernanceMode,
    pub repository: Option<String>,
    pub default_branch: Option<String>,
    pub checked_branches: Vec<String>,
    pub attempted: bool,
    pub unavailable_reason: Option<String>,
    pub drifts: Vec<String>,
    pub local_intent_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoRef {
    owner: String,
    name: String,
}

impl RepoRef {
    fn display_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalGovernanceIntent {
    protected_branches: Vec<String>,
    block_force_pushes: bool,
    block_deletions: bool,
    require_admin_enforcement: bool,
    minimum_approvals: Option<usize>,
    require_code_owner_reviews: bool,
    dismiss_stale_reviews: bool,
    expects_rulesets: bool,
    expects_active_rulesets: bool,
}

impl LocalGovernanceIntent {
    fn is_empty(&self) -> bool {
        self.protected_branches.is_empty()
            && !self.block_force_pushes
            && !self.block_deletions
            && !self.require_admin_enforcement
            && self.minimum_approvals.is_none()
            && !self.require_code_owner_reviews
            && !self.dismiss_stale_reviews
            && !self.expects_rulesets
            && !self.expects_active_rulesets
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveBranchProtection {
    allow_force_pushes: bool,
    allow_deletions: bool,
    enforce_admins: bool,
    required_approving_review_count: usize,
    require_code_owner_reviews: bool,
    dismiss_stale_reviews: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveRulesetSummary {
    total: usize,
    active: usize,
}

#[derive(Deserialize)]
struct RepoInfoResponse {
    default_branch: String,
}

#[derive(Deserialize)]
struct BranchProtectionResponse {
    allow_force_pushes: Option<EnabledField>,
    allow_deletions: Option<EnabledField>,
    enforce_admins: Option<EnabledField>,
    required_pull_request_reviews: Option<RequiredPullRequestReviews>,
}

#[derive(Deserialize)]
struct EnabledField {
    enabled: bool,
}

#[derive(Deserialize)]
struct RequiredPullRequestReviews {
    dismiss_stale_reviews: bool,
    require_code_owner_reviews: bool,
    required_approving_review_count: usize,
}

#[derive(Deserialize)]
struct RulesetResponse {
    enforcement: Option<String>,
}

pub fn verify_live_governance(repo_root: &Path) -> AppResult<LiveGovernanceVerification> {
    let mode = GithubGovernanceMode::resolve()?;
    let Some(repo) = resolve_repo_ref(repo_root)? else {
        return Ok(LiveGovernanceVerification {
            mode,
            repository: None,
            default_branch: None,
            checked_branches: Vec::new(),
            attempted: false,
            unavailable_reason: None,
            drifts: Vec::new(),
            local_intent_present: false,
        });
    };

    let repo_display = repo.display_name();
    let intent = infer_local_governance_intent(repo_root)?;
    if intent.is_empty() {
        return Ok(LiveGovernanceVerification {
            mode,
            repository: Some(repo_display),
            default_branch: None,
            checked_branches: Vec::new(),
            attempted: false,
            unavailable_reason: None,
            drifts: Vec::new(),
            local_intent_present: false,
        });
    }

    if mode == GithubGovernanceMode::Off {
        return Ok(LiveGovernanceVerification {
            mode,
            repository: Some(repo_display),
            default_branch: None,
            checked_branches: Vec::new(),
            attempted: false,
            unavailable_reason: None,
            drifts: Vec::new(),
            local_intent_present: true,
        });
    }

    match fetch_live_governance(&repo, &intent) {
        Ok((default_branch, checked_branches, branch_protections, live_rulesets)) => {
            let drifts = compare_live_governance(
                &intent,
                &default_branch,
                &branch_protections,
                live_rulesets,
            );
            Ok(LiveGovernanceVerification {
                mode,
                repository: Some(repo_display),
                default_branch: Some(default_branch),
                checked_branches,
                attempted: true,
                unavailable_reason: None,
                drifts,
                local_intent_present: true,
            })
        }
        Err(error) => Ok(LiveGovernanceVerification {
            mode,
            repository: Some(repo_display),
            default_branch: None,
            checked_branches: Vec::new(),
            attempted: true,
            unavailable_reason: Some(error.to_string()),
            drifts: Vec::new(),
            local_intent_present: true,
        }),
    }
}

pub fn push_blocking_finding(repo_root: &Path) -> AppResult<Option<Finding>> {
    let verification = verify_live_governance(repo_root)?;
    push_blocking_finding_from_verification(&verification)
}

fn push_blocking_finding_from_verification(
    verification: &LiveGovernanceVerification,
) -> AppResult<Option<Finding>> {
    if verification.mode == GithubGovernanceMode::Off
        || verification.repository.is_none()
        || !verification.local_intent_present
    {
        return Ok(None);
    }

    let Some(repository) = verification.repository.as_deref() else {
        return Ok(None);
    };

    if let Some(reason) = verification.unavailable_reason.as_deref() {
        if verification.mode != GithubGovernanceMode::Require {
            return Ok(None);
        }

        let detail = format!(
            "protected push requires live GitHub governance verification for `{repository}`, but the verification could not complete: {reason}"
        );
        let fingerprint =
            governance_fingerprint("unavailable", verification, std::slice::from_ref(&detail))?;
        return Ok(Some(Finding::new(
            "policy.github.live-governance.unavailable",
            GITHUB_GOVERNANCE_SCANNER,
            Severity::High,
            Confidence::High,
            FindingCategory::Policy,
            None,
            "Required live GitHub governance verification is unavailable",
            detail,
            "Repair GitHub CLI authentication or reachability, or create a short-lived `policy` override receipt for this exact verification failure after review.",
            fingerprint,
        )));
    }

    if verification.drifts.is_empty() {
        return Ok(None);
    }

    let branch_scope = if verification.checked_branches.is_empty() {
        "<unknown branches>".to_string()
    } else {
        verification.checked_branches.join(", ")
    };
    let detail = format!(
        "protected push detected live GitHub governance drift for `{repository}` across checked branches ({branch_scope}): {}",
        verification.drifts.join(" ")
    );
    let fingerprint = governance_fingerprint("drift", verification, &verification.drifts)?;
    Ok(Some(Finding::new(
        "policy.github.live-governance.drift",
        GITHUB_GOVERNANCE_SCANNER,
        Severity::High,
        Confidence::High,
        FindingCategory::Policy,
        None,
        "Live GitHub governance drift blocks protected push",
        detail,
        "Align live GitHub branch protection and rulesets with the repository's governance-as-code intent, or create a short-lived `policy` override receipt for this exact drift after review.",
        fingerprint,
    )))
}

fn resolve_repo_ref(repo_root: &Path) -> AppResult<Option<RepoRef>> {
    let Some(remote) = git::preferred_remote(repo_root)? else {
        return Ok(None);
    };
    let Some(url) = git::remote_url(repo_root, &remote)? else {
        return Ok(None);
    };

    Ok(parse_github_repo_url(&url))
}

fn infer_local_governance_intent(repo_root: &Path) -> AppResult<LocalGovernanceIntent> {
    let mut intent = LocalGovernanceIntent::default();

    for relative in [
        ".github/settings.yml",
        ".github/settings.yaml",
        ".github/repository.yml",
        ".github/repository.yaml",
    ] {
        let path = repo_root.join(relative);
        if !path.exists() {
            continue;
        }

        let contents = fs::read_to_string(path)?;
        let lower = contents.to_ascii_lowercase();
        for branch in parse_branch_names(&contents) {
            if !intent
                .protected_branches
                .iter()
                .any(|existing| existing == &branch)
            {
                intent.protected_branches.push(branch);
            }
        }
        if lower.contains("allow_force_pushes: false")
            || lower.contains("\"allow_force_pushes\": false")
            || lower.contains("allows_force_pushes: false")
            || lower.contains("\"allows_force_pushes\": false")
        {
            intent.block_force_pushes = true;
        }
        if lower.contains("allow_deletions: false")
            || lower.contains("\"allow_deletions\": false")
            || lower.contains("allows_deletions: false")
            || lower.contains("\"allows_deletions\": false")
        {
            intent.block_deletions = true;
        }
        if lower.contains("enforce_admins: true") || lower.contains("\"enforce_admins\": true") {
            intent.require_admin_enforcement = true;
        }
        if lower.contains("require_code_owner_reviews: true")
            || lower.contains("\"require_code_owner_reviews\": true")
            || lower.contains("require_code_owner_review: true")
            || lower.contains("\"require_code_owner_review\": true")
        {
            intent.require_code_owner_reviews = true;
        }
        if lower.contains("dismiss_stale_reviews: true")
            || lower.contains("\"dismiss_stale_reviews\": true")
        {
            intent.dismiss_stale_reviews = true;
        }
        if let Some(count) = parse_required_approvals(&contents) {
            intent.minimum_approvals = Some(
                intent
                    .minimum_approvals
                    .map_or(count, |current| current.max(count)),
            );
        }
    }

    let rulesets_dir = repo_root.join(".github/rulesets");
    if rulesets_dir.exists() {
        intent.expects_rulesets = true;
        for entry in walk_files(&rulesets_dir)? {
            let contents = fs::read_to_string(entry)?;
            let lower = contents.to_ascii_lowercase();
            if lower.contains("enforcement: active")
                || lower.contains("\"enforcement\": \"active\"")
            {
                intent.expects_active_rulesets = true;
            }
            if lower.contains("non_fast_forward") || lower.contains("non-fast-forward") {
                intent.block_force_pushes = true;
            }
        }
    }

    Ok(intent)
}

fn walk_files(root: &Path) -> AppResult<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = fs::metadata(&path)?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        } else {
            files.push(path);
        }
    }
    Ok(files)
}

fn fetch_live_governance(
    repo: &RepoRef,
    intent: &LocalGovernanceIntent,
) -> AppResult<(
    String,
    Vec<String>,
    Vec<(String, Option<LiveBranchProtection>)>,
    LiveRulesetSummary,
)> {
    let repo_info: RepoInfoResponse = gh_api_json(&format!("repos/{}/{}", repo.owner, repo.name))?;
    let mut checked_branches = if intent.protected_branches.is_empty() {
        vec![repo_info.default_branch.clone()]
    } else {
        intent.protected_branches.clone()
    };
    if !checked_branches
        .iter()
        .any(|branch| branch == &repo_info.default_branch)
    {
        checked_branches.push(repo_info.default_branch.clone());
    }

    let mut branch_protections = Vec::new();
    for branch in &checked_branches {
        let encoded_branch = percent_encode_path_segment(branch);
        let branch_protection = gh_api_json::<BranchProtectionResponse>(&format!(
            "repos/{}/{}/branches/{}/protection",
            repo.owner, repo.name, encoded_branch
        ))
        .map(Some)
        .or_else(|error| {
            let message = error.to_string();
            if message.contains("404") || message.contains("Branch not protected") {
                Ok(None)
            } else {
                Err(error)
            }
        })?;

        let branch_protection = branch_protection.map(|value| LiveBranchProtection {
            allow_force_pushes: value
                .allow_force_pushes
                .map(|field| field.enabled)
                .unwrap_or(false),
            allow_deletions: value
                .allow_deletions
                .map(|field| field.enabled)
                .unwrap_or(false),
            enforce_admins: value
                .enforce_admins
                .map(|field| field.enabled)
                .unwrap_or(false),
            required_approving_review_count: value
                .required_pull_request_reviews
                .as_ref()
                .map(|reviews| reviews.required_approving_review_count)
                .unwrap_or(0),
            require_code_owner_reviews: value
                .required_pull_request_reviews
                .as_ref()
                .map(|reviews| reviews.require_code_owner_reviews)
                .unwrap_or(false),
            dismiss_stale_reviews: value
                .required_pull_request_reviews
                .as_ref()
                .map(|reviews| reviews.dismiss_stale_reviews)
                .unwrap_or(false),
        });
        branch_protections.push((branch.clone(), branch_protection));
    }

    let live_rulesets = gh_api_json::<Vec<RulesetResponse>>(&format!(
        "repos/{}/{}/rulesets?includes_parents=true&per_page=100",
        repo.owner, repo.name
    ))?;

    let active_rulesets = live_rulesets
        .iter()
        .filter(|ruleset| {
            matches!(
                ruleset.enforcement.as_deref(),
                Some("active") | Some("ACTIVE")
            )
        })
        .count();

    Ok((
        repo_info.default_branch,
        checked_branches,
        branch_protections,
        LiveRulesetSummary {
            total: live_rulesets.len(),
            active: active_rulesets,
        },
    ))
}

fn compare_live_governance(
    intent: &LocalGovernanceIntent,
    _default_branch: &str,
    branch_protections: &[(String, Option<LiveBranchProtection>)],
    live_rulesets: LiveRulesetSummary,
) -> Vec<String> {
    let mut drifts = Vec::new();
    for (branch, branch_protection) in branch_protections {
        if let Some(live) = branch_protection {
            if intent.block_force_pushes && live.allow_force_pushes {
                drifts.push(format!(
                    "live branch protection on `{branch}` still allows force pushes."
                ));
            }
            if intent.block_deletions && live.allow_deletions {
                drifts.push(format!(
                    "live branch protection on `{branch}` still allows deletions."
                ));
            }
            if intent.require_admin_enforcement && !live.enforce_admins {
                drifts.push(format!(
                    "live branch protection on `{branch}` does not enforce rules for administrators."
                ));
            }
            if let Some(minimum_approvals) = intent.minimum_approvals {
                if live.required_approving_review_count < minimum_approvals {
                    drifts.push(format!(
                        "live branch protection on `{branch}` requires {} approving review(s), below the repo-as-code expectation of {}.",
                        live.required_approving_review_count, minimum_approvals
                    ));
                }
            }
            if intent.require_code_owner_reviews && !live.require_code_owner_reviews {
                drifts.push(format!(
                    "live branch protection on `{branch}` does not require code-owner review."
                ));
            }
            if intent.dismiss_stale_reviews && !live.dismiss_stale_reviews {
                drifts.push(format!(
                    "live branch protection on `{branch}` keeps stale approvals after new commits."
                ));
            }
        } else if intent.block_force_pushes
            || intent.block_deletions
            || intent.require_admin_enforcement
            || intent.minimum_approvals.is_some()
            || intent.require_code_owner_reviews
            || intent.dismiss_stale_reviews
        {
            drifts.push(format!(
                "live branch protection is not enabled on governed branch `{branch}`."
            ));
        }
    }

    if intent.expects_rulesets && live_rulesets.total == 0 {
        drifts.push("local repository governance declares rulesets, but no live GitHub rulesets were returned.".to_string());
    }
    if intent.expects_active_rulesets && live_rulesets.active == 0 {
        drifts.push("local repository governance expects active rulesets, but GitHub returned no active live rulesets.".to_string());
    }

    drifts
}

fn parse_branch_names(contents: &str) -> Vec<String> {
    let mut branches = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        let branch = if let Some(value) = trimmed.strip_prefix("- name:") {
            value.trim().trim_matches('"').trim_matches('\'')
        } else if let Some(value) = trimmed.strip_prefix("name:") {
            value.trim().trim_matches('"').trim_matches('\'')
        } else if let Some((key, value)) = trimmed.split_once(':') {
            if key.trim_matches('"') == "name" {
                value.trim().trim_matches('"').trim_matches('\'')
            } else {
                continue;
            }
        } else {
            continue;
        };

        if branch.is_empty()
            || branch.eq_ignore_ascii_case("main-branch")
            || branch.eq_ignore_ascii_case("default")
        {
            continue;
        }

        if branch
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '-' | '_' | '.'))
            && !branches.iter().any(|existing| existing == branch)
        {
            branches.push(branch.to_string());
        }
    }

    branches
}

fn gh_api_json<T: for<'de> Deserialize<'de>>(path: &str) -> AppResult<T> {
    let output = Command::new("gh")
        .args([
            "api",
            "--silent",
            "-H",
            "Accept: application/vnd.github+json",
            "--cache",
            GITHUB_API_TIMEOUT_SECONDS,
            path,
        ])
        .output();

    let output = match output {
        Ok(output) => output,
        Err(error) => {
            return Err(AppError::Git(format!(
                "failed to execute `gh api`: {error}"
            )))
        }
    };

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    serde_json::from_slice(&output.stdout).map_err(|error| {
        AppError::Config(format!(
            "failed to parse GitHub API response payload: {error}"
        ))
    })
}

fn parse_github_repo_url(url: &str) -> Option<RepoRef> {
    let trimmed = url.trim().trim_end_matches('/');
    let path = if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://github.com/") {
        rest
    } else {
        return None;
    };

    let path = path.trim_end_matches(".git");
    let mut segments = path.split('/');
    let owner = segments.next()?.trim();
    let name = segments.next()?.trim();
    if owner.is_empty() || name.is_empty() || segments.next().is_some() {
        return None;
    }

    Some(RepoRef {
        owner: owner.to_string(),
        name: name.to_string(),
    })
}

fn parse_required_approvals(contents: &str) -> Option<usize> {
    contents.lines().find_map(|line| {
        let trimmed = line.trim();
        let (_, value) = trimmed.split_once(':')?;
        if !trimmed.contains("required_approving_review_count") {
            return None;
        }

        value.trim().trim_matches(',').parse::<usize>().ok()
    })
}

fn percent_encode_path_segment(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{:02X}", byte).chars().collect(),
        })
        .collect()
}

fn governance_fingerprint(
    state: &str,
    verification: &LiveGovernanceVerification,
    details: &[String],
) -> AppResult<String> {
    let payload = format!(
        "state={state}\nmode={}\nrepository={}\ndefault_branch={}\nchecked_branches={}\ndetails={}",
        verification.mode,
        verification.repository.as_deref().unwrap_or_default(),
        verification.default_branch.as_deref().unwrap_or_default(),
        verification.checked_branches.join(","),
        details.join("\n"),
    );
    Ok(format!(
        "policy:github-live-governance-{state}:{}",
        git::hash_text(&payload)?
    ))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        compare_live_governance, infer_local_governance_intent, parse_branch_names,
        parse_github_repo_url, parse_required_approvals, push_blocking_finding_from_verification,
        GithubGovernanceMode, LiveBranchProtection, LiveGovernanceVerification, LiveRulesetSummary,
        LocalGovernanceIntent,
    };

    #[test]
    fn defaults_live_github_governance_mode_to_auto() {
        let previous = std::env::var("WOLFENCE_GITHUB_GOVERNANCE").ok();
        unsafe {
            std::env::remove_var("WOLFENCE_GITHUB_GOVERNANCE");
        }
        assert_eq!(
            GithubGovernanceMode::resolve().expect("mode should resolve"),
            GithubGovernanceMode::Auto
        );
        restore_mode(previous);
    }

    #[test]
    fn parses_require_live_github_governance_mode() {
        let previous = std::env::var("WOLFENCE_GITHUB_GOVERNANCE").ok();
        unsafe {
            std::env::set_var("WOLFENCE_GITHUB_GOVERNANCE", "require");
        }
        assert_eq!(
            GithubGovernanceMode::resolve().expect("mode should resolve"),
            GithubGovernanceMode::Require
        );
        restore_mode(previous);
    }

    #[test]
    fn parses_github_remote_urls() {
        assert_eq!(
            parse_github_repo_url("git@github.com:openai/wolfence.git")
                .expect("ssh remote should parse")
                .display_name(),
            "openai/wolfence"
        );
        assert_eq!(
            parse_github_repo_url("https://github.com/openai/wolfence")
                .expect("https remote should parse")
                .display_name(),
            "openai/wolfence"
        );
        assert!(parse_github_repo_url("https://example.com/openai/wolfence").is_none());
    }

    #[test]
    fn infers_local_governance_intent_from_repo_files() {
        let root = temp_repo_root("github-governance-intent");
        fs::create_dir_all(root.join(".github/rulesets")).expect("rulesets dir should exist");
        fs::write(
            root.join(".github/settings.yml"),
            "branches:\n  - name: main\n    protection:\n      enforce_admins: true\n      required_pull_request_reviews:\n        required_approving_review_count: 2\n        dismiss_stale_reviews: true\n        require_code_owner_reviews: true\n      allow_force_pushes: false\n      allow_deletions: false\n",
        )
        .expect("settings file should be written");
        fs::write(
            root.join(".github/rulesets/main.yml"),
            "name: main-branch\nenforcement: active\nrules:\n  - type: non_fast_forward\n",
        )
        .expect("ruleset file should be written");

        let intent = infer_local_governance_intent(&root).expect("intent should load");

        assert!(intent.block_force_pushes);
        assert!(intent.block_deletions);
        assert!(intent.require_admin_enforcement);
        assert_eq!(intent.minimum_approvals, Some(2));
        assert!(intent.require_code_owner_reviews);
        assert!(intent.dismiss_stale_reviews);
        assert!(intent.expects_rulesets);
        assert!(intent.expects_active_rulesets);
        assert!(intent
            .protected_branches
            .iter()
            .any(|branch| branch == "main"));
        fs::remove_dir_all(root).expect("temp directory cleanup should succeed");
    }

    #[test]
    fn compares_local_intent_against_weaker_live_state() {
        let drifts = compare_live_governance(
            &LocalGovernanceIntent {
                protected_branches: vec!["main".to_string(), "release".to_string()],
                block_force_pushes: true,
                block_deletions: true,
                require_admin_enforcement: true,
                minimum_approvals: Some(2),
                require_code_owner_reviews: true,
                dismiss_stale_reviews: true,
                expects_rulesets: true,
                expects_active_rulesets: true,
            },
            "main",
            &[
                (
                    "main".to_string(),
                    Some(LiveBranchProtection {
                        allow_force_pushes: true,
                        allow_deletions: true,
                        enforce_admins: false,
                        required_approving_review_count: 1,
                        require_code_owner_reviews: false,
                        dismiss_stale_reviews: false,
                    }),
                ),
                ("release".to_string(), None),
            ],
            LiveRulesetSummary {
                total: 0,
                active: 0,
            },
        );

        assert!(drifts.iter().any(|drift| drift.contains("force pushes")));
        assert!(drifts.iter().any(|drift| drift.contains("deletions")));
        assert!(drifts.iter().any(|drift| drift.contains("administrators")));
        assert!(drifts
            .iter()
            .any(|drift| drift.contains("below the repo-as-code expectation")));
        assert!(drifts
            .iter()
            .any(|drift| drift.contains("code-owner review")));
        assert!(drifts.iter().any(|drift| drift.contains("stale approvals")));
        assert!(drifts
            .iter()
            .any(|drift| drift.contains("no live GitHub rulesets")));
        assert!(drifts
            .iter()
            .any(|drift| drift.contains("no active live rulesets")));
        assert!(drifts
            .iter()
            .any(|drift| drift.contains("governed branch `release`")));
    }

    #[test]
    fn parses_required_approval_counts() {
        assert_eq!(
            parse_required_approvals(
                "required_pull_request_reviews:\n  required_approving_review_count: 3\n"
            ),
            Some(3)
        );
    }

    #[test]
    fn parses_branch_names_from_settings() {
        let branches = parse_branch_names(
            "branches:\n  - name: main\n  - name: release/2026\nrepository:\n  default_branch: main\n",
        );

        assert_eq!(
            branches,
            vec!["main".to_string(), "release/2026".to_string()]
        );
    }

    #[test]
    fn push_gate_ignores_auto_mode_unavailability() {
        let finding = push_blocking_finding_from_verification(&LiveGovernanceVerification {
            mode: GithubGovernanceMode::Auto,
            repository: Some("openai/wolfence".to_string()),
            default_branch: Some("main".to_string()),
            checked_branches: vec!["main".to_string()],
            attempted: true,
            unavailable_reason: Some("gh auth expired".to_string()),
            drifts: Vec::new(),
            local_intent_present: true,
        })
        .expect("push gate should resolve");

        assert!(finding.is_none());
    }

    #[test]
    fn push_gate_blocks_on_live_governance_drift() {
        let finding = push_blocking_finding_from_verification(&LiveGovernanceVerification {
            mode: GithubGovernanceMode::Auto,
            repository: Some("openai/wolfence".to_string()),
            default_branch: Some("main".to_string()),
            checked_branches: vec!["main".to_string(), "release".to_string()],
            attempted: true,
            unavailable_reason: None,
            drifts: vec!["live branch protection on `main` still allows force pushes.".to_string()],
            local_intent_present: true,
        })
        .expect("push gate should resolve")
        .expect("drift should create a blocking finding");

        assert_eq!(finding.id, "policy.github.live-governance.drift");
        assert!(finding.detail.contains("drift"));
        assert!(finding
            .fingerprint
            .starts_with("policy:github-live-governance-drift:"));
    }

    #[test]
    fn push_gate_blocks_when_required_verification_is_unavailable() {
        let finding = push_blocking_finding_from_verification(&LiveGovernanceVerification {
            mode: GithubGovernanceMode::Require,
            repository: Some("openai/wolfence".to_string()),
            default_branch: Some("main".to_string()),
            checked_branches: vec!["main".to_string()],
            attempted: true,
            unavailable_reason: Some("gh api returned 401".to_string()),
            drifts: Vec::new(),
            local_intent_present: true,
        })
        .expect("push gate should resolve")
        .expect("required unavailability should block");

        assert_eq!(finding.id, "policy.github.live-governance.unavailable");
        assert!(finding
            .fingerprint
            .starts_with("policy:github-live-governance-unavailable:"));
    }

    fn restore_mode(previous: Option<String>) {
        match previous {
            Some(value) => unsafe { std::env::set_var("WOLFENCE_GITHUB_GOVERNANCE", value) },
            None => unsafe { std::env::remove_var("WOLFENCE_GITHUB_GOVERNANCE") },
        }
    }

    fn temp_repo_root(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "wolfence-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        env::temp_dir().join(unique)
    }
}
