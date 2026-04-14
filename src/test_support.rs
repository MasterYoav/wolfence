use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::Value;

use crate::core::audit;
use crate::core::context::ProtectedAction;
use crate::core::findings::{Finding, FindingCategory};
use crate::core::github_governance;
use crate::core::receipts::{
    draft_checksum, generate_receipt_id, render_receipt_file, signed_receipt_payload, ReceiptDraft,
    RECEIPTS_DIR_RELATIVE_PATH,
};
use crate::core::trust::{sign_payload_with_private_key, TRUST_DIR_RELATIVE_PATH};

pub fn process_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Deserialize)]
struct RepoFixtureManifest {
    prepare: RepoFixturePrepare,
    remote_origin: Option<String>,
    upstream_fixture: Option<String>,
    live_github_governance: Option<RepoFixtureLiveGithubGovernance>,
    live_github_governance_receipt: Option<RepoFixtureLiveGithubGovernanceReceipt>,
    #[serde(default)]
    expectations: RepoFixtureExpectations,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RepoFixturePrepare {
    Stage,
    Commit,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoFixtureExpectations {
    pub staged: Option<RepoFixtureExpectation>,
    pub push: Option<RepoFixtureExpectation>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoFixtureExpectation {
    pub verdict: RepoFixtureVerdict,
    #[serde(default)]
    pub command_exit: Option<RepoFixtureCommandExit>,
    #[serde(default)]
    pub finding_ids: Vec<String>,
    #[serde(default)]
    pub not_finding_ids: Vec<String>,
    #[serde(default)]
    pub json: Option<RepoFixtureJsonExpectation>,
    #[serde(default)]
    pub audit: Option<RepoFixtureAuditExpectation>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoFixtureJsonExpectation {
    pub status: Option<String>,
    pub result: Option<String>,
    pub has_report: Option<bool>,
    pub has_decision: Option<bool>,
    pub has_finding_history: Option<bool>,
    pub has_finding_baseline: Option<bool>,
    pub receipt_issue_count: Option<usize>,
    pub receipt_overrides_applied: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RepoFixtureAuditExpectation {
    pub entries: Option<usize>,
    pub healthy: Option<bool>,
    #[serde(default)]
    pub outcomes: Vec<String>,
    #[serde(default)]
    pub overrides_applied: Vec<usize>,
    #[serde(default)]
    pub receipt_issues: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoFixtureLiveGithubGovernance {
    pub repository: String,
    pub mode: String,
    pub scenario: RepoFixtureLiveGithubGovernanceScenario,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoFixtureLiveGithubGovernanceReceipt {
    pub scenario: RepoFixtureLiveGithubGovernanceScenario,
    pub reason: String,
    #[serde(default)]
    pub signing: RepoFixtureLiveGithubGovernanceReceiptSigning,
    #[serde(default)]
    pub trust_required: bool,
    pub key_id: Option<String>,
    pub trusted_key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepoFixtureLiveGithubGovernanceReceiptSigning {
    #[default]
    Unsigned,
    Trusted,
    Untrusted,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepoFixtureLiveGithubGovernanceScenario {
    Drift,
    DriftAlternate,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoFixtureVerdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoFixtureCommandExit {
    Success,
    Failure,
}

pub fn assert_fixture_json_expectation(
    fixture_name: &str,
    scope: &str,
    json: &Value,
    expectation: &RepoFixtureJsonExpectation,
) {
    if let Some(status) = &expectation.status {
        assert_eq!(
            json.get("status").and_then(Value::as_str),
            Some(status.as_str()),
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected JSON status"
        );
    }

    if let Some(result) = &expectation.result {
        assert_eq!(
            json.get("result").and_then(Value::as_str),
            Some(result.as_str()),
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected JSON result"
        );
    }

    if let Some(has_report) = expectation.has_report {
        assert_eq!(
            !json.get("report").unwrap_or(&Value::Null).is_null(),
            has_report,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected JSON report presence"
        );
    }

    if let Some(has_decision) = expectation.has_decision {
        assert_eq!(
            !json.get("decision").unwrap_or(&Value::Null).is_null(),
            has_decision,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected JSON decision presence"
        );
    }

    if let Some(has_history) = expectation.has_finding_history {
        let has_value = json
            .get("report")
            .and_then(|report| report.get("finding_history"))
            .is_some_and(|value| !value.is_null());
        assert_eq!(
            has_value, has_history,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected finding_history presence"
        );
    }

    if let Some(has_baseline) = expectation.has_finding_baseline {
        let has_value = json
            .get("report")
            .and_then(|report| report.get("finding_baseline"))
            .is_some_and(|value| !value.is_null());
        assert_eq!(
            has_value, has_baseline,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected finding_baseline presence"
        );
    }

    if let Some(receipt_issue_count) = expectation.receipt_issue_count {
        assert_eq!(
            json.get("receipts")
                .and_then(|receipts| receipts.get("issue_count"))
                .and_then(Value::as_u64),
            Some(receipt_issue_count as u64),
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected receipt issue count"
        );
    }

    if let Some(receipt_overrides_applied) = expectation.receipt_overrides_applied {
        assert_eq!(
            json.get("receipts")
                .and_then(|receipts| receipts.get("overrides_applied"))
                .and_then(Value::as_u64),
            Some(receipt_overrides_applied as u64),
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected overrides_applied count"
        );
    }
}

pub fn assert_fixture_audit_expectation(
    fixture_name: &str,
    scope: &str,
    repo_root: &Path,
    expectation: &RepoFixtureAuditExpectation,
) {
    let verification = audit::verify_audit_log(repo_root).expect("audit verification should load");
    let entries = audit::read_audit_log(repo_root).expect("audit log should load");

    if let Some(expected_entries) = expectation.entries {
        assert_eq!(
            entries.len(),
            expected_entries,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected audit entry count"
        );
    }

    if let Some(expected_healthy) = expectation.healthy {
        assert_eq!(
            verification.healthy, expected_healthy,
            "fixture `{fixture_name}` scope `{scope}` produced an unexpected audit health state"
        );
    }

    if !expectation.outcomes.is_empty() {
        let actual_outcomes = entries
            .iter()
            .map(|entry| entry.outcome.as_str())
            .collect::<Vec<_>>();
        let expected_outcomes = expectation
            .outcomes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_outcomes, expected_outcomes,
            "fixture `{fixture_name}` scope `{scope}` produced unexpected audit outcomes"
        );
    }

    if !expectation.overrides_applied.is_empty() {
        let actual_overrides = entries
            .iter()
            .map(|entry| entry.overrides_applied)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_overrides, expectation.overrides_applied,
            "fixture `{fixture_name}` scope `{scope}` produced unexpected audit override counts"
        );
    }

    if !expectation.receipt_issues.is_empty() {
        let actual_receipt_issues = entries
            .iter()
            .map(|entry| entry.receipt_issues)
            .collect::<Vec<_>>();
        assert_eq!(
            actual_receipt_issues,
            expectation.receipt_issues,
            "fixture `{fixture_name}` scope `{scope}` produced unexpected audit receipt issue counts"
        );
    }
}

#[derive(Debug, Clone)]
pub struct MaterializedRepoFixture {
    pub name: String,
    pub repo_root: PathBuf,
    pub live_github_governance: Option<RepoFixtureLiveGithubGovernance>,
    pub live_github_governance_receipt: Option<RepoFixtureLiveGithubGovernanceReceipt>,
    pub expectations: RepoFixtureExpectations,
}

#[derive(Debug, Clone)]
pub struct ActiveLiveGithubGovernanceFixture {
    previous_governance: Option<String>,
    previous_path: Option<String>,
}

pub fn materialize_repo_fixture(name: &str) -> MaterializedRepoFixture {
    let fixture_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("repos")
        .join(name);
    let manifest_path = fixture_root.join(".fixture.json");
    let manifest_contents =
        fs::read_to_string(&manifest_path).expect("fixture manifest should exist");
    let manifest: RepoFixtureManifest =
        serde_json::from_str(&manifest_contents).expect("fixture manifest should parse");

    let repo_root = make_temp_repo(name);
    fs::create_dir_all(&repo_root).expect("fixture repo root should create");
    run_git(&repo_root, &["init", "-b", "main"]);
    run_git(&repo_root, &["config", "user.name", "Wolfence Fixture"]);
    run_git(
        &repo_root,
        &["config", "user.email", "fixtures@wolfence.local"],
    );

    if let Some(upstream_fixture_name) = manifest.upstream_fixture.as_deref() {
        let upstream_root = fixture_root.join(upstream_fixture_name);
        assert!(
            upstream_root.is_dir(),
            "fixture `{name}` declared upstream snapshot `{upstream_fixture_name}`, but that directory is missing"
        );

        copy_fixture_tree(&upstream_root, &repo_root, &[]);
        run_git(&repo_root, &["add", "."]);
        run_git(&repo_root, &["commit", "-m", "load upstream fixture"]);

        let remote_root = make_temp_remote(name);
        initialize_bare_remote(&remote_root);
        let remote_origin = remote_root.to_string_lossy().into_owned();
        run_git(&repo_root, &["remote", "add", "origin", &remote_origin]);
        run_git(&repo_root, &["push", "-u", "origin", "main"]);

        clear_repo_worktree(&repo_root);
        copy_fixture_tree(&fixture_root, &repo_root, &[upstream_fixture_name]);
    } else {
        copy_fixture_tree(&fixture_root, &repo_root, &[]);
        if let Some(remote_origin) = manifest.remote_origin.as_deref() {
            run_git(&repo_root, &["remote", "add", "origin", remote_origin]);
        }
    }

    match manifest.prepare {
        RepoFixturePrepare::Stage => {
            run_git(&repo_root, &["add", "."]);
        }
        RepoFixturePrepare::Commit => {
            run_git(&repo_root, &["add", "."]);
            run_git(&repo_root, &["commit", "-m", "load fixture"]);
        }
    }

    MaterializedRepoFixture {
        name: name.to_string(),
        repo_root,
        live_github_governance: manifest.live_github_governance,
        live_github_governance_receipt: manifest.live_github_governance_receipt,
        expectations: manifest.expectations,
    }
}

pub fn activate_live_github_governance_fixture(
    repo_root: &Path,
    config: Option<&RepoFixtureLiveGithubGovernance>,
) -> Option<ActiveLiveGithubGovernanceFixture> {
    let config = config?;
    let previous_governance = env::var("WOLFENCE_GITHUB_GOVERNANCE").ok();
    let previous_path = env::var("PATH").ok();

    let remote_url = format!("https://github.com/{}.git", config.repository);
    run_git(repo_root, &["remote", "set-url", "origin", &remote_url]);

    env::set_var("WOLFENCE_GITHUB_GOVERNANCE", &config.mode);
    let fake_bin = install_fake_gh(repo_root, &config.repository, config.scenario);
    set_test_path(&fake_bin, previous_path.as_deref());

    Some(ActiveLiveGithubGovernanceFixture {
        previous_governance,
        previous_path,
    })
}

pub fn restore_live_github_governance_fixture(state: Option<ActiveLiveGithubGovernanceFixture>) {
    let Some(state) = state else {
        return;
    };

    if let Some(value) = state.previous_governance {
        env::set_var("WOLFENCE_GITHUB_GOVERNANCE", value);
    } else {
        env::remove_var("WOLFENCE_GITHUB_GOVERNANCE");
    }

    if let Some(value) = state.previous_path {
        env::set_var("PATH", value);
    } else {
        env::remove_var("PATH");
    }
}

pub fn install_live_github_governance_receipt(
    repo_root: &Path,
    active_config: Option<&RepoFixtureLiveGithubGovernance>,
    receipt_config: Option<&RepoFixtureLiveGithubGovernanceReceipt>,
) {
    let (Some(active_config), Some(receipt_config)) = (active_config, receipt_config) else {
        return;
    };

    let previous_path = env::var("PATH").ok();
    let fake_bin = install_fake_gh(
        repo_root,
        &active_config.repository,
        receipt_config.scenario,
    );
    set_test_path(&fake_bin, previous_path.as_deref());

    let finding = github_governance::push_blocking_finding(repo_root)
        .expect("governance finding should resolve")
        .expect("fixture governance receipt should target a blocking finding");

    if let Some(value) = previous_path {
        env::set_var("PATH", value);
    } else {
        env::remove_var("PATH");
    }

    let receipts_dir = repo_root.join(RECEIPTS_DIR_RELATIVE_PATH);
    fs::create_dir_all(&receipts_dir).expect("should create receipts dir");

    let mut draft = ReceiptDraft {
        receipt_id: String::new(),
        action: ProtectedAction::Push,
        category: FindingCategory::Policy,
        fingerprint: finding.fingerprint,
        owner: "security-team".to_string(),
        reviewer: None,
        reviewed_on: None,
        reason: receipt_config.reason.clone(),
        created_on: "2026-04-10".to_string(),
        expires_on: "2099-12-31".to_string(),
        category_bound: true,
    };
    draft.receipt_id = generate_receipt_id(&draft).expect("receipt id should generate");
    let checksum = draft_checksum(&draft).expect("checksum should generate");
    let key_id = receipt_config.key_id.as_deref().unwrap_or("security-team");
    let trusted_key_id = receipt_config
        .trusted_key_id
        .as_deref()
        .unwrap_or("security-team");

    if receipt_config.trust_required {
        install_test_trust_keypair(repo_root, trusted_key_id);
    }

    let private_key_path = match receipt_config.signing {
        RepoFixtureLiveGithubGovernanceReceiptSigning::Unsigned => None,
        RepoFixtureLiveGithubGovernanceReceiptSigning::Trusted => {
            if receipt_config.trust_required && trusted_key_id == key_id {
                Some(repo_root.join(format!("{key_id}-private.pem")))
            } else {
                Some(install_test_trust_keypair(repo_root, key_id))
            }
        }
        RepoFixtureLiveGithubGovernanceReceiptSigning::Untrusted => {
            Some(install_test_untrusted_keypair(repo_root, key_id))
        }
    };

    let (approver, key_id, signature) = match receipt_config.signing {
        RepoFixtureLiveGithubGovernanceReceiptSigning::Unsigned => (None, None, None),
        RepoFixtureLiveGithubGovernanceReceiptSigning::Trusted => {
            let private_key_path = private_key_path
                .as_ref()
                .expect("trusted signing should install a private key");
            let payload = signed_receipt_payload(&draft, key_id, key_id, &checksum);
            let signature = sign_payload_with_private_key(&private_key_path, &payload)
                .expect("signed live governance receipt should sign");
            (Some(key_id), Some(key_id), Some(signature))
        }
        RepoFixtureLiveGithubGovernanceReceiptSigning::Untrusted => {
            let private_key_path = private_key_path
                .as_ref()
                .expect("untrusted signing should install a private key");
            let payload = signed_receipt_payload(&draft, key_id, key_id, &checksum);
            let signature = sign_payload_with_private_key(&private_key_path, &payload)
                .expect("untrusted live governance receipt should sign");
            (Some(key_id), Some(key_id), Some(signature))
        }
    };
    let contents = render_receipt_file(&draft, &checksum, approver, key_id, signature.as_deref());
    fs::write(receipts_dir.join("live-governance-override.toml"), contents)
        .expect("receipt should write");
}

pub fn assert_fixture_expectation(
    fixture_name: &str,
    scope: &str,
    actual_exit: ExitCode,
    findings: &[Finding],
    expectation: &RepoFixtureExpectation,
) {
    let expected_exit = match expectation
        .command_exit
        .unwrap_or(match expectation.verdict {
            RepoFixtureVerdict::Allow => RepoFixtureCommandExit::Success,
            RepoFixtureVerdict::Block => RepoFixtureCommandExit::Failure,
        }) {
        RepoFixtureCommandExit::Success => ExitCode::SUCCESS,
        RepoFixtureCommandExit::Failure => ExitCode::FAILURE,
    };
    assert_eq!(
        actual_exit, expected_exit,
        "fixture `{fixture_name}` scope `{scope}` produced an unexpected verdict"
    );

    for expected_id in &expectation.finding_ids {
        assert!(
            findings.iter().any(|finding| finding.id == *expected_id),
            "fixture `{fixture_name}` scope `{scope}` expected finding `{expected_id}`, but it was missing from {:#?}",
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>()
        );
    }

    for unexpected_id in &expectation.not_finding_ids {
        assert!(
            findings.iter().all(|finding| finding.id != *unexpected_id),
            "fixture `{fixture_name}` scope `{scope}` unexpectedly produced finding `{unexpected_id}` from {:#?}",
            findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>()
        );
    }
}

fn copy_fixture_tree(source_root: &Path, destination_root: &Path, excluded_names: &[&str]) {
    for entry in fs::read_dir(source_root).expect("fixture directory should list") {
        let entry = entry.expect("fixture entry should load");
        let source_path = entry.path();
        let name = entry.file_name();
        if name == ".fixture.json"
            || excluded_names
                .iter()
                .any(|excluded| name == std::ffi::OsStr::new(excluded))
        {
            continue;
        }

        let destination_path = destination_root.join(&name);
        let file_type = entry.file_type().expect("fixture file type should load");
        if file_type.is_dir() {
            fs::create_dir_all(&destination_path).expect("fixture dir should create");
            copy_fixture_tree(&source_path, &destination_path, &[]);
        } else if file_type.is_file() {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).expect("fixture file parent should create");
            }
            fs::copy(&source_path, &destination_path).expect("fixture file should copy");
        }
    }
}

fn clear_repo_worktree(repo_root: &Path) {
    for entry in fs::read_dir(repo_root).expect("repo root should list") {
        let entry = entry.expect("repo entry should load");
        let path = entry.path();
        if entry.file_name() == ".git" {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path).expect("repo dir should clear");
        } else {
            fs::remove_file(&path).expect("repo file should clear");
        }
    }
}

fn install_fake_gh(
    repo_root: &Path,
    repository: &str,
    scenario: RepoFixtureLiveGithubGovernanceScenario,
) -> PathBuf {
    let scenario_name = match scenario {
        RepoFixtureLiveGithubGovernanceScenario::Drift => "drift",
        RepoFixtureLiveGithubGovernanceScenario::DriftAlternate => "drift-alternate",
        RepoFixtureLiveGithubGovernanceScenario::Unavailable => "unavailable",
    };
    let bin_dir = repo_root.join(format!("test-bin-{scenario_name}"));
    fs::create_dir_all(&bin_dir).expect("should create fake bin dir");

    let script = match scenario {
        RepoFixtureLiveGithubGovernanceScenario::Unavailable => {
            "#!/bin/sh\necho 'gh auth expired' >&2\nexit 1\n".to_string()
        }
        RepoFixtureLiveGithubGovernanceScenario::Drift => {
            let branch_path = format!("repos/{repository}/branches/main/protection");
            let repo_path = format!("repos/{repository}");
            let ruleset_path =
                format!("repos/{repository}/rulesets?includes_parents=true&per_page=100");
            format!(
                "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n  {repo_path})\n    printf '{{\"default_branch\":\"main\"}}'\n    ;;\n  {branch_path})\n    printf '{{\"allow_force_pushes\":{{\"enabled\":true}},\"allow_deletions\":{{\"enabled\":true}},\"enforce_admins\":{{\"enabled\":false}},\"required_pull_request_reviews\":{{\"dismiss_stale_reviews\":false,\"require_code_owner_reviews\":false,\"required_approving_review_count\":1}}}}'\n    ;;\n  '{ruleset_path}')\n    printf '[]'\n    ;;\n  *)\n    echo \"unexpected gh api path: $last\" >&2\n    exit 1\n    ;;\n esac\n"
            )
        }
        RepoFixtureLiveGithubGovernanceScenario::DriftAlternate => {
            let branch_path = format!("repos/{repository}/branches/main/protection");
            let repo_path = format!("repos/{repository}");
            let ruleset_path =
                format!("repos/{repository}/rulesets?includes_parents=true&per_page=100");
            format!(
                "#!/bin/sh\nfor last; do :; done\ncase \"$last\" in\n  {repo_path})\n    printf '{{\"default_branch\":\"main\"}}'\n    ;;\n  {branch_path})\n    printf '{{\"allow_force_pushes\":{{\"enabled\":false}},\"allow_deletions\":{{\"enabled\":false}},\"enforce_admins\":{{\"enabled\":true}},\"required_pull_request_reviews\":{{\"dismiss_stale_reviews\":true,\"require_code_owner_reviews\":true,\"required_approving_review_count\":2}}}}'\n    ;;\n  '{ruleset_path}')\n    printf '[]'\n    ;;\n  *)\n    echo \"unexpected gh api path: $last\" >&2\n    exit 1\n    ;;\n esac\n"
            )
        }
    };

    let gh_path = bin_dir.join("gh");
    fs::write(&gh_path, script).expect("should write fake gh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&gh_path)
            .expect("metadata should load")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&gh_path, permissions).expect("permissions should set");
    }

    bin_dir
}

fn set_test_path(fake_bin: &Path, previous_path: Option<&str>) {
    let updated = match previous_path {
        Some(value) if !value.is_empty() => format!("{}:{value}", fake_bin.display()),
        _ => fake_bin.display().to_string(),
    };
    env::set_var("PATH", updated);
}

fn install_test_trust_keypair(repo_root: &Path, key_id: &str) -> PathBuf {
    let trust_dir = repo_root.join(TRUST_DIR_RELATIVE_PATH);
    fs::create_dir_all(&trust_dir).expect("trust dir should create");

    let private_key_path = repo_root.join(format!("{key_id}-private.pem"));
    let public_key_path = trust_dir.join(format!("{key_id}.pem"));
    generate_test_keypair(&private_key_path, &public_key_path);
    fs::write(
        trust_dir.join(format!("{key_id}.toml")),
        format!("owner = \"{key_id}\"\nexpires_on = \"2099-12-31\"\n"),
    )
    .expect("trust metadata should write");
    private_key_path
}

fn install_test_untrusted_keypair(repo_root: &Path, key_id: &str) -> PathBuf {
    let private_key_path = repo_root.join(format!("{key_id}-private.pem"));
    let public_key_path = repo_root.join(format!("{key_id}-public.pem"));
    generate_test_keypair(&private_key_path, &public_key_path);
    private_key_path
}

fn generate_test_keypair(private_key_path: &PathBuf, public_key_path: &PathBuf) {
    let private = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            private_key_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("private key generation should run");
    assert!(
        private.status.success(),
        "private key generation failed: {}",
        String::from_utf8_lossy(&private.stderr)
    );

    let public = Command::new("openssl")
        .args([
            "pkey",
            "-in",
            private_key_path.to_string_lossy().as_ref(),
            "-pubout",
            "-out",
            public_key_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("public key export should run");
    assert!(
        public.status.success(),
        "public key export failed: {}",
        String::from_utf8_lossy(&public.stderr)
    );
}

fn initialize_bare_remote(remote_root: &Path) {
    if let Some(parent) = remote_root.parent() {
        fs::create_dir_all(parent).expect("remote parent should create");
    }

    let output = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(remote_root)
        .output()
        .expect("bare git init should spawn");
    assert!(
        output.status.success(),
        "git init --bare failed: {}",
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

fn make_temp_repo(name: &str) -> PathBuf {
    let unique = format!(
        "wolfence-fixture-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    env::temp_dir().join(unique)
}

fn make_temp_remote(name: &str) -> PathBuf {
    let unique = format!(
        "wolfence-fixture-remote-{name}-{}-{}.git",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    env::temp_dir().join(unique)
}
