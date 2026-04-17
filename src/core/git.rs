//! Git process integration.
//!
//! Wolfence is intentionally not a Git library. The product sits in front of
//! the canonical Git executable, so using process boundaries is acceptable and
//! keeps behavior aligned with what developers already trust.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{io::Write, process::Stdio};

use crate::app::{AppError, AppResult};

/// How a protected push relates to local and remote Git history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushStatus {
    /// The repository has no commits yet, so there is nothing meaningful to push.
    NoCommits,
    /// The current branch is not ahead of its upstream.
    UpToDate,
    /// The current branch has content that would be sent during a push.
    Ready {
        current_branch: String,
        upstream_branch: Option<String>,
        commits_ahead: usize,
        candidate_files: Vec<PathBuf>,
    },
}

/// Discovers the current repository root by asking Git directly.
pub fn discover_repo_root() -> AppResult<PathBuf> {
    let output = run_git(&["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(output.trim()))
}

/// Discovers the repository root for an arbitrary path by asking Git directly.
pub fn discover_repo_root_from(start_path: &Path) -> AppResult<PathBuf> {
    let output = run_git_in_repo(start_path, &["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(output.trim()))
}

/// Resolves the repository hooks directory path.
pub fn hooks_dir(repo_root: &Path) -> AppResult<PathBuf> {
    let output = run_git_in_repo(repo_root, &["rev-parse", "--git-path", "hooks"])?;
    let path = PathBuf::from(output.trim());

    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(repo_root.join(path))
    }
}

/// Returns whether Git would ignore the provided repository-relative path.
pub fn is_path_ignored(repo_root: &Path, relative_path: &Path) -> AppResult<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["check-ignore", "-q"])
        .arg(relative_path)
        .output()?;

    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

/// Returns the effective Git config value for one key in the current repository context.
pub fn config_value(repo_root: &Path, key: &str) -> AppResult<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["config", "--get", key])
        .output()?;

    match output.status.code() {
        Some(0) => Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        )),
        Some(1) => Ok(None),
        _ => Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        )),
    }
}

/// Returns the configured URL for one Git remote in the current repository context.
pub fn remote_url(repo_root: &Path, remote: &str) -> AppResult<Option<String>> {
    config_value(repo_root, &format!("remote.{remote}.url"))
}

/// Reads one repository-relative file as it exists at a specific Git reference.
pub fn file_contents_at_ref(
    repo_root: &Path,
    reference: &str,
    relative_path: &Path,
) -> AppResult<Option<String>> {
    let object = format!("{reference}:{}", relative_path.display());
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["show", &object])
        .output()?;

    if output.status.success() {
        return Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("exists on disk, but not in")
        || stderr.contains("does not exist in")
        || stderr.contains("pathspec")
        || stderr.contains("invalid object name")
        || stderr.contains("bad revision")
        || stderr.contains("unknown revision")
    {
        return Ok(None);
    }

    Err(AppError::Git(stderr.trim().to_string()))
}

/// Returns the preferred remote for an initial push. Prefers `origin`, then falls
/// back to the first configured remote.
pub fn preferred_remote(repo_root: &Path) -> AppResult<Option<String>> {
    let output = run_git_in_repo(repo_root, &["remote"])?;
    let remotes = output
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if remotes.is_empty() {
        return Ok(None);
    }

    if remotes.iter().any(|remote| remote == "origin") {
        return Ok(Some("origin".to_string()));
    }

    Ok(remotes.into_iter().next())
}

/// Returns Git's content hash for one text payload.
pub fn hash_text(contents: &str) -> AppResult<String> {
    let mut child = Command::new("git")
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(contents.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Lists staged files that should be scanned before a protected operation.
pub fn staged_files(repo_root: &Path) -> AppResult<Vec<PathBuf>> {
    run_git_in_repo(
        repo_root,
        &["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
    )
    .map(parse_paths)
}

/// Loads the candidate file set that would be affected by a protected push.
pub fn push_status(repo_root: &Path) -> AppResult<PushStatus> {
    if !head_exists(repo_root)? {
        return Ok(PushStatus::NoCommits);
    }

    let current_branch = current_branch(repo_root)?;
    let upstream_branch = upstream_branch(repo_root)?;

    let commits_ahead = match upstream_branch.as_deref() {
        Some(upstream) => rev_list_count(repo_root, &format!("{upstream}..HEAD"))?,
        None => rev_list_count(repo_root, "HEAD")?,
    };

    if commits_ahead == 0 {
        return Ok(PushStatus::UpToDate);
    }

    let candidate_files = match upstream_branch.as_deref() {
        Some(upstream) => run_git_in_repo(
            repo_root,
            &[
                "diff",
                "--name-only",
                "--diff-filter=ACMR",
                &format!("{upstream}..HEAD"),
            ],
        )
        .map(parse_paths)?,
        None => run_git_in_repo(repo_root, &["ls-tree", "-r", "--name-only", "HEAD"])
            .map(parse_paths)?,
    };

    Ok(PushStatus::Ready {
        current_branch,
        upstream_branch,
        commits_ahead,
        candidate_files,
    })
}

/// Executes the final push once policy has allowed it.
pub fn push(
    repo_root: &Path,
    current_branch: &str,
    upstream_branch: Option<&str>,
) -> AppResult<()> {
    let args = if upstream_branch.is_some() {
        vec!["push".to_string()]
    } else {
        let Some(remote) = preferred_remote(repo_root)? else {
            return Err(AppError::Git(
                "no git remote is configured for this repository. Add a remote before running an initial protected push."
                    .to_string(),
            ));
        };
        vec![
            "push".to_string(),
            "--set-upstream".to_string(),
            remote,
            current_branch.to_string(),
        ]
    };

    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(())
}

/// Verifies that the outbound push snapshot still matches the earlier scanned state.
pub fn verify_push_status_unchanged(repo_root: &Path, expected: &PushStatus) -> AppResult<()> {
    let current = push_status(repo_root)?;
    if &current == expected {
        return Ok(());
    }

    Err(AppError::Git(
        "the outbound push snapshot changed after Wolfence evaluated it. Re-run `wolf push` so the current branch state is rescanned before transport."
            .to_string(),
    ))
}

/// Returns the current local branch name.
pub fn current_branch(repo_root: &Path) -> AppResult<String> {
    run_git_in_repo(repo_root, &["branch", "--show-current"]).map(|value| value.trim().to_string())
}

fn upstream_branch(repo_root: &Path) -> AppResult<Option<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args([
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ])
        .output()?;

    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_string(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("no upstream configured") || stderr.contains("no such branch") {
        return Ok(None);
    }

    Err(AppError::Git(stderr.trim().to_string()))
}

fn head_exists(repo_root: &Path) -> AppResult<bool> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;

    Ok(output.status.success())
}

fn rev_list_count(repo_root: &Path, range: &str) -> AppResult<usize> {
    let output = run_git_in_repo(repo_root, &["rev-list", "--count", range])?;
    output.trim().parse::<usize>().map_err(|error| {
        AppError::Git(format!(
            "failed to parse git rev-list count `{}`: {error}",
            output.trim()
        ))
    })
}

fn parse_paths(output: String) -> Vec<PathBuf> {
    output.lines().map(PathBuf::from).collect()
}

fn run_git(args: &[&str]) -> AppResult<String> {
    let output = Command::new("git").args(args).output()?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_git_in_repo(repo_root: &Path, args: &[&str]) -> AppResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()?;

    if !output.status.success() {
        return Err(AppError::Git(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{preferred_remote, verify_push_status_unchanged, PushStatus};

    #[test]
    fn preferred_remote_prefers_origin_when_present() {
        let repo_root = make_temp_repo("git-remote-origin");
        initialize_repo(&repo_root);
        run_git(
            &repo_root,
            &["remote", "add", "backup", "https://example.com/backup.git"],
        );
        run_git(
            &repo_root,
            &["remote", "add", "origin", "https://example.com/origin.git"],
        );

        let remote = preferred_remote(&repo_root).expect("remote lookup should succeed");
        assert_eq!(remote.as_deref(), Some("origin"));
    }

    #[test]
    fn preferred_remote_falls_back_to_first_configured_remote() {
        let repo_root = make_temp_repo("git-remote-fallback");
        initialize_repo(&repo_root);
        run_git(
            &repo_root,
            &["remote", "add", "backup", "https://example.com/backup.git"],
        );

        let remote = preferred_remote(&repo_root).expect("remote lookup should succeed");
        assert_eq!(remote.as_deref(), Some("backup"));
    }

    #[test]
    fn preferred_remote_returns_none_when_repo_has_no_remotes() {
        let repo_root = make_temp_repo("git-remote-none");
        initialize_repo(&repo_root);

        let remote = preferred_remote(&repo_root).expect("remote lookup should succeed");
        assert_eq!(remote, None);
    }

    #[test]
    fn verify_push_status_unchanged_detects_outbound_snapshot_drift() {
        let repo_root = make_temp_repo("git-push-status-drift");
        initialize_repo(&repo_root);
        configure_identity(&repo_root);
        fs::write(repo_root.join("README.md"), "# Demo\n").expect("should write readme");
        run_git(&repo_root, &["add", "."]);
        run_git(&repo_root, &["commit", "-m", "initial"]);

        let expected = PushStatus::Ready {
            current_branch: "main".to_string(),
            upstream_branch: None,
            commits_ahead: 1,
            candidate_files: vec![PathBuf::from("README.md")],
        };
        verify_push_status_unchanged(&repo_root, &expected)
            .expect("initial push status should match");

        fs::write(repo_root.join("CHANGELOG.md"), "release notes\n")
            .expect("should write changelog");
        run_git(&repo_root, &["add", "."]);
        run_git(&repo_root, &["commit", "-m", "changelog"]);

        let error = verify_push_status_unchanged(&repo_root, &expected)
            .expect_err("drifted push status should fail");
        assert!(error.to_string().contains("outbound push snapshot changed"));
    }

    fn initialize_repo(repo_root: &Path) {
        fs::create_dir_all(repo_root).expect("should create repo root");
        run_git(repo_root, &["init", "-b", "main"]);
    }

    fn configure_identity(repo_root: &Path) {
        run_git(repo_root, &["config", "user.name", "Wolfence Test"]);
        run_git(repo_root, &["config", "user.email", "wolfence@example.com"]);
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
            "wolfence-git-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        env::temp_dir().join(unique)
    }
}
