//! Managed Git hook installation.
//!
//! Wolfence installs a repository-local pre-push hook as an optional
//! enforcement layer. The current implementation is intentionally
//! conservative: it only refreshes hooks already managed by Wolfence and avoids
//! overwriting unrelated custom hooks.

use std::fs;
use std::path::{Path, PathBuf};

use crate::app::AppResult;

use super::git;

pub const MANAGED_MARKER: &str = "wolfence-managed-hook";

/// Result of attempting to install or refresh one hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookInstallStatus {
    Installed,
    Updated,
    SkippedExisting,
    Removed,
}

/// Per-hook installation report.
#[derive(Debug, Clone)]
pub struct HookInstallReport {
    pub hook_name: &'static str,
    pub path: PathBuf,
    pub status: HookInstallStatus,
}

/// Static inspection state for one hook file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookState {
    Missing,
    Managed,
    Unmanaged,
}

/// Read-only hook inspection report used by diagnostics.
#[derive(Debug, Clone)]
pub struct HookInspection {
    pub hook_name: &'static str,
    pub path: PathBuf,
    pub state: HookState,
    pub executable: bool,
}

/// Installs or refreshes the managed Wolfence hooks for one repository.
pub fn install_managed_hooks(repo_root: &Path) -> AppResult<Vec<HookInstallReport>> {
    let hooks_dir = git::hooks_dir(repo_root)?;
    fs::create_dir_all(&hooks_dir)?;

    let pre_push = install_one_hook(&hooks_dir, "pre-push", hook_script("hook-pre-push"))?;
    let removed_pre_commit = remove_managed_hook_if_present(&hooks_dir, "pre-commit")?;
    let removed_commit_msg = remove_managed_hook_if_present(&hooks_dir, "commit-msg")?;

    let mut reports = vec![pre_push];
    if let Some(report) = removed_pre_commit {
        reports.push(report);
    }
    if let Some(report) = removed_commit_msg {
        reports.push(report);
    }

    Ok(reports)
}

/// Inspects one repository hook without modifying it.
pub fn inspect_hook(repo_root: &Path, hook_name: &'static str) -> AppResult<HookInspection> {
    let hooks_dir = git::hooks_dir(repo_root)?;
    let path = hooks_dir.join(hook_name);

    if !path.exists() {
        return Ok(HookInspection {
            hook_name,
            path,
            state: HookState::Missing,
            executable: false,
        });
    }

    let contents = fs::read_to_string(&path)?;
    let state = if contents.contains(MANAGED_MARKER) {
        HookState::Managed
    } else {
        HookState::Unmanaged
    };

    Ok(HookInspection {
        hook_name,
        executable: is_executable(&path)?,
        path,
        state,
    })
}

fn install_one_hook(
    hooks_dir: &Path,
    hook_name: &'static str,
    script_contents: String,
) -> AppResult<HookInstallReport> {
    let path = hooks_dir.join(hook_name);
    let status = if path.exists() {
        let existing = fs::read_to_string(&path)?;
        if existing == script_contents {
            HookInstallStatus::Updated
        } else if existing.contains(MANAGED_MARKER) {
            fs::write(&path, &script_contents)?;
            HookInstallStatus::Updated
        } else {
            HookInstallStatus::SkippedExisting
        }
    } else {
        fs::write(&path, &script_contents)?;
        HookInstallStatus::Installed
    };

    if status != HookInstallStatus::SkippedExisting {
        ensure_executable(&path)?;
    }

    Ok(HookInstallReport {
        hook_name,
        path,
        status,
    })
}

fn remove_managed_hook_if_present(
    hooks_dir: &Path,
    hook_name: &'static str,
) -> AppResult<Option<HookInstallReport>> {
    let path = hooks_dir.join(hook_name);
    if !path.exists() {
        return Ok(None);
    }

    let existing = fs::read_to_string(&path)?;
    if !existing.contains(MANAGED_MARKER) {
        return Ok(None);
    }

    fs::remove_file(&path)?;

    Ok(Some(HookInstallReport {
        hook_name,
        path,
        status: HookInstallStatus::Removed,
    }))
}

fn hook_script(command: &str) -> String {
    format!(
        "#!/bin/sh\n# {MANAGED_MARKER}\nset -eu\nREPO_ROOT=\"$(git rev-parse --show-toplevel)\"\ncd \"$REPO_ROOT\"\nexec cargo run --quiet -- {command}\n"
    )
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> AppResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> AppResult<bool> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    Ok(mode & 0o111 != 0)
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> AppResult<()> {
    Ok(())
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> AppResult<bool> {
    Ok(true)
}
