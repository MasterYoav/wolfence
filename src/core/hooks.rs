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
const LAUNCHER_MARKER: &str = "wolfence-launcher";

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
    pub launcher: Option<HookLauncherKind>,
}

/// How one managed hook tries to execute Wolfence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookLauncherKind {
    BinaryPath,
    CargoFallback,
}

impl HookLauncherKind {
    pub fn description(self) -> &'static str {
        match self {
            Self::BinaryPath => "pinned Wolf binary with PATH/cargo fallback",
            Self::CargoFallback => "cargo fallback only",
        }
    }
}

/// Installs or refreshes the managed Wolfence hooks for one repository.
pub fn install_managed_hooks(repo_root: &Path) -> AppResult<Vec<HookInstallReport>> {
    let hooks_dir = git::hooks_dir(repo_root)?;
    fs::create_dir_all(&hooks_dir)?;

    let pre_push = install_one_hook(&hooks_dir, "pre-push", hook_script("hook-pre-push")?)?;
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
            launcher: None,
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
        launcher: detect_launcher_kind(&contents),
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

pub fn runtime_binary_path() -> AppResult<PathBuf> {
    Ok(std::env::current_exe()?)
}

fn hook_script(command: &str) -> AppResult<String> {
    let binary = shell_quote(&runtime_binary_path()?.display().to_string());

    Ok(format!(
        "#!/bin/sh\n# {MANAGED_MARKER}\n# {LAUNCHER_MARKER}: binary-path\nset -eu\nREPO_ROOT=\"$(git rev-parse --show-toplevel)\"\ncd \"$REPO_ROOT\"\nWOLF_BIN={binary}\nif [ -x \"$WOLF_BIN\" ]; then\n  exec \"$WOLF_BIN\" {command}\nfi\nif command -v wolf >/dev/null 2>&1; then\n  exec wolf {command}\nfi\nif [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then\n  exec cargo run --quiet --bin wolf -- {command}\nfi\necho \"wolf: unable to locate a runnable Wolfence binary for the managed pre-push hook.\" >&2\nexit 1\n"
    ))
}

fn detect_launcher_kind(contents: &str) -> Option<HookLauncherKind> {
    if !contents.contains(MANAGED_MARKER) {
        return None;
    }

    if contents.contains("# wolfence-launcher: binary-path") {
        return Some(HookLauncherKind::BinaryPath);
    }

    if contents.contains("cargo run --quiet --bin wolf --") {
        return Some(HookLauncherKind::CargoFallback);
    }

    None
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
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

#[cfg(test)]
mod tests {
    use super::{detect_launcher_kind, hook_script, HookLauncherKind};

    #[test]
    fn managed_hook_script_prefers_binary_launcher_and_keeps_fallbacks() {
        let script = hook_script("hook-pre-push").expect("hook script should render");

        assert!(script.contains("# wolfence-launcher: binary-path"));
        assert!(script.contains("WOLF_BIN="));
        assert!(script.contains("exec \"$WOLF_BIN\" hook-pre-push"));
        assert!(script.contains("exec wolf hook-pre-push"));
        assert!(script.contains("cargo run --quiet --bin wolf -- hook-pre-push"));
        assert_eq!(
            detect_launcher_kind(&script),
            Some(HookLauncherKind::BinaryPath)
        );
    }

    #[test]
    fn legacy_managed_hook_without_launcher_marker_is_detected_as_cargo_fallback() {
        let legacy =
            "# wolfence-managed-hook\nexec cargo run --quiet --bin wolf -- hook-pre-push\n";
        assert_eq!(
            detect_launcher_kind(legacy),
            Some(HookLauncherKind::CargoFallback)
        );
    }
}
