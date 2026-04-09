//! Execution context construction.
//!
//! The context object gathers all data that downstream scanners and policies
//! need, so they do not each have to rediscover Git state. That keeps the
//! product deterministic and easier to test.

use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use crate::app::AppResult;

use super::config::ResolvedConfig;
use super::git;
use super::git::PushStatus;
use super::receipts::ReceiptIndex;

/// The user-intent we are protecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedAction {
    Push,
    Scan,
}

impl Display for ProtectedAction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Push => write!(f, "push"),
            Self::Scan => write!(f, "scan"),
        }
    }
}

/// Immutable repository snapshot used for one command execution.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// The protected operator action the user asked Wolfence to perform.
    pub action: ProtectedAction,
    /// Repository root discovered from local Git state.
    pub repo_root: PathBuf,
    /// Number of candidate files discovered before repo-local exclusions applied.
    pub discovered_candidate_files: usize,
    /// The concrete file set the current command should analyze.
    pub candidate_files: Vec<PathBuf>,
    /// Candidate files excluded from scanning by repo-local config.
    pub ignored_candidate_files: Vec<PathBuf>,
    /// Effective repo-local configuration for the current run.
    pub config: ResolvedConfig,
    /// Loaded override receipts and non-fatal receipt issues.
    pub receipts: ReceiptIndex,
    /// Push-specific metadata when the protected action is `push`.
    pub push_status: Option<PushStatus>,
}

impl ExecutionContext {
    /// Loads repository metadata from Git and packages it for downstream use.
    pub fn load(action: ProtectedAction) -> AppResult<Self> {
        let repo_root = git::discover_repo_root()?;
        let config = ResolvedConfig::load_for_repo(&repo_root)?;
        let receipts = ReceiptIndex::load_for_repo(&repo_root)?;
        let (discovered_candidate_files, candidate_files, ignored_candidate_files, push_status) =
            match action {
                ProtectedAction::Push => {
                    let push_status = git::push_status(&repo_root)?;
                    let discovered_candidate_files = match &push_status {
                        PushStatus::Ready {
                            candidate_files, ..
                        } => candidate_files.clone(),
                        PushStatus::NoCommits | PushStatus::UpToDate => Vec::new(),
                    };
                    let discovered_candidate_count = discovered_candidate_files.len();
                    let (candidate_files, ignored_candidate_files): (Vec<_>, Vec<_>) =
                        discovered_candidate_files
                            .into_iter()
                            .partition(|path| !config.should_ignore_path(path));

                    (
                        discovered_candidate_count,
                        candidate_files,
                        ignored_candidate_files,
                        Some(push_status),
                    )
                }
                ProtectedAction::Scan => {
                    let discovered_candidate_files = git::staged_files(&repo_root)?;
                    let discovered_candidate_count = discovered_candidate_files.len();
                    let (candidate_files, ignored_candidate_files): (Vec<_>, Vec<_>) =
                        discovered_candidate_files
                            .into_iter()
                            .partition(|path| !config.should_ignore_path(path));
                    (
                        discovered_candidate_count,
                        candidate_files,
                        ignored_candidate_files,
                        None,
                    )
                }
            };

        Ok(Self {
            action,
            repo_root,
            discovered_candidate_files,
            candidate_files,
            ignored_candidate_files,
            config,
            receipts,
            push_status,
        })
    }
}
