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
    /// The concrete file set the current command should analyze.
    pub candidate_files: Vec<PathBuf>,
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
        let (candidate_files, push_status) = match action {
            ProtectedAction::Push => {
                let push_status = git::push_status(&repo_root)?;
                let candidate_files = match &push_status {
                    PushStatus::Ready {
                        candidate_files, ..
                    } => candidate_files.clone(),
                    PushStatus::NoCommits | PushStatus::UpToDate => Vec::new(),
                };

                (candidate_files, Some(push_status))
            }
            ProtectedAction::Scan => (git::staged_files(&repo_root)?, None),
        };

        Ok(Self {
            action,
            repo_root,
            candidate_files,
            config,
            receipts,
            push_status,
        })
    }
}
