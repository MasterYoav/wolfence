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
    pub fingerprint: String,
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
        Self {
            id: id.into(),
            scanner,
            severity,
            confidence,
            category,
            file,
            line: None,
            title: title.into(),
            detail: detail.into(),
            remediation: remediation.into(),
            fingerprint: fingerprint.into(),
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
