//! Advisory lookup port — distinct from [`crate::transport::Transport`].
//!
//! Target probing is scoped to `--target` / `--scope` (ADR 0014). Advisory
//! traffic talks to an allowlisted vulnerability database and must never share
//! that scope or receive source code (ADR 0016).

use async_trait::async_trait;

/// One package version to look up.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageQuery {
    /// OSV ecosystem id, e.g. `npm`.
    pub ecosystem: String,
    /// Package name as recorded in the lockfile.
    pub name: String,
    /// Exact resolved version.
    pub version: String,
}

/// One vulnerability affecting a queried package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryHit {
    /// OSV id (often a GHSA).
    pub id: String,
    /// Optional CVE id.
    pub cve: Option<String>,
    /// Short summary from the advisory, already length-capped by the adapter.
    pub summary: String,
    /// The query that produced this hit.
    pub package: PackageQuery,
}

/// Why an advisory lookup failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdvisoryError {
    /// The run did not enable advisory lookup.
    #[error("advisory lookup is not enabled for this scan")]
    NotEnabled,
    /// The adapter refused the request (allowlist, size, or protocol).
    #[error("advisory request refused: {message}")]
    Refused {
        /// Human-readable reason.
        message: String,
    },
    /// The remote service or transport failed.
    #[error("advisory lookup failed: {message}")]
    Lookup {
        /// Human-readable reason (no response body).
        message: String,
    },
}

/// The only way a detector queries an advisory database.
#[async_trait]
pub trait AdvisoryClient: Send + Sync {
    /// Looks up vulnerabilities for the given packages.
    ///
    /// Implementations must bound batch size and response bytes. Callers must
    /// already have capped `queries`.
    async fn query(&self, queries: &[PackageQuery]) -> Result<Vec<AdvisoryHit>, AdvisoryError>;
}
