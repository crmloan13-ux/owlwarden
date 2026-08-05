//! The `ScopeResolver` port: what the scanner is allowed to touch.
//!
//! Deny-by-default, and the default resolver denies *everything*. A scanner
//! that probes a host nobody listed is, at best, a support ticket and at worst
//! unauthorised access to someone else's system. The user declares scope; we do
//! not infer it.

/// Something we are considering touching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Scheme, e.g. `http` or `https`.
    pub scheme: String,
    /// Hostname or IP literal, lowercased.
    pub host: String,
    /// Port, resolved from the scheme when the URL omitted it.
    pub port: u16,
    /// Path, used by resolvers that scope to a sub-path.
    pub path: String,
}

/// The answer. `Deny` carries a reason because it is shown to the user and
/// written to the audit log — "denied" with no explanation is a bug report
/// waiting to happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    /// In scope.
    Allow,
    /// Out of scope, with the reason to show the user.
    Deny(String),
}

impl ScopeDecision {
    /// Whether the target may be touched.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Decides whether a target is in scope.
pub trait ScopeResolver: Send + Sync {
    /// Allow or deny, with a reason on denial.
    fn in_scope(&self, target: &Target) -> ScopeDecision;
}

/// The default: nothing is in scope.
///
/// This is what a static-only run uses, and it is what any run gets before
/// config is applied. If a detector somehow reaches the network during a
/// passive scan, this refuses it — defence in depth behind the capability
/// check, not instead of it.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllScope;

impl ScopeResolver for DenyAllScope {
    fn in_scope(&self, target: &Target) -> ScopeDecision {
        ScopeDecision::Deny(format!(
            "no scope declared; add {}://{}:{} to scope.allow to permit it",
            target.scheme, target.host, target.port
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn default_scope_denies_localhost_too() {
        // Localhost is not implicitly trusted: a dev machine reaches plenty of
        // internal services, and "it was only localhost" is how tools end up
        // probing a colleague's staging database.
        let decision = DenyAllScope.in_scope(&Target {
            scheme: "http".into(),
            host: "localhost".into(),
            port: 3000,
            path: "/".into(),
        });
        assert!(!decision.is_allowed());
        match decision {
            ScopeDecision::Deny(reason) => assert!(reason.contains("scope.allow")),
            ScopeDecision::Allow => unreachable!("just asserted it was denied"),
        }
    }
}
