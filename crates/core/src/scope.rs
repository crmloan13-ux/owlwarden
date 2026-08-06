//! The `ScopeResolver` port: what the scanner is allowed to touch.
//!
//! Deny-by-default, and the default resolver denies *everything*. A scanner
//! that probes a host nobody listed is, at best, a support ticket and at worst
//! unauthorised access to someone else's system. The user declares scope; we do
//! not infer it.
//!
//! See [ADR 0014](../../../docs/adr/0014-passive-dynamic-and-correlation.md).

use std::fmt;

/// Something we are considering touching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Scheme, e.g. `http` or `https`.
    pub scheme: String,
    /// Hostname or IP literal, lowercased for DNS names.
    pub host: String,
    /// Port, resolved from the scheme when the URL omitted it.
    pub port: u16,
    /// Path, used by resolvers that scope to a sub-path. Always starts with `/`.
    pub path: String,
}

impl Target {
    /// Parses an absolute `http` or `https` URL into a [`Target`].
    ///
    /// # Errors
    /// [`ScopeParseError`] when the URL is not an absolute http(s) URL, has a
    /// userinfo component, or is otherwise unusable as a scan target.
    pub fn parse(url: &str) -> Result<Self, ScopeParseError> {
        if url.len() > crate::limits::http::MAX_URL_BYTES {
            return Err(ScopeParseError::UrlTooLong {
                len: url.len(),
                max: crate::limits::http::MAX_URL_BYTES,
            });
        }
        if url.bytes().any(|b| b == b'\0' || b == b'\r' || b == b'\n') {
            return Err(ScopeParseError::InvalidUrl {
                input: truncate(url),
                message: "URL must not contain NUL or line breaks".to_owned(),
            });
        }
        let parsed = url::Url::parse(url).map_err(|error| ScopeParseError::InvalidUrl {
            input: truncate(url),
            message: error.to_string(),
        })?;
        Self::from_url(&parsed)
    }

    /// Builds a [`Target`] from an already-parsed URL.
    ///
    /// # Errors
    /// [`ScopeParseError`] for schemes other than http(s), credentials in the
    /// URL, or a missing host.
    pub fn from_url(parsed: &url::Url) -> Result<Self, ScopeParseError> {
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ScopeParseError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            });
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            // Credentials in a probe URL end up in argv, shell history, and
            // CI logs. Refuse rather than strip — stripping would surprise.
            return Err(ScopeParseError::CredentialsNotAllowed);
        }
        let host = match parsed.host() {
            Some(url::Host::Domain(name)) => name.to_ascii_lowercase(),
            Some(url::Host::Ipv4(addr)) => addr.to_string(),
            Some(url::Host::Ipv6(addr)) => addr.to_string(),
            None => {
                return Err(ScopeParseError::MissingHost {
                    input: truncate(parsed.as_str()),
                });
            }
        };
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| ScopeParseError::MissingHost {
                input: truncate(parsed.as_str()),
            })?;
        let path = {
            let path = parsed.path();
            if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            }
        };
        Ok(Self {
            scheme: scheme.to_owned(),
            host,
            port,
            path,
        })
    }

    /// Origin form `scheme://host:port`, always with an explicit port.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// One allowlist entry: an origin, optionally narrowed to a path prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEntry {
    /// `http` or `https`.
    pub scheme: String,
    /// Hostname or IP literal, lowercased for DNS names.
    pub host: String,
    /// Port, resolved from the scheme when omitted.
    pub port: u16,
    /// Path prefix. `/` means the whole origin.
    pub path_prefix: String,
}

impl ScopeEntry {
    /// Parses a scope entry of the form `scheme://host[:port][/path]`.
    ///
    /// # Errors
    /// [`ScopeParseError`] for the same reasons as [`Target::parse`].
    pub fn parse(entry: &str) -> Result<Self, ScopeParseError> {
        let target = Target::parse(entry)?;
        Ok(Self {
            scheme: target.scheme,
            host: target.host,
            port: target.port,
            path_prefix: normalise_prefix(&target.path),
        })
    }

    /// Whether `target` matches this entry.
    #[must_use]
    pub fn matches(&self, target: &Target) -> bool {
        self.scheme == target.scheme
            && self.host == target.host
            && self.port == target.port
            && path_under_prefix(&target.path, &self.path_prefix)
    }
}

/// An allowlist [`ScopeResolver`]. Empty allowlists deny everything.
#[derive(Debug, Clone, Default)]
pub struct AllowlistScope {
    entries: Vec<ScopeEntry>,
}

impl AllowlistScope {
    /// Hard cap on allowlist entries. A hundred origins is already a smell;
    /// thousands is a config bug or an attack on the resolver.
    pub const MAX_ENTRIES: usize = 64;

    /// Builds an allowlist from pre-parsed entries.
    ///
    /// # Errors
    /// [`ScopeParseError::TooManyEntries`] when the list exceeds [`Self::MAX_ENTRIES`].
    pub fn new(entries: Vec<ScopeEntry>) -> Result<Self, ScopeParseError> {
        if entries.len() > Self::MAX_ENTRIES {
            return Err(ScopeParseError::TooManyEntries {
                count: entries.len(),
                max: Self::MAX_ENTRIES,
            });
        }
        Ok(Self { entries })
    }

    /// Parses string entries into an allowlist.
    ///
    /// # Errors
    /// [`ScopeParseError`] when any entry is invalid or the list is too long.
    pub fn parse(entries: &[String]) -> Result<Self, ScopeParseError> {
        if entries.len() > Self::MAX_ENTRIES {
            return Err(ScopeParseError::TooManyEntries {
                count: entries.len(),
                max: Self::MAX_ENTRIES,
            });
        }
        let mut parsed = Vec::with_capacity(entries.len());
        for entry in entries.iter().take(Self::MAX_ENTRIES) {
            parsed.push(ScopeEntry::parse(entry)?);
        }
        Ok(Self { entries: parsed })
    }

    /// Allowlist containing exactly the origin of `target` (path `/`).
    #[must_use]
    pub fn from_target_origin(target: &Target) -> Self {
        Self {
            entries: vec![ScopeEntry {
                scheme: target.scheme.clone(),
                host: target.host.clone(),
                port: target.port,
                path_prefix: "/".to_owned(),
            }],
        }
    }

    /// The entries, for the report's `target.scope` field.
    #[must_use]
    pub fn entries(&self) -> &[ScopeEntry] {
        &self.entries
    }

    /// Wire forms suitable for `Report.target.scope`.
    #[must_use]
    pub fn as_report_strings(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| {
                if entry.path_prefix == "/" {
                    format!("{}://{}:{}", entry.scheme, entry.host, entry.port)
                } else {
                    format!(
                        "{}://{}:{}{}",
                        entry.scheme, entry.host, entry.port, entry.path_prefix
                    )
                }
            })
            .collect()
    }
}

impl ScopeResolver for AllowlistScope {
    fn in_scope(&self, target: &Target) -> ScopeDecision {
        if self.entries.is_empty() {
            return ScopeDecision::Deny(
                "no scope declared; pass --scope or rely on --target's origin".to_owned(),
            );
        }
        if self.entries.iter().any(|entry| entry.matches(target)) {
            return ScopeDecision::Allow;
        }
        ScopeDecision::Deny(format!(
            "{}://{}:{}{} is not in the allowlist",
            target.scheme, target.host, target.port, target.path
        ))
    }
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

/// Failure parsing a target URL or scope entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeParseError {
    /// The string was not a usable URL.
    #[error("invalid URL {input:?}: {message}")]
    InvalidUrl {
        /// Truncated input.
        input: String,
        /// Parser message.
        message: String,
    },
    /// Only http and https are accepted.
    #[error("unsupported URL scheme {scheme:?}; only http and https are allowed")]
    UnsupportedScheme {
        /// Scheme that was refused.
        scheme: String,
    },
    /// Userinfo in the URL.
    #[error("URLs must not contain credentials; pass a token via a future auth flag, not the URL")]
    CredentialsNotAllowed,
    /// No host to scope against.
    #[error("URL {input:?} has no host")]
    MissingHost {
        /// Truncated input.
        input: String,
    },
    /// Allowlist longer than [`AllowlistScope::MAX_ENTRIES`].
    #[error("scope allowlist has {count} entries; maximum is {max}")]
    TooManyEntries {
        /// Observed count.
        count: usize,
        /// Cap.
        max: usize,
    },
    /// URL longer than [`crate::limits::http::MAX_URL_BYTES`].
    #[error("URL is {len} bytes; maximum is {max}")]
    UrlTooLong {
        /// Observed length.
        len: usize,
        /// Cap.
        max: usize,
    },
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}:{}{}",
            self.scheme, self.host, self.port, self.path
        )
    }
}

fn normalise_prefix(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".to_owned();
    }
    // Strip trailing slash so `/api` and `/api/` mean the same prefix, except
    // the root which stays `/`.
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn path_under_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path == prefix
        || path.starts_with(&format!("{prefix}/"))
        || path.starts_with(&format!("{prefix}?"))
}

/// Caps untrusted strings that appear in errors so a 10 KiB argv cannot inflate
/// every log line that mentions it.
fn truncate(input: &str) -> String {
    const MAX: usize = 128;
    if input.len() <= MAX {
        input.to_owned()
    } else {
        let mut cut = MAX;
        while cut > 0 && !input.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &input[..cut])
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

    #[test]
    fn target_defaults_https_port_and_lowercases_host() {
        let target = Target::parse("https://Example.COM/api").unwrap();
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.path, "/api");
    }

    #[test]
    fn credentials_in_url_are_refused() {
        assert!(matches!(
            Target::parse("http://user:pass@localhost:3000/"),
            Err(ScopeParseError::CredentialsNotAllowed)
        ));
    }

    #[test]
    fn file_scheme_is_refused() {
        assert!(matches!(
            Target::parse("file:///etc/passwd"),
            Err(ScopeParseError::UnsupportedScheme { .. })
        ));
    }

    #[test]
    fn allowlist_matches_origin_and_path_prefix() {
        let scope = AllowlistScope::parse(&["http://localhost:3000/api".to_owned()]).unwrap();
        assert!(
            scope
                .in_scope(&Target::parse("http://localhost:3000/api/users").unwrap())
                .is_allowed()
        );
        assert!(
            !scope
                .in_scope(&Target::parse("http://localhost:3000/other").unwrap())
                .is_allowed()
        );
        assert!(
            !scope
                .in_scope(&Target::parse("https://localhost:3000/api").unwrap())
                .is_allowed()
        );
    }

    #[test]
    fn path_prefix_does_not_treat_api_as_prefix_of_apiv2() {
        let entry = ScopeEntry::parse("http://localhost:3000/api").unwrap();
        let bait = Target::parse("http://localhost:3000/apiv2").unwrap();
        assert!(!entry.matches(&bait));
    }

    #[test]
    fn from_target_origin_allows_any_path_on_that_origin() {
        let target = Target::parse("http://127.0.0.1:8080/app").unwrap();
        let scope = AllowlistScope::from_target_origin(&target);
        assert!(
            scope
                .in_scope(&Target::parse("http://127.0.0.1:8080/anything").unwrap())
                .is_allowed()
        );
        assert!(
            !scope
                .in_scope(&Target::parse("http://127.0.0.1:8081/").unwrap())
                .is_allowed()
        );
    }

    #[test]
    fn empty_allowlist_denies() {
        let scope = AllowlistScope::new(Vec::new()).unwrap();
        assert!(
            !scope
                .in_scope(&Target::parse("http://localhost:3000/").unwrap())
                .is_allowed()
        );
    }

    #[test]
    fn too_many_entries_are_refused() {
        let entries: Vec<String> = (0..=AllowlistScope::MAX_ENTRIES)
            .map(|i| format!("http://host{i}.example:80/"))
            .collect();
        assert!(matches!(
            AllowlistScope::parse(&entries),
            Err(ScopeParseError::TooManyEntries { .. })
        ));
    }

    #[test]
    fn ipv6_literal_round_trips() {
        let target = Target::parse("http://[::1]:3000/").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 3000);
    }

    #[test]
    fn userinfo_host_confusion_is_refused() {
        // `http://allowed.example@evil.example/` parses as user=allowed,
        // host=evil — refusing credentials closes that classic bypass.
        assert!(matches!(
            Target::parse("http://allowed.example@evil.example/"),
            Err(ScopeParseError::CredentialsNotAllowed)
        ));
    }

    #[test]
    fn oversized_url_is_refused() {
        let huge = format!("http://example.com/{}", "a".repeat(10_000));
        assert!(matches!(
            Target::parse(&huge),
            Err(ScopeParseError::UrlTooLong { .. })
        ));
    }

    #[test]
    fn url_with_embedded_newline_is_refused() {
        assert!(matches!(
            Target::parse("http://example.com/\nX-Injected: yes"),
            Err(ScopeParseError::InvalidUrl { .. })
        ));
    }
}
