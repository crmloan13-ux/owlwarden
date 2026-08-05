//! The `Transport` port: the only way a detector reaches the network.
//!
//! No adapter ships in v0.0 — the static engine is passive by definition and
//! needs none. The port exists now because the *limits* are the interesting
//! part and they belong in core, where a reviewer can find them, not in
//! whichever HTTP client we happen to pick (`ARCHITECTURE.md` §3, §9).
//!
//! Two invariants an implementation must uphold, and is tested for:
//!
//! 1. **Scope is checked here, not by the caller.** A detector cannot reach the
//!    network any other way, so scope cannot be bypassed by forgetting a check.
//! 2. **Every limit in [`HttpLimits`] is enforced while streaming**, not after.
//!    Checking `Content-Length` is not enforcement; a hostile server lies about
//!    it, and a 10 GiB body has already been read by the time you look.

use async_trait::async_trait;

use crate::limits;

/// HTTP method. Anything that changes state requires `--allow-active`, which is
/// why the enum is explicit rather than a free-form string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// HEAD.
    Head,
    /// OPTIONS.
    Options,
    /// POST — state-changing.
    Post,
    /// PUT — state-changing.
    Put,
    /// PATCH — state-changing.
    Patch,
    /// DELETE — state-changing.
    Delete,
}

impl Method {
    /// Whether this method may change state on the target.
    ///
    /// Detectors using one of these need the `active` capability *and* a run
    /// with `--allow-active`. Note this is about our intent: a GET can of
    /// course mutate a badly designed endpoint, which is exactly why we do not
    /// probe endpoints outside declared scope at all.
    #[must_use]
    pub const fn is_state_changing(self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch | Self::Delete)
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// The caps applied to one exchange. Defaults come from
/// [`crate::limits::http`]; config may tighten or loosen them, never remove
/// them.
#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    /// Wall-clock ceiling for the exchange.
    pub timeout: std::time::Duration,
    /// Maximum response body buffered, in bytes.
    pub max_body_bytes: u64,
    /// Redirect hops followed. Off-scope redirects are never followed,
    /// regardless of this number — that is the SSRF-bait case.
    pub max_redirects: u8,
    /// Maximum decompressed-to-compressed size ratio.
    pub max_decompress_ratio: u32,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            timeout: limits::http::TIMEOUT,
            max_body_bytes: limits::http::MAX_BODY_BYTES,
            max_redirects: limits::http::MAX_REDIRECTS,
            max_decompress_ratio: limits::http::MAX_DECOMPRESS_RATIO,
        }
    }
}

/// A request that carries its own limits, so no code path can issue an
/// unbounded one.
#[derive(Debug, Clone)]
pub struct BoundedRequest {
    /// Absolute URL. Validated against scope by the transport.
    pub url: String,
    /// HTTP method.
    pub method: Method,
    /// Request headers as `(name, value)` pairs.
    pub headers: Vec<(String, String)>,
    /// Optional body, capped at [`crate::limits::http::MAX_REQUEST_BODY_BYTES`].
    pub body: Option<Vec<u8>>,
    /// Limits for this exchange.
    pub limits: HttpLimits,
}

impl BoundedRequest {
    /// Builds a passive GET with default limits.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Get,
            headers: Vec::new(),
            body: None,
            limits: HttpLimits::default(),
        }
    }

    /// Rejects a request whose body is over the cap.
    ///
    /// # Errors
    /// [`TransportError::RequestTooLarge`] when the body exceeds the cap.
    pub fn validate(&self) -> Result<(), TransportError> {
        if let Some(body) = &self.body
            && body.len() > limits::http::MAX_REQUEST_BODY_BYTES
        {
            return Err(TransportError::RequestTooLarge {
                size: body.len(),
                max: limits::http::MAX_REQUEST_BODY_BYTES,
            });
        }
        Ok(())
    }
}

/// A response that was read under the limits of its request.
#[derive(Debug, Clone)]
pub struct BoundedResponse {
    /// Final URL after any followed redirects.
    pub url: String,
    /// Status code.
    pub status: u16,
    /// Response headers, lowercased names.
    pub headers: Vec<(String, String)>,
    /// Body bytes actually read (already clamped).
    pub body: Vec<u8>,
    /// True when the body hit the cap and was cut short. Detectors must check
    /// this before concluding anything from an absence in the body.
    pub body_truncated: bool,
    /// Round-trip duration.
    pub elapsed: std::time::Duration,
}

impl BoundedResponse {
    /// First value of a header, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The port. One method, because every extra one is another place scope could
/// be forgotten.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends a request, enforcing scope and limits.
    ///
    /// # Errors
    /// [`TransportError`] for scope denial, timeout, size violation, or an
    /// underlying network failure.
    async fn send(&self, request: BoundedRequest) -> Result<BoundedResponse, TransportError>;
}

/// Failure sending a request or reading a response.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The target was not in the declared scope. Deny-by-default: a URL that
    /// nobody allowed is denied, not allowed-unless-blocked.
    #[error("{url} is out of scope: {reason}")]
    OutOfScope {
        /// URL that was refused.
        url: String,
        /// Which scope rule refused it.
        reason: String,
    },

    /// A state-changing request without `--allow-active`.
    #[error("{method} {url} is a state-changing request; re-run with --allow-active to permit it")]
    ActiveNotPermitted {
        /// Method attempted.
        method: &'static str,
        /// URL attempted.
        url: String,
    },

    /// The request body exceeded the cap.
    #[error("request body is {size} bytes, over the {max}-byte limit")]
    RequestTooLarge {
        /// Actual size.
        size: usize,
        /// Cap.
        max: usize,
    },

    /// The response body exceeded the cap while streaming.
    #[error("response body exceeded the {max}-byte limit")]
    ResponseTooLarge {
        /// Cap.
        max: u64,
    },

    /// A compressed body expanded past the allowed ratio (zip bomb).
    #[error("response expanded {ratio}x, over the {max}x decompression limit")]
    DecompressionBomb {
        /// Observed ratio.
        ratio: u32,
        /// Cap.
        max: u32,
    },

    /// Too many redirect hops.
    #[error("exceeded {max} redirects starting from {url}")]
    TooManyRedirects {
        /// Starting URL.
        url: String,
        /// Cap.
        max: u8,
    },

    /// The exchange ran out of time.
    #[error("{url} timed out after {}ms", timeout.as_millis())]
    Timeout {
        /// URL attempted.
        url: String,
        /// The timeout that elapsed.
        timeout: std::time::Duration,
    },

    /// The scan's request budget is spent.
    #[error("scan request budget exhausted ({max} requests)")]
    BudgetExhausted {
        /// Cap.
        max: u32,
    },

    /// Anything else the network did.
    #[error("network error for {url}: {message}")]
    Network {
        /// URL attempted.
        url: String,
        /// Redacted message. Never include headers or cookies here.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn state_changing_methods_are_classified() {
        assert!(!Method::Get.is_state_changing());
        assert!(!Method::Head.is_state_changing());
        assert!(!Method::Options.is_state_changing());
        for method in [Method::Post, Method::Put, Method::Patch, Method::Delete] {
            assert!(
                method.is_state_changing(),
                "{} must be active",
                method.as_str()
            );
        }
    }

    #[test]
    fn oversized_request_body_is_refused() {
        let mut request = BoundedRequest::get("http://localhost:3000/");
        request.body = Some(vec![0u8; limits::http::MAX_REQUEST_BODY_BYTES + 1]);
        assert!(matches!(
            request.validate(),
            Err(TransportError::RequestTooLarge { .. })
        ));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let response = BoundedResponse {
            url: "http://localhost:3000/".into(),
            status: 200,
            headers: vec![("Content-Type".into(), "text/html".into())],
            body: Vec::new(),
            body_truncated: false,
            elapsed: std::time::Duration::ZERO,
        };
        assert_eq!(response.header("content-type"), Some("text/html"));
        assert_eq!(response.header("x-missing"), None);
    }
}
