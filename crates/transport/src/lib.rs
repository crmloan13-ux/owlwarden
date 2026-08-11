//! Bounded HTTP transport for owlwarden.
//!
//! The only production [`Transport`](owlwarden_core::Transport) adapter. Scope
//! is checked on the initial URL and on every redirect hop; body bytes are
//! counted while streaming; automatic decompression is off so a hostile
//! `Content-Encoding` cannot expand past the cap before we notice.
//!
//! See [ADR 0014](../../docs/adr/0014-passive-dynamic-and-correlation.md).

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod osv;
pub mod osv_index;

pub use osv::OsvHttpClient;
pub use osv_index::{
    OsvIndex, OsvIndexClient, fetch_index, prepare_advisory_client, serialize_index,
};

use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use owlwarden_core::budget::Budget;
use owlwarden_core::limits;
use owlwarden_core::scope::{ScopeResolver, Target};
use owlwarden_core::transport::{
    BoundedRequest, BoundedResponse, Method, Transport, TransportError,
};
use reqwest::Client;
use reqwest::redirect::Policy;

/// One line of the request audit log (method, URL, status). No bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// HTTP method name.
    pub method: String,
    /// Absolute URL that was requested (after redirects: the hop URL).
    pub url: String,
    /// Response status when the exchange completed; `None` on hard failure.
    pub status: Option<u16>,
}

/// Production transport: reqwest behind the core port.
pub struct ReqwestTransport {
    client: Client,
    scope: Arc<dyn ScopeResolver>,
    budget: Arc<Budget>,
    allow_active: bool,
    /// Last state-changing request time — enforces [`limits::scan::ACTIVE_MIN_INTERVAL`].
    last_active_at: Mutex<Option<Instant>>,
    /// Bounded request audit trail for `--allow-active` operators.
    audit: Mutex<Vec<AuditEntry>>,
}

impl ReqwestTransport {
    /// Builds a transport.
    ///
    /// Redirects are followed manually so each hop can be scope-checked.
    /// Response decompression is disabled (no gzip/brotli features) so wire
    /// bytes and buffered bytes stay equal under the body cap.
    ///
    /// # Errors
    /// [`TransportBuildError`] when the underlying client cannot be constructed.
    pub fn new(
        scope: Arc<dyn ScopeResolver>,
        budget: Arc<Budget>,
        allow_active: bool,
    ) -> Result<Self, TransportBuildError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(owlwarden_core::limits::http::TIMEOUT)
            .user_agent(concat!("owlwarden/", env!("CARGO_PKG_VERSION")))
            .pool_max_idle_per_host(2)
            .build()
            .map_err(|error| TransportBuildError {
                message: error.to_string(),
            })?;
        Ok(Self {
            client,
            scope,
            budget,
            allow_active,
            last_active_at: Mutex::new(None),
            audit: Mutex::new(Vec::new()),
        })
    }

    /// Snapshot of the audit log (method, URL, status). Bodies are never stored.
    #[must_use]
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    fn record_audit(&self, method: Method, url: &str, status: Option<u16>) {
        let Ok(mut guard) = self.audit.lock() else {
            return;
        };
        if guard.len() >= limits::scan::MAX_AUDIT_ENTRIES {
            return;
        }
        guard.push(AuditEntry {
            method: method.as_str().to_owned(),
            url: url.to_owned(),
            status,
        });
    }

    async fn pace_active(&self, method: Method) {
        if !method.is_state_changing() {
            return;
        }
        // Reserve the next slot under the lock so concurrent active detectors
        // cannot all sleep for the same gap and then fire together.
        let wait = {
            let Ok(mut guard) = self.last_active_at.lock() else {
                return;
            };
            let now = Instant::now();
            let wait = guard.and_then(|previous| {
                let earliest = previous + limits::scan::ACTIVE_MIN_INTERVAL;
                earliest.checked_duration_since(now)
            });
            let reserved_at = wait.map_or(now, |duration| now + duration);
            *guard = Some(reserved_at);
            wait
        };
        if let Some(duration) = wait {
            tokio::time::sleep(duration).await;
        }
    }
}

/// The HTTP client itself failed to construct. Rare; usually a TLS backend
/// problem on a broken host.
#[derive(Debug, thiserror::Error)]
#[error("could not build HTTP client: {message}")]
pub struct TransportBuildError {
    message: String,
}

#[async_trait]
impl Transport for ReqwestTransport {
    async fn send(&self, request: BoundedRequest) -> Result<BoundedResponse, TransportError> {
        request.validate()?;

        if request.method.is_state_changing() && !self.allow_active {
            return Err(TransportError::ActiveNotPermitted {
                method: request.method.as_str(),
                url: request.url.clone(),
            });
        }

        if !self.budget.try_spend_request() {
            return Err(TransportError::BudgetExhausted {
                max: owlwarden_core::limits::scan::MAX_REQUESTS,
            });
        }

        self.pace_active(request.method).await;

        let mut current_url = request.url.clone();
        let mut redirects: u8 = 0;
        let started = Instant::now();
        // After the first hop we issue GET to the Location; body/headers from
        // the original request do not follow a cross-origin redirect.
        let mut carry_body = true;

        loop {
            let target = Target::parse(&current_url).map_err(|error| TransportError::Network {
                url: current_url.clone(),
                message: error.to_string(),
            })?;
            match self.scope.in_scope(&target) {
                owlwarden_core::scope::ScopeDecision::Allow => {}
                owlwarden_core::scope::ScopeDecision::Deny(reason) => {
                    self.record_audit(request.method, &current_url, None);
                    return Err(TransportError::OutOfScope {
                        url: current_url,
                        reason,
                    });
                }
            }

            let method = if carry_body {
                request.method
            } else {
                Method::Get
            };
            let mut builder = self
                .client
                .request(to_reqwest(method), &current_url)
                .timeout(request.limits.timeout);
            if carry_body {
                builder = apply_request_headers(builder, &request.headers)?;
                if let Some(body) = &request.body {
                    builder = builder.body(body.clone());
                }
            }

            let response = builder.send().await.map_err(|error| {
                self.record_audit(method, &current_url, None);
                map_reqwest_error(error, &current_url, request.limits.timeout)
            })?;

            let status = response.status();
            self.record_audit(method, &current_url, Some(status.as_u16()));
            if status.is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                // Drop the redirect body without buffering it. A hostile 302
                // with a multi-gigabyte body must not be read before we decide.
                drop(response);
                let Some(location) = location else {
                    return Err(TransportError::Network {
                        url: current_url,
                        message: "redirect response had no Location header".to_owned(),
                    });
                };
                if redirects >= request.limits.max_redirects {
                    return Err(TransportError::TooManyRedirects {
                        url: request.url.clone(),
                        max: request.limits.max_redirects,
                    });
                }
                redirects = redirects.saturating_add(1);
                current_url = resolve_redirect(&current_url, &location)?;
                carry_body = false;
                // Redirect hops share the original request's budget spend; we
                // do not charge again. A redirect loop is bounded by
                // max_redirects instead.
                continue;
            }

            return read_response(
                response,
                current_url,
                started,
                request.limits.max_body_bytes,
            )
            .await;
        }
    }
}

fn to_reqwest(method: Method) -> reqwest::Method {
    match method {
        Method::Get => reqwest::Method::GET,
        Method::Head => reqwest::Method::HEAD,
        Method::Options => reqwest::Method::OPTIONS,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
    }
}

fn apply_request_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &[(String, String)],
) -> Result<reqwest::RequestBuilder, TransportError> {
    for (name, value) in headers.iter().take(limits::http::MAX_REQUEST_HEADERS) {
        validate_header_component(name, "name")?;
        validate_header_component(value, "value")?;
        builder = builder.header(name, value);
    }
    Ok(builder)
}

fn validate_header_component(value: &str, kind: &str) -> Result<(), TransportError> {
    if value.is_empty() {
        return Err(TransportError::Network {
            url: String::new(),
            message: format!("request header {kind} must not be empty"),
        });
    }
    if value.len() > limits::http::MAX_HEADER_VALUE_BYTES {
        return Err(TransportError::Network {
            url: String::new(),
            message: format!("request header {kind} exceeds size cap"),
        });
    }
    if value
        .bytes()
        .any(|b| b == b'\0' || b == b'\r' || b == b'\n')
    {
        return Err(TransportError::Network {
            url: String::new(),
            message: format!("request header {kind} must not contain control characters"),
        });
    }
    Ok(())
}

fn resolve_redirect(base: &str, location: &str) -> Result<String, TransportError> {
    if location.len() > limits::http::MAX_URL_BYTES {
        return Err(TransportError::Network {
            url: base.to_owned(),
            message: "redirect Location exceeds size cap".to_owned(),
        });
    }
    if location
        .bytes()
        .any(|b| b == b'\0' || b == b'\r' || b == b'\n')
    {
        return Err(TransportError::Network {
            url: base.to_owned(),
            message: "redirect Location must not contain control characters".to_owned(),
        });
    }
    let base_url = url::Url::parse(base).map_err(|error| TransportError::Network {
        url: base.to_owned(),
        message: error.to_string(),
    })?;
    let mut joined = base_url
        .join(location)
        .map_err(|error| TransportError::Network {
            url: base.to_owned(),
            message: format!("invalid redirect Location: {error}"),
        })?;
    // Re-validate through Target so credentials, schemes, and length caps
    // apply to every hop — including protocol-relative `//evil/…` Locations.
    Target::from_url(&joined).map_err(|error| TransportError::Network {
        url: base.to_owned(),
        message: error.to_string(),
    })?;
    let _ = joined.set_username("");
    let _ = joined.set_password(None);
    let wire = joined.to_string();
    if wire.len() > limits::http::MAX_URL_BYTES {
        return Err(TransportError::Network {
            url: base.to_owned(),
            message: "redirect URL exceeds size cap".to_owned(),
        });
    }
    Ok(wire)
}

fn map_reqwest_error(
    error: reqwest::Error,
    url: &str,
    timeout: std::time::Duration,
) -> TransportError {
    if error.is_timeout() {
        return TransportError::Timeout {
            url: url.to_owned(),
            timeout,
        };
    }
    TransportError::Network {
        url: url.to_owned(),
        // reqwest messages can include the URL; strip nothing secret-bearing
        // beyond what we already refuse (credentials in URLs).
        message: error.without_url().to_string(),
    }
}

async fn read_response(
    response: reqwest::Response,
    url: String,
    started: Instant,
    max_body_bytes: u64,
) -> Result<BoundedResponse, TransportError> {
    let status = response.status().as_u16();
    let headers = collect_response_headers(response.headers());

    // Headers-only probes must not pull even one body chunk into memory: a
    // non-compliant server can answer HEAD with a multi-megabyte payload.
    if max_body_bytes == 0 {
        drop(response);
        return Ok(BoundedResponse {
            url,
            status,
            headers,
            body: Vec::new(),
            body_truncated: false,
            elapsed: started.elapsed(),
        });
    }

    let max_body_bytes = max_body_bytes.min(limits::http::MAX_BODY_BYTES);
    let mut body = Vec::new();
    let mut truncated = false;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| TransportError::Network {
            url: url.clone(),
            message: error.without_url().to_string(),
        })?;
        let remaining = max_body_bytes.saturating_sub(body.len() as u64);
        if remaining == 0 {
            truncated = true;
            break;
        }
        if (chunk.len() as u64) > remaining {
            let take = usize::try_from(remaining).unwrap_or(0);
            let (head, _) = chunk.split_at(take);
            body.extend_from_slice(head);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok(BoundedResponse {
        url,
        status,
        headers,
        body,
        body_truncated: truncated,
        elapsed: started.elapsed(),
    })
}

fn collect_response_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers.iter().take(limits::http::MAX_RESPONSE_HEADERS) {
        let Ok(text) = value.to_str() else {
            continue;
        };
        if text.len() > limits::http::MAX_HEADER_VALUE_BYTES {
            // Drop, do not truncate: a half CSP would be a false sense of cover.
            continue;
        }
        if text.bytes().any(|b| b == b'\0') {
            continue;
        }
        out.push((name.as_str().to_ascii_lowercase(), text.to_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Write;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use owlwarden_core::budget::Budget;
    use owlwarden_core::scope::{AllowlistScope, Target};
    use owlwarden_core::transport::{
        BoundedRequest, HttpLimits, Method, Transport, TransportError,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn serve(handler: fn(&[u8]) -> Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = buf.get(..n).unwrap_or(&[]);
                let response = handler(request);
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            }
        });
        // Give the accept loop a tick.
        tokio::task::yield_now().await;
        (addr, handle)
    }

    fn transport_for(addr: SocketAddr, max_requests: u32) -> ReqwestTransport {
        let origin = format!("http://{}:{}", addr.ip(), addr.port());
        let target = Target::parse(&origin).unwrap();
        let scope = Arc::new(AllowlistScope::from_target_origin(&target));
        let budget = Arc::new(Budget::new(
            max_requests,
            std::time::Duration::from_secs(30),
        ));
        ReqwestTransport::new(scope, budget, false).unwrap()
    }

    #[tokio::test]
    async fn get_returns_headers_and_body() {
        let (addr, server) =
            serve(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello".to_vec())
                .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let response = transport.send(BoundedRequest::get(url)).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("x-test"), Some("yes"));
        server.abort();
    }

    #[tokio::test]
    async fn off_scope_redirect_is_refused() {
        let (addr, server) = serve(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let error = transport.send(BoundedRequest::get(url)).await.unwrap_err();
        assert!(matches!(error, TransportError::OutOfScope { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn in_scope_redirect_is_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // First connection: redirect to /final on same origin.
            let (mut a, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = a.read(&mut buf).await;
            let location = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{}:{}/final\r\nContent-Length: 0\r\n\r\n",
                addr.ip(),
                addr.port()
            );
            a.write_all(location.as_bytes()).await.unwrap();
            let _ = a.shutdown().await;
            // Second connection: final response.
            let (mut b, _) = listener.accept().await.unwrap();
            let _ = b.read(&mut buf).await;
            b.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            let _ = b.shutdown().await;
        });
        tokio::task::yield_now().await;

        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/start", addr.ip(), addr.port());
        let response = transport.send(BoundedRequest::get(url)).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        assert!(response.url.ends_with("/final"));
        server.abort();
    }

    #[tokio::test]
    async fn body_cap_truncates_without_buffering_the_rest() {
        let (addr, server) = serve(|_| {
            let mut out = Vec::new();
            write!(out, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").unwrap();
            out.extend(std::iter::repeat_n(b'A', 100));
            out
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let mut request = BoundedRequest::get(url);
        request.limits = HttpLimits {
            max_body_bytes: 16,
            ..HttpLimits::default()
        };
        let response = transport.send(request).await.unwrap();
        assert!(response.body_truncated);
        assert_eq!(response.body.len(), 16);
        server.abort();
    }

    #[tokio::test]
    async fn post_without_allow_active_is_refused() {
        let (addr, server) =
            serve(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let mut request = BoundedRequest::get(&url);
        request.method = Method::Post;
        let error = transport.send(request).await.unwrap_err();
        assert!(matches!(error, TransportError::ActiveNotPermitted { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn budget_exhaustion_stops_further_requests() {
        let (addr, server) =
            serve(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let transport = transport_for(addr, 1);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        transport
            .send(BoundedRequest::get(url.clone()))
            .await
            .unwrap();
        let error = transport.send(BoundedRequest::get(url)).await.unwrap_err();
        assert!(matches!(error, TransportError::BudgetExhausted { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn url_outside_allowlist_never_connects() {
        // No server listening on this port — if we connect, the error would be
        // Network, not OutOfScope.
        let scope = Arc::new(AllowlistScope::parse(&["http://127.0.0.1:9/".to_owned()]).unwrap());
        let budget = Arc::new(Budget::new(10, std::time::Duration::from_secs(5)));
        let transport = ReqwestTransport::new(scope, budget, false).unwrap();
        let error = transport
            .send(BoundedRequest::get("http://127.0.0.1:1/"))
            .await
            .unwrap_err();
        assert!(matches!(error, TransportError::OutOfScope { .. }));
    }

    #[tokio::test]
    async fn protocol_relative_redirect_is_scope_checked() {
        // `Location: //evil.example/` must not inherit the allowed host.
        let (addr, server) = serve(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: //evil.example/\r\nContent-Length: 0\r\n\r\n".to_vec()
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let error = transport.send(BoundedRequest::get(url)).await.unwrap_err();
        assert!(
            matches!(error, TransportError::OutOfScope { .. }),
            "got {error:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn redirect_with_credentials_is_refused() {
        let (addr, server) = serve(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: http://user:pass@evil.example/\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let error = transport.send(BoundedRequest::get(url)).await.unwrap_err();
        assert!(
            matches!(error, TransportError::Network { .. }),
            "got {error:?}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn javascript_location_is_refused() {
        let (addr, server) = serve(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: javascript:alert(1)\r\nContent-Length: 0\r\n\r\n"
                .to_vec()
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let error = transport.send(BoundedRequest::get(url)).await.unwrap_err();
        assert!(matches!(error, TransportError::Network { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn too_many_redirects_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..10 {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let location = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{}:{}/next\r\nContent-Length: 0\r\n\r\n",
                    addr.ip(),
                    addr.port()
                );
                let _ = socket.write_all(location.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        tokio::task::yield_now().await;

        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/start", addr.ip(), addr.port());
        let mut request = BoundedRequest::get(url);
        request.limits.max_redirects = 2;
        let error = transport.send(request).await.unwrap_err();
        assert!(matches!(error, TransportError::TooManyRedirects { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn headers_only_probe_does_not_buffer_body() {
        let (addr, server) = serve(|_| {
            let mut out = Vec::new();
            write!(
                out,
                "HTTP/1.1 200 OK\r\nX-Ok: 1\r\nContent-Length: 1000000\r\n\r\n"
            )
            .unwrap();
            out.extend(std::iter::repeat_n(b'Z', 1_000_000));
            out
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let mut request = BoundedRequest::get(url);
        request.limits.max_body_bytes = 0;
        let response = transport.send(request).await.unwrap();
        assert_eq!(response.header("x-ok"), Some("1"));
        assert!(response.body.is_empty());
        assert!(!response.body_truncated);
        server.abort();
    }

    #[tokio::test]
    async fn oversized_response_header_is_dropped_not_kept() {
        let (addr, server) = serve(|_| {
            let huge = "A".repeat(limits::http::MAX_HEADER_VALUE_BYTES + 1);
            format!("HTTP/1.1 200 OK\r\nX-Huge: {huge}\r\nX-Small: ok\r\nContent-Length: 0\r\n\r\n")
                .into_bytes()
        })
        .await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let response = transport.send(BoundedRequest::get(url)).await.unwrap();
        assert_eq!(response.header("x-small"), Some("ok"));
        assert_eq!(response.header("x-huge"), None);
        server.abort();
    }

    #[tokio::test]
    async fn crlf_in_request_header_is_refused() {
        let (addr, server) =
            serve(|_| b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let transport = transport_for(addr, 10);
        let url = format!("http://{}:{}/", addr.ip(), addr.port());
        let mut request = BoundedRequest::get(url);
        request
            .headers
            .push(("X-Inject".into(), "one\r\nX-Evil: two".into()));
        let error = transport.send(request).await.unwrap_err();
        assert!(matches!(error, TransportError::Network { .. }));
        server.abort();
    }

    #[test]
    fn resolve_redirect_rejects_userinfo_host_confusion() {
        let error = resolve_redirect(
            "http://127.0.0.1:3000/",
            "http://allowed.example@evil.example/",
        )
        .unwrap_err();
        assert!(matches!(error, TransportError::Network { .. }));
    }
}
