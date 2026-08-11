//! Active CSRF probe: gate, canary POST, and 2xx finding ([ADR 0019]).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::scope::{AllowlistScope, ScopeResolver, Target};
use owlwarden_core::source::{FileSelector, SourceError, SourceFile, SourceProvider};
use owlwarden_core::transport::Transport;
use owlwarden_detectors::csrf_cross_origin_post_detector;
use owlwarden_transport::ReqwestTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct EmptySource;

impl SourceProvider for EmptySource {
    fn root(&self) -> &std::path::Path {
        std::path::Path::new(".")
    }
    fn files(&self, _: &FileSelector) -> Result<Vec<SourceFile>, SourceError> {
        Ok(Vec::new())
    }
    fn read(&self, _: &SourceFile) -> Result<Arc<str>, SourceError> {
        Ok(Arc::from(""))
    }
}

async fn spawn_once(status_line: &'static str) -> (String, Arc<std::sync::Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{}:{}/csrf", addr.ip(), addr.port());
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let seen_server = Arc::clone(&seen);
    tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).into_owned();
        *seen_server.lock().unwrap() = request;
        let body = b"ok";
        let response = format!(
            "{status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.write_all(body).await;
        let _ = socket.shutdown().await;
    });
    tokio::task::yield_now().await;
    (url, seen)
}

async fn run_probe(
    url: &str,
    transport_allow_active: bool,
    settings_allow_active: bool,
) -> Result<Vec<owlwarden_core::finding::Finding>, owlwarden_core::detector::DetectorError> {
    let target = Target::parse(url).unwrap();
    let scope: Arc<dyn ScopeResolver> = Arc::new(AllowlistScope::from_target_origin(&target));
    let budget = Arc::new(Budget::new(10, std::time::Duration::from_secs(10)));
    let transport = ReqwestTransport::new(
        Arc::clone(&scope),
        Arc::clone(&budget),
        transport_allow_active,
    )
    .unwrap();
    let settings = ScanSettings {
        allow_active: settings_allow_active,
        ..ScanSettings::default()
    };
    let source = EmptySource;
    let ctx = ScanContext::new(
        &source,
        Some(&transport as &dyn Transport),
        scope.as_ref(),
        &settings,
        budget.as_ref(),
    );
    let detector = csrf_cross_origin_post_detector(url.to_owned(), "/csrf");
    detector.run(&ctx).await
}

#[tokio::test]
async fn active_probe_fires_on_2xx_and_sends_canary() {
    let (url, seen) = spawn_once("HTTP/1.1 204 No Content").await;
    let findings = run_probe(&url, true, true).await.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id.as_str(), "csrf-cross-origin-post");
    let request = seen.lock().unwrap().clone();
    assert!(request.starts_with("POST "));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("origin: https://owlwarden-untrusted.invalid")
    );
    assert!(request.contains("owlwarden_probe=1"));
}

#[tokio::test]
async fn non_2xx_is_silent() {
    let (url, _) = spawn_once("HTTP/1.1 403 Forbidden").await;
    let findings = run_probe(&url, true, true).await.unwrap();
    assert!(findings.is_empty());
}

#[tokio::test]
async fn settings_without_allow_active_stay_silent() {
    // Defence in depth: even if a transport somehow allows POST, the detector
    // itself must not fire when the run did not pass `--allow-active`.
    let (url, _) = spawn_once("HTTP/1.1 204 No Content").await;
    let findings = run_probe(&url, true, false).await.unwrap();
    assert!(findings.is_empty());
}

#[tokio::test]
async fn transport_without_allow_active_refuses_post() {
    let (url, _) = spawn_once("HTTP/1.1 204 No Content").await;
    let err = run_probe(&url, false, true).await.unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("allow-active") || message.contains("state-changing"),
        "{message}"
    );
}
