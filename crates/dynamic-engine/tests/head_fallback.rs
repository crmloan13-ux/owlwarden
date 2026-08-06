//! HEAD → GET fallback when the server rejects HEAD.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use owlwarden_core::budget::Budget;
use owlwarden_core::context::{ScanContext, ScanSettings};
use owlwarden_core::detector::Detector;
use owlwarden_core::scope::{AllowlistScope, ScopeResolver, Target};
use owlwarden_core::source::{FileSelector, SourceError, SourceFile, SourceProvider};
use owlwarden_dynamic::{DynamicEngine, ProbeTarget};
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
    fn read(&self, _: &SourceFile) -> Result<std::sync::Arc<str>, SourceError> {
        Ok(std::sync::Arc::from(""))
    }
}

#[tokio::test]
async fn head_405_falls_back_to_get() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_server = Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
            hits_server.fetch_add(1, Ordering::SeqCst);
            let body = if request.starts_with("HEAD ") {
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 0\r\n\r\n"
            };
            let _ = socket.write_all(body.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    tokio::task::yield_now().await;

    let origin = format!("http://{}:{}", addr.ip(), addr.port());
    let target = Target::parse(&origin).unwrap();
    let scope: Arc<dyn ScopeResolver> = Arc::new(AllowlistScope::from_target_origin(&target));
    let budget = Arc::new(Budget::new(10, std::time::Duration::from_secs(10)));
    let transport = ReqwestTransport::new(Arc::clone(&scope), Arc::clone(&budget), false).unwrap();
    let settings = ScanSettings::default();
    let source = EmptySource;
    let ctx = ScanContext::new(
        &source,
        Some(&transport),
        scope.as_ref(),
        &settings,
        budget.as_ref(),
    );

    let engine = DynamicEngine::new(ProbeTarget::from_target(&target));
    let findings = engine.run(&ctx).await.unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(engine.routes_probed(), 1);
    assert_eq!(findings.len(), 1);
    assert!(
        findings
            .first()
            .unwrap()
            .context
            .evidence
            .as_deref()
            .unwrap()
            .contains("missing:")
    );
    server.abort();
}
