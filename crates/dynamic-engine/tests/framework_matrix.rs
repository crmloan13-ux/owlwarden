//! Dynamic correlation across every supported framework fixture.
//!
//! Mirrors the static matrix in `detectors/tests/fixtures.rs`: if a framework
//! is advertised, dynamic confirmation must work on its vulnerable twin and
//! must not invent a `security-headers-missing` finding on its clean twin when
//! the live response agrees.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Location};
use owlwarden_core::report::Report;
use owlwarden_detectors::{SecurityHeadersMissing, rules_for_preset};
use owlwarden_dynamic::{correlate, prepare_live};
use owlwarden_static::ScanRequest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Row {
    framework: &'static str,
    vulnerable: &'static str,
    clean: &'static str,
}

/// Same frameworks as the static fixture matrix — kept as a table so a
/// framework without a dynamic row fails CI the same way.
const MATRIX: &[Row] = &[
    Row {
        framework: "next",
        vulnerable: "vulnerable/next-api",
        clean: "should-not-fire/next-api-clean",
    },
    Row {
        framework: "nuxt",
        vulnerable: "vulnerable/nuxt-api",
        clean: "should-not-fire/nuxt-api-clean",
    },
    Row {
        framework: "nest",
        vulnerable: "vulnerable/nest-api",
        clean: "should-not-fire/nest-api-clean",
    },
    Row {
        framework: "express",
        vulnerable: "vulnerable/express-api",
        clean: "should-not-fire/express-api-clean",
    },
    Row {
        framework: "fastify",
        vulnerable: "vulnerable/fastify-api",
        clean: "should-not-fire/fastify-api-clean",
    },
    Row {
        framework: "hono",
        vulnerable: "vulnerable/hono-api",
        clean: "should-not-fire/hono-api-clean",
    },
    Row {
        framework: "koa",
        vulnerable: "vulnerable/koa-api",
        clean: "should-not-fire/koa-api-clean",
    },
    Row {
        framework: "hapi",
        vulnerable: "vulnerable/hapi-api",
        clean: "should-not-fire/hapi-api-clean",
    },
    Row {
        framework: "sails",
        vulnerable: "vulnerable/sails-api",
        clean: "should-not-fire/sails-api-clean",
    },
    Row {
        framework: "astro",
        vulnerable: "vulnerable/astro-api",
        clean: "should-not-fire/astro-api-clean",
    },
    Row {
        framework: "remix",
        vulnerable: "vulnerable/remix-api",
        clean: "should-not-fire/remix-api-clean",
    },
    Row {
        framework: "gatsby",
        vulnerable: "vulnerable/gatsby-api",
        clean: "should-not-fire/gatsby-api-clean",
    },
];

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn headers_rule(report: &Report) -> Vec<&owlwarden_core::finding::Finding> {
    report
        .findings
        .iter()
        .filter(|finding| finding.id == SecurityHeadersMissing::meta().id)
        .collect()
}

async fn serve(response: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(response).await;
            let _ = socket.shutdown().await;
        }
    });
    tokio::task::yield_now().await;
    (addr, handle)
}

const MISSING: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";

const PRESENT: &[u8] = b"\
HTTP/1.1 200 OK\r\n\
Strict-Transport-Security: max-age=63072000\r\n\
Content-Security-Policy: default-src 'self'\r\n\
X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: no-referrer\r\n\
Content-Length: 0\r\n\
\r\n";

async fn scan_live(relative: &str, target: &str) -> Report {
    let live = prepare_live(target, &[], false).unwrap();
    let (file_rules, project_rules) = rules_for_preset("deep");
    owlwarden_static::scan_project_with(
        fixture(relative),
        file_rules,
        project_rules,
        ScanRequest {
            settings: ScanSettings {
                preset: "deep".into(),
                ..ScanSettings::default()
            },
            suppressions: owlwarden_core::suppression::SuppressionPolicy::Honour,
            extra_detectors: vec![live.engine],
            network: Some(live.network),
            correlate: Some(correlate),
            ..ScanRequest::default()
        },
    )
    .await
    .expect("live scan should complete")
}

#[tokio::test]
async fn matrix_covers_every_supported_framework() {
    for framework in owlwarden_detectors::SUPPORTED_FRAMEWORKS {
        assert!(
            MATRIX.iter().any(|row| row.framework == framework.as_str()),
            "{} is advertised but has no dynamic fixture row",
            framework.as_str()
        );
    }
}

#[tokio::test]
async fn vulnerable_plus_missing_headers_confirms_on_every_framework() {
    let (addr, server) = serve(MISSING).await;
    let target = format!("http://{}:{}/", addr.ip(), addr.port());

    for row in MATRIX {
        let report = scan_live(row.vulnerable, &target).await;
        let headers = headers_rule(&report);
        assert_eq!(
            headers.len(),
            1,
            "{}: expected one headers finding, got {:?}",
            row.framework,
            report
                .findings
                .iter()
                .map(|f| (f.id.as_str(), f.confidence))
                .collect::<Vec<_>>()
        );
        let finding = headers.first().expect("len checked");
        assert_eq!(
            finding.confidence,
            Confidence::Confirmed,
            "{}: static+live missing headers must confirm",
            row.framework
        );
        assert!(
            finding.location.as_source().is_some(),
            "{}: confirmed finding keeps the source location",
            row.framework
        );
        assert!(
            finding
                .context
                .evidence
                .as_deref()
                .unwrap_or("")
                .contains("confirmed at runtime"),
            "{}: evidence must name the probe",
            row.framework
        );
        assert!(
            report
                .findings
                .iter()
                .all(|f| !matches!(f.location, Location::Endpoint(_))),
            "{}: endpoint duplicate must be merged away",
            row.framework
        );
        assert_eq!(
            finding
                .context
                .framework
                .as_ref()
                .map(owlwarden_core::finding::Framework::as_str),
            Some(row.framework),
            "{}: framework attribution must survive correlation",
            row.framework
        );
    }

    server.abort();
}

#[tokio::test]
async fn vulnerable_plus_present_headers_clears_gap_on_every_framework() {
    let (addr, server) = serve(PRESENT).await;
    let target = format!("http://{}:{}/", addr.ip(), addr.port());

    for row in MATRIX {
        let report = scan_live(row.vulnerable, &target).await;
        assert!(
            headers_rule(&report).is_empty(),
            "{}: live headers should clear the static gap, got {:?}",
            row.framework,
            headers_rule(&report)
                .iter()
                .map(|f| f.confidence)
                .collect::<Vec<_>>()
        );
    }

    server.abort();
}

#[tokio::test]
async fn clean_plus_present_headers_stays_silent_on_every_framework() {
    // Clean fixtures already configure headers in source. A live response that
    // also sets them must not invent a finding — that is the dynamic half of
    // the false-positive corpus.
    let (addr, server) = serve(PRESENT).await;
    let target = format!("http://{}:{}/", addr.ip(), addr.port());

    for row in MATRIX {
        let report = scan_live(row.clean, &target).await;
        assert!(
            headers_rule(&report).is_empty(),
            "{} clean: expected no security-headers-missing with agreeing runtime, got {:?}",
            row.framework,
            report
                .findings
                .iter()
                .filter(|f| f.id == SecurityHeadersMissing::meta().id)
                .map(|f| (f.confidence, f.context.evidence.clone()))
                .collect::<Vec<_>>()
        );
    }

    server.abort();
}

#[tokio::test]
async fn clean_plus_missing_live_reports_runtime_only() {
    // Source is clean (helmet / next.config headers). The live target is not.
    // Correlation must not invent Confirmed — there is no static finding to
    // raise — and must surface a Likely endpoint observation instead.
    let (addr, server) = serve(MISSING).await;
    let target = format!("http://{}:{}/", addr.ip(), addr.port());

    for row in MATRIX {
        let report = scan_live(row.clean, &target).await;
        let headers = headers_rule(&report);
        assert_eq!(
            headers.len(),
            1,
            "{} clean vs bad live: expected one runtime-only finding",
            row.framework
        );
        let finding = headers.first().expect("len checked");
        assert_eq!(finding.confidence, Confidence::Likely);
        assert!(
            matches!(finding.location, Location::Endpoint(_)),
            "{}: runtime-only finding stays on the endpoint",
            row.framework
        );
        assert!(
            !finding
                .context
                .evidence
                .as_deref()
                .unwrap_or("")
                .contains("confirmed at runtime"),
            "{}: must not claim Confirmed without a static half",
            row.framework
        );
    }

    server.abort();
}
