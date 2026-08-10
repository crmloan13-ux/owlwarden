//! Allowlisted Google OSV advisory client ([ADR 0016](../../../docs/adr/0016-osv-advisory-lookup.md)).
//!
//! Distinct from [`crate::ReqwestTransport`]: this adapter may only speak HTTPS
//! to `api.osv.dev`, never shares `--target` scope, and never sends source.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use owlwarden_core::advisory::{AdvisoryClient, AdvisoryError, AdvisoryHit, PackageQuery};
use owlwarden_core::limits;
use reqwest::Client;
use reqwest::redirect::Policy;
use serde::Deserialize;

/// Only host this adapter will contact.
const OSV_HOST: &str = "api.osv.dev";
/// `QueryBatch` endpoint (HTTPS, fixed path).
const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// Production [`AdvisoryClient`] for Google OSV.
pub struct OsvHttpClient {
    client: Client,
}

impl OsvHttpClient {
    /// Builds a client that may only call `api.osv.dev` over HTTPS.
    ///
    /// Redirects are disabled: a 3xx is a refusal, never followed, so a
    /// compromised or misconfigured hop cannot move traffic off-host.
    ///
    /// # Errors
    /// [`AdvisoryError::Refused`] when the underlying HTTP client cannot be built.
    pub fn new() -> Result<Self, AdvisoryError> {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(limits::advisory::TIMEOUT)
            .user_agent(concat!("owlwarden/", env!("CARGO_PKG_VERSION")))
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|error| AdvisoryError::Refused {
                message: format!("could not build OSV HTTP client: {error}"),
            })?;
        Ok(Self { client })
    }
}

#[async_trait]
impl AdvisoryClient for OsvHttpClient {
    async fn query(&self, queries: &[PackageQuery]) -> Result<Vec<AdvisoryHit>, AdvisoryError> {
        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let mut hits = Vec::new();
        let mut batches = queries.chunks(limits::advisory::MAX_BATCH_SIZE).peekable();
        while let Some(chunk) = batches.next() {
            let batch = self.query_batch(chunk).await?;
            hits.extend(batch);
            if hits.len() >= limits::advisory::MAX_FINDINGS {
                hits.truncate(limits::advisory::MAX_FINDINGS);
                break;
            }
            // Small gap between batches so a large lockfile does not slam the
            // public API; first batch is immediate.
            if batches.peek().is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        Ok(hits)
    }
}

impl OsvHttpClient {
    async fn query_batch(
        &self,
        queries: &[PackageQuery],
    ) -> Result<Vec<AdvisoryHit>, AdvisoryError> {
        let body = build_querybatch_body(queries)?;
        if body.len() as u64 > limits::advisory::MAX_BODY_BYTES {
            return Err(AdvisoryError::Refused {
                message: "OSV request body exceeds size cap".to_owned(),
            });
        }

        let response = self
            .client
            .post(OSV_QUERYBATCH_URL)
            .timeout(limits::advisory::TIMEOUT)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|error| map_reqwest(error, limits::advisory::TIMEOUT))?;

        ensure_osv_response(&response)?;

        let status = response.status();
        if !status.is_success() {
            // Drop the body — do not buffer an error page into the report.
            drop(response);
            return Err(AdvisoryError::Lookup {
                message: format!("OSV returned HTTP {status}"),
            });
        }

        let bytes = read_body(response, limits::advisory::MAX_BODY_BYTES).await?;
        parse_batch_response(&bytes, queries)
    }
}

fn build_querybatch_body(queries: &[PackageQuery]) -> Result<Vec<u8>, AdvisoryError> {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        queries: Vec<Query<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Query<'a> {
        package: Package<'a>,
        version: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Package<'a> {
        ecosystem: &'a str,
        name: &'a str,
    }

    let payload = Body {
        queries: queries
            .iter()
            .map(|query| Query {
                package: Package {
                    ecosystem: query.ecosystem.as_str(),
                    name: query.name.as_str(),
                },
                version: query.version.as_str(),
            })
            .collect(),
    };
    serde_json::to_vec(&payload).map_err(|error| AdvisoryError::Refused {
        message: format!("could not encode OSV query: {error}"),
    })
}

fn ensure_osv_response(response: &reqwest::Response) -> Result<(), AdvisoryError> {
    let url = response.url();
    if url.scheme() != "https" {
        return Err(AdvisoryError::Refused {
            message: "OSV response was not HTTPS".to_owned(),
        });
    }
    let host = url.host_str().unwrap_or("");
    if host != OSV_HOST {
        return Err(AdvisoryError::Refused {
            message: format!("OSV response host {host:?} is not allowlisted"),
        });
    }
    if response.status().is_redirection() {
        return Err(AdvisoryError::Refused {
            message: "OSV redirected; redirects are not followed".to_owned(),
        });
    }
    Ok(())
}

fn map_reqwest(error: reqwest::Error, timeout: Duration) -> AdvisoryError {
    if error.is_timeout() {
        return AdvisoryError::Lookup {
            message: format!("OSV request timed out after {}s", timeout.as_secs()),
        };
    }
    AdvisoryError::Lookup {
        message: error.without_url().to_string(),
    }
}

async fn read_body(response: reqwest::Response, max_bytes: u64) -> Result<Vec<u8>, AdvisoryError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| AdvisoryError::Lookup {
            message: error.without_url().to_string(),
        })?;
        let remaining = max_bytes.saturating_sub(body.len() as u64);
        if remaining == 0 {
            return Err(AdvisoryError::Refused {
                message: "OSV response exceeds size cap".to_owned(),
            });
        }
        if (chunk.len() as u64) > remaining {
            return Err(AdvisoryError::Refused {
                message: "OSV response exceeds size cap".to_owned(),
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    #[serde(default)]
    results: Vec<BatchResult>,
}

#[derive(Debug, Deserialize)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<BatchVuln>,
}

#[derive(Debug, Deserialize)]
struct BatchVuln {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    aliases: Vec<String>,
}

/// Parses a `QueryBatch` JSON body into hits aligned with `queries`.
///
/// Public for unit tests; the HTTP adapter is the only production caller.
///
/// # Errors
/// [`AdvisoryError::Refused`] when the body exceeds the size cap;
/// [`AdvisoryError::Lookup`] when the JSON is invalid.
pub fn parse_batch_response(
    body: &[u8],
    queries: &[PackageQuery],
) -> Result<Vec<AdvisoryHit>, AdvisoryError> {
    if body.len() as u64 > limits::advisory::MAX_BODY_BYTES {
        return Err(AdvisoryError::Refused {
            message: "OSV response exceeds size cap".to_owned(),
        });
    }
    let parsed: BatchResponse =
        serde_json::from_slice(body).map_err(|error| AdvisoryError::Lookup {
            message: format!("OSV response was not valid JSON: {error}"),
        })?;

    let mut hits = Vec::new();
    for (index, result) in parsed.results.into_iter().take(queries.len()).enumerate() {
        let Some(package) = queries.get(index).cloned() else {
            break;
        };
        for vuln in result
            .vulns
            .into_iter()
            .take(limits::advisory::MAX_FINDINGS)
        {
            if hits.len() >= limits::advisory::MAX_FINDINGS {
                return Ok(hits);
            }
            let id = truncate_chars(&vuln.id, 128);
            if id.is_empty() {
                continue;
            }
            let cve = vuln
                .aliases
                .into_iter()
                .find(|alias| alias.starts_with("CVE-"))
                .map(|alias| truncate_chars(&alias, 64));
            let summary = {
                let raw = if vuln.summary.trim().is_empty() {
                    format!(
                        "Known vulnerability {id} in {}@{}",
                        package.name, package.version
                    )
                } else {
                    vuln.summary
                };
                truncate_summary(&raw)
            };
            hits.push(AdvisoryHit {
                id,
                cve,
                summary,
                package: package.clone(),
            });
        }
    }
    Ok(hits)
}

fn truncate_summary(value: &str) -> String {
    truncate_chars(
        &sanitize_advisory_text(value),
        limits::advisory::MAX_SUMMARY_BYTES,
    )
}

/// Strips C0/C1 controls and ANSI escapes from advisory prose before it enters
/// a finding — same posture as plugin-host / MCP text sanitisation.
fn sanitize_advisory_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| {
            let code = *ch as u32;
            // Allow tab/newline/carriage-return as ordinary whitespace; drop
            // everything else below 0x20 and the C1 range 0x7f–0x9f.
            *ch == '\t'
                || *ch == '\n'
                || *ch == '\r'
                || (code >= 0x20 && code != 0x7f && !(0x80..=0x9f).contains(&code))
        })
        .collect()
}

fn truncate_chars(value: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        let next = out.len() + ch.len_utf8();
        if next > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn query(name: &str, version: &str) -> PackageQuery {
        PackageQuery {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn parse_maps_vulns_to_queries_in_order() {
        let body = br#"{
          "results": [
            {"vulns":[{"id":"GHSA-aaaa","summary":"bad lodash","aliases":["CVE-2021-23337"]}]},
            {"vulns":[]}
          ]
        }"#;
        let queries = vec![query("lodash", "4.17.19"), query("left-pad", "1.0.0")];
        let hits = parse_batch_response(body, &queries).unwrap();
        assert_eq!(hits.len(), 1);
        let hit = hits.first().unwrap();
        assert_eq!(hit.id, "GHSA-aaaa");
        assert_eq!(hit.cve.as_deref(), Some("CVE-2021-23337"));
        assert_eq!(hit.package.name, "lodash");
        assert!(hit.summary.contains("bad lodash"));
    }

    #[test]
    fn empty_summary_gets_a_fallback() {
        let body = br#"{"results":[{"vulns":[{"id":"GHSA-bbbb","aliases":[]}]}]}"#;
        let hits = parse_batch_response(body, &[query("foo", "1.0.0")]).unwrap();
        assert_eq!(hits.len(), 1);
        let hit = hits.first().unwrap();
        assert!(hit.summary.contains("GHSA-bbbb"));
        assert!(hit.summary.contains("foo@1.0.0"));
    }

    #[test]
    fn summary_is_capped() {
        let huge = "A".repeat(limits::advisory::MAX_SUMMARY_BYTES + 80);
        let body =
            format!(r#"{{"results":[{{"vulns":[{{"id":"GHSA-cccc","summary":"{huge}"}}]}}]}}"#);
        let hits = parse_batch_response(body.as_bytes(), &[query("bar", "2.0.0")]).unwrap();
        assert_eq!(
            hits.first().unwrap().summary.len(),
            limits::advisory::MAX_SUMMARY_BYTES
        );
    }

    #[test]
    fn summary_strips_control_and_ansi() {
        let body = br#"{"results":[{"vulns":[{"id":"GHSA-dddd","summary":"bad\u001b[31mred\u0000null"}]}]}"#;
        let hits = parse_batch_response(body, &[query("evil", "1.0.0")]).unwrap();
        let summary = &hits.first().unwrap().summary;
        assert!(!summary.contains('\u{001b}'));
        assert!(!summary.contains('\0'));
        assert!(summary.contains("bad"));
        assert!(summary.contains("red"));
    }

    #[test]
    fn oversized_body_is_refused() {
        let len = usize::try_from(limits::advisory::MAX_BODY_BYTES)
            .unwrap()
            .saturating_add(1);
        let mut body = vec![b' '; len];
        if let Some(first) = body.first_mut() {
            *first = b'{';
        }
        let error = parse_batch_response(&body, &[]).unwrap_err();
        assert!(matches!(error, AdvisoryError::Refused { .. }));
    }

    #[test]
    fn invalid_json_is_a_lookup_error() {
        let error = parse_batch_response(b"not-json", &[]).unwrap_err();
        assert!(matches!(error, AdvisoryError::Lookup { .. }));
    }

    #[test]
    fn querybatch_body_only_sends_name_version_ecosystem() {
        let body = build_querybatch_body(&[query("lodash", "4.17.19")]).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("\"ecosystem\":\"npm\""));
        assert!(text.contains("\"name\":\"lodash\""));
        assert!(text.contains("\"version\":\"4.17.19\""));
        assert!(!text.contains("source"));
        assert!(!text.contains("path"));
    }
}
