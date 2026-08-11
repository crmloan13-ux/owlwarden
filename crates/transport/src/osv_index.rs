//! File-backed OSV advisory index ([ADR 0020](../../../docs/adr/0020-offline-osv-cache.md)).
//!
//! Distinct from [`super::OsvHttpClient`]: this adapter never opens a network
//! socket. Operators build the index with `owlwarden osv update` on a connected
//! machine and commit or cache it for air-gapped CI.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use owlwarden_core::advisory::{AdvisoryClient, AdvisoryError, AdvisoryHit, PackageQuery};
use owlwarden_core::limits;
use serde::{Deserialize, Serialize};

use super::osv::OsvHttpClient;

/// On-disk index header and package map (schema version 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvIndex {
    /// Always `1` for this release.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// OSV ecosystem id, e.g. `npm`.
    pub ecosystem: String,
    /// When the index was built, RFC3339 UTC.
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    /// Package name → resolved version → advisory ids (often GHSA).
    pub packages: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl OsvIndex {
    /// Empty npm index with a fresh timestamp.
    #[must_use]
    pub fn empty_npm(updated_at: String) -> Self {
        Self {
            schema_version: 1,
            ecosystem: "npm".to_owned(),
            updated_at,
            packages: BTreeMap::new(),
        }
    }

    /// Records one advisory id for a package version (deduplicated).
    pub fn insert_id(&mut self, package: &PackageQuery, id: &str) {
        if package.ecosystem != self.ecosystem {
            return;
        }
        let id = truncate_id(id);
        if id.is_empty() {
            return;
        }
        let versions = self.packages.entry(package.name.clone()).or_default();
        let ids = versions.entry(package.version.clone()).or_default();
        if !ids.iter().any(|existing| existing == &id) {
            ids.push(id);
        }
    }
}

/// Production [`AdvisoryClient`] backed by a local index file.
#[derive(Debug)]
pub struct OsvIndexClient {
    index: OsvIndex,
}

impl OsvIndexClient {
    /// Loads and validates an on-disk index. No network.
    ///
    /// # Errors
    /// [`AdvisoryError::Refused`] when the path, size, or schema is invalid.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AdvisoryError> {
        let path = path.as_ref();
        let meta = std::fs::metadata(path).map_err(|error| AdvisoryError::Refused {
            message: format!("could not read OSV index {}: {error}", path.display()),
        })?;
        if meta.len() > limits::advisory::MAX_INDEX_BYTES {
            return Err(AdvisoryError::Refused {
                message: "OSV index file exceeds size cap".to_owned(),
            });
        }
        let bytes = std::fs::read(path).map_err(|error| AdvisoryError::Refused {
            message: format!("could not read OSV index {}: {error}", path.display()),
        })?;
        let index = parse_index_bytes(&bytes)?;
        Ok(Self { index })
    }

    /// Parses index bytes (for tests and callers that already bounded the read).
    ///
    /// # Errors
    /// [`AdvisoryError::Refused`] when the body exceeds the cap or fails validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AdvisoryError> {
        Ok(Self {
            index: parse_index_bytes(bytes)?,
        })
    }
}

#[async_trait]
impl AdvisoryClient for OsvIndexClient {
    async fn query(&self, queries: &[PackageQuery]) -> Result<Vec<AdvisoryHit>, AdvisoryError> {
        if queries.is_empty() {
            return Ok(Vec::new());
        }
        let mut hits = Vec::new();
        for query in queries.iter().take(limits::advisory::MAX_PACKAGES) {
            if query.ecosystem != self.index.ecosystem {
                continue;
            }
            let Some(versions) = self.index.packages.get(&query.name) else {
                continue;
            };
            let Some(ids) = versions.get(&query.version) else {
                continue;
            };
            for id in ids.iter().take(limits::advisory::MAX_FINDINGS) {
                if hits.len() >= limits::advisory::MAX_FINDINGS {
                    return Ok(hits);
                }
                let id = truncate_id(id);
                if id.is_empty() {
                    continue;
                }
                hits.push(AdvisoryHit {
                    id: id.clone(),
                    cve: None,
                    summary: format!(
                        "Known vulnerability {id} in {}@{}",
                        query.name, query.version
                    ),
                    package: query.clone(),
                });
            }
        }
        Ok(hits)
    }
}

/// Builds an index by querying OSV for lockfile packages (online update path).
///
/// # Errors
/// Propagates [`AdvisoryError`] from the HTTP client.
pub async fn fetch_index(
    client: &OsvHttpClient,
    queries: &[PackageQuery],
) -> Result<OsvIndex, AdvisoryError> {
    let updated_at = rfc3339_now();
    let mut index = OsvIndex::empty_npm(updated_at);
    if queries.is_empty() {
        return Ok(index);
    }
    let hits = client.query(queries).await?;
    for hit in hits {
        index.insert_id(&hit.package, &hit.id);
    }
    Ok(index)
}

/// Serializes an index to JSON, refusing when the encoded size exceeds the cap.
///
/// # Errors
/// [`AdvisoryError::Refused`] when serialization fails or the body is too large.
pub fn serialize_index(index: &OsvIndex) -> Result<Vec<u8>, AdvisoryError> {
    let body = serde_json::to_vec(index).map_err(|error| AdvisoryError::Refused {
        message: format!("could not encode OSV index: {error}"),
    })?;
    if body.len() as u64 > limits::advisory::MAX_INDEX_BYTES {
        return Err(AdvisoryError::Refused {
            message: "OSV index exceeds size cap".to_owned(),
        });
    }
    Ok(body)
}

/// Wires `--osv` / `--osv-db` / `--offline` into an advisory client.
///
/// Returns `None` when advisory lookup is not enabled. Fails closed when
/// `--osv --offline` is set without `--osv-db`.
///
/// # Errors
/// Human-readable refusal strings for the CLI / napi envelope.
pub fn prepare_advisory_client(
    osv: bool,
    osv_db: Option<&str>,
    osv_offline: bool,
) -> Result<Option<Arc<dyn AdvisoryClient>>, String> {
    let enabled = osv || osv_db.is_some();
    if !enabled {
        return Ok(None);
    }
    if osv_offline && osv_db.is_none() {
        return Err(
            "--osv --offline requires --osv-db; build an index with `owlwarden osv update`"
                .to_owned(),
        );
    }
    if let Some(path) = osv_db {
        let client = OsvIndexClient::from_file(path).map_err(|error| error.to_string())?;
        return Ok(Some(Arc::new(client)));
    }
    let client = OsvHttpClient::new().map_err(|error| error.to_string())?;
    Ok(Some(Arc::new(client)))
}

fn parse_index_bytes(bytes: &[u8]) -> Result<OsvIndex, AdvisoryError> {
    if bytes.len() as u64 > limits::advisory::MAX_INDEX_BYTES {
        return Err(AdvisoryError::Refused {
            message: "OSV index file exceeds size cap".to_owned(),
        });
    }
    let index: OsvIndex =
        serde_json::from_slice(bytes).map_err(|error| AdvisoryError::Refused {
            message: format!("OSV index was not valid JSON: {error}"),
        })?;
    if index.schema_version != 1 {
        return Err(AdvisoryError::Refused {
            message: format!(
                "OSV index schemaVersion {} is not supported (expected 1)",
                index.schema_version
            ),
        });
    }
    if index.ecosystem.is_empty() || index.ecosystem.len() > 64 {
        return Err(AdvisoryError::Refused {
            message: "OSV index ecosystem is missing or too long".to_owned(),
        });
    }
    if index.packages.len() > limits::advisory::MAX_PACKAGES {
        return Err(AdvisoryError::Refused {
            message: "OSV index package count exceeds cap".to_owned(),
        });
    }
    Ok(index)
}

fn truncate_id(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        let next = out.len() + ch.len_utf8();
        if next > 128 {
            break;
        }
        out.push(ch);
    }
    out
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn fixture_index_returns_hits_without_network() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/osv/osv-index-demo.json"
        );
        let client = OsvIndexClient::from_file(path).unwrap();
        let queries = vec![PackageQuery {
            ecosystem: "npm".to_owned(),
            name: "lodash".to_owned(),
            version: "4.17.19".to_owned(),
        }];
        let hits = futures_executor::block_on(client.query(&queries)).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits.first().unwrap().id, "GHSA-aaaa-demo");
    }

    #[test]
    fn clean_package_is_silent() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/osv/osv-index-demo.json"
        );
        let client = OsvIndexClient::from_file(path).unwrap();
        let queries = vec![PackageQuery {
            ecosystem: "npm".to_owned(),
            name: "left-pad".to_owned(),
            version: "1.0.0".to_owned(),
        }];
        let hits = futures_executor::block_on(client.query(&queries)).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn oversized_index_is_refused() {
        let len = usize::try_from(limits::advisory::MAX_INDEX_BYTES)
            .unwrap()
            .saturating_add(1);
        let mut bytes = vec![b' '; len];
        if let Some(first) = bytes.first_mut() {
            *first = b'{';
        }
        let error = OsvIndexClient::from_bytes(&bytes).unwrap_err();
        assert!(matches!(error, AdvisoryError::Refused { .. }));
    }

    #[test]
    fn serialize_respects_size_cap() {
        let mut index = OsvIndex::empty_npm("1970-01-01T00:00:00Z".to_owned());
        for i in 0..limits::advisory::MAX_PACKAGES {
            index.insert_id(
                &PackageQuery {
                    ecosystem: "npm".to_owned(),
                    name: format!("pkg-{i}"),
                    version: "1.0.0".to_owned(),
                },
                "GHSA-test",
            );
        }
        let body = serialize_index(&index).unwrap();
        assert!(body.len() as u64 <= limits::advisory::MAX_INDEX_BYTES);
    }

    #[test]
    fn prepare_offline_without_db_is_refused() {
        assert!(prepare_advisory_client(true, None, true).is_err());
    }

    #[test]
    fn hits_from_batch_can_be_merged_into_index() {
        use crate::osv::parse_batch_response;
        let body = br#"{"results":[{"vulns":[{"id":"GHSA-xyz","summary":"x","aliases":[]}]}]}"#;
        let queries = vec![PackageQuery {
            ecosystem: "npm".to_owned(),
            name: "foo".to_owned(),
            version: "1.0.0".to_owned(),
        }];
        let hits = parse_batch_response(body, &queries).unwrap();
        let mut index = OsvIndex::empty_npm("1970-01-01T00:00:00Z".to_owned());
        for hit in hits {
            index.insert_id(&hit.package, &hit.id);
        }
        let versions = index.packages.get("foo").expect("package foo");
        let ids = versions.get("1.0.0").expect("version 1.0.0");
        assert_eq!(ids, &vec!["GHSA-xyz".to_owned()]);
    }
}
