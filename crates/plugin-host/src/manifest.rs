//! `owlwarden.plugin.json` — parsed once, validated at the boundary, and
//! turned into the same [`DetectorMeta`] a first-party rule would build.
//!
//! Everything in this module treats the manifest as hostile input: unknown
//! fields are rejected (`deny_unknown_fields`), every string has a length
//! cap before it can be allocated further, and rule ids go through the exact
//! [`RuleId::parse`] a config-supplied id would.

use std::borrow::Cow;
use std::collections::HashMap;

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{Confidence, OwaspRef, RuleId, Severity};
use owlwarden_core::limits::plugin as limits;
use serde::Deserialize;

use crate::capability::ManifestCapabilities;
use crate::error::PluginError;

/// The only `schemaVersion` this host understands. Bumping it is a breaking
/// change to the plugin ABI and belongs in an ADR, not a patch release.
pub const SCHEMA_VERSION: u32 = 1;

/// Plugin id and version string length cap. Generous for a slug or a semver
/// string, tight enough that neither can be used to smuggle a large
/// allocation through a manifest field.
const MAX_ID_BYTES: usize = 64;
const MAX_VERSION_BYTES: usize = 32;
/// Cap for the free-text fields: title, category, description, and the OWASP
/// reference string. `RULES.md`-style prose fits comfortably under this.
const MAX_TEXT_BYTES: usize = 4_096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawManifest {
    schema_version: u64,
    id: String,
    version: String,
    #[serde(default)]
    capabilities: ManifestCapabilities,
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRule {
    id: String,
    title: String,
    severity: Severity,
    max_confidence: Confidence,
    #[serde(default)]
    owasp: Option<String>,
    #[serde(default)]
    cwe: Option<u32>,
    category: String,
    description: String,
}

/// One rule a plugin contributes.
///
/// A thin wrapper around [`DetectorMeta`] today; kept as its own type because
/// a future manifest field that applies per-rule but is not part of the
/// public catalogue (a guest-side rule index, say) has somewhere to live
/// without widening `DetectorMeta` itself.
#[derive(Debug, Clone)]
pub struct PluginRule {
    /// The rule's stable, public metadata.
    pub meta: DetectorMeta,
}

/// A parsed, validated `owlwarden.plugin.json`.
#[derive(Debug, Clone)]
pub struct PluginManifest {
    /// The plugin's own id (distinct from any of its rule ids).
    pub id: String,
    /// Free-form version string, e.g. `"0.1.0"`. Not parsed as semver: this
    /// host does no compatibility resolution on it, only display.
    pub version: String,
    /// What the plugin asked for.
    pub capabilities: ManifestCapabilities,
    /// The rules it contributes. Never empty — [`Self::parse`] refuses a
    /// manifest that declares none.
    pub rules: Vec<PluginRule>,
}

impl PluginManifest {
    /// Parses and validates a manifest already read into memory.
    ///
    /// `path` is used only to make error messages point somewhere; the caller
    /// is responsible for bounding the number of bytes read
    /// ([`limits::MAX_MANIFEST_BYTES`]) before calling this.
    ///
    /// # Errors
    /// [`PluginError`] if the JSON does not match the documented shape, the
    /// schema version is not [`SCHEMA_VERSION`], a capability is refused, a
    /// field exceeds its length cap, or a rule id fails
    /// [`RuleId::parse`].
    pub fn parse(json: &str, path: &str) -> Result<Self, PluginError> {
        let raw: RawManifest =
            serde_json::from_str(json).map_err(|error| PluginError::ManifestInvalid {
                path: path.to_owned(),
                message: error.to_string(),
            })?;

        if raw.schema_version != u64::from(SCHEMA_VERSION) {
            return Err(PluginError::UnsupportedSchemaVersion {
                path: path.to_owned(),
                found: raw.schema_version,
                expected: SCHEMA_VERSION,
            });
        }

        validate_id(&raw.id)?;
        let version = bounded(raw.version, "version", MAX_VERSION_BYTES)?;
        raw.capabilities.ensure_supported(&raw.id)?;

        if raw.rules.is_empty() {
            return Err(PluginError::NoRules { id: raw.id });
        }
        if raw.rules.len() > limits::MAX_RULES_PER_PLUGIN {
            return Err(PluginError::TooManyRules {
                id: raw.id,
                found: raw.rules.len(),
                max: limits::MAX_RULES_PER_PLUGIN,
            });
        }

        let rules = raw
            .rules
            .into_iter()
            .map(build_rule)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            id: raw.id,
            version,
            capabilities: raw.capabilities,
            rules,
        })
    }

    /// Rule metadata keyed by rule id — what `emit_finding` validates claims
    /// against, and what a `WasmDetector` reports through
    /// [`owlwarden_core::coverage`].
    #[must_use]
    pub fn rule_map(&self) -> HashMap<String, DetectorMeta> {
        self.rules
            .iter()
            .map(|rule| (rule.meta.id.as_str().to_owned(), rule.meta.clone()))
            .collect()
    }
}

fn build_rule(raw: RawRule) -> Result<PluginRule, PluginError> {
    let id = RuleId::parse(&raw.id).map_err(|source| PluginError::InvalidRuleId {
        id: raw.id.clone(),
        source,
    })?;
    let title = bounded(raw.title, "rules[].title", MAX_TEXT_BYTES)?;
    let category = bounded(raw.category, "rules[].category", MAX_TEXT_BYTES)?;
    let description = bounded(raw.description, "rules[].description", MAX_TEXT_BYTES)?;
    let owasp = raw
        .owasp
        .map(|value| bounded(value, "rules[].owasp", MAX_TEXT_BYTES))
        .transpose()?
        .map(|value| OwaspRef(Cow::Owned(value)));

    Ok(PluginRule {
        meta: DetectorMeta {
            id,
            title: Cow::Owned(title),
            severity: raw.severity,
            max_confidence: raw.max_confidence,
            owasp,
            cwe: raw.cwe,
            category: Cow::Owned(category),
            description: Cow::Owned(description),
        },
    })
}

/// Same charset as [`RuleId`]: a plugin id ends up in paths and log lines, so
/// it gets the same restricted alphabet rather than a second, looser rule.
fn validate_id(id: &str) -> Result<(), PluginError> {
    if id.is_empty() {
        return Err(PluginError::InvalidPluginId {
            id: id.to_owned(),
            reason: "empty".to_owned(),
        });
    }
    if id.len() > MAX_ID_BYTES {
        return Err(PluginError::InvalidPluginId {
            id: id.to_owned(),
            reason: format!("longer than {MAX_ID_BYTES} bytes"),
        });
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(PluginError::InvalidPluginId {
            id: id.to_owned(),
            reason: format!("contains {bad:?}; allowed characters are a-z, 0-9 and '-'"),
        });
    }
    Ok(())
}

fn bounded(value: String, field: &'static str, max: usize) -> Result<String, PluginError> {
    if value.len() > max {
        return Err(PluginError::FieldTooLong {
            field: field.to_owned(),
            len: value.len(),
            max,
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn valid_manifest() -> String {
        r#"{
            "schemaVersion": 1,
            "id": "demo-plugin",
            "version": "0.1.0",
            "capabilities": { "source": true, "network": false, "active": false },
            "rules": [
                {
                    "id": "demo-rule",
                    "title": "Demo finding",
                    "severity": "medium",
                    "maxConfidence": "likely",
                    "owasp": "A05:2021",
                    "cwe": 200,
                    "category": "demo",
                    "description": "A demonstration rule."
                }
            ]
        }"#
        .to_owned()
    }

    #[test]
    fn a_well_formed_manifest_parses() {
        let manifest = PluginManifest::parse(&valid_manifest(), "owlwarden.plugin.json").unwrap();
        assert_eq!(manifest.id, "demo-plugin");
        assert_eq!(manifest.rules.len(), 1);
        assert_eq!(manifest.rules[0].meta.id.as_str(), "demo-rule");
        assert_eq!(manifest.rules[0].meta.cwe, Some(200));
    }

    #[test]
    fn unknown_fields_are_rejected_rather_than_ignored() {
        let json = valid_manifest().replace(
            "\"version\": \"0.1.0\",",
            "\"version\": \"0.1.0\", \"extra\": true,",
        );
        assert!(PluginManifest::parse(&json, "p").is_err());
    }

    #[test]
    fn an_unsupported_schema_version_is_refused() {
        let json = valid_manifest().replace("\"schemaVersion\": 1", "\"schemaVersion\": 99");
        let error = PluginManifest::parse(&json, "p").unwrap_err();
        assert!(matches!(
            error,
            PluginError::UnsupportedSchemaVersion {
                found: 99,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn network_capability_refuses_the_whole_plugin() {
        let json = valid_manifest().replace("\"network\": false", "\"network\": true");
        let error = PluginManifest::parse(&json, "p").unwrap_err();
        assert!(matches!(
            error,
            PluginError::UnsupportedCapability {
                capability: "network",
                ..
            }
        ));
    }

    #[test]
    fn a_manifest_with_no_rules_is_refused() {
        let json = valid_manifest().replace(
            r#"[
                {
                    "id": "demo-rule",
                    "title": "Demo finding",
                    "severity": "medium",
                    "maxConfidence": "likely",
                    "owasp": "A05:2021",
                    "cwe": 200,
                    "category": "demo",
                    "description": "A demonstration rule."
                }
            ]"#,
            "[]",
        );
        assert!(matches!(
            PluginManifest::parse(&json, "p"),
            Err(PluginError::NoRules { .. })
        ));
    }

    #[test]
    fn an_invalid_rule_id_is_rejected() {
        let json = valid_manifest().replace("\"demo-rule\"", "\"Demo Rule!\"");
        assert!(matches!(
            PluginManifest::parse(&json, "p"),
            Err(PluginError::InvalidRuleId { .. })
        ));
    }

    #[test]
    fn a_plugin_id_outside_the_ruleid_charset_is_rejected() {
        let json = valid_manifest().replace("\"demo-plugin\"", "\"Demo Plugin\"");
        assert!(matches!(
            PluginManifest::parse(&json, "p"),
            Err(PluginError::InvalidPluginId { .. })
        ));
    }

    #[test]
    fn an_oversized_description_is_rejected_before_it_is_stored() {
        let huge = "x".repeat(MAX_TEXT_BYTES + 1);
        let json = valid_manifest().replace("A demonstration rule.", &huge);
        assert!(matches!(
            PluginManifest::parse(&json, "p"),
            Err(PluginError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn too_many_rules_is_rejected() {
        let rule = r#"{
            "id": "demo-rule",
            "title": "Demo finding",
            "severity": "medium",
            "maxConfidence": "likely",
            "category": "demo",
            "description": "A demonstration rule."
        }"#;
        // Distinct ids so the count, not a duplicate-id check, is what fires.
        let rules: Vec<String> = (0..=limits::MAX_RULES_PER_PLUGIN)
            .map(|i| rule.replace("demo-rule", &format!("demo-rule-{i}")))
            .collect();
        let json = format!(
            r#"{{
                "schemaVersion": 1,
                "id": "demo-plugin",
                "version": "0.1.0",
                "rules": [{}]
            }}"#,
            rules.join(",")
        );
        assert!(matches!(
            PluginManifest::parse(&json, "p"),
            Err(PluginError::TooManyRules { .. })
        ));
    }
}
