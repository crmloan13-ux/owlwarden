//! The guest ABI: the one import a plugin gets, and everything the host
//! checks before trusting what comes through it.
//!
//! v0.2 ships source-only detectors, so exactly one host function is wired —
//! `owlwarden::emit_finding`. There is no clock, no filesystem, no network,
//! and no WASI: a plugin's only way to affect anything outside its own linear
//! memory is this one call, and this file is where every claim it makes is
//! checked against the plugin's own manifest before it becomes a [`Finding`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{Confidence, Finding, Location, SourceLocation};
use owlwarden_core::limits::plugin as limits;
use owlwarden_core::source::RelPath;
use serde::Deserialize;
use wasmtime::{Caller, Extern, Linker, StoreLimits};

use crate::error::PluginError;

/// One claim submitted through `emit_finding`, before it is checked against
/// anything.
///
/// Every field is untrusted: it came from inside the sandbox. Parsing it into
/// this struct is the *only* trust this data gets — `HostState::try_emit`
/// still has to look up `rule_id` in the plugin's own manifest and normalize
/// `path` through [`RelPath`] before any of it reaches a [`Finding`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuestFinding {
    rule_id: String,
    path: String,
    #[serde(default = "one")]
    line: u32,
    #[serde(default = "one")]
    col: u32,
    #[serde(default)]
    why: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
}

const fn one() -> u32 {
    1
}

/// Per-invocation store data: the memory limiter plus everything
/// `emit_finding` needs to validate and collect a claim.
pub struct HostState {
    /// Enforces [`limits::MAX_MEMORY_BYTES`]. Public to this crate only so
    /// `detector.rs` can wire `Store::limiter` onto it.
    pub(crate) limits: StoreLimits,
    rules: Arc<HashMap<String, DetectorMeta>>,
    findings: Vec<Finding>,
    host_calls: u32,
}

impl HostState {
    /// Builds fresh per-invocation state.
    ///
    /// `rules` is the plugin's own declared rule set — the only ids
    /// `emit_finding` will accept — keyed by rule id for an O(1) check on
    /// every call.
    #[must_use]
    pub fn new(rules: Arc<HashMap<String, DetectorMeta>>, limits: StoreLimits) -> Self {
        Self {
            limits,
            rules,
            findings: Vec::new(),
            host_calls: 0,
        }
    }

    /// Consumes the state and returns whatever findings were accepted.
    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }

    /// Host calls made so far, accepted or not. Exposed for the sandbox-escape
    /// tests; the cap itself is enforced in [`add_emit_finding`].
    #[must_use]
    pub fn host_calls(&self) -> u32 {
        self.host_calls
    }

    /// Validates one claim and, if it checks out, appends a [`Finding`].
    ///
    /// Returns whether it was accepted. Rejection is silent from the guest's
    /// point of view — malformed JSON, an unknown rule id, a path that
    /// escapes the project root, or having already hit
    /// [`limits::MAX_FINDINGS_PER_INVOCATION`] are all just "no", not a trap.
    /// A plugin misbehaving on one call must not cost it every call after.
    fn try_emit(&mut self, raw: &[u8]) -> bool {
        if self.findings.len() >= limits::MAX_FINDINGS_PER_INVOCATION {
            return false;
        }
        let Ok(claim) = serde_json::from_slice::<GuestFinding>(raw) else {
            return false;
        };
        let Some(meta) = self.rules.get(claim.rule_id.as_str()) else {
            return false;
        };
        let Ok(rel_path) = RelPath::new(Path::new(&claim.path)) else {
            return false;
        };

        // A plugin cannot claim more confidence than its own manifest
        // declared as its ceiling — the same rule `DetectorMeta::max_confidence`
        // enforces for first-party rules (`ARCHITECTURE.md` §5), applied here
        // because nothing upstream of this function checks it for a plugin.
        let confidence = claim
            .confidence
            .as_deref()
            .and_then(Confidence::from_str_opt)
            .unwrap_or(Confidence::Possible)
            .min(meta.max_confidence);

        // Cap free text so a guest cannot shove the source snapshot into the
        // report as an exfil channel (payload size alone still allows many KiB).
        let why = claim.why.unwrap_or_default();
        if why.len() > limits::MAX_WHY_BYTES {
            return false;
        }

        let mut builder = Finding::builder(meta.id.clone(), meta.severity, meta.title.clone())
            .confidence(confidence)
            .why(why)
            .location(Location::Source(SourceLocation {
                path: rel_path.as_str().to_owned(),
                line: claim.line.max(1),
                col: claim.col.max(1),
            }));
        if let Some(owasp) = &meta.owasp {
            builder = builder.owasp(owasp.clone());
        }
        if let Some(cwe) = meta.cwe {
            builder = builder.cwe(cwe);
        }
        self.findings.push(builder.build());
        true
    }
}

/// Wires the one import a plugin gets: `owlwarden::emit_finding(ptr, len) -> i32`.
///
/// Returns `1` if the finding was accepted, `0` otherwise. Both are
/// successful calls from wasm's point of view — the guest is not told *why*
/// a claim was rejected, so there is no oracle here for probing what the host
/// would accept.
///
/// # Errors
/// [`PluginError::AbiMismatch`] only if defining the import itself fails,
/// which happens only if the name is already taken in this linker — it does
/// not happen in normal use of this crate.
pub fn add_emit_finding(
    linker: &mut Linker<HostState>,
    plugin_id: &str,
) -> Result<(), PluginError> {
    linker
        .func_wrap(
            "owlwarden",
            "emit_finding",
            move |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> wasmtime::Result<i32> {
                if caller.data().host_calls >= limits::MAX_HOST_CALLS {
                    // A flood that costs the host a validation per call is
                    // bounded independently of how cheap it is for the guest
                    // to keep asking — trap rather than keep saying no.
                    anyhow::bail!("exceeded {} calls to emit_finding", limits::MAX_HOST_CALLS);
                }
                caller.data_mut().host_calls += 1;

                if ptr < 0 || len < 0 || (len as usize) > limits::MAX_FINDING_JSON_BYTES {
                    return Ok(0);
                }
                let len = usize::try_from(len).unwrap_or(0);
                let ptr = usize::try_from(ptr).unwrap_or(0);

                let Some(memory) = caller.get_export("memory").and_then(Extern::into_memory) else {
                    anyhow::bail!("plugin has no exported memory");
                };

                let mut buf = vec![0u8; len];
                if memory.read(&caller, ptr, &mut buf).is_err() {
                    return Ok(0);
                }

                Ok(i32::from(caller.data_mut().try_emit(&buf)))
            },
        )
        .map_err(|error| PluginError::AbiMismatch {
            id: plugin_id.to_owned(),
            reason: error.to_string(),
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use owlwarden_core::finding::{RuleId, Severity};
    use wasmtime::StoreLimitsBuilder;

    use super::*;

    fn rules() -> Arc<HashMap<String, DetectorMeta>> {
        let mut map = HashMap::new();
        map.insert(
            "demo-rule".to_owned(),
            DetectorMeta {
                id: RuleId::new_static("demo-rule"),
                title: "Demo".into(),
                severity: Severity::Medium,
                max_confidence: Confidence::Likely,
                owasp: None,
                cwe: None,
                category: "demo".into(),
                description: "demo".into(),
            },
        );
        Arc::new(map)
    }

    fn state() -> HostState {
        HostState::new(rules(), StoreLimitsBuilder::new().build())
    }

    #[test]
    fn a_well_formed_claim_for_a_declared_rule_is_accepted() {
        let mut state = state();
        let json =
            br#"{"ruleId":"demo-rule","path":"src/index.ts","line":3,"col":1,"why":"because"}"#;
        assert!(state.try_emit(json));
        let findings = state.into_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id.as_str(), "demo-rule");
        assert_eq!(findings[0].why, "because");
    }

    #[test]
    fn an_undeclared_rule_id_is_rejected_silently() {
        let mut state = state();
        let json = br#"{"ruleId":"not-mine","path":"src/index.ts"}"#;
        assert!(!state.try_emit(json));
        assert!(state.into_findings().is_empty());
    }

    #[test]
    fn a_path_that_escapes_the_project_root_is_rejected() {
        let mut state = state();
        let json = br#"{"ruleId":"demo-rule","path":"../../etc/passwd"}"#;
        assert!(!state.try_emit(json));
        assert!(state.into_findings().is_empty());
    }

    #[test]
    fn confidence_cannot_exceed_the_rules_own_ceiling() {
        let mut state = state();
        // demo-rule's max_confidence is Likely; the guest asks for Confirmed.
        let json = br#"{"ruleId":"demo-rule","path":"a.ts","confidence":"confirmed"}"#;
        assert!(state.try_emit(json));
        let findings = state.into_findings();
        assert_eq!(findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn malformed_json_is_rejected_not_panicked_on() {
        let mut state = state();
        assert!(!state.try_emit(b"not json"));
        assert!(state.into_findings().is_empty());
    }

    #[test]
    fn the_per_invocation_cap_stops_accepting_after_the_limit() {
        let mut state = state();
        let json = br#"{"ruleId":"demo-rule","path":"a.ts"}"#;
        for _ in 0..limits::MAX_FINDINGS_PER_INVOCATION {
            assert!(state.try_emit(json));
        }
        assert!(!state.try_emit(json), "the cap must stop accepting");
        assert_eq!(
            state.into_findings().len(),
            limits::MAX_FINDINGS_PER_INVOCATION
        );
    }
}
