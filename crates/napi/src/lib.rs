//! The Node bridge.
//!
//! # Why the boundary is JSON
//!
//! Everything crossing this boundary is a JSON string, in both directions.
//! Mirroring the whole finding model as napi structs would create a *second*
//! definition of the report format, and two definitions drift. With one JSON
//! contract there is exactly one shape to document, one to validate (zod, on
//! the TypeScript side), and one to fuzz.
//!
//! It also keeps the ABI trivial. A prebuilt `.node` from an older release
//! loaded by a newer CLI exchanges strings, not structs, so a mismatch is a
//! schema-version check rather than undefined behaviour.
//!
//! The cost is one serialize/deserialize per scan — microseconds against a
//! multi-second analysis.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]
#![allow(clippy::needless_pass_by_value)] // napi hands us owned Strings.

use napi_derive::napi;
use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Severity};
use owlwarden_reporters::{JsonReporter, PrettyOptions};
use serde::{Deserialize, Serialize};

/// What the CLI asks for. Field names are camelCase to match the TypeScript
/// side; zod validates this before it ever reaches us, and serde validates it
/// again here — the addon does not assume its caller is our own CLI.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScanRequest {
    /// Absolute or relative path to the project root.
    project_root: String,
    /// Preset name. Unknown names are an error, never a silent fallback.
    #[serde(default = "default_preset")]
    preset: String,
    /// Drop findings below this confidence.
    #[serde(default)]
    min_confidence: Option<String>,
    /// Drop findings below this severity.
    #[serde(default)]
    min_severity: Option<String>,
}

fn default_preset() -> String {
    owlwarden_detectors::DEFAULT_PRESET.to_owned()
}

/// The envelope every call returns.
///
/// Errors are data, not exceptions: a structured `code`/`message`/`help` triple
/// survives the boundary intact, where a thrown string would have to be parsed
/// back apart by the caller (`ARCHITECTURE.md` §5).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<owlwarden_core::report::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<EngineError>,
}

/// A failure the user can act on.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EngineError {
    /// Stable machine-readable code, e.g. `E_UNKNOWN_PRESET`.
    code: &'static str,
    /// One line, written for a human.
    message: String,
    /// Where to read more.
    help: String,
}

impl Envelope {
    fn ok(report: owlwarden_core::report::Report) -> Self {
        Self {
            ok: true,
            report: Some(report),
            error: None,
        }
    }

    fn err(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            report: None,
            error: Some(EngineError {
                code,
                message: message.into(),
                help: owlwarden_core::error_url(code),
            }),
        }
    }

    /// Encodes the envelope.
    ///
    /// Serialization of our own types cannot fail; if it somehow did, a
    /// hand-written error envelope is still valid JSON, so the caller always
    /// gets something parseable.
    fn encode(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"ok":false,"error":{"code":"E_ENCODE","message":"failed to encode the report","help":"https://github.com/suthat/owlwarden/blob/main/docs/reference/errors.md#e_encode"}}"#
                .to_owned()
        })
    }
}

/// Runs a passive static scan.
///
/// Takes a JSON [`ScanRequest`] and returns a JSON envelope containing either
/// the report or a structured error. Never throws for a scan failure — only an
/// unparseable request is a JavaScript exception, because that is a programming
/// error in the caller rather than a condition the user can fix.
///
/// # Errors
/// Throws only when `request_json` is not valid JSON matching [`ScanRequest`].
#[napi]
pub fn scan(request_json: String) -> napi::Result<String> {
    let request: ScanRequest = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid scan request: {error}")))?;

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(&request.preset);
    if file_rules.is_empty() && project_rules.is_empty() {
        let known: Vec<&str> = owlwarden_detectors::PRESETS
            .iter()
            .map(|preset| preset.name)
            .collect();
        return Ok(Envelope::err(
            "E_UNKNOWN_PRESET",
            format!(
                "unknown preset {:?}; available presets are {}",
                request.preset,
                known.join(", ")
            ),
        )
        .encode());
    }

    let settings = ScanSettings {
        allow_active: false,
        min_confidence: request
            .min_confidence
            .as_deref()
            .and_then(Confidence::from_str_opt)
            .unwrap_or(Confidence::Possible),
        min_severity: request
            .min_severity
            .as_deref()
            .and_then(Severity::from_str_opt)
            .unwrap_or(Severity::Info),
        preset: request.preset.clone(),
    };

    let outcome = futures_executor::block_on(owlwarden_static::scan_project(
        &request.project_root,
        file_rules,
        project_rules,
        settings,
    ));

    Ok(match outcome {
        Ok(report) => Envelope::ok(report),
        Err(owlwarden_static::RunError::Source(error)) => Envelope::err(
            "E_PROJECT_UNREADABLE",
            format!("could not read {}: {error}", request.project_root),
        ),
        Err(owlwarden_static::RunError::Scan(error)) => {
            Envelope::err("E_SCAN_FAILED", error.to_string())
        }
    }
    .encode())
}

/// Rendering options accepted by [`render`].
///
/// The booleans are independent presentation switches that the caller has
/// already resolved from flags, `NO_COLOR`, and TTY detection; collapsing them
/// into an enum would only re-encode combinations that all occur in practice.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RenderRequest {
    /// `pretty` or `json`.
    format: String,
    #[serde(default)]
    color: bool,
    #[serde(default)]
    unicode: bool,
    #[serde(default)]
    hyperlinks: bool,
    /// Indent JSON output.
    #[serde(default)]
    pretty_json: bool,
}

/// Renders a report that was produced by [`scan`].
///
/// Rendering lives in Rust so the terminal layout has exactly one
/// implementation. A second one in TypeScript would drift from the first within
/// a release.
///
/// # Errors
/// Throws if the report or the options cannot be parsed, or if the format name
/// is not one we have.
#[napi]
pub fn render(report_json: String, options_json: String) -> napi::Result<String> {
    let report: owlwarden_core::report::Report = serde_json::from_str(&report_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid report: {error}")))?;
    let options: RenderRequest = serde_json::from_str(&options_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid render options: {error}")))?;

    match options.format.as_str() {
        "pretty" => owlwarden_reporters::render_to_string(
            &report,
            PrettyOptions {
                color: options.color,
                unicode: options.unicode,
                hyperlinks: options.hyperlinks,
            },
        )
        .map_err(|error| napi::Error::from_reason(error.to_string())),
        "json" => JsonReporter::to_string(&report, options.pretty_json)
            .map_err(|error| napi::Error::from_reason(error.to_string())),
        other => Err(napi::Error::from_reason(format!(
            "unknown format {other:?}; available: {}",
            owlwarden_reporters::AVAILABLE_FORMATS.join(", ")
        ))),
    }
}

/// The full rule catalogue as JSON.
///
/// The CLI, the docs site, and the MCP `list_rules` tool all read this, so none
/// of them can carry a stale copy of the rule list.
///
/// # Errors
/// Throws only if the catalogue cannot be encoded, which would be a bug here.
#[napi]
pub fn list_rules() -> napi::Result<String> {
    serde_json::to_string(&owlwarden_detectors::all_rule_metas())
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// The coverage table as JSON: which OWASP categories the shipped rules reach,
/// and which they do not.
///
/// Exposed to JavaScript rather than kept behind the native CLI because the
/// docs site and the MCP surface both need it, and a second hand-written copy
/// of "what do we cover" would be wrong within a release.
///
/// # Errors
/// Throws only if the table cannot be encoded, which would be a bug here.
#[napi]
pub fn coverage() -> napi::Result<String> {
    serde_json::to_string(&owlwarden_detectors::coverage_report())
        .map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// The coverage table rendered for a terminal.
///
/// Rendered in Rust so the native CLI and the Node CLI cannot drift apart in
/// how they present the same numbers.
///
/// # Errors
/// Throws if the options are not valid JSON.
#[napi]
pub fn render_coverage(options_json: String) -> napi::Result<String> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct CoverageRequest {
        #[serde(default)]
        color: bool,
        #[serde(default)]
        unicode: bool,
    }

    let options: CoverageRequest = serde_json::from_str(&options_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid coverage options: {error}")))?;

    Ok(owlwarden_reporters::coverage::render(
        &owlwarden_detectors::coverage_report(),
        owlwarden_reporters::coverage::CoverageOptions {
            color: options.color,
            unicode: options.unicode,
        },
    ))
}

/// The startup banner as a string, for the caller to write to stderr.
///
/// The addon does not print it itself. Deciding *whether* to show decoration
/// needs to know about the caller's TTY, its `--quiet`, and its output stream —
/// all of which live in the CLI. The art lives here so there is one copy of it.
///
/// # Errors
/// Throws if the options are not valid JSON.
#[napi]
pub fn banner(options_json: String) -> napi::Result<String> {
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct BannerRequest {
        #[serde(default)]
        color: bool,
        #[serde(default)]
        unicode: bool,
    }

    let options: BannerRequest = serde_json::from_str(&options_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid banner options: {error}")))?;

    let mut buffer = Vec::new();
    owlwarden_reporters::render_banner(
        &mut buffer,
        &owlwarden_reporters::BannerOpts {
            color: options.color,
            unicode: options.unicode,
            quiet: false,
        },
    )
    .map_err(|error| napi::Error::from_reason(error.to_string()))?;

    String::from_utf8(buffer).map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// The long-form write-up for one rule, as JSON: `{ meta, fixes, references }`.
///
/// Returns `null` for an unknown id rather than throwing — asking about a rule
/// that does not exist is a question, not a failure.
///
/// # Errors
/// Throws only if the explanation cannot be encoded.
#[napi]
pub fn explain_rule(rule_id: String) -> napi::Result<Option<String>> {
    owlwarden_detectors::explain(&rule_id)
        .map(|explanation| {
            serde_json::to_string(&explanation)
                .map_err(|error| napi::Error::from_reason(error.to_string()))
        })
        .transpose()
}

/// The available presets as JSON: `[{ name, description, rules }]`.
///
/// # Errors
/// Throws only if the list cannot be encoded.
#[napi]
pub fn list_presets() -> napi::Result<String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PresetInfo {
        name: &'static str,
        description: &'static str,
        rules: Vec<String>,
    }

    let presets: Vec<PresetInfo> = owlwarden_detectors::PRESETS
        .iter()
        .map(|preset| PresetInfo {
            name: preset.name,
            description: preset.description,
            // Resolved rather than listed: a preset is defined by a property of
            // a rule, so the membership is computed from the rules that exist.
            rules: owlwarden_detectors::preset_rule_ids(preset.name),
        })
        .collect();

    serde_json::to_string(&presets).map_err(|error| napi::Error::from_reason(error.to_string()))
}

/// The engine version, which is also what appears in `report.tool.version`.
#[napi]
#[must_use]
pub fn engine_version() -> String {
    owlwarden_core::ENGINE_VERSION.to_owned()
}

/// The report schema version the addon produces.
#[napi]
#[must_use]
pub fn schema_version() -> String {
    owlwarden_core::report::SCHEMA_VERSION.to_owned()
}
