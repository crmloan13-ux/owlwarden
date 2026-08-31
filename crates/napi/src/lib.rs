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
///
/// Independent presentation / trust switches; not a state machine.
#[allow(clippy::struct_excessive_bools)]
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
    /// JSON contents of a baseline file. Absent means no baseline filter.
    #[serde(default)]
    baseline_json: Option<String>,
    /// When set, write the post-suppression findings here before filtering.
    #[serde(default)]
    write_baseline: Option<String>,
    /// When false, list inline suppressions but do not hide findings.
    /// Defaults to true; the CLI sets false under `--ci` unless opted in.
    #[serde(default = "default_honor_suppressions")]
    honor_suppressions: bool,
    /// Absolute URL to probe. Operator intent only — never from project config
    /// ([ADR 0014](../../docs/adr/0014-passive-dynamic-and-correlation.md)).
    #[serde(default)]
    target: Option<String>,
    /// Extra scope allowlist entries. When empty, the target's origin is used.
    #[serde(default)]
    scope: Vec<String>,
    /// Paths to WASM plugin directories (or bare `.wasm` files with a sidecar
    /// manifest) to load alongside the first-party detectors. Operator intent
    /// only. Under `ci: true`, also requires `allow_plugins: true` — the
    /// native boundary re-checks so a caller that skips the TS CLI cannot
    /// quietly load WASM on an untrusted tree (`ARCHITECTURE.md` §6).
    #[serde(default)]
    plugins: Vec<String>,
    /// True when the operator passed `--ci` (or an equivalent trust-hostile
    /// mode). Defaults to false for local interactive use.
    #[serde(default)]
    ci: bool,
    /// Permit `plugins` when `ci` is true. Off by default.
    #[serde(default)]
    allow_plugins: bool,
    /// Refuse plugins whose detached ed25519 signature did not verify (ADR 0021).
    #[serde(default)]
    require_signed_plugins: bool,
    /// Permit state-changing HTTP methods with `--target` (`--allow-active`).
    #[serde(default)]
    allow_active: bool,
    /// Opt into Google OSV lockfile advisory lookup (`--osv`).
    #[serde(default)]
    osv: bool,
    /// Path to a cached OSV index (`--osv-db`). File-backed; no network.
    #[serde(default)]
    osv_db: Option<String>,
    /// When true with `--osv`, `--osv-db` is required ([ADR 0020](../../docs/adr/0020-offline-osv-cache.md)).
    #[serde(default)]
    osv_offline: bool,
    /// Project-relative paths that changed since the last scan (watch mode).
    #[serde(default)]
    dirty_paths: Vec<String>,
    /// Restricts the scan to these project-relative paths (`--since`,
    /// `--staged`, `--paths`). The CLI resolves a git ref into this list; the
    /// engine never runs a subprocess.
    #[serde(default)]
    scoped_paths: Vec<String>,
    /// Human-readable description of the scope, for the report header.
    #[serde(default)]
    diff_scope: Option<String>,
    /// Project-relative paths written during the current agent session.
    ///
    /// Inline suppressions in these files are listed and **not honoured**: a
    /// directive written thirty seconds ago by the thing being gated is not a
    /// decision the team made
    /// ([ADR 0026](../../docs/adr/0026-deterministic-agent-gate.md) §3).
    #[serde(default)]
    session_paths: Vec<String>,
    /// Previous report JSON for incremental merge in watch mode.
    #[serde(default)]
    previous_report_json: Option<String>,
    /// Read the user- and managed-configuration tiers (`--include-user-config`).
    ///
    /// Off by default, which is what keeps "reads stay inside the project root"
    /// true for every scan nobody explicitly opted out of it for.
    #[serde(default)]
    include_user_config: bool,
}

fn default_honor_suppressions() -> bool {
    true
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
    /// Request audit when `--allow-active` was set (method, URL, status only).
    #[serde(skip_serializing_if = "Option::is_none")]
    audit: Option<Vec<AuditLine>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditLine {
    method: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
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
            audit: None,
        }
    }

    fn ok_with_audit(report: owlwarden_core::report::Report, audit: Vec<AuditLine>) -> Self {
        Self {
            ok: true,
            report: Some(report),
            error: None,
            audit: if audit.is_empty() { None } else { Some(audit) },
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
            audit: None,
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

/// Runs a passive scan (static, and optionally a live probe).
///
/// Async + `spawn_blocking` on purpose: a sync native call blocks the Node
/// event loop, so a `--target` probe aimed at a server in the same process can
/// never complete (the loop cannot accept the connection). The Promise frees
/// the loop; the scan itself runs on a worker thread with its own Tokio
/// runtime ([`owlwarden_dynamic::run_scan`]).
///
/// Takes a JSON [`ScanRequest`] and returns a JSON envelope containing either
/// the report or a structured error. Never throws for a scan failure — only an
/// unparseable request is a JavaScript exception, because that is a programming
/// error in the caller rather than a condition the user can fix.
///
/// # Errors
/// Throws only when `request_json` is not valid JSON matching [`ScanRequest`].
#[napi]
pub async fn scan(request_json: String) -> napi::Result<String> {
    // Validate JSON on the calling thread so a bad request stays a thrown Error
    // rather than a rejected Promise of an encoded envelope — same contract as
    // the previous sync API.
    let _: ScanRequest = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid scan request: {error}")))?;

    napi::bindgen_prelude::spawn_blocking(move || scan_blocking(request_json))
        .await
        .map_err(|error| napi::Error::from_reason(format!("scan worker failed: {error}")))
}

/// Loads every plugin path the caller asked for into first-party-shaped
/// detectors.
///
/// The `--ci`/`--allow-plugins` trust decision is made by the caller before
/// `plugins` is ever populated (the native CLI decides locally; the npm CLI
/// decides in TypeScript) — this addon only loads what it is handed.
fn load_requested_plugins(
    paths: &[String],
    require_signed_plugins: bool,
    project_root: &str,
) -> Result<Vec<std::sync::Arc<dyn owlwarden_core::detector::Detector>>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let paths: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
    let options = owlwarden_plugin_host::LoadOptions {
        require_signed_plugins,
        // The operator's project, never the plugin's own directory — see
        // `LoadOptions::trust_root_dir`.
        trust_root_dir: Some(std::path::PathBuf::from(project_root)),
    };
    owlwarden_plugin_host::load_plugins_with(&paths, &options).map_err(|error| error.to_string())
}

/// Resolves `target`/`scope` into a dynamic engine, wiring it into
/// `scan_request` — extracted out of [`scan_blocking`] to stay under the
/// line cap. Takes the two fields it needs rather than the whole request so
/// a caller that has already partially moved other fields out of its own
/// request (as `scan_blocking` has, building `write_baseline`) can still
/// call this.
type LiveWire = (
    Option<std::sync::Arc<owlwarden_dynamic::DynamicEngine>>,
    Option<std::sync::Arc<owlwarden_transport::ReqwestTransport>>,
);

fn prepare_dynamic_engine(
    target: Option<&str>,
    scope: &[String],
    allow_active: bool,
    scan_request: &mut owlwarden_static::ScanRequest,
) -> Result<LiveWire, String> {
    let Some(target) = target else {
        if !scope.is_empty() {
            return Err("--scope requires --target".to_owned());
        }
        if allow_active {
            return Err("--allow-active requires --target".to_owned());
        }
        return Ok((None, None));
    };
    let live = owlwarden_dynamic::prepare_live(target, scope, allow_active)
        .map_err(|error| error.to_string())?;
    let engine = live.engine.clone();
    let http = std::sync::Arc::clone(&live.http);
    scan_request.network = Some(live.network);
    scan_request.extra_detectors.push(live.engine);
    if allow_active {
        scan_request
            .extra_detectors
            .push(owlwarden_detectors::csrf_cross_origin_post_detector(
                live.probe.url.clone(),
                live.probe.path.clone(),
            ));
    }
    scan_request.correlate = Some(owlwarden_dynamic::correlate);
    Ok((Some(engine), Some(http)))
}

/// Wires `--osv` / `--osv-db`: advisory client + the advisory detector.
fn prepare_osv(
    osv: bool,
    osv_db: Option<&str>,
    osv_offline: bool,
    scan_request: &mut owlwarden_static::ScanRequest,
) -> Result<(), String> {
    let Some(client) = owlwarden_transport::prepare_advisory_client(osv, osv_db, osv_offline)?
    else {
        return Ok(());
    };
    scan_request.advisory = Some(client);
    scan_request
        .extra_detectors
        .push(owlwarden_detectors::osv_detector());
    Ok(())
}

fn settings_from_request(request: &ScanRequest) -> ScanSettings {
    ScanSettings {
        allow_active: request.allow_active,
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
        dirty_paths: None,
        scoped_paths: if request.scoped_paths.is_empty() {
            None
        } else {
            Some(request.scoped_paths.clone())
        },
        include_user_config: request.include_user_config,
        home_override: None,
    }
}

/// Loads plugins / OSV / live stack onto `scan_request`.
///
/// On failure returns `(error_code, message)` for the envelope — not
/// [`Envelope`] itself, which is too large for a `Result` err variant.
fn wire_extras(
    request: &ScanRequest,
    scan_request: &mut owlwarden_static::ScanRequest,
) -> Result<LiveWire, (&'static str, String)> {
    if request.ci && !request.plugins.is_empty() && !request.allow_plugins {
        return Err((
            "E_PLUGIN_INVALID",
            "--plugin under --ci requires --allow-plugins; \
             omit --plugin on untrusted PRs, or pass --allow-plugins on a trusted tree"
                .to_owned(),
        ));
    }
    match load_requested_plugins(
        &request.plugins,
        request.require_signed_plugins,
        &request.project_root,
    ) {
        Ok(detectors) => scan_request.extra_detectors.extend(detectors),
        Err(message) => return Err(("E_PLUGIN_INVALID", message)),
    }
    if let Err(message) = prepare_osv(
        request.osv,
        request.osv_db.as_deref(),
        request.osv_offline,
        scan_request,
    ) {
        return Err(("E_SCAN_FAILED", message));
    }
    prepare_dynamic_engine(
        request.target.as_deref(),
        &request.scope,
        request.allow_active,
        scan_request,
    )
    .map_err(|message| ("E_TARGET_INVALID", message))
}

fn scan_blocking(request_json: String) -> String {
    let request: ScanRequest = match serde_json::from_str(&request_json) {
        Ok(request) => request,
        Err(error) => {
            return Envelope::err("E_SCAN_FAILED", format!("invalid scan request: {error}"))
                .encode();
        }
    };

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(&request.preset);
    if file_rules.is_empty() && project_rules.is_empty() {
        return Envelope::err("E_UNKNOWN_PRESET", unknown_preset_message(&request.preset)).encode();
    }

    let mut scan_request = match build_scan_request(&request) {
        Ok(built) => built,
        Err((code, message)) => return Envelope::err(code, message).encode(),
    };

    let (dynamic_engine, http) = match wire_extras(&request, &mut scan_request) {
        Ok(wired) => wired,
        Err((code, message)) => return Envelope::err(code, message).encode(),
    };

    encode_scan_drive(
        owlwarden_dynamic::run_scan(
            &request.project_root,
            file_rules,
            project_rules,
            scan_request,
            dynamic_engine,
        ),
        &request,
        http.as_deref(),
    )
}

fn unknown_preset_message(preset: &str) -> String {
    let known: Vec<&str> = owlwarden_detectors::PRESETS
        .iter()
        .map(|entry| entry.name)
        .collect();
    format!(
        "unknown preset {preset:?}; available presets are {}",
        known.join(", ")
    )
}

fn build_scan_request(
    request: &ScanRequest,
) -> Result<owlwarden_static::ScanRequest, (&'static str, String)> {
    let baseline = match request.baseline_json.as_deref() {
        Some(json) => match owlwarden_core::baseline::BaselineFile::parse(json) {
            Ok(file) => Some(file),
            Err(error) => return Err(("E_BASELINE_INVALID", error.to_string())),
        },
        None => None,
    };
    let previous_report = match request.previous_report_json.as_deref() {
        None => None,
        Some(json) => match serde_json::from_str(json) {
            Ok(report) => Some(report),
            Err(error) => {
                return Err(("E_SCAN_FAILED", format!("invalid previous report: {error}")));
            }
        },
    };
    Ok(owlwarden_static::ScanRequest {
        settings: settings_from_request(request),
        baseline,
        write_baseline: request
            .write_baseline
            .as_ref()
            .map(std::path::PathBuf::from),
        suppressions: if request.honor_suppressions {
            if request.session_paths.is_empty() {
                owlwarden_core::suppression::SuppressionPolicy::Honour
            } else {
                // The gate's posture: a directive committed last month still
                // works; one that appeared in a file written during this
                // session does not.
                owlwarden_core::suppression::SuppressionPolicy::HonourExcept(
                    request.session_paths.clone(),
                )
            }
        } else {
            owlwarden_core::suppression::SuppressionPolicy::ReportOnly
        },
        extra_detectors: Vec::new(),
        network: None,
        advisory: None,
        correlate: None,
        dirty_paths: if request.dirty_paths.is_empty() {
            None
        } else {
            Some(request.dirty_paths.clone())
        },
        diff_scope: request.diff_scope.clone(),
        previous_report,
    })
}

fn encode_scan_drive(
    result: Result<owlwarden_core::report::Report, owlwarden_dynamic::DriveError>,
    request: &ScanRequest,
    http: Option<&owlwarden_transport::ReqwestTransport>,
) -> String {
    match result {
        Ok(report) => {
            if request.allow_active {
                let audit = http
                    .map(|transport| {
                        transport
                            .audit_log()
                            .into_iter()
                            .map(|entry| AuditLine {
                                method: entry.method,
                                url: entry.url,
                                status: entry.status,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Envelope::ok_with_audit(report, audit)
            } else {
                Envelope::ok(report)
            }
        }
        Err(owlwarden_dynamic::DriveError::Run(owlwarden_static::RunError::Source(error))) => {
            Envelope::err(
                "E_PROJECT_UNREADABLE",
                format!("could not read {}: {error}", request.project_root),
            )
        }
        Err(owlwarden_dynamic::DriveError::Run(owlwarden_static::RunError::BaselineWrite {
            path,
            message,
        })) => Envelope::err(
            "E_BASELINE_WRITE",
            format!("could not write {path}: {message}"),
        ),
        Err(owlwarden_dynamic::DriveError::Run(
            owlwarden_static::RunError::InvalidDirtyPaths { message },
        )) => Envelope::err("E_SCAN_FAILED", format!("invalid dirty paths: {message}")),
        Err(error) => Envelope::err("E_SCAN_FAILED", error.to_string()),
    }
    .encode()
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
    /// `pretty`, `json`, `sarif`, or `junit`.
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
        "sarif" => if options.pretty_json {
            owlwarden_reporters::SarifReporter::to_string_pretty(&report)
        } else {
            owlwarden_reporters::SarifReporter::to_string(&report)
        }
        .map_err(|error| napi::Error::from_reason(error.to_string())),
        "junit" => owlwarden_reporters::JunitReporter::to_string(&report)
            .map_err(|error| napi::Error::from_reason(error.to_string())),
        "md" => owlwarden_reporters::MdReporter::to_string(&report)
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

/// Builds a lockfile-scoped OSV index JSON string for [`owlwarden osv update`].
///
/// Queries `api.osv.dev` with the same allowlisted client as `--osv`. Runs on a
/// worker thread with its own Tokio runtime so Node's event loop stays free.
///
/// # Errors
/// Throws when the project cannot be read, OSV refuses the lookup, or encoding fails.
#[napi]
pub async fn build_osv_index(project_root: String) -> napi::Result<String> {
    napi::bindgen_prelude::spawn_blocking(move || build_osv_index_blocking(&project_root))
        .await
        .map_err(|error| napi::Error::from_reason(format!("osv index worker failed: {error}")))?
}

fn build_osv_index_blocking(project_root: &str) -> napi::Result<String> {
    let provider = owlwarden_static::FsSourceProvider::new(project_root)
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
    let packages = owlwarden_detectors::lockfile::collect_packages(&provider);
    let mut seen = std::collections::HashSet::new();
    let mut queries = Vec::new();
    for package in packages {
        let key = (
            package.query.ecosystem.clone(),
            package.query.name.clone(),
            package.query.version.clone(),
        );
        if !seen.insert(key) {
            continue;
        }
        queries.push(package.query);
        if queries.len() >= owlwarden_core::limits::advisory::MAX_PACKAGES {
            break;
        }
    }
    let client = owlwarden_transport::OsvHttpClient::new()
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
    let index =
        match owlwarden_dynamic::block_on(owlwarden_transport::fetch_index(&client, &queries)) {
            Ok(Ok(index)) => index,
            Ok(Err(error)) => {
                return Err(napi::Error::from_reason(error.to_string()));
            }
            Err(error) => {
                return Err(napi::Error::from_reason(error.to_string()));
            }
        };
    let bytes = owlwarden_transport::serialize_index(&index)
        .map_err(|error| napi::Error::from_reason(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| napi::Error::from_reason(error.to_string()))
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

// ---------------------------------------------------------------------------
// gate
// ---------------------------------------------------------------------------

/// What the CLI asks the gate to do.
///
/// The CLI does the two things the engine must not: it reads stdin, and it runs
/// git to turn `--since` into a path list. Everything after that is here.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GateRequestJson {
    /// Adapter id: `claude-code`, `cursor`, `generic`.
    host: String,
    /// The host's event payload, verbatim from stdin.
    event: String,
    /// Project root.
    project_root: String,
    /// Paths to scan. Empty means the whole project.
    #[serde(default)]
    scoped_paths: Vec<String>,
    /// Paths written during this session.
    #[serde(default)]
    session_paths: Vec<String>,
    /// Severity at or above which the gate denies.
    #[serde(default)]
    fail_on: Option<String>,
    /// Confidence at or above which a finding counts.
    #[serde(default)]
    min_confidence: Option<String>,
    /// Whether a post-execution failure denies instead of allowing.
    #[serde(default)]
    fail_closed: bool,
    /// What the scanned project's own config asked for. Tightenings are
    /// applied; loosenings are refused and reported.
    #[serde(default)]
    project_fail_on: Option<String>,
    /// As above, for confidence.
    #[serde(default)]
    project_min_confidence: Option<String>,
    /// How hard to react to agent-surface drift: `off`, `advisory`, `strict`.
    #[serde(default)]
    seal: Option<String>,
    /// A trust root file for the seal's signature. Operator-supplied, and never
    /// a path inside the scanned tree.
    #[serde(default)]
    seal_trust_file: Option<String>,
    /// Whether an unsigned or badly-signed seal is a failure.
    #[serde(default)]
    require_signed_seal: bool,
}

/// What the gate hands back to the CLI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateResponse {
    ok: bool,
    /// Written to stdout verbatim, in the host's own shape.
    stdout: String,
    /// Written to stderr, when the developer needs to see something.
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
    /// The process exit code the host expects.
    exit_code: i32,
    /// The decision itself, for logging and for `--format json`.
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<owlwarden_gate::GateDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<EngineError>,
}

/// Resolves one host's agent configuration, with provenance per key.
///
/// The engine side of `owlwarden effective`. Values that won from outside the
/// scan root are rendered as a placeholder here exactly as they are in the
/// binary — the privacy rule lives at one choke point in the resolver, not in
/// each caller.
///
/// # Errors
/// Throws only when `request_json` is not valid JSON matching the request
/// shape, which is a programming error in the caller.
#[napi]
pub fn effective(request_json: String) -> napi::Result<String> {
    let request: EffectiveRequestJson = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid effective request: {error}")))?;

    let Ok(host) = owlwarden_core::finding::AgentHost::parse(&request.host) else {
        return Ok(encode_effective_error("unknown host"));
    };
    let policy = if request.include_user_config {
        owlwarden_static::agentws::tiers::TierPolicy::IncludeUserConfig
    } else {
        owlwarden_static::agentws::tiers::TierPolicy::ProjectOnly
    };
    let config = owlwarden_static::agentws::tiers::resolve(
        std::path::Path::new(&request.project_root),
        &host,
        policy,
    );
    let profile = owlwarden_static::agentws::tiers::profile_for(&host);

    let keys: Vec<serde_json::Value> = config
        .keys
        .iter()
        .filter(|entry| {
            request
                .key
                .as_deref()
                .is_none_or(|wanted| entry.key == wanted)
        })
        .map(|entry| {
            serde_json::json!({
                "key": entry.key,
                "value": entry.rendered_value(),
                "winner": entry.winner.as_str(),
                "winnerSource": entry.winner_source,
                "shadowsProject": entry.shadows_project(),
                "losers": entry
                    .losers
                    .iter()
                    .map(|(kind, source)| serde_json::json!({
                        "tier": kind.as_str(),
                        "source": source,
                    }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();

    let body = serde_json::json!({
        "ok": true,
        "host": host.as_str(),
        "verifiedAgainst": profile.verified_against,
        "includeUserConfig": request.include_user_config,
        "keys": keys,
        "keysOnlyAboveRoot": config.keys_only_above_root,
        "tiersRead": config
            .tiers_read
            .iter()
            .map(|(kind, source)| serde_json::json!({
                "tier": kind.as_str(),
                "source": source,
            }))
            .collect::<Vec<_>>(),
        "tiersSkipped": config
            .tiers_skipped
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
    });
    Ok(serde_json::to_string(&body).unwrap_or_else(|_| encode_effective_error("could not encode")))
}

/// The JSON shape `effective` accepts.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EffectiveRequestJson {
    /// Project root.
    project_root: String,
    /// Which host's resolution order to follow.
    host: String,
    /// Restrict the answer to one key.
    #[serde(default)]
    key: Option<String>,
    /// Also read the user and managed tiers.
    #[serde(default)]
    include_user_config: bool,
}

fn encode_effective_error(message: &str) -> String {
    serde_json::json!({ "ok": false, "error": message }).to_string()
}

/// Runs one `owlwarden seal` invocation.
///
/// The decision logic is `owlwarden_seal::command`, shared with the standalone
/// binary so the two cannot answer differently. This wrapper owns exactly the
/// two things the process owns: whether a human is present, and how to run the
/// agent-surface scan the "look behind the door" check needs.
///
/// # Errors
/// Throws only when `request_json` is not valid JSON matching the request
/// shape, which is a programming error in the caller.
#[napi]
pub async fn seal(request_json: String) -> napi::Result<String> {
    let _: SealRequestJson = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid seal request: {error}")))?;
    napi::bindgen_prelude::spawn_blocking(move || seal_blocking(&request_json))
        .await
        .map_err(|error| napi::Error::from_reason(format!("seal worker failed: {error}")))
}

/// The JSON shape `seal` accepts.
///
/// Independent switches, mirroring `SealRequest` on the other side of the
/// boundary. Folding them into an enum would mean inventing combinations the
/// command line cannot express.
#[allow(clippy::struct_excessive_bools)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealRequestJson {
    /// Project root.
    project_root: String,
    /// `write`, `verify`, `diff`, or `accept`.
    #[serde(default)]
    mode: Option<String>,
    /// Emit JSON instead of text.
    #[serde(default)]
    json: bool,
    /// Whether a human is present: a TTY, or an explicit `--yes`.
    #[serde(default)]
    attended: bool,
    /// `(fingerprint, reason)` pairs.
    #[serde(default)]
    accept: Vec<SealAcceptJson>,
    /// Trust root file for the detached signature.
    #[serde(default)]
    trust: Option<String>,
    /// Whether an unsigned or badly-signed seal is a failure.
    #[serde(default)]
    require_signed: bool,
    /// Restrict output to ASCII.
    #[serde(default)]
    ascii: bool,
}

#[derive(serde::Deserialize)]
struct SealAcceptJson {
    fingerprint: String,
    reason: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SealResponse {
    ok: bool,
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn seal_blocking(request_json: &str) -> String {
    let Ok(request) = serde_json::from_str::<SealRequestJson>(request_json) else {
        return encode_seal(&SealResponse {
            ok: false,
            stdout: String::new(),
            stderr: "error: the seal request could not be parsed\n".to_owned(),
            exit_code: 2,
        });
    };

    let outcome = owlwarden_seal::command::run(
        &owlwarden_seal::SealRequest {
            mode: match request.mode.as_deref() {
                Some("verify") => owlwarden_seal::SealMode::Verify,
                Some("diff") => owlwarden_seal::SealMode::Diff,
                Some("accept") => owlwarden_seal::SealMode::Accept,
                _ => owlwarden_seal::SealMode::Write,
            },
            json: request.json,
            attended: request.attended,
            accept: request
                .accept
                .into_iter()
                .map(|entry| (entry.fingerprint, entry.reason))
                .collect(),
            trust: request.trust.map(std::path::PathBuf::from),
            require_signed: request.require_signed,
            ascii: request.ascii,
        },
        std::path::Path::new(&request.project_root),
        &seal_scan,
    );

    encode_seal(&SealResponse {
        ok: true,
        stdout: outcome.stdout,
        stderr: outcome.stderr,
        exit_code: outcome.exit_code,
    })
}

/// One agent-surface scan for the seal's block check.
///
/// `ReportOnly` suppressions: a repository must not be able to comment its way
/// to a clean seal.
fn seal_scan(root: &std::path::Path) -> Result<owlwarden_core::report::Report, String> {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("agent-surface");
    futures_executor::block_on(owlwarden_static::runner::scan_project_with(
        root.to_path_buf(),
        file_rules,
        project_rules,
        owlwarden_static::runner::ScanRequest {
            settings: owlwarden_core::context::ScanSettings {
                allow_active: false,
                min_confidence: Confidence::Possible,
                min_severity: Severity::Info,
                preset: "agent-surface".to_owned(),
                dirty_paths: None,
                scoped_paths: None,
                // The seal records the repository's surface, not the
                // developer's: a seal that varied by whose laptop wrote it
                // would not be a shared record of anything.
                include_user_config: false,
                home_override: None,
            },
            baseline: None,
            write_baseline: None,
            suppressions: owlwarden_core::suppression::SuppressionPolicy::ReportOnly,
            extra_detectors: Vec::new(),
            network: None,
            advisory: None,
            correlate: None,
            dirty_paths: None,
            diff_scope: None,
            previous_report: None,
        },
    ))
    .map_err(|error| format!("could not scan the agent surface: {error}"))
}

fn encode_seal(response: &SealResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|_| {
        "{\"ok\":false,\"stdout\":\"\",\"stderr\":\"error: could not encode the seal response\
         \\n\",\"exitCode\":2}"
            .to_owned()
    })
}

/// Runs one gate event.
///
/// Never throws for a gate failure. A hook that throws is a hook that shows a
/// developer a stack trace in the middle of their session; the failure posture
/// (`ask` before execution, `allow` after) is the answer, and it is encoded in
/// the response like any other.
///
/// # Errors
/// Throws only when `request_json` is not valid JSON matching the request
/// shape, which is a programming error in the caller.
#[napi]
pub async fn gate(request_json: String) -> napi::Result<String> {
    let _: GateRequestJson = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid gate request: {error}")))?;

    napi::bindgen_prelude::spawn_blocking(move || gate_blocking(&request_json))
        .await
        .map_err(|error| napi::Error::from_reason(format!("gate worker failed: {error}")))
}

fn gate_blocking(request_json: &str) -> String {
    let Ok(request) = serde_json::from_str::<GateRequestJson>(request_json) else {
        return encode_gate_error("E_GATE_REQUEST", "the gate request could not be parsed");
    };

    let Some(adapter) = owlwarden_gate::adapter_for(&request.host) else {
        return encode_gate_error(
            "E_GATE_HOST",
            format!(
                "unknown --host {:?}; available: {}",
                request.host,
                owlwarden_gate::available_hosts().join(", ")
            ),
        );
    };

    let event = match adapter.parse(&request.event) {
        Ok(event) => event,
        Err(error) => {
            // An event this adapter does not recognise is not an allow. The
            // CLI cannot tell whether it preceded execution, so the safest
            // shape that still lets a session continue is `defer` with the
            // reason on stderr — the host's own permission model decides.
            let decision = owlwarden_gate::GateDecision::new(
                owlwarden_gate::Verdict::Defer,
                format!("owlwarden gate: {error}"),
            )
            .degraded();
            let encoded = adapter.encode(
                &owlwarden_gate::GateEvent::new(
                    &request.host,
                    owlwarden_gate::GateEventKind::FileEdited,
                ),
                &decision,
            );
            return encode_gate_response(&encoded, Some(decision));
        }
    };

    let policy = owlwarden_gate::GatePolicy {
        fail_on: request
            .fail_on
            .as_deref()
            .and_then(Severity::from_str_opt)
            .unwrap_or(Severity::High),
        min_confidence: request
            .min_confidence
            .as_deref()
            .and_then(Confidence::from_str_opt)
            .unwrap_or(Confidence::Likely),
        fail_closed: request.fail_closed,
        seal: request
            .seal
            .as_deref()
            .and_then(owlwarden_gate::SealPosture::from_str_opt)
            .unwrap_or_default(),
    };
    let posture = owlwarden_gate::ProjectPosture {
        fail_on: request
            .project_fail_on
            .as_deref()
            .and_then(Severity::from_str_opt),
        min_confidence: request
            .project_min_confidence
            .as_deref()
            .and_then(Confidence::from_str_opt),
    };

    // A gate scan is static-only: no transport, no live target, so the
    // lightweight executor is enough and a Tokio runtime per hook invocation
    // would be cost on a keystroke path.
    let decision = futures_executor::block_on(owlwarden_gate::run(owlwarden_gate::GateRequest {
        project_root: std::path::Path::new(&request.project_root),
        event: &event,
        scoped_paths: request.scoped_paths.clone(),
        session_paths: request.session_paths.clone(),
        policy,
        project_posture: posture,
        seal_trust_file: request.seal_trust_file.as_deref().map(std::path::Path::new),
        require_signed_seal: request.require_signed_seal,
    }));

    let encoded = adapter.encode(&event, &decision);
    encode_gate_response(&encoded, Some(decision))
}

fn encode_gate_response(
    encoded: &owlwarden_gate::Encoded,
    decision: Option<owlwarden_gate::GateDecision>,
) -> String {
    let response = GateResponse {
        ok: true,
        stdout: encoded.stdout.clone(),
        stderr: encoded.stderr.clone(),
        exit_code: encoded.exit_code,
        decision,
        error: None,
    };
    serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"ok":false,"stdout":"{}","exitCode":2}"#.to_owned())
}

fn encode_gate_error(code: &'static str, message: impl Into<String>) -> String {
    let message = message.into();
    let response = GateResponse {
        ok: false,
        // Nothing the host can act on, so nothing on stdout: an empty object is
        // valid for every adapter and asks the host to carry on.
        stdout: "{}".to_owned(),
        stderr: Some(format!("owlwarden gate: {message}")),
        // `2` is "could not run" everywhere else in the CLI.
        exit_code: 2,
        decision: None,
        error: Some(EngineError {
            code,
            message,
            help: owlwarden_core::error_url(code),
        }),
    };
    serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"ok":false,"stdout":"{}","exitCode":2}"#.to_owned())
}

/// The JSON shape [`turn`] accepts.
///
/// Both reports arrive already rendered rather than being re-scanned here: the
/// CLI is the only layer that knows how to materialise a tree at a commit, and
/// the engine's rule against executing anything means it is never going to be
/// the layer that runs git.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TurnRequest {
    /// Project root, for the surface read.
    project_root: String,
    /// The report over the base version of the changed paths.
    before_report_json: String,
    /// The report over the working-tree version of the same paths.
    after_report_json: String,
    /// What the operator asked for, e.g. `HEAD`.
    base_ref: String,
    /// What it resolved to, when git could say.
    #[serde(default)]
    base_commit: Option<String>,
    /// Files the turn touched.
    #[serde(default)]
    files_changed: u32,
    /// Wall-clock cost of the whole verdict, measured by the caller.
    #[serde(default)]
    duration_ms: u32,
    /// Severity floor.
    #[serde(default)]
    fail_on: Option<String>,
    /// Confidence floor.
    #[serde(default)]
    min_confidence: Option<String>,
    /// Exposure floor.
    #[serde(default)]
    fail_on_exposure: Option<String>,
    /// Whether to read and report the agent execution surface.
    #[serde(default)]
    surface: bool,
    /// Anything that stopped the turn from being fully answered.
    #[serde(default)]
    notes: Vec<String>,
}

/// The envelope [`turn`] returns.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TurnEnvelope {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    turn: Option<owlwarden_core::turn::TurnReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<EngineError>,
}

/// Classifies one turn: what did these changes introduce, carry, and fix.
///
/// The diff lives in `owlwarden_core::turn` so that both CLIs and any future
/// consumer reach the same verdict from the same two reports. Doing it in
/// TypeScript would have meant reimplementing the baseline fingerprint there,
/// and a second implementation of "the same finding" is a second answer.
///
/// # Errors
/// Throws only when `request_json` does not match the request shape, which is a
/// programming error in the caller. A report that will not parse comes back as
/// an error envelope, because that is a version-skew problem the user can act
/// on.
#[napi]
pub async fn turn(request_json: String) -> napi::Result<String> {
    let _: TurnRequest = serde_json::from_str(&request_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid turn request: {error}")))?;

    napi::bindgen_prelude::spawn_blocking(move || turn_blocking(&request_json))
        .await
        .map_err(|error| napi::Error::from_reason(format!("turn worker failed: {error}")))
}

fn turn_blocking(request_json: &str) -> String {
    let Ok(request) = serde_json::from_str::<TurnRequest>(request_json) else {
        return encode_turn(&TurnEnvelope {
            ok: false,
            turn: None,
            error: Some(turn_error(
                "E_TURN_REQUEST",
                "the turn request could not be parsed",
            )),
        });
    };

    let (Ok(before), Ok(after)) = (
        serde_json::from_str::<owlwarden_core::report::Report>(&request.before_report_json),
        serde_json::from_str::<owlwarden_core::report::Report>(&request.after_report_json),
    ) else {
        return encode_turn(&TurnEnvelope {
            ok: false,
            turn: None,
            error: Some(turn_error(
                "E_TURN_REPORT",
                "a report handed to the turn diff could not be read; \
                 reinstall owlwarden so the CLI and the engine come from one release",
            )),
        });
    };

    let gate = owlwarden_core::turn::TurnGate {
        fail_on: request
            .fail_on
            .as_deref()
            .and_then(Severity::from_str_opt)
            .unwrap_or(Severity::Medium),
        min_confidence: request
            .min_confidence
            .as_deref()
            .and_then(Confidence::from_str_opt)
            .unwrap_or(Confidence::Possible),
        fail_on_exposure: request
            .fail_on_exposure
            .as_deref()
            .and_then(owlwarden_core::finding::Exposure::from_str_opt),
    };

    let diff = owlwarden_core::turn::TurnDiff::between(&before.findings, &after.findings);
    let mut record = owlwarden_core::turn::TurnReport::new(
        &diff,
        owlwarden_core::turn::TurnBase {
            reference: request.base_ref,
            commit: request.base_commit,
        },
        request.files_changed,
        u64::from(request.duration_ms),
        gate,
    );
    record.notes = request.notes;

    // A truncated scan on either side means the comparison is between two sets
    // that do not know their own size, and "nothing introduced" would be a
    // claim neither report can support.
    if before.truncated || after.truncated {
        record.notes.push(
            "a scan hit the findings cap, so this turn's comparison is incomplete".to_owned(),
        );
    }

    if request.surface {
        record.surface = Some(read_surface(std::path::Path::new(&request.project_root)));
    }

    encode_turn(&TurnEnvelope {
        ok: true,
        turn: Some(record),
        error: None,
    })
}

/// The agent execution surface as it stands, and whether it has moved.
///
/// Never fails the turn: a surface that cannot be read is reported as
/// `unreadable` with zero counts, because a verdict about the *code* is still
/// worth having when the seal machinery is unavailable — and saying `sealed`
/// over a failed read would be the one lie this whole feature exists to avoid.
fn read_surface(root: &std::path::Path) -> owlwarden_core::turn::TurnSurface {
    let Ok(current) = owlwarden_seal::command::current_surface(root) else {
        return owlwarden_core::turn::TurnSurface {
            state: "unreadable".to_owned(),
            files: 0,
            hooks: 0,
            mcp_servers: 0,
            changes: Vec::new(),
        };
    };
    let count = |len: usize| u32::try_from(len).unwrap_or(u32::MAX);
    let files = count(current.files.len());
    let hooks = count(current.hooks.len());
    let mcp_servers = count(current.mcp_servers.len());

    let Ok((lock, _bytes)) = owlwarden_seal::store::load(root) else {
        return owlwarden_core::turn::TurnSurface {
            state: "unsealed".to_owned(),
            files,
            hooks,
            mcp_servers,
            changes: Vec::new(),
        };
    };

    let stamp = owlwarden_seal::extract::engine_stamp();
    let comparison = owlwarden_seal::diff::compare(&lock, &current, &stamp.catalogue_digest);
    // A reformat is reported by `seal --diff` and is not drift; repeating it on
    // every turn would train the reader to skip the line that matters.
    let changes: Vec<String> = comparison
        .changes
        .iter()
        .filter(|change| change.semantic)
        .map(|change| {
            let automatic = if change.automatic {
                " (runs automatically)"
            } else {
                ""
            };
            format!(
                "{} {}: {}{automatic}",
                change.kind.word(),
                change.category,
                change.detail
            )
        })
        .collect();

    owlwarden_core::turn::TurnSurface {
        state: if changes.is_empty() {
            "unchanged"
        } else {
            "moved"
        }
        .to_owned(),
        files,
        hooks,
        mcp_servers,
        changes,
    }
}

/// Renders a turn record.
///
/// # Errors
/// Throws if the record or the options cannot be parsed, or the format is one
/// this command does not have. `turn` deliberately offers fewer formats than
/// `scan`: a SARIF file describing one turn is a code-scanning upload that
/// overwrites the repository's real findings with a seven-file slice.
#[napi]
pub fn render_turn(turn_json: String, options_json: String) -> napi::Result<String> {
    let record: owlwarden_core::turn::TurnReport = serde_json::from_str(&turn_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid turn record: {error}")))?;
    let options: RenderRequest = serde_json::from_str(&options_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid render options: {error}")))?;

    match options.format.as_str() {
        "pretty" => owlwarden_reporters::turn::render_to_string(
            &record,
            PrettyOptions {
                color: options.color,
                unicode: options.unicode,
                hyperlinks: options.hyperlinks,
            },
        )
        .map_err(|error| napi::Error::from_reason(error.to_string())),
        "json" => if options.pretty_json {
            serde_json::to_string_pretty(&record)
        } else {
            serde_json::to_string(&record)
        }
        .map(|json| json + "\n")
        .map_err(|error| napi::Error::from_reason(error.to_string())),
        other => Err(napi::Error::from_reason(format!(
            "turn renders as pretty or json, not {other:?}"
        ))),
    }
}

fn turn_error(code: &'static str, message: &str) -> EngineError {
    EngineError {
        code,
        message: message.to_owned(),
        help: owlwarden_core::error_url(code),
    }
}

fn encode_turn(envelope: &TurnEnvelope) -> String {
    serde_json::to_string(envelope).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"E_ENCODE","message":"failed to encode the turn record","help":""}}"#
            .to_owned()
    })
}

/// Encodes a turn verdict in one host's hook shape.
///
/// # Why this reuses the gate's adapters
///
/// A Stop hook is a Stop hook. Claude Code reads `decision: "block"` with a
/// `reason`; Cursor reads its own shape; the generic adapter emits owlwarden's.
/// Those three translations already exist, are tested against each host's
/// schema, and get updated when a host changes — writing a fourth one here for
/// the turn verdict would give the project two places to be wrong about the
/// same JSON, and only one of them would get fixed.
///
/// # Errors
/// Throws when the record cannot be parsed or the host is not one we have.
#[napi]
pub fn encode_turn_hook(turn_json: String, host: String) -> napi::Result<String> {
    let record: owlwarden_core::turn::TurnReport = serde_json::from_str(&turn_json)
        .map_err(|error| napi::Error::from_reason(format!("invalid turn record: {error}")))?;
    let adapter = owlwarden_gate::adapters::adapter_for(&host).ok_or_else(|| {
        napi::Error::from_reason(format!(
            "unknown host {host:?}; available: {}",
            owlwarden_gate::adapters::available_hosts().join(", ")
        ))
    })?;

    let base = record.base.commit.as_deref().map_or_else(
        || record.base.reference.clone(),
        |commit| commit.chars().take(7).collect(),
    );

    // Only the findings that met the gate reach the model. Everything else the
    // turn introduced is in the record and on the developer's terminal; a hook
    // reason is not a report.
    let blocking: Vec<owlwarden_core::finding::Finding> = record
        .introduced
        .iter()
        .filter(|finding| {
            owlwarden_core::report::fails_gate(
                finding,
                record.gate.fail_on,
                record.gate.min_confidence,
                record.gate.fail_on_exposure,
            )
        })
        .cloned()
        .collect();

    let event = owlwarden_gate::event::GateEvent::new(
        &host,
        owlwarden_gate::event::GateEventKind::TurnBoundary,
    );
    let decision = if blocking.is_empty() {
        owlwarden_gate::decision::GateDecision::new(
            owlwarden_gate::decision::Verdict::Allow,
            format!(
                "owlwarden: nothing introduced at or above {} since {base}",
                record.gate.fail_on.as_str()
            ),
        )
    } else {
        owlwarden_gate::decision::GateDecision::new(
            owlwarden_gate::decision::Verdict::Deny,
            owlwarden_gate::policy::turn_reason(&blocking, record.counts.carried, &base),
        )
        .with_findings(blocking)
    };

    let encoded = adapter.encode(&event, &decision);
    serde_json::to_string(&serde_json::json!({
        "stdout": encoded.stdout,
        "stderr": encoded.stderr,
        "exitCode": encoded.exit_code,
    }))
    .map_err(|error| napi::Error::from_reason(error.to_string()))
}
