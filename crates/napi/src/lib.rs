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
    /// Previous report JSON for incremental merge in watch mode.
    #[serde(default)]
    previous_report_json: Option<String>,
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
) -> Result<Vec<std::sync::Arc<dyn owlwarden_core::detector::Detector>>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let paths: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
    let options = owlwarden_plugin_host::LoadOptions {
        require_signed_plugins,
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
    match load_requested_plugins(&request.plugins, request.require_signed_plugins) {
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
        honor_suppressions: request.honor_suppressions,
        extra_detectors: Vec::new(),
        network: None,
        advisory: None,
        correlate: None,
        dirty_paths: if request.dirty_paths.is_empty() {
            None
        } else {
            Some(request.dirty_paths.clone())
        },
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
