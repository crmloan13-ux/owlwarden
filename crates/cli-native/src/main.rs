//! The standalone `owlwarden` binary.
//!
//! Same engine as the npm package, no Node required — useful in a container, in
//! a pre-commit hook, and for anyone who would rather not install a JavaScript
//! toolchain to run a security scanner.
//!
//! Exit codes are a documented contract (`docs/how-to/ci.md`):
//! `0` clean · `1` findings at or above `--fail-on` · `2` the scan could not run.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic)]

mod cli;
mod git;

use std::io::{IsTerminal, Write};

use owlwarden_core::context::ScanSettings;
use owlwarden_core::report::Report;
use owlwarden_core::untrusted_text;
use owlwarden_reporters::{BannerOpts, PrettyOptions, print_banner};

use cli::{Command, ScanArgs};

/// Caps for the three repository-controlled strings in the suppression listing.
///
/// A path and a rule id both have their own length limits well under these, so
/// in practice the caps only ever fire on a reason — which is capped at parse
/// time too, and is capped again here because the report may have come from a
/// file rather than from this process.
const MAX_SUPPRESSION_PATH_CHARS: usize = 200;
const MAX_SUPPRESSION_RULE_CHARS: usize = 80;
const MAX_SUPPRESSION_REASON_CHARS: usize = 280;

/// Exit code when the scan ran and found nothing to fail on.
const EXIT_CLEAN: i32 = 0;
/// Exit code when findings met the `--fail-on` threshold.
const EXIT_FINDINGS: i32 = 1;
/// Exit code when the scan could not run at all.
const EXIT_ERROR: i32 = 2;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let command = match cli::parse(&args) {
        Ok(command) => command,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "error: {error}\n\nRun `owlwarden --help`."
            );
            return exit(EXIT_ERROR);
        }
    };

    let code = match command {
        Command::Help => {
            print!("{}", cli::help_text());
            EXIT_CLEAN
        }
        Command::Version => {
            println!("owlwarden {}", owlwarden_core::ENGINE_VERSION);
            EXIT_CLEAN
        }
        Command::Rules { json } => run_rules(json),
        Command::Coverage {
            json,
            no_color,
            ascii,
        } => run_coverage(json, no_color, ascii),
        Command::Explain { rule, json } => run_explain(&rule, json),
        Command::Scan(args) | Command::Vet(args) => run_scan(&args),
        Command::Gate {
            host,
            path,
            fail_on,
            min_confidence,
            since,
            seal,
            seal_trust,
            require_signed_seal,
        } => run_gate(&GateInvocation {
            host: &host,
            path: &path,
            fail_on,
            min_confidence,
            since: since.as_deref(),
            seal,
            seal_trust: seal_trust.as_deref(),
            require_signed_seal,
        }),
        Command::Seal(args) => run_seal(&args),
        Command::Effective {
            path,
            host,
            key,
            json,
            include_user_config,
            ascii,
        } => run_effective(
            &path,
            &host,
            key.as_deref(),
            json,
            include_user_config,
            ascii,
        ),
        Command::Watch(args) => run_watch(&args),
        Command::OsvUpdate { path, out } => run_osv_update(&path, out.as_deref()),
    };

    exit(code)
}

fn exit(code: i32) -> std::process::ExitCode {
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(2))
}

/// Reports a failure the user can act on, and returns the error exit code.
fn fail(message: &str) -> i32 {
    let _ = writeln!(std::io::stderr(), "error: {message}");
    EXIT_ERROR
}

/// Whether colour should be used, given the environment and the flags.
///
/// `NO_COLOR` is honoured unconditionally: it is a user preference, not a hint.
fn use_color(no_color: bool) -> bool {
    !no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn run_scan(args: &ScanArgs) -> i32 {
    run_scan_inner(args, None).0
}

/// Runs one gate event: read the host's payload from stdin, scan what it names,
/// decide, and write the host's own shape back.
///
/// Never returns the error code for a *gate* failure. A hook that fails hard
/// shows the developer a stack trace mid-session and leaves the host with no
/// verdict; the failure posture — `ask` before execution, `allow` after — is
/// the answer, and it is chosen in `owlwarden_gate::decide` rather than here.
struct GateInvocation<'a> {
    host: &'a str,
    path: &'a str,
    fail_on: Option<owlwarden_core::finding::Severity>,
    min_confidence: Option<owlwarden_core::finding::Confidence>,
    since: Option<&'a str>,
    seal: owlwarden_gate::SealPosture,
    seal_trust: Option<&'a str>,
    require_signed_seal: bool,
}

fn run_gate(invocation: &GateInvocation<'_>) -> i32 {
    use std::io::Read as _;

    let GateInvocation {
        host,
        path,
        fail_on,
        min_confidence,
        since,
        seal,
        seal_trust,
        require_signed_seal,
    } = *invocation;

    let Some(adapter) = owlwarden_gate::adapter_for(host) else {
        return fail(&format!(
            "unknown --host {host:?}; available: {}",
            owlwarden_gate::available_hosts().join(", ")
        ));
    };

    let mut payload = String::new();
    if let Err(error) = std::io::stdin()
        .take(owlwarden_gate::event::MAX_EVENT_BYTES as u64)
        .read_to_string(&mut payload)
    {
        return fail(&format!("could not read the event from stdin: {error}"));
    }

    let event = match adapter.parse(payload.trim()) {
        Ok(event) => event,
        Err(error) => {
            // Not an allow. The host's own permission model is left to decide,
            // and the developer sees why on stderr.
            let decision = owlwarden_gate::GateDecision::new(
                owlwarden_gate::Verdict::Defer,
                format!("owlwarden gate: {error}"),
            )
            .degraded();
            let fallback =
                owlwarden_gate::GateEvent::new(host, owlwarden_gate::GateEventKind::FileEdited);
            return emit_gate(&*adapter, &fallback, &decision);
        }
    };

    // A turn boundary names nothing, so the scope is the diff. Any other event
    // carries its own paths, and widening them here would undo the narrowing
    // the host asked for.
    let scoped_paths = since
        .and_then(|reference| {
            git::resolve_scope(path, Some(reference), false, &[])
                .ok()
                .flatten()
        })
        .map(|scope| scope.paths)
        .unwrap_or_default();

    let policy = owlwarden_gate::GatePolicy {
        fail_on: fail_on.unwrap_or(owlwarden_core::finding::Severity::High),
        min_confidence: min_confidence.unwrap_or(owlwarden_core::finding::Confidence::Likely),
        // Off by default: the default should be the one that keeps people from
        // removing the hook.
        fail_closed: std::env::var("OWLWARDEN_GATE_FAIL").is_ok_and(|value| value == "closed"),
        seal,
    };

    let decision =
        match owlwarden_dynamic::block_on(owlwarden_gate::run(owlwarden_gate::GateRequest {
            project_root: std::path::Path::new(path),
            event: &event,
            scoped_paths,
            session_paths: git::session_paths(path),
            policy,
            // The native CLI does not read the project's owlwarden config for a
            // gate at all, which is the strictest reading of the tighten-only
            // rule: nothing in the tree can move the threshold in either
            // direction.
            project_posture: owlwarden_gate::ProjectPosture::default(),
            seal_trust_file: seal_trust.map(std::path::Path::new),
            require_signed_seal,
        })) {
            Ok(decision) => decision,
            Err(error) => owlwarden_gate::GateDecision::new(
                owlwarden_gate::Verdict::Ask,
                format!("owlwarden gate could not run: {error}"),
            )
            .degraded(),
        };

    emit_gate(&*adapter, &event, &decision)
}

/// Runs `owlwarden seal`.
///
/// The decision logic lives in `owlwarden_seal::command` so the npm CLI and
/// this binary cannot answer differently. What is left here is the two things
/// this process owns: whether a human is present, and how to run a scan.
fn run_seal(args: &cli::SealArgs) -> i32 {
    let request = owlwarden_seal::SealRequest {
        mode: match args.mode {
            cli::SealMode::Write => owlwarden_seal::SealMode::Write,
            cli::SealMode::Verify => owlwarden_seal::SealMode::Verify,
            cli::SealMode::Diff => owlwarden_seal::SealMode::Diff,
            cli::SealMode::Accept => owlwarden_seal::SealMode::Accept,
        },
        json: args.json,
        // `--yes` or a real terminal. Nothing else counts as a human.
        attended: args.yes || std::io::stdin().is_terminal(),
        accept: args.accept.clone(),
        trust: args.trust.as_ref().map(std::path::PathBuf::from),
        require_signed: args.require_signed,
        ascii: args.ascii,
    };
    let outcome = owlwarden_seal::command::run(
        &request,
        std::path::Path::new(&args.path),
        &scan_agent_surface,
    );
    if !outcome.stdout.is_empty() {
        let _ = write!(std::io::stdout(), "{}", outcome.stdout);
    }
    if !outcome.stderr.is_empty() {
        let _ = write!(std::io::stderr(), "{}", outcome.stderr);
    }
    outcome.exit_code
}

/// One agent-surface scan, for the seal's "look behind the door" check.
///
/// `ReportOnly` suppressions: a repository must not be able to comment its way
/// to a clean seal.
fn scan_agent_surface(root: &std::path::Path) -> Result<Report, String> {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("agent-surface");
    let outcome = owlwarden_dynamic::block_on(owlwarden_static::runner::scan_project_with(
        root.to_path_buf(),
        file_rules,
        project_rules,
        owlwarden_static::runner::ScanRequest {
            settings: ScanSettings {
                allow_active: false,
                min_confidence: owlwarden_core::finding::Confidence::Possible,
                min_severity: owlwarden_core::finding::Severity::Info,
                preset: "agent-surface".to_owned(),
                dirty_paths: None,
                scoped_paths: None,
                // The seal records the repository's surface, not the
                // developer's. A key shadowed on this machine is still shipped
                // to the next reader, and a seal that varied by whose laptop
                // wrote it would not be a shared record of anything.
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
    ));
    match outcome {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(format!("could not scan the agent surface: {error}")),
        Err(error) => Err(format!("could not scan the agent surface: {error}")),
    }
}

/// Runs `owlwarden effective`.
///
/// A diagnostic, not a check: it always exits 0 when it could run at all.
/// "Which of these four files is deciding my agent's behaviour" has no good
/// answer in any tool today — developers debug it by deleting files — and the
/// answer is not a pass or a fail.
fn run_effective(
    path: &str,
    host: &str,
    key: Option<&str>,
    json: bool,
    include_user_config: bool,
    ascii: bool,
) -> i32 {
    use owlwarden_static::agentws::tiers::{self, TierPolicy};

    let Ok(host) = owlwarden_core::finding::AgentHost::parse(host) else {
        return fail("unknown --host");
    };
    let policy = if include_user_config {
        TierPolicy::IncludeUserConfig
    } else {
        TierPolicy::ProjectOnly
    };
    let config = tiers::resolve(std::path::Path::new(path), &host, policy);
    let profile = tiers::profile_for(&host);
    let selected: Vec<&tiers::ResolvedKey> = config
        .keys
        .iter()
        .filter(|entry| key.is_none_or(|wanted| entry.key == wanted))
        .collect();

    let rendered = if json {
        match serde_json::to_string_pretty(&effective_json(
            &host,
            &profile,
            &config,
            &selected,
            include_user_config,
        )) {
            Ok(text) => text,
            Err(error) => return fail(&error.to_string()),
        }
    } else {
        effective_text(&host, &profile, &config, &selected, ascii)
    };
    let _ = writeln!(std::io::stdout(), "{rendered}");
    0
}

/// The machine-readable rendering.
fn effective_json(
    host: &owlwarden_core::finding::AgentHost,
    profile: &owlwarden_static::agentws::tiers::AgentHostProfile,
    config: &owlwarden_static::agentws::tiers::EffectiveConfig,
    selected: &[&owlwarden_static::agentws::tiers::ResolvedKey],
    include_user_config: bool,
) -> serde_json::Value {
    serde_json::json!({
        "host": host.as_str(),
        "verifiedAgainst": profile.verified_against,
        "includeUserConfig": include_user_config,
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
        // Counted, never named: a key only a tier above the root sets is a line
        // of the developer's own configuration.
        "keysOnlyAboveRoot": config.keys_only_above_root,
        "keys": selected
            .iter()
            .map(|entry| serde_json::json!({
                "key": entry.key,
                // The single choke point for the privacy rule: a value that won
                // from outside the root renders as a placeholder here exactly
                // as it does in the text output.
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
            }))
            .collect::<Vec<_>>(),
    })
}

/// The provenance table a human reads.
fn effective_text(
    host: &owlwarden_core::finding::AgentHost,
    profile: &owlwarden_static::agentws::tiers::AgentHostProfile,
    config: &owlwarden_static::agentws::tiers::EffectiveConfig,
    selected: &[&owlwarden_static::agentws::tiers::ResolvedKey],
    ascii: bool,
) -> String {
    use owlwarden_static::agentws::tiers::TierKind;
    use std::fmt::Write as _;

    let mut out = format!(
        "\n{} effective configuration · {}  (order verified against {})\n\n",
        owlwarden_reporters::banner::owl_mark(!ascii),
        host.as_str(),
        profile.verified_against
    );
    if selected.is_empty() {
        out.push_str("  (nothing resolved)\n");
    }
    for entry in selected {
        let _ = writeln!(
            out,
            "  {:<28}{}",
            untrusted_text::one_line(&entry.key, 26),
            entry.rendered_value()
        );
        let _ = writeln!(
            out,
            "  {:<28}✓ {}  ({})",
            "",
            entry.winner_source,
            entry.winner.as_str()
        );
        for (kind, source) in &entry.losers {
            let note = if entry.shadows_project() && *kind == TierKind::Project {
                "shadowed"
            } else {
                "lost"
            };
            let _ = writeln!(out, "  {:<28}✗ {source}  ({}, {note})", "", kind.as_str());
        }
        out.push('\n');
    }
    if config.keys_only_above_root > 0 {
        let _ = writeln!(
            out,
            "  {} key(s) set only above this project, not listed — their names are the \
             developer's configuration, not this repository's",
            config.keys_only_above_root
        );
    }
    if !config.tiers_skipped.is_empty() {
        let skipped: Vec<&str> = config
            .tiers_skipped
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        let _ = writeln!(
            out,
            "  not opened: {} — pass --include-user-config to resolve against them",
            skipped.join(", ")
        );
    }
    out
}

/// Writes an encoded decision and returns the host's exit code.
fn emit_gate(
    adapter: &dyn owlwarden_gate::HostAdapter,
    event: &owlwarden_gate::GateEvent,
    decision: &owlwarden_gate::GateDecision,
) -> i32 {
    let encoded = adapter.encode(event, decision);
    let _ = writeln!(std::io::stdout(), "{}", encoded.stdout);
    if let Some(message) = &encoded.stderr {
        let _ = writeln!(std::io::stderr(), "{message}");
    }
    encoded.exit_code
}

/// Optional incremental inputs for watch re-scans.
struct IncrementalHint {
    dirty_paths: Vec<String>,
    previous_report: Report,
}

/// Runs a scan and returns the exit code plus the report when the scan completed.
fn run_scan_inner(args: &ScanArgs, incremental: Option<IncrementalHint>) -> (i32, Option<Report>) {
    let color = use_color(args.no_color);
    print_banner(&BannerOpts {
        color,
        unicode: !args.ascii,
        quiet: args.quiet || args.format != "pretty",
    });

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(&args.preset);
    if file_rules.is_empty() && project_rules.is_empty() {
        return (fail(&unknown_preset_message(&args.preset)), None);
    }

    if let Err(code) = ci_scan_gates(args) {
        return (code, None);
    }
    note_ci_suppressions(args);

    let mut scan_request = match build_scan_request(args, incremental) {
        Ok(request) => request,
        Err(message) => return (fail(&message), None),
    };

    let dynamic_engine = match prepare_dynamic_engine(args, &mut scan_request) {
        Ok(engine) => engine,
        Err(message) => return (fail(&message), None),
    };

    let report = match owlwarden_dynamic::run_scan(
        &args.path,
        file_rules,
        project_rules,
        scan_request,
        dynamic_engine,
    ) {
        Ok(report) => report,
        Err(error) => return (fail(&error.to_string()), None),
    };

    finish_scan_report(args, &report, color)
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

fn note_ci_suppressions(args: &ScanArgs) {
    // stderr even under `--ci --quiet` — stdout stays one JSON object.
    if args.ci && !args.allow_suppressions {
        let _ = writeln!(
            std::io::stderr(),
            "note: --ci ignores inline suppressions\n  \
             pass --allow-suppressions on a trusted tree"
        );
    }
}

fn build_scan_request(
    args: &ScanArgs,
    incremental: Option<IncrementalHint>,
) -> Result<owlwarden_static::ScanRequest, String> {
    let baseline = load_baseline(args.baseline.as_deref())?;
    let (dirty_paths, previous_report) = match incremental {
        Some(hint) => (Some(hint.dirty_paths), Some(hint.previous_report)),
        None => (None, None),
    };
    let scope = git::resolve_scope(&args.path, args.since.as_deref(), args.staged, &args.paths)?;
    let mut scan_request = owlwarden_static::ScanRequest {
        settings: ScanSettings {
            allow_active: args.allow_active,
            min_confidence: args.min_confidence,
            min_severity: owlwarden_core::finding::Severity::Info,
            preset: args.preset.clone(),
            dirty_paths: None,
            scoped_paths: scope.as_ref().map(|scope| scope.paths.clone()),
            include_user_config: args.include_user_config,
            home_override: None,
        },
        baseline,
        write_baseline: args.write_baseline.as_ref().map(std::path::PathBuf::from),
        suppressions: if !args.ci || args.allow_suppressions {
            owlwarden_core::suppression::SuppressionPolicy::Honour
        } else {
            owlwarden_core::suppression::SuppressionPolicy::ReportOnly
        },
        extra_detectors: Vec::new(),
        network: None,
        advisory: None,
        correlate: None,
        dirty_paths,
        diff_scope: scope.map(|scope| scope.label),
        previous_report,
    };
    scan_request.extra_detectors.extend(load_requested_plugins(
        &args.plugins,
        args.require_signed_plugins,
        std::path::Path::new(&args.path),
    )?);
    prepare_osv(
        args.osv,
        args.osv_db.as_deref(),
        args.offline,
        &mut scan_request,
    )?;
    Ok(scan_request)
}

fn finish_scan_report(args: &ScanArgs, report: &Report, color: bool) -> (i32, Option<Report>) {
    if args.write_baseline.is_some() && !args.quiet {
        let _ = writeln!(
            std::io::stderr(),
            "wrote baseline to {}",
            args.write_baseline.as_deref().unwrap_or("")
        );
    }
    if let Err(error) = write_report(args, report, color) {
        return (fail(&error), None);
    }
    if args.report_suppressions {
        write_suppressions(report);
    }
    let exit = if report.should_fail_with(args.fail_on, args.min_confidence, args.fail_on_exposure)
    {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    };
    (exit, Some(report.clone()))
}

/// Resolves `--target`/`--scope` into a dynamic engine, wiring it into
/// `scan_request` as `run_scan` did inline before this was extracted to stay
/// under the line cap.
fn prepare_dynamic_engine(
    args: &ScanArgs,
    scan_request: &mut owlwarden_static::ScanRequest,
) -> Result<Option<std::sync::Arc<owlwarden_dynamic::DynamicEngine>>, String> {
    let Some(target) = args.target.as_deref() else {
        if !args.scope.is_empty() {
            return Err("--scope requires --target".to_owned());
        }
        return Ok(None);
    };
    let live = owlwarden_dynamic::prepare_live(target, &args.scope, args.allow_active)
        .map_err(|error| error.to_string())?;
    let engine = live.engine.clone();
    scan_request.network = Some(live.network);
    scan_request.extra_detectors.push(live.engine);
    if args.allow_active {
        scan_request
            .extra_detectors
            .push(owlwarden_detectors::csrf_cross_origin_post_detector(
                live.probe.url.clone(),
                live.probe.path.clone(),
            ));
    }
    scan_request.correlate = Some(owlwarden_dynamic::correlate);
    Ok(Some(engine))
}

/// Wires `--osv` / `--osv-db`: advisory client + the advisory detector.
fn prepare_osv(
    osv: bool,
    osv_db: Option<&str>,
    offline: bool,
    scan_request: &mut owlwarden_static::ScanRequest,
) -> Result<(), String> {
    let Some(client) = owlwarden_transport::prepare_advisory_client(osv, osv_db, offline)? else {
        return Ok(());
    };
    scan_request.advisory = Some(client);
    scan_request
        .extra_detectors
        .push(owlwarden_detectors::osv_detector());
    Ok(())
}

/// Loads every plugin path from `--plugin` into first-party-shaped detectors.
///
/// A separate function (rather than inlining this in `run_scan`) both keeps
/// that function under the line cap and gives the napi bridge, which needs
/// the identical conversion, a symmetrical shape to mirror.
fn load_requested_plugins(
    paths: &[String],
    require_signed_plugins: bool,
    project_root: &std::path::Path,
) -> Result<Vec<std::sync::Arc<dyn owlwarden_core::detector::Detector>>, String> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let paths: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
    let options = owlwarden_plugin_host::LoadOptions {
        require_signed_plugins,
        // The operator's project, never the plugin's own directory — see
        // `LoadOptions::trust_root_dir`.
        trust_root_dir: Some(project_root.to_path_buf()),
    };
    owlwarden_plugin_host::load_plugins_with(&paths, &options).map_err(|error| error.to_string())
}

/// CI trust gates that must pass before a scan runs.
fn ci_scan_gates(args: &ScanArgs) -> Result<(), i32> {
    if args.ci && args.baseline.is_some() && !args.allow_baseline {
        return Err(fail(
            "--baseline under --ci requires --allow-baseline\n  \
             omit --baseline on untrusted PRs, or pass --allow-baseline on a trusted tree",
        ));
    }

    if args.ci && !args.plugins.is_empty() && !args.allow_plugins {
        return Err(fail(
            "--plugin under --ci requires --allow-plugins\n  \
             omit --plugin on untrusted PRs, or pass --allow-plugins on a trusted tree",
        ));
    }

    Ok(())
}

fn run_osv_update(project_root: &str, out: Option<&str>) -> i32 {
    let default_out = std::path::Path::new(project_root).join(".owlwarden/osv-index.json");
    let out_path = out.map_or(default_out, std::path::PathBuf::from);

    let provider = match owlwarden_static::FsSourceProvider::new(project_root) {
        Ok(provider) => provider,
        Err(error) => return fail(&error.to_string()),
    };
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

    let client = match owlwarden_transport::OsvHttpClient::new() {
        Ok(client) => client,
        Err(error) => return fail(&error.to_string()),
    };
    let index =
        match owlwarden_dynamic::block_on(owlwarden_transport::fetch_index(&client, &queries)) {
            Ok(Ok(index)) => index,
            Ok(Err(error)) => return fail(&error.to_string()),
            Err(error) => return fail(&error.to_string()),
        };
    let bytes = match owlwarden_transport::serialize_index(&index) {
        Ok(bytes) => bytes,
        Err(error) => return fail(&error.to_string()),
    };

    // Same nofollow write path as the npm CLI — do not follow a planted symlink
    // at the destination (or a symlinked parent) into an attacker-chosen file.
    if let Err(error) = owlwarden_static::safe_io::write_replacing(&out_path, &bytes) {
        return fail(&format!("could not write {}: {error}", out_path.display()));
    }

    let _ = writeln!(
        std::io::stderr(),
        "wrote OSV index ({} packages queried) to {}",
        queries.len(),
        out_path.display()
    );
    EXIT_CLEAN
}

fn load_baseline(
    path: Option<&str>,
) -> Result<Option<owlwarden_core::baseline::BaselineFile>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = owlwarden_static::read_bounded(
        std::path::Path::new(path),
        owlwarden_core::baseline::MAX_BASELINE_BYTES as u64,
    )
    .map_err(|error| format!("could not read baseline {path}: {error}"))?;
    let json = String::from_utf8(bytes)
        .map_err(|_| format!("could not read baseline {path}: not valid UTF-8"))?;
    owlwarden_core::baseline::BaselineFile::parse(&json)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn write_suppressions(report: &Report) {
    // stderr so `--format json` on stdout stays one parseable object.
    let mut err = std::io::stderr();
    if report.suppressions.is_empty() {
        let _ = writeln!(err, "No inline suppressions found.");
        return;
    }
    let _ = writeln!(err, "\n{} suppression(s)", report.suppressions.len());
    for record in &report.suppressions {
        // Missing-reason directives never hide a finding; do not call them "active".
        let flags = if record.missing_reason {
            "missing-reason"
        } else if record.stale {
            "stale"
        } else {
            "active"
        };
        // Every string on these two lines comes out of the scanned repository:
        // the reason is a comment somebody wrote, and a path is a filename,
        // which on every platform this runs on may contain an escape byte.
        // `--report-suppressions` exists so a reviewer can audit what a tree has
        // silenced, and `\x1b[2K\x1b[1A\x1b[2K` in a reason erased the entry
        // above it — deleting a line from the audit, from inside the audit.
        let reason = if record.reason.is_empty() {
            "(no reason)".to_owned()
        } else {
            untrusted_text::one_line(&record.reason, MAX_SUPPRESSION_REASON_CHARS)
        };
        let _ = writeln!(
            err,
            "  {}:{}  {}  [{}]",
            untrusted_text::one_line(&record.path, MAX_SUPPRESSION_PATH_CHARS),
            record.line,
            untrusted_text::one_line(&record.rule, MAX_SUPPRESSION_RULE_CHARS),
            flags
        );
        let _ = writeln!(err, "    {reason}");
    }
}

/// Polls the project tree and re-scans when anything changes.
///
/// No watcher crate: a security tool's install footprint is part of its
/// argument, and a half-second poll is enough for an editor save loop.
fn run_watch(args: &ScanArgs) -> i32 {
    if args.target.is_some() || !args.scope.is_empty() {
        return fail(
            "watch is static-only; omit --target / --scope (re-probing on every \
             save is hostile to the developer's own server)",
        );
    }

    let mut watch_args = ScanArgs {
        // Watch owns its own incrementality (ADR 0023); a diff scope on top
        // would narrow every re-scan to the first diff and quietly stop
        // reporting anything else.
        since: None,
        staged: false,
        paths: Vec::new(),
        budget: args.budget,
        max_findings: args.max_findings,
        include_user_config: args.include_user_config,
        vet: args.vet,
        path: args.path.clone(),
        preset: args.preset.clone(),
        format: args.format.clone(),
        fail_on: args.fail_on,
        fail_on_exposure: args.fail_on_exposure,
        min_confidence: args.min_confidence,
        out: args.out.clone(),
        baseline: args.baseline.clone(),
        write_baseline: args.write_baseline.clone(),
        report_suppressions: args.report_suppressions,
        ci: args.ci,
        allow_suppressions: args.allow_suppressions,
        allow_baseline: args.allow_baseline,
        no_color: args.no_color,
        ascii: args.ascii,
        quiet: true,
        hyperlinks: args.hyperlinks,
        target: None,
        scope: Vec::new(),
        plugins: args.plugins.clone(),
        allow_plugins: args.allow_plugins,
        require_signed_plugins: args.require_signed_plugins,
        allow_active: false,
        // Re-querying OSV on every save would hammer the API and the developer's
        // network; watch stays offline. Use a one-shot `scan --osv` instead.
        osv: false,
        osv_db: None,
        offline: false,
    };

    let (_exit, mut previous_report) = run_scan_inner(&watch_args, None);
    // Write the baseline at most once — see the TS watch command.
    watch_args.write_baseline = None;
    let _ = writeln!(
        std::io::stderr(),
        "watching {} — press Ctrl+C to stop",
        args.path
    );

    let root = std::path::Path::new(&args.path);
    let mut previous_snapshot = tree_snapshot(root);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let current = tree_snapshot(root);
        if current != previous_snapshot {
            let dirty_paths = diff_snapshots(&previous_snapshot, &current);
            previous_snapshot = current;
            let _ = writeln!(std::io::stderr(), "\n— re-scan —");
            let hint = previous_report.as_ref().map(|previous| IncrementalHint {
                dirty_paths,
                previous_report: previous.clone(),
            });
            let (_exit, report) = run_scan_inner(&watch_args, hint);
            if report.is_some() {
                previous_report = report;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileSnapshot {
    mtime: u64,
    size: u64,
}

/// Relative path → mtime/size for incremental dirty detection.
fn tree_snapshot(root: &std::path::Path) -> std::collections::HashMap<String, FileSnapshot> {
    let mut snapshot = std::collections::HashMap::new();
    walk_snapshot(root, root, 0, &mut snapshot);
    snapshot
}

fn walk_snapshot(
    root: &std::path::Path,
    dir: &std::path::Path,
    depth: usize,
    snapshot: &mut std::collections::HashMap<String, FileSnapshot>,
) {
    if depth > 8 || snapshot.len() >= owlwarden_core::limits::incremental::MAX_DIRTY_PATHS * 4 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten().take(512) {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(
            name.as_ref(),
            "node_modules" | ".git" | "target" | "dist" | "build" | ".next" | ".nuxt"
        ) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            walk_snapshot(root, &path, depth + 1, snapshot);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs());
        let rel = path
            .strip_prefix(root)
            .map(|relative| relative.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if rel.is_empty() {
            continue;
        }
        snapshot.insert(
            rel,
            FileSnapshot {
                mtime,
                size: meta.len(),
            },
        );
    }
}

fn diff_snapshots(
    previous: &std::collections::HashMap<String, FileSnapshot>,
    current: &std::collections::HashMap<String, FileSnapshot>,
) -> Vec<String> {
    let mut dirty = Vec::new();
    for (path, snap) in current {
        match previous.get(path) {
            Some(prev) if prev == snap => {}
            _ => dirty.push(path.clone()),
        }
    }
    for path in previous.keys() {
        if !current.contains_key(path) {
            dirty.push(path.clone());
        }
    }
    dirty.truncate(owlwarden_core::limits::incremental::MAX_DIRTY_PATHS);
    dirty
}

/// Renders the report to stdout or to `--out`.
fn write_report(args: &ScanArgs, report: &Report, color: bool) -> Result<(), String> {
    let options = PrettyOptions {
        // Colour is meaningless in a file.
        color: color && args.out.is_none(),
        unicode: !args.ascii,
        hyperlinks: args.hyperlinks,
    };

    let rendered = match args.format.as_str() {
        "pretty" => owlwarden_reporters::render_to_string(report, options),
        "json" => owlwarden_reporters::JsonReporter::to_string(report, args.out.is_some()),
        "sarif" => {
            if args.out.is_some() {
                owlwarden_reporters::SarifReporter::to_string_pretty(report)
            } else {
                owlwarden_reporters::SarifReporter::to_string(report)
            }
        }
        "junit" => owlwarden_reporters::JunitReporter::to_string(report),
        "md" => owlwarden_reporters::MdReporter::to_string(report),
        "agent" => Ok(owlwarden_reporters::agent::render(
            report,
            owlwarden_reporters::AgentOptions {
                budget_tokens: args
                    .budget
                    .unwrap_or(owlwarden_reporters::DEFAULT_BUDGET_TOKENS),
                max_findings: args.max_findings,
            },
        )),
        other => {
            return Err(format!(
                "unknown format {other:?}; available: {}",
                owlwarden_reporters::AVAILABLE_FORMATS.join(", ")
            ));
        }
    }
    .map_err(|error| error.to_string())?;

    if let Some(path) = &args.out {
        return owlwarden_static::write_replacing(std::path::Path::new(path), rendered.as_bytes())
            .map_err(|error| format!("cannot write {path}: {error}"));
    }

    // anstream translates ANSI for Windows consoles and strips it when stdout is
    // redirected.
    let mut out = anstream::stdout();
    writeln!(out, "{rendered}").map_err(|error| error.to_string())?;
    out.flush().map_err(|error| error.to_string())
}

fn run_rules(json: bool) -> i32 {
    let metas = owlwarden_detectors::all_rule_metas();

    if json {
        return match serde_json::to_string_pretty(&metas) {
            Ok(encoded) => {
                println!("{encoded}");
                EXIT_CLEAN
            }
            Err(error) => fail(&error.to_string()),
        };
    }

    println!("{} rules\n", metas.len());
    for meta in metas {
        let owasp = meta
            .owasp
            .as_ref()
            .map_or_else(String::new, |owasp| format!("  {owasp}"));
        println!(
            "{:<28} {:<7}{owasp}\n  {}\n",
            meta.id.as_str(),
            meta.severity.as_str(),
            meta.title
        );
    }
    EXIT_CLEAN
}

fn run_coverage(json: bool, no_color: bool, ascii: bool) -> i32 {
    let report = owlwarden_detectors::coverage_report();

    if json {
        return match serde_json::to_string_pretty(&report) {
            Ok(encoded) => {
                println!("{encoded}");
                EXIT_CLEAN
            }
            Err(error) => fail(&error.to_string()),
        };
    }

    print!(
        "{}",
        owlwarden_reporters::coverage::render(
            &report,
            owlwarden_reporters::coverage::CoverageOptions {
                color: use_color(no_color),
                unicode: !ascii,
            },
        )
    );
    EXIT_CLEAN
}

fn run_explain(rule: &str, json: bool) -> i32 {
    let Some(explanation) = owlwarden_detectors::explain(rule) else {
        return fail(&format!(
            "unknown rule {rule:?}; run `owlwarden rules` to list them"
        ));
    };

    if json {
        return match serde_json::to_string_pretty(&explanation) {
            Ok(encoded) => {
                println!("{encoded}");
                EXIT_CLEAN
            }
            Err(error) => fail(&error.to_string()),
        };
    }

    let meta = &explanation.meta;
    println!("{}  ({})\n", meta.title, meta.id);
    println!("severity   {}", meta.severity);
    println!("confidence at most {}", meta.max_confidence);
    if let Some(owasp) = &meta.owasp {
        println!("owasp      {owasp}");
    }
    if let Some(cwe) = meta.cwe {
        println!("cwe        CWE-{cwe}");
    }
    println!("\n{}\n", meta.description);

    println!("FIXES");
    for fix in &explanation.fixes {
        let framework = fix
            .framework
            .as_ref()
            .map_or_else(|| "any".to_owned(), ToString::to_string);
        println!("\n  [{framework}] {}", fix.summary);
        if let Some(patch) = &fix.patch {
            for line in patch.lines() {
                println!("      {line}");
            }
        }
    }

    println!("\nREFERENCES");
    for reference in &explanation.references {
        println!("  {}  {}", reference.id, reference.url);
    }
    EXIT_CLEAN
}
