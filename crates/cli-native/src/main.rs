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

use std::io::{IsTerminal, Write};

use owlwarden_core::context::ScanSettings;
use owlwarden_core::report::Report;
use owlwarden_reporters::{BannerOpts, PrettyOptions, print_banner};

use cli::{Command, ScanArgs};

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
        Command::Scan(args) => run_scan(&args),
        Command::Watch(args) => run_watch(&args),
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
    let color = use_color(args.no_color);
    print_banner(&BannerOpts {
        color,
        unicode: !args.ascii,
        quiet: args.quiet || args.format != "pretty",
    });

    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset(&args.preset);
    if file_rules.is_empty() && project_rules.is_empty() {
        let known: Vec<&str> = owlwarden_detectors::PRESETS
            .iter()
            .map(|preset| preset.name)
            .collect();
        return fail(&format!(
            "unknown preset {:?}; available presets are {}",
            args.preset,
            known.join(", ")
        ));
    }

    let settings = ScanSettings {
        allow_active: false,
        min_confidence: args.min_confidence,
        min_severity: owlwarden_core::finding::Severity::Info,
        preset: args.preset.clone(),
    };

    let baseline = match load_baseline(args.baseline.as_deref()) {
        Ok(baseline) => baseline,
        Err(message) => return fail(&message),
    };

    let report = match futures_executor::block_on(owlwarden_static::scan_project_with(
        &args.path,
        file_rules,
        project_rules,
        owlwarden_static::ScanRequest {
            settings,
            baseline,
            write_baseline: args.write_baseline.as_ref().map(std::path::PathBuf::from),
        },
    )) {
        Ok(report) => report,
        Err(error) => return fail(&error.to_string()),
    };

    if args.write_baseline.is_some() && !args.quiet {
        let _ = writeln!(
            std::io::stderr(),
            "wrote baseline to {}",
            args.write_baseline.as_deref().unwrap_or("")
        );
    }

    if let Err(error) = write_report(args, &report, color) {
        return fail(&error);
    }

    if args.report_suppressions {
        write_suppressions(&report);
    }

    if report.should_fail(args.fail_on, args.min_confidence) {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
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
        let reason = if record.reason.is_empty() {
            "(no reason)"
        } else {
            record.reason.as_str()
        };
        let _ = writeln!(
            err,
            "  {}:{}  {}  [{}]",
            record.path, record.line, record.rule, flags
        );
        let _ = writeln!(err, "    {reason}");
    }
}

/// Polls the project tree and re-scans when anything changes.
///
/// No watcher crate: a security tool's install footprint is part of its
/// argument, and a half-second poll is enough for an editor save loop.
fn run_watch(args: &ScanArgs) -> i32 {
    let mut watch_args = ScanArgs {
        path: args.path.clone(),
        preset: args.preset.clone(),
        format: args.format.clone(),
        fail_on: args.fail_on,
        min_confidence: args.min_confidence,
        out: args.out.clone(),
        baseline: args.baseline.clone(),
        write_baseline: args.write_baseline.clone(),
        report_suppressions: args.report_suppressions,
        no_color: args.no_color,
        ascii: args.ascii,
        quiet: true,
        hyperlinks: args.hyperlinks,
    };

    let _ = run_scan(&watch_args);
    // Write the baseline at most once — see the TS watch command.
    watch_args.write_baseline = None;
    let _ = writeln!(
        std::io::stderr(),
        "watching {} — press Ctrl+C to stop",
        args.path
    );

    let mut previous = tree_fingerprint(std::path::Path::new(&args.path));
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let current = tree_fingerprint(std::path::Path::new(&args.path));
        if current != previous {
            previous = current;
            let _ = writeln!(std::io::stderr(), "\n— re-scan —");
            let _ = run_scan(&watch_args);
        }
    }
}

/// A cheap change detector: max mtime + file count under the project root.
fn tree_fingerprint(root: &std::path::Path) -> (u64, u64) {
    let mut count = 0u64;
    let mut newest = 0u64;
    walk_fingerprint(root, 0, &mut count, &mut newest);
    (count, newest)
}

fn walk_fingerprint(dir: &std::path::Path, depth: usize, count: &mut u64, newest: &mut u64) {
    if depth > 8 || *count >= 5_000 {
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
            walk_fingerprint(&path, depth + 1, count, newest);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        *count = count.saturating_add(1);
        if let Ok(meta) = entry.metadata()
            && let Ok(modified) = meta.modified()
            && let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH)
        {
            *newest = (*newest).max(duration.as_secs());
        }
    }
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
