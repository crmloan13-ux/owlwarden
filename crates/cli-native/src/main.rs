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

    let report = match futures_executor::block_on(owlwarden_static::scan_project(
        &args.path,
        file_rules,
        project_rules,
        settings,
    )) {
        Ok(report) => report,
        Err(error) => return fail(&error.to_string()),
    };

    if let Err(error) = write_report(args, &report, color) {
        return fail(&error);
    }

    if report.should_fail(args.fail_on, args.min_confidence) {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
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
        return std::fs::write(path, rendered)
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
