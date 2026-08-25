//! Argument parsing.
//!
//! Hand-written rather than pulled from a crate. The surface is small, the
//! parsing is fully tested below, and every dependency in a security tool is a
//! dependency its users have to trust. If the surface grows past what fits in
//! this file, that trade-off should be revisited in a PR, not stretched.

use owlwarden_core::finding::{Confidence, Severity};

/// What the user asked us to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Scan a project.
    Scan(Box<ScanArgs>),
    /// Re-scan on change (static only).
    Watch(Box<ScanArgs>),
    /// List the rule catalogue.
    Rules {
        /// Emit JSON instead of text.
        json: bool,
    },
    /// Print what the shipped rules cover, and what they do not.
    Coverage {
        /// Emit JSON instead of text.
        json: bool,
        /// Force colour off.
        no_color: bool,
        /// Restrict output to ASCII.
        ascii: bool,
    },
    /// Print the long-form write-up for one rule.
    Explain {
        /// Rule id.
        rule: String,
        /// Emit JSON instead of text.
        json: bool,
    },
    /// Print the help text.
    Help,
    /// Print the version.
    Version,
    /// Fetch OSV advisories for lockfile packages and write a local index.
    OsvUpdate {
        /// Project root.
        path: String,
        /// Output path (default `.owlwarden/osv-index.json` under the project).
        out: Option<String>,
    },
}

/// Options for `owlwarden scan`.
///
/// Yes, that is a lot of booleans. They are independent presentation switches,
/// and folding them into an enum would mean inventing combinations the user
/// cannot actually express on a command line.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, PartialEq, Eq)]
pub struct ScanArgs {
    /// Project root. Defaults to the current directory.
    pub path: String,
    /// Preset name.
    pub preset: String,
    /// Output format.
    pub format: String,
    /// Severity at which findings fail the run.
    pub fail_on: Severity,
    /// Findings below this confidence are dropped.
    pub min_confidence: Confidence,
    /// Write the report here instead of stdout.
    pub out: Option<String>,
    /// Baseline file; only new findings are reported.
    pub baseline: Option<String>,
    /// Write current findings to this baseline path.
    pub write_baseline: Option<String>,
    /// List every inline suppression and flag stale ones.
    pub report_suppressions: bool,
    /// True when `--ci` was passed.
    pub ci: bool,
    /// Honour inline suppressions under `--ci`.
    pub allow_suppressions: bool,
    /// Permit `--baseline` under `--ci`.
    pub allow_baseline: bool,
    /// Force colour off.
    pub no_color: bool,
    /// Use the ASCII glyph set.
    pub ascii: bool,
    /// Suppress decoration.
    pub quiet: bool,
    /// Emit OSC-8 hyperlinks.
    pub hyperlinks: bool,
    /// Live target URL for passive dynamic probing. Operator intent only.
    pub target: Option<String>,
    /// Extra scope allowlist entries. Empty means the target's origin.
    pub scope: Vec<String>,
    /// Paths to WASM plugin directories (or bare `.wasm` files with a
    /// sidecar manifest) to load alongside the first-party detectors.
    pub plugins: Vec<String>,
    /// Permit `--plugin` under `--ci`.
    pub allow_plugins: bool,
    /// Refuse plugins without a verified detached signature (ADR 0021).
    pub require_signed_plugins: bool,
    /// Permit state-changing HTTP methods with `--target`.
    pub allow_active: bool,
    /// Opt into Google OSV lockfile advisory lookup.
    pub osv: bool,
    /// Cached OSV index path (`--osv-db`).
    pub osv_db: Option<String>,
    /// `--offline` with `--osv` requires `--osv-db`.
    pub offline: bool,
    /// Scan only what changed since this git ref.
    pub since: Option<String>,
    /// Scan only what is staged.
    pub staged: bool,
    /// Scan only these project-relative paths.
    pub paths: Vec<String>,
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            path: ".".to_owned(),
            preset: owlwarden_detectors::DEFAULT_PRESET.to_owned(),
            format: "pretty".to_owned(),
            // "Any finding fails" is the documented default; confidence is what
            // keeps that from being unusable, since `Possible` findings never
            // fail on their own.
            fail_on: Severity::Info,
            min_confidence: Confidence::Possible,
            out: None,
            baseline: None,
            write_baseline: None,
            report_suppressions: false,
            ci: false,
            allow_suppressions: false,
            allow_baseline: false,
            no_color: false,
            ascii: false,
            quiet: false,
            hyperlinks: false,
            target: None,
            scope: Vec::new(),
            plugins: Vec::new(),
            allow_plugins: false,
            require_signed_plugins: false,
            allow_active: false,
            osv: false,
            osv_db: None,
            offline: false,
            since: None,
            staged: false,
            paths: Vec::new(),
        }
    }
}

/// A command line we could not make sense of.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArgError {
    /// A flag we do not have.
    #[error("unknown option {0:?}")]
    UnknownOption(String),
    /// A subcommand we do not have.
    #[error("unknown command {0:?}")]
    UnknownCommand(String),
    /// A flag that needs a value did not get one.
    #[error("{0} requires a value")]
    MissingValue(&'static str),
    /// A value outside the accepted set.
    #[error("invalid value {value:?} for {option}; expected one of: {expected}")]
    InvalidValue {
        /// The flag.
        option: &'static str,
        /// What the user wrote.
        value: String,
        /// The accepted values.
        expected: &'static str,
    },
    /// A required positional argument was absent.
    #[error("{0} requires an argument")]
    MissingArgument(&'static str),
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`ArgError`] for anything unrecognised. We never guess at what a typo meant:
/// silently scanning something other than what was asked for is worse than an
/// error, especially in CI.
pub fn parse(args: &[String]) -> Result<Command, ArgError> {
    let mut rest = args.iter();
    let Some(first) = rest.next() else {
        return Ok(Command::Help);
    };

    match first.as_str() {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "scan" => parse_scan(rest).map(|args| Command::Scan(Box::new(args))),
        "watch" => parse_scan(rest).map(|args| Command::Watch(Box::new(args))),
        "rules" => Ok(Command::Rules {
            json: rest.any(|arg| arg == "--json"),
        }),
        "coverage" => {
            let (mut json, mut no_color, mut ascii) = (false, false, false);
            for arg in rest {
                match arg.as_str() {
                    "--json" => json = true,
                    "--no-color" => no_color = true,
                    "--ascii" => ascii = true,
                    other => return Err(ArgError::UnknownOption(other.to_owned())),
                }
            }
            Ok(Command::Coverage {
                json,
                no_color,
                ascii,
            })
        }
        "explain" => {
            let mut rule = None;
            let mut json = false;
            for arg in rest {
                if arg == "--json" {
                    json = true;
                } else if arg.starts_with('-') {
                    return Err(ArgError::UnknownOption(arg.clone()));
                } else {
                    rule = Some(arg.clone());
                }
            }
            rule.map_or(Err(ArgError::MissingArgument("explain")), |rule| {
                Ok(Command::Explain { rule, json })
            })
        }
        "osv" => {
            let tail: Vec<String> = rest.cloned().collect();
            parse_osv(&tail)
        }
        other => Err(ArgError::UnknownCommand(other.to_owned())),
    }
}

fn parse_osv(args: &[String]) -> Result<Command, ArgError> {
    let Some(sub) = args.first() else {
        return Err(ArgError::UnknownCommand("osv".to_owned()));
    };
    if sub != "update" {
        return Err(ArgError::UnknownCommand(format!("osv {sub}")));
    }
    let mut path = ".".to_owned();
    let mut out = None;
    let mut rest = args.iter().skip(1).peekable();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                out = Some(
                    rest.next()
                        .cloned()
                        .ok_or(ArgError::MissingValue("--out"))?,
                );
            }
            other if other.starts_with('-') => {
                return Err(ArgError::UnknownOption(other.to_owned()));
            }
            project => project.clone_into(&mut path),
        }
    }
    Ok(Command::OsvUpdate { path, out })
}

/// What the command line said, before defaults are applied.
///
/// Collected as options and resolved once at the end rather than written
/// straight into [`ScanArgs`]: it keeps "the user did not say" distinguishable
/// from "the user said the default", which is what makes `--ci --format pretty`
/// behave the way you would expect.
#[allow(clippy::struct_excessive_bools)] // Same reasoning as `ScanArgs`.
#[derive(Default)]
struct RawScan {
    path: Option<String>,
    preset: Option<String>,
    format: Option<String>,
    out: Option<String>,
    baseline: Option<String>,
    write_baseline: Option<String>,
    fail_on: Option<Severity>,
    min_confidence: Option<Confidence>,
    report_suppressions: bool,
    ci: bool,
    allow_suppressions: bool,
    allow_baseline: bool,
    no_color: bool,
    ascii: bool,
    quiet: bool,
    hyperlinks: bool,
    target: Option<String>,
    scope: Vec<String>,
    plugins: Vec<String>,
    allow_plugins: bool,
    require_signed_plugins: bool,
    allow_active: bool,
    osv: bool,
    osv_db: Option<String>,
    offline: bool,
    since: Option<String>,
    staged: bool,
    paths: Vec<String>,
}

/// Parses the flags of `scan`.
fn parse_scan<'a>(args: impl Iterator<Item = &'a String>) -> Result<ScanArgs, ArgError> {
    let mut raw = RawScan::default();
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        let mut value =
            |option: &'static str| args.next().cloned().ok_or(ArgError::MissingValue(option));

        match arg.as_str() {
            "--preset" => raw.preset = Some(value("--preset")?),
            "--format" => raw.format = Some(value("--format")?),
            "--out" => raw.out = Some(value("--out")?),
            "--baseline" => raw.baseline = Some(value("--baseline")?),
            "--write-baseline" => raw.write_baseline = Some(value("--write-baseline")?),
            "--target" => raw.target = Some(value("--target")?),
            "--scope" => {
                let entry = value("--scope")?;
                if raw.scope.len() >= owlwarden_core::scope::AllowlistScope::MAX_ENTRIES {
                    return Err(ArgError::InvalidValue {
                        option: "--scope",
                        value: entry,
                        expected: "at most 64 entries",
                    });
                }
                raw.scope.push(entry);
            }
            "--plugin" => raw.plugins.push(value("--plugin")?),
            "--report-suppressions" => raw.report_suppressions = true,
            "--allow-suppressions" => raw.allow_suppressions = true,
            "--allow-baseline" => raw.allow_baseline = true,
            "--allow-plugins" => raw.allow_plugins = true,
            "--require-signed-plugins" => raw.require_signed_plugins = true,
            "--allow-active" => raw.allow_active = true,
            "--osv" => raw.osv = true,
            "--osv-db" => raw.osv_db = Some(value("--osv-db")?),
            "--offline" => raw.offline = true,
            "--since" => raw.since = Some(value("--since")?),
            "--staged" => raw.staged = true,
            "--paths" => {
                // Comma-separated, because a hook passes one string and a shell
                // user types one flag. Repeating `--paths` also works and the
                // lists concatenate.
                let entry = value("--paths")?;
                raw.paths.extend(
                    entry
                        .split(',')
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(str::to_owned),
                );
            }
            "--fail-on" => {
                let text = value("--fail-on")?;
                let level = Severity::from_str_opt(&text).ok_or(ArgError::InvalidValue {
                    option: "--fail-on",
                    value: text,
                    expected: "high, medium, low, info",
                })?;
                raw.fail_on = Some(level);
            }
            "--min-confidence" => {
                let text = value("--min-confidence")?;
                let level = Confidence::from_str_opt(&text).ok_or(ArgError::InvalidValue {
                    option: "--min-confidence",
                    value: text,
                    expected: "confirmed, likely, possible",
                })?;
                raw.min_confidence = Some(level);
            }
            "--no-color" => raw.no_color = true,
            "--ascii" => raw.ascii = true,
            "--quiet" | "-q" => raw.quiet = true,
            "--hyperlinks" => raw.hyperlinks = true,
            // `--ci` sets machine-readable defaults and refuses project-controlled
            // mute switches unless explicitly allowed.
            "--ci" => raw.ci = true,
            other if other.starts_with('-') => {
                return Err(ArgError::UnknownOption(other.to_owned()));
            }
            path if raw.path.is_none() => raw.path = Some(path.to_owned()),
            extra => return Err(ArgError::UnknownOption(extra.to_owned())),
        }
    }

    if raw.allow_active && raw.target.is_none() {
        return Err(ArgError::InvalidValue {
            option: "--allow-active",
            value: "true".to_owned(),
            expected: "use with --target",
        });
    }
    let narrowings = usize::from(raw.since.is_some())
        + usize::from(raw.staged)
        + usize::from(!raw.paths.is_empty());
    if narrowings > 1 {
        return Err(ArgError::InvalidValue {
            option: "--since / --staged / --paths",
            value: "more than one".to_owned(),
            expected: "exactly one narrowing flag",
        });
    }
    if raw.osv && raw.offline && raw.osv_db.is_none() {
        return Err(ArgError::InvalidValue {
            option: "--osv --offline",
            value: "true".to_owned(),
            expected: "requires --osv-db",
        });
    }

    Ok(raw.into_scan_args())
}

impl RawScan {
    fn into_scan_args(self) -> ScanArgs {
        let defaults = ScanArgs::default();
        ScanArgs {
            path: self.path.unwrap_or(defaults.path),
            preset: self.preset.unwrap_or(defaults.preset),
            format: self.format.unwrap_or_else(|| {
                if self.ci {
                    "json".to_owned()
                } else {
                    defaults.format
                }
            }),
            fail_on: self.fail_on.unwrap_or(defaults.fail_on),
            min_confidence: self.min_confidence.unwrap_or(defaults.min_confidence),
            out: self.out,
            baseline: self.baseline,
            write_baseline: self.write_baseline,
            report_suppressions: self.report_suppressions,
            ci: self.ci,
            allow_suppressions: self.allow_suppressions,
            allow_baseline: self.allow_baseline,
            no_color: self.no_color || self.ci,
            ascii: self.ascii,
            quiet: self.quiet || self.ci,
            hyperlinks: self.hyperlinks,
            target: self.target,
            scope: self.scope,
            plugins: self.plugins,
            allow_plugins: self.allow_plugins,
            require_signed_plugins: self.require_signed_plugins,
            allow_active: self.allow_active,
            osv: self.osv,
            osv_db: self.osv_db,
            offline: self.offline,
            since: self.since,
            staged: self.staged,
            paths: self.paths,
        }
    }
}

/// The help text.
#[must_use]
pub fn help_text() -> String {
    let presets = owlwarden_detectors::PRESETS
        .iter()
        .map(|preset| {
            format!(
                "                     {:<14} {}",
                preset.name, preset.description
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "owlwarden {version} — security scanner for Node apps

USAGE
  owlwarden scan [PATH] [OPTIONS]
  owlwarden watch [PATH] [OPTIONS]
  owlwarden osv update [PATH] [--out FILE]
  owlwarden rules [--json]
  owlwarden coverage [--json] [--no-color] [--ascii]
  owlwarden explain <RULE_ID> [--json]
  owlwarden --version

  Runs locally. No telemetry. Use --target only if you want a live probe
  (scoped; deny by default). Prefer --format json for CI and agents.

  watch re-scans on change. Static only — never opens a network path.

SCAN OPTIONS
  --preset <NAME>      Rule bundle to run. Default: {default_preset}
{presets}
  --format <FORMAT>    pretty (default), json, sarif, junit, or md
  --out <FILE>         Write the report to a file instead of stdout
  --baseline <FILE>    Report only findings new since this baseline
  --write-baseline <F> Write current findings to a baseline file
  --report-suppressions  List every inline suppression; flag stale ones
  --allow-suppressions Under --ci, honour inline suppressions (off by default)
  --allow-baseline     Under --ci, permit --baseline (off by default)
  --fail-on <LEVEL>    Exit 1 at this severity or above. Default: info
  --min-confidence <L> Drop findings below this confidence. Default: possible
  --target <URL>       Probe this URL (passive GET/HEAD). Operator-only —
                       never read from project config
  --scope <URL>        Allowlist entry (repeatable). Default: origin of --target
  --plugin <PATH>      Load a WASM detector (repeatable). Directory with
                       owlwarden.plugin.json + plugin.wasm, or a bare .wasm
                       with a sidecar manifest. Sandboxed; source-only
  --allow-plugins      Under --ci, permit --plugin (off by default)
  --require-signed-plugins  Refuse plugins without a verified .sig (ADR 0021)
  --allow-active       With --target, permit state-changing HTTP methods
  --osv                Opt into Google OSV lockfile advisory lookup
                       (sends name+version to api.osv.dev; never source)
  --osv-db <PATH>      Use a cached OSV index file (no network)
  --offline            With --osv, require --osv-db (fail closed)
  --ci                 JSON + quiet + no-color; ignores suppressions and
                       --baseline unless allow-* is set
  --no-color           Disable colour (also honours NO_COLOR)
  --ascii              Use ASCII box drawing instead of Unicode
  --hyperlinks         Emit OSC-8 links (only if your terminal supports them)
  -q, --quiet          Suppress the banner and progress output

EXIT CODES
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  the scan could not run

Without --target / --osv, scans are static-only and never touch the network.
With --target, only passive methods are used unless --allow-active; scope is
deny-by-default. --osv talks only to api.osv.dev (package names/versions).
",
        version = owlwarden_core::ENGINE_VERSION,
        default_preset = owlwarden_detectors::DEFAULT_PRESET,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn no_arguments_shows_help_rather_than_scanning_the_cwd() {
        // Scanning by accident is a surprise; a scanner should never start work
        // the user did not ask for.
        assert_eq!(parse(&[]).unwrap(), Command::Help);
    }

    #[test]
    fn scan_defaults_are_passive_and_pretty() {
        let Command::Scan(parsed) = parse(&args(&["scan"])).unwrap() else {
            panic!("expected a scan command");
        };
        assert_eq!(parsed.path, ".");
        assert_eq!(parsed.format, "pretty");
        assert_eq!(parsed.preset, owlwarden_detectors::DEFAULT_PRESET);
        assert_eq!(parsed.fail_on, Severity::Info);
        assert!(parsed.target.is_none());
        assert!(parsed.scope.is_empty());
    }

    #[test]
    fn target_and_repeated_scope_parse() {
        let Command::Scan(parsed) = parse(&args(&[
            "scan",
            "--target",
            "http://127.0.0.1:3000/",
            "--scope",
            "http://127.0.0.1:3000/",
            "--scope",
            "http://127.0.0.1:3000/api",
        ]))
        .unwrap() else {
            panic!("expected a scan command");
        };
        assert_eq!(parsed.target.as_deref(), Some("http://127.0.0.1:3000/"));
        assert_eq!(
            parsed.scope,
            vec![
                "http://127.0.0.1:3000/".to_owned(),
                "http://127.0.0.1:3000/api".to_owned()
            ]
        );
    }

    #[test]
    fn repeated_plugin_flags_accumulate_in_order() {
        let Command::Scan(parsed) = parse(&args(&[
            "scan",
            "--plugin",
            "plugins/a",
            "--plugin",
            "plugins/b",
        ]))
        .unwrap() else {
            panic!("expected a scan command");
        };
        assert_eq!(
            parsed.plugins,
            vec!["plugins/a".to_owned(), "plugins/b".to_owned()]
        );
        assert!(!parsed.allow_plugins);
    }

    #[test]
    fn allow_plugins_is_off_by_default() {
        let Command::Scan(parsed) = parse(&args(&["scan", "--allow-plugins"])).unwrap() else {
            panic!("expected a scan command");
        };
        assert!(parsed.allow_plugins);
        assert!(parsed.plugins.is_empty());
    }

    #[test]
    fn osv_is_opt_in() {
        let Command::Scan(parsed) = parse(&args(&["scan", "--osv"])).unwrap() else {
            panic!("expected a scan command");
        };
        assert!(parsed.osv);
        assert!(!parsed.allow_active);
    }

    #[test]
    fn osv_offline_without_db_is_refused() {
        assert!(parse(&args(&["scan", "--osv", "--offline"])).is_err());
    }

    #[test]
    fn osv_update_defaults_path() {
        let Command::OsvUpdate { path, out } = parse(&args(&["osv", "update"])).unwrap() else {
            panic!("expected osv update");
        };
        assert_eq!(path, ".");
        assert_eq!(out, None);
    }

    #[test]
    fn osv_db_flag_parses() {
        let Command::Scan(parsed) =
            parse(&args(&["scan", "--osv-db", ".owlwarden/osv-index.json"])).unwrap()
        else {
            panic!("expected a scan command");
        };
        assert_eq!(parsed.osv_db.as_deref(), Some(".owlwarden/osv-index.json"));
    }

    #[test]
    fn allow_active_requires_target() {
        assert!(parse(&args(&["scan", "--allow-active"])).is_err());
        let Command::Scan(parsed) = parse(&args(&[
            "scan",
            "--target",
            "http://127.0.0.1:3000/",
            "--allow-active",
        ]))
        .unwrap() else {
            panic!("expected a scan command");
        };
        assert!(parsed.allow_active);
    }

    #[test]
    fn ci_is_a_shorthand_not_a_separate_mode() {
        let Command::Scan(parsed) = parse(&args(&["scan", "--ci"])).unwrap() else {
            panic!("expected a scan command");
        };
        assert_eq!(parsed.format, "json");
        assert!(parsed.quiet);
        assert!(parsed.no_color);
    }

    #[test]
    fn a_path_and_flags_can_be_mixed() {
        let Command::Scan(parsed) = parse(&args(&[
            "scan",
            "./app",
            "--preset",
            "deep",
            "--fail-on",
            "high",
        ]))
        .unwrap() else {
            panic!("expected a scan command");
        };
        assert_eq!(parsed.path, "./app");
        assert_eq!(parsed.preset, "deep");
        assert_eq!(parsed.fail_on, Severity::High);
    }

    #[test]
    fn a_typo_is_an_error_not_a_default() {
        assert_eq!(
            parse(&args(&["scan", "--presset", "deep"])),
            Err(ArgError::UnknownOption("--presset".to_owned()))
        );
        assert_eq!(
            parse(&args(&["scna"])),
            Err(ArgError::UnknownCommand("scna".to_owned()))
        );
    }

    #[test]
    fn an_invalid_level_lists_the_valid_ones() {
        let error = parse(&args(&["scan", "--fail-on", "critical"])).unwrap_err();
        assert_eq!(
            error,
            ArgError::InvalidValue {
                option: "--fail-on",
                value: "critical".to_owned(),
                expected: "high, medium, low, info",
            }
        );
        assert!(error.to_string().contains("high, medium, low, info"));
    }

    #[test]
    fn a_flag_without_its_value_is_reported() {
        assert_eq!(
            parse(&args(&["scan", "--preset"])),
            Err(ArgError::MissingValue("--preset"))
        );
    }

    #[test]
    fn explain_requires_a_rule_id() {
        assert_eq!(
            parse(&args(&["explain"])),
            Err(ArgError::MissingArgument("explain"))
        );
        assert_eq!(
            parse(&args(&["explain", "stack-trace-leak"])).unwrap(),
            Command::Explain {
                rule: "stack-trace-leak".to_owned(),
                json: false
            }
        );
    }

    #[test]
    fn help_lists_every_preset() {
        let help = help_text();
        for preset in owlwarden_detectors::PRESETS {
            assert!(help.contains(preset.name), "help omits {}", preset.name);
        }
    }
}
