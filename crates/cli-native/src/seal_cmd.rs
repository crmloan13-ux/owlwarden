//! `owlwarden seal` — write, verify, diff, and accept.
//!
//! # Sealing is never unattended
//!
//! [`run`] refuses to write without a TTY unless `--yes` is passed, and nothing
//! else in this binary calls it: not `gate`, not `scan`, and `init` does not
//! wire it into a hook.
//!
//! That is the whole defence against the obvious objection — that whatever
//! wrote the drift can also run `seal`. It is a *partial* defence. It raises
//! the cost; it does not close the hole, and
//! [ADR 0027](../../../docs/adr/0027-workspace-seal.md) says so in the document
//! rather than in a footnote.
//!
//! # You cannot lock a door you have not looked behind
//!
//! Writing a first seal on an already-compromised repository seals the
//! compromise. So `seal` runs a full `--preset agent-surface` scan first and
//! refuses to write while findings at or above `high` are unaccepted, printing
//! them.

use std::io::{IsTerminal, Write};
use std::path::Path;

use owlwarden_core::context::ScanSettings;
use owlwarden_core::finding::{Confidence, Finding, Severity};
use owlwarden_core::suppression::SuppressionPolicy;
use owlwarden_seal::{AcceptedFinding, SurfaceLock, diff, extract, model, signature, store};

use crate::cli::{SealArgs, SealMode};

/// Exit code when the surface has drifted.
const EXIT_DRIFT: i32 = 1;
/// Exit code when the command could not run at all.
const EXIT_ERROR: i32 = 2;

/// Runs `owlwarden seal`.
pub fn run(args: &SealArgs) -> i32 {
    let root = Path::new(&args.path);
    match args.mode {
        SealMode::Verify => verify(args, root, false),
        SealMode::Diff => verify(args, root, true),
        SealMode::Write => write_seal(args, root),
        SealMode::Accept => accept(args, root),
    }
}

/// Reads the current surface, or reports why it could not.
fn current_surface(root: &Path) -> Result<model::SurfaceRecord, String> {
    let provider = owlwarden_static::FsSourceProvider::new(root)
        .map_err(|error| format!("could not read {}: {error}", root.display()))?;
    let workspace = owlwarden_static::agentws::AgentWorkspace::load(&provider)
        .map_err(|error| format!("could not walk the agent workspace: {error}"))?;
    Ok(extract::extract(&workspace))
}

fn verify(args: &SealArgs, root: &Path, diff_only: bool) -> i32 {
    let (lock, bytes) = match store::load(root) {
        Ok(loaded) => loaded,
        Err(error) => return report_error(args, &error.to_string()),
    };
    let current = match current_surface(root) {
        Ok(record) => record,
        Err(message) => return report_error(args, &message),
    };

    let stamp = extract::engine_stamp();
    let comparison = diff::compare(&lock, &current, &stamp.catalogue_digest);
    let status = signature::verify_detached(
        &bytes,
        signature::read_signature(&store::signature_path(root)).as_deref(),
        args.trust.as_deref().map(Path::new),
    );

    if args.json {
        emit_json(&comparison, status);
    } else {
        emit_text(args, &comparison, status);
    }

    if args.require_signed && status != signature::SignatureStatus::Verified {
        return EXIT_DRIFT;
    }
    if diff_only {
        // `--diff` reports; it does not judge. A developer running it to see
        // what moved should not have to remember that it also sets an exit
        // code their shell might act on.
        return 0;
    }
    i32::from(!comparison.is_clean())
}

fn write_seal(args: &SealArgs, root: &Path) -> i32 {
    write_seal_with(args, root, Vec::new())
}

/// [`write_seal`], with acceptances to add before the block check runs.
fn write_seal_with(args: &SealArgs, root: &Path, extra: Vec<AcceptedFinding>) -> i32 {
    if !args.yes && !std::io::stdin().is_terminal() {
        return report_error(
            args,
            "`owlwarden seal` will not write without a terminal. Pass --yes if you meant to \
             run it unattended — and read the threat model in SECURITY.md first, because \
             whatever wrote the drift can pass --yes too.",
        );
    }

    // You cannot lock a door you have not looked behind.
    let mut accepted: Vec<AcceptedFinding> = store::load(root)
        .ok()
        .map(|(lock, _)| lock.accepted)
        .unwrap_or_default();
    for entry in extra {
        if !accepted
            .iter()
            .any(|existing| existing.fingerprint == entry.fingerprint)
        {
            accepted.push(entry);
        }
    }
    accepted.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));

    match blocking_findings(root, &accepted) {
        Ok(blocking) if !blocking.is_empty() => {
            let _ = writeln!(
                std::io::stderr(),
                "refusing to seal: {} unaccepted finding(s) at or above high on the agent \
                 surface.\nSealing now would record the compromise as the agreed state.\n",
                blocking.len()
            );
            for finding in blocking.iter().take(20) {
                // The fingerprint is printed because `--accept` needs one, and
                // a flag whose argument the user has to go and derive from
                // somewhere else is a flag nobody uses.
                let _ = writeln!(
                    std::io::stderr(),
                    "  {} {}  {}\n    fingerprint {}",
                    finding.severity.as_str(),
                    finding.id.as_str(),
                    location_of(finding),
                    owlwarden_core::baseline::fingerprint(finding)
                );
            }
            let _ = writeln!(
                std::io::stderr(),
                "\nFix them, or record the decision:\n  owlwarden seal --accept <fingerprint> \
                 --reason \"…\""
            );
            return EXIT_ERROR;
        }
        Ok(_) => {}
        Err(message) => return report_error(args, &message),
    }

    let current = match current_surface(root) {
        Ok(record) => record,
        Err(message) => return report_error(args, &message),
    };
    let lock = SurfaceLock {
        schema_version: model::SCHEMA_VERSION,
        sealed_at: owlwarden_core::report::now_rfc3339(),
        engine: extract::engine_stamp(),
        surface: current,
        // Acceptances survive a re-seal. They are decisions the team made, not
        // observations of the tree, and losing them on every seal would make
        // `--accept` a thing nobody uses twice.
        accepted,
    };
    match store::write(root, &lock) {
        Ok(path) => {
            let _ = writeln!(
                std::io::stdout(),
                "sealed {} item(s) → {}",
                lock.item_count(),
                path.display()
            );
            0
        }
        Err(error) => report_error(args, &error.to_string()),
    }
}

/// Records a finding as deliberately accepted.
///
/// On a sealed repository this only edits the acceptance list — the surface is
/// left exactly as it was, because accepting a finding is not the same decision
/// as agreeing to whatever else has changed since.
///
/// On an unsealed one it writes the first seal *with* the acceptance applied,
/// because the alternative is a deadlock: `seal` refuses while a high finding
/// is unaccepted, and `--accept` would refuse because there is nothing to
/// accept into. The block check still runs on everything else, so this cannot
/// be used to accept one finding into an unchecked seal.
fn accept(args: &SealArgs, root: &Path) -> i32 {
    if args.accept.is_empty() {
        return report_error(args, "--accept needs a fingerprint");
    }
    let entries: Vec<AcceptedFinding> = args
        .accept
        .iter()
        .map(|(fingerprint, reason)| AcceptedFinding {
            rule: rule_for(root, fingerprint).unwrap_or_else(|| "unknown".to_owned()),
            fingerprint: fingerprint.clone(),
            reason: reason.clone(),
        })
        .collect();

    match store::load(root) {
        Ok((mut lock, _)) => {
            let mut added = 0usize;
            for entry in entries {
                if lock.accepts(&entry.fingerprint) {
                    let _ = writeln!(std::io::stdout(), "already accepted: {}", entry.fingerprint);
                    continue;
                }
                let _ = writeln!(std::io::stdout(), "accepted {}", entry.fingerprint);
                lock.accepted.push(entry);
                added = added.saturating_add(1);
            }
            if added == 0 {
                return 0;
            }
            lock.accepted
                .sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
            match store::write(root, &lock) {
                Ok(_) => 0,
                Err(error) => report_error(args, &error.to_string()),
            }
        }
        Err(store::SealError::Missing { .. }) => {
            let _ = writeln!(
                std::io::stdout(),
                "no seal yet; writing the first one with {} acceptance(s) applied",
                entries.len()
            );
            write_seal_with(args, root, entries)
        }
        Err(error) => report_error(args, &error.to_string()),
    }
}

/// The agent-surface findings that must be dealt with before a seal is written.
fn blocking_findings(root: &Path, accepted: &[AcceptedFinding]) -> Result<Vec<Finding>, String> {
    let report = scan_agent_surface(root)?;
    Ok(report
        .findings
        .into_iter()
        .filter(|finding| finding.severity >= Severity::High)
        // A `possible` finding is a guess, and refusing to seal on a guess
        // would make the first seal an argument rather than a decision.
        .filter(|finding| finding.confidence > Confidence::Possible)
        .filter(|finding| {
            let fingerprint = owlwarden_core::baseline::fingerprint(finding);
            !accepted
                .iter()
                .any(|entry| entry.fingerprint == fingerprint)
        })
        .collect())
}

fn scan_agent_surface(root: &Path) -> Result<owlwarden_core::report::Report, String> {
    let (file_rules, project_rules) = owlwarden_detectors::rules_for_preset("agent-surface");
    let outcome = owlwarden_dynamic::block_on(owlwarden_static::runner::scan_project_with(
        root.to_path_buf(),
        file_rules,
        project_rules,
        owlwarden_static::runner::ScanRequest {
            settings: ScanSettings {
                allow_active: false,
                min_confidence: Confidence::Possible,
                min_severity: Severity::Info,
                preset: "agent-surface".to_owned(),
                dirty_paths: None,
                scoped_paths: None,
            },
            baseline: None,
            write_baseline: None,
            // A repository must not be able to suppress its way to a clean seal.
            suppressions: SuppressionPolicy::ReportOnly,
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

/// The rule a fingerprint belongs to, by re-scanning.
///
/// A fingerprint alone does not name its rule, and an `accepted` entry that
/// could not say which rule it accepts would be an entry nobody can review.
fn rule_for(root: &Path, fingerprint: &str) -> Option<String> {
    let report = scan_agent_surface(root).ok()?;
    report
        .findings
        .iter()
        .find(|finding| owlwarden_core::baseline::fingerprint(finding) == fingerprint)
        .map(|finding| finding.id.to_string())
}

fn location_of(finding: &Finding) -> String {
    match &finding.location {
        owlwarden_core::finding::Location::Source(source) => {
            format!("{}:{}", source.path, source.line)
        }
        owlwarden_core::finding::Location::Endpoint(endpoint) => endpoint.url.clone(),
    }
}

fn emit_text(args: &SealArgs, comparison: &diff::SurfaceDiff, status: signature::SignatureStatus) {
    let mark = owlwarden_reporters::banner::owl_mark(!args.ascii);
    let mut out = std::io::stdout();
    if comparison.is_clean() {
        let _ = writeln!(out, "\n{mark} surface unchanged");
        // A reformat is not drift, and is still worth a line: an investigator
        // reading this wants to know the file was rewritten.
        for change in comparison.changes.iter().filter(|change| !change.semantic) {
            let _ = writeln!(out, "  · {}  {}", change.key, change.detail);
        }
    } else {
        let count = comparison.semantic_changes().count();
        let plural = if count == 1 { "change" } else { "changes" };
        let _ = writeln!(out, "\n{mark} surface drift · {count} {plural}\n");
        for change in &comparison.changes {
            let _ = writeln!(
                out,
                "  {} {:<12}  {}  {}",
                change.kind.marker(),
                change.category,
                change.key,
                change.detail
            );
            if let Some(location) = &change.location {
                let _ = writeln!(out, "                  {location}");
            }
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "  seal taken {} by engine {} · {}",
        comparison.sealed_at,
        comparison.sealed_engine,
        status.explanation()
    );
    if comparison.catalogue_drifted {
        let _ = writeln!(
            out,
            "  note: this seal was taken under a different rule catalogue, so the comparison \
             is not like-for-like"
        );
    }
}

fn emit_json(comparison: &diff::SurfaceDiff, status: signature::SignatureStatus) {
    let changes: Vec<serde_json::Value> = comparison
        .changes
        .iter()
        .map(|change| {
            serde_json::json!({
                "kind": match change.kind {
                    diff::ChangeKind::Added => "added",
                    diff::ChangeKind::Removed => "removed",
                    diff::ChangeKind::Modified => "modified",
                },
                "category": change.category,
                "key": change.key,
                "detail": change.detail,
                "location": change.location,
                "automatic": change.automatic,
            })
        })
        .collect();
    let body = serde_json::json!({
        "clean": comparison.is_clean(),
        "sealedAt": comparison.sealed_at,
        "sealedEngine": comparison.sealed_engine,
        "catalogueDrifted": comparison.catalogue_drifted,
        "signature": match status {
            signature::SignatureStatus::Absent => "absent",
            signature::SignatureStatus::Verified => "verified",
            signature::SignatureStatus::Untrusted => "untrusted",
        },
        "changes": changes,
    });
    if let Ok(text) = serde_json::to_string_pretty(&body) {
        let _ = writeln!(std::io::stdout(), "{text}");
    }
}

fn report_error(args: &SealArgs, message: &str) -> i32 {
    if args.json {
        let body = serde_json::json!({ "error": message });
        if let Ok(text) = serde_json::to_string_pretty(&body) {
            let _ = writeln!(std::io::stdout(), "{text}");
        }
    } else {
        let _ = writeln!(std::io::stderr(), "error: {message}");
    }
    EXIT_ERROR
}
