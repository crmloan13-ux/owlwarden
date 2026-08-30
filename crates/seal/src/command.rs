//! `owlwarden seal` — write, verify, diff, and accept.
//!
//! The decision logic lives here rather than in either CLI, so the npm package
//! and the standalone binary cannot answer differently — the same reason the
//! gate's runtime is shared. The one thing this module does not own is *how to
//! run a scan*: the caller supplies that, because an async runtime in a crate
//! whose job is digests would be a dependency nobody asked for.
//!
//! # Sealing is never unattended
//!
//! [`run`] refuses to write unless the caller says a human is present, and
//! nothing else calls it: not `gate`, not `scan`, and `init` does not wire it
//! into a hook.
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

use std::fmt::Write as _;
use std::path::Path;

use owlwarden_core::finding::{Confidence, Finding, Severity};
use owlwarden_core::report::Report;

use crate::model::{AcceptedFinding, SurfaceLock};
use crate::{diff, extract, model, signature, store};

/// Exit code when the surface has drifted.
pub const EXIT_DRIFT: i32 = 1;
/// Exit code when the command could not run at all.
pub const EXIT_ERROR: i32 = 2;

/// What `owlwarden seal` should do.
///
/// Four verbs and one file. Deliberately not four commands: they all operate on
/// the same lockfile, and a reader who knows `seal` should not have to learn
/// `seal-verify` as a separate thing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SealMode {
    /// Write or update the lockfile. Interactive; requires a TTY or `--yes`.
    #[default]
    Write,
    /// Exit 0 if unchanged, 1 on drift, 2 if it could not run.
    Verify,
    /// Show what changed without writing.
    Diff,
    /// Record a finding as deliberately accepted.
    Accept,
}

/// One invocation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealRequest {
    /// What to do.
    pub mode: SealMode,
    /// Emit JSON instead of text.
    pub json: bool,
    /// Whether the caller has established that a human is present — a TTY, or
    /// an explicit `--yes`.
    ///
    /// Passed in rather than detected here: this crate has no business knowing
    /// what a terminal is, and a caller that wants to test the refusal should
    /// not have to acquire one.
    pub attended: bool,
    /// `--accept <fingerprint> --reason <text>` pairs, in the order given.
    pub accept: Vec<(String, String)>,
    /// A trust root file for the detached signature.
    pub trust: Option<std::path::PathBuf>,
    /// Whether an unsigned or badly-signed seal is a failure.
    pub require_signed: bool,
    /// Restrict output to ASCII.
    pub ascii: bool,
}

/// What one invocation produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealOutcome {
    /// Text for stdout.
    pub stdout: String,
    /// Text for stderr.
    pub stderr: String,
    /// The process exit code.
    pub exit_code: i32,
}

/// How the caller runs an agent-surface scan.
///
/// A function rather than a trait: there is one implementation on each side of
/// the boundary and neither needs to be swapped at run time.
pub type ScanFn<'a> = &'a dyn Fn(&Path) -> Result<Report, String>;

/// Runs `owlwarden seal`.
pub fn run(request: &SealRequest, root: &Path, scan: ScanFn<'_>) -> SealOutcome {
    match request.mode {
        SealMode::Verify => verify(request, root, false),
        SealMode::Diff => verify(request, root, true),
        SealMode::Write => write_seal_with(request, root, Vec::new(), scan),
        SealMode::Accept => accept(request, root, scan),
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

fn verify(request: &SealRequest, root: &Path, diff_only: bool) -> SealOutcome {
    let (lock, bytes) = match store::load(root) {
        Ok(loaded) => loaded,
        Err(error) => return error_outcome(request, &error.to_string()),
    };
    let current = match current_surface(root) {
        Ok(record) => record,
        Err(message) => return error_outcome(request, &message),
    };

    let stamp = extract::engine_stamp();
    let comparison = diff::compare(&lock, &current, &stamp.catalogue_digest);
    let status = signature::verify_detached(
        &bytes,
        signature::read_signature(&store::signature_path(root)).as_deref(),
        request.trust.as_deref(),
    );

    let stdout = if request.json {
        render_json(&comparison, status)
    } else {
        render_text(request, &comparison, status)
    };

    let exit_code = if request.require_signed && status != signature::SignatureStatus::Verified {
        EXIT_DRIFT
    } else if diff_only {
        // `--diff` reports; it does not judge. A developer running it to see
        // what moved should not have to remember that it also sets an exit
        // code their shell might act on.
        0
    } else {
        i32::from(!comparison.is_clean())
    };

    SealOutcome {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

/// Records findings as deliberately accepted.
///
/// On a sealed repository this only edits the acceptance list — the surface is
/// left exactly as it was, because accepting a finding is not the same decision
/// as agreeing to whatever else has changed since.
///
/// On an unsealed one it writes the first seal *with* the acceptances applied,
/// because the alternative is a deadlock: `seal` refuses while a high finding
/// is unaccepted, and `--accept` would refuse because there is nothing to
/// accept into. The block check still runs on everything else, so this cannot
/// be used to accept one finding into an unchecked seal.
fn accept(request: &SealRequest, root: &Path, scan: ScanFn<'_>) -> SealOutcome {
    if request.accept.is_empty() {
        return error_outcome(request, "--accept needs a fingerprint");
    }
    if let Some((fingerprint, _)) = request
        .accept
        .iter()
        .find(|(_, reason)| reason.trim().is_empty())
    {
        return error_outcome(
            request,
            &format!(
                "--accept {fingerprint} needs --reason; an acceptance nobody can explain is an acceptance nobody decided"
            ),
        );
    }

    let scanned = scan(root).ok();
    let entries: Vec<AcceptedFinding> = request
        .accept
        .iter()
        .map(|(fingerprint, reason)| AcceptedFinding {
            rule: rule_for(scanned.as_ref(), fingerprint),
            fingerprint: fingerprint.clone(),
            reason: reason.clone(),
        })
        .collect();

    match store::load(root) {
        Ok((mut lock, _)) => {
            let mut stdout = String::new();
            let mut added = 0usize;
            for entry in entries {
                if lock.accepts(&entry.fingerprint) {
                    let _ = writeln!(stdout, "already accepted: {}", entry.fingerprint);
                    continue;
                }
                let _ = writeln!(stdout, "accepted {}", entry.fingerprint);
                lock.accepted.push(entry);
                added = added.saturating_add(1);
            }
            if added == 0 {
                return SealOutcome {
                    stdout,
                    ..SealOutcome::default()
                };
            }
            lock.accepted
                .sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
            match store::write(root, &lock) {
                Ok(_) => SealOutcome {
                    stdout,
                    ..SealOutcome::default()
                },
                Err(error) => error_outcome(request, &error.to_string()),
            }
        }
        Err(store::SealError::Missing { .. }) => {
            let mut outcome = write_seal_with(request, root, entries, scan);
            outcome.stdout.insert_str(
                0,
                "no seal yet; writing the first one with the acceptances applied\n",
            );
            outcome
        }
        Err(error) => error_outcome(request, &error.to_string()),
    }
}

/// Writes the lockfile, with acceptances to add before the block check runs.
fn write_seal_with(
    request: &SealRequest,
    root: &Path,
    extra: Vec<AcceptedFinding>,
    scan: ScanFn<'_>,
) -> SealOutcome {
    if !request.attended {
        return error_outcome(
            request,
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

    let report = match scan(root) {
        Ok(report) => report,
        Err(message) => return error_outcome(request, &message),
    };
    let blocking = blocking_findings(&report, &accepted);
    if !blocking.is_empty() {
        return error_outcome(request, &refusal(&blocking));
    }

    let current = match current_surface(root) {
        Ok(record) => record,
        Err(message) => return error_outcome(request, &message),
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
        Ok(path) => SealOutcome {
            stdout: format!(
                "sealed {} item(s) → {}\n",
                lock.item_count(),
                path.display()
            ),
            ..SealOutcome::default()
        },
        Err(error) => error_outcome(request, &error.to_string()),
    }
}

/// The message a refused seal prints.
fn refusal(blocking: &[Finding]) -> String {
    let mut text = format!(
        "refusing to seal: {} unaccepted finding(s) at or above high on the agent surface.\n\
         Sealing now would record the compromise as the agreed state.\n\n",
        blocking.len()
    );
    for finding in blocking.iter().take(20) {
        // The fingerprint is printed because `--accept` needs one, and a flag
        // whose argument the user has to go and derive from somewhere else is a
        // flag nobody uses.
        let _ = writeln!(
            text,
            "  {} {}  {}\n    fingerprint {}",
            finding.severity.as_str(),
            finding.id.as_str(),
            location_of(finding),
            owlwarden_core::baseline::fingerprint(finding)
        );
    }
    let _ = write!(
        text,
        "\nFix them, or record the decision:\n  owlwarden seal --accept <fingerprint> \
         --reason \"…\"\n"
    );
    text
}

/// The agent-surface findings that must be dealt with before a seal is written.
fn blocking_findings(report: &Report, accepted: &[AcceptedFinding]) -> Vec<Finding> {
    report
        .findings
        .iter()
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
        .cloned()
        .collect()
}

/// The rule a fingerprint belongs to.
///
/// An `accepted` entry that could not say which rule it accepts would be an
/// entry nobody can review, so an unresolvable fingerprint records `unknown`
/// rather than being silently dropped.
fn rule_for(report: Option<&Report>, fingerprint: &str) -> String {
    report
        .and_then(|report| {
            report
                .findings
                .iter()
                .find(|finding| owlwarden_core::baseline::fingerprint(finding) == fingerprint)
        })
        .map_or_else(|| "unknown".to_owned(), |finding| finding.id.to_string())
}

fn location_of(finding: &Finding) -> String {
    match &finding.location {
        owlwarden_core::finding::Location::Source(source) => {
            format!("{}:{}", source.path, source.line)
        }
        owlwarden_core::finding::Location::Endpoint(endpoint) => endpoint.url.clone(),
    }
}

/// The owl mark, or its ASCII fallback.
///
/// Duplicated from the reporters rather than depended on: this crate has no
/// other reason to pull in a rendering crate, and the two characters are not a
/// contract anyone else reads.
fn owl_mark(ascii: bool) -> &'static str {
    if ascii { "(o.o)" } else { "◉ᴥ◉" }
}

fn render_text(
    request: &SealRequest,
    comparison: &diff::SurfaceDiff,
    status: signature::SignatureStatus,
) -> String {
    let mark = owl_mark(request.ascii);
    let mut out = String::new();
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
    out
}

fn render_json(comparison: &diff::SurfaceDiff, status: signature::SignatureStatus) -> String {
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
                "semantic": change.semantic,
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
    serde_json::to_string_pretty(&body).unwrap_or_else(|_| "{}".to_owned()) + "\n"
}

fn error_outcome(request: &SealRequest, message: &str) -> SealOutcome {
    if request.json {
        let body = serde_json::json!({ "error": message });
        SealOutcome {
            stdout: serde_json::to_string_pretty(&body).unwrap_or_default() + "\n",
            stderr: String::new(),
            exit_code: EXIT_ERROR,
        }
    } else {
        SealOutcome {
            stdout: String::new(),
            stderr: format!("error: {message}\n"),
            exit_code: EXIT_ERROR,
        }
    }
}
