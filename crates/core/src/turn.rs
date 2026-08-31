//! The turn verdict: which of these findings did *this* turn introduce.
//!
//! # The problem this exists for
//!
//! Twenty-five rules on a six-month-old repository produce a flat list. 1.2
//! made that list triageable — [`crate::finding::Exposure`] says which findings
//! an anonymous caller can reach. It did not change who the list belongs to.
//! Every finding in it is somebody's, some day, and a list that is everybody's
//! problem is nobody's.
//!
//! A turn is different. A developer, or an agent, changed seven files in the
//! last thirty seconds. Of the findings now standing on those files, some were
//! there before the turn started and some were not, and only the second kind is
//! a thing the person at the keyboard can act on *right now* while the context
//! is still in their head.
//!
//! So this module answers one question — *what did this turn change* — by
//! diffing two finding sets keyed on [`crate::baseline::fingerprint_at`]:
//!
//! | state | meaning | fails the turn |
//! |---|---|---|
//! | [`TurnState::Introduced`] | in `after`, not in `before` | **yes** |
//! | [`TurnState::Carried`] | in both | no |
//! | [`TurnState::Fixed`] | in `before`, not in `after` | no — it is the good news |
//!
//! **Carried findings never fail a turn.** That is the whole design. A gate
//! that blocks on debt the turn did not create is a gate that gets removed on
//! the second day, and everything it would have caught goes with it.
//!
//! # Why the baseline fingerprint and not the location
//!
//! Line numbers move. A fix on line 8 shifts a finding on line 40 down by two,
//! and a diff keyed on `rule@path:line` reports it as one finding fixed and one
//! introduced — the exact shape of noise this module exists to remove. The
//! baseline fingerprint drops the line, collapses whitespace, and carries an
//! occurrence index, so it is stable across the reformat that a turn very often
//! is ([`crate::baseline`]).
//!
//! Using the *same* identity as `--baseline` and `seal --accept` is deliberate:
//! one notion of "the same finding" in the whole tool, tested in one place.
//!
//! # What this cannot do
//!
//! `before` has to come from somewhere, and that somewhere is a commit. So the
//! anchor is exactly as trustworthy as the commit is: an agent that can commit
//! can commit a finding and then report it as pre-existing. This is the same
//! limit the seal states about itself — a detection and review control, not a
//! containment one — and it is why the verdict names the base it measured
//! against on every line of output rather than saying "clean".

use serde::{Deserialize, Serialize};

use crate::baseline::fingerprints;
use crate::finding::{Confidence, Exposure, Finding, Severity};
use crate::report::fails_gate;

/// Where one finding stands relative to the base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TurnState {
    /// Not present at the base. The turn put it there.
    Introduced,
    /// Present at the base and still present. Debt, not a regression.
    Carried,
    /// Present at the base and gone now.
    Fixed,
}

impl TurnState {
    /// The word used in output. Stable — agents and CI branch on it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Introduced => "introduced",
            Self::Carried => "carried",
            Self::Fixed => "fixed",
        }
    }
}

/// Counts by [`TurnState`]. Present even when zero, so a consumer renders the
/// line without special-casing and a zero reads as a statement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnCounts {
    /// Findings the turn introduced.
    pub introduced: u32,
    /// Findings that were already there.
    pub carried: u32,
    /// Findings the turn removed.
    pub fixed: u32,
}

/// The classified difference between two scans of the same paths.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TurnDiff {
    /// In `after`, not in `before`, in report order.
    pub introduced: Vec<Finding>,
    /// In both, in report order.
    pub carried: Vec<Finding>,
    /// In `before`, not in `after`, in report order.
    pub fixed: Vec<Finding>,
}

impl TurnDiff {
    /// Classifies `after` against `before`.
    ///
    /// Both sides are fingerprinted with the same occurrence walk, so two
    /// identical `err.stack` findings in one file stay two findings rather than
    /// collapsing into one and reporting the second as fixed.
    #[must_use]
    pub fn between(before: &[Finding], after: &[Finding]) -> Self {
        let before_keys = fingerprints(before);
        let after_keys = fingerprints(after);

        let known: std::collections::BTreeSet<&str> =
            before_keys.iter().map(String::as_str).collect();
        let still: std::collections::BTreeSet<&str> =
            after_keys.iter().map(String::as_str).collect();

        let mut diff = Self::default();
        for (finding, key) in after.iter().zip(&after_keys) {
            if known.contains(key.as_str()) {
                diff.carried.push(finding.clone());
            } else {
                diff.introduced.push(finding.clone());
            }
        }
        for (finding, key) in before.iter().zip(&before_keys) {
            if !still.contains(key.as_str()) {
                diff.fixed.push(finding.clone());
            }
        }
        diff
    }

    /// The counts, for the summary line.
    #[must_use]
    pub fn counts(&self) -> TurnCounts {
        TurnCounts {
            introduced: u32::try_from(self.introduced.len()).unwrap_or(u32::MAX),
            carried: u32::try_from(self.carried.len()).unwrap_or(u32::MAX),
            fixed: u32::try_from(self.fixed.len()).unwrap_or(u32::MAX),
        }
    }

    /// The introduced findings that meet the gate.
    ///
    /// Only [`TurnState::Introduced`] is considered. `carried` is deliberately
    /// not filtered and offered here: there is no threshold at which a turn
    /// should fail for debt it did not create, so there is no code path that
    /// could accidentally grow one.
    #[must_use]
    pub fn blocking(
        &self,
        fail_on: Severity,
        min_confidence: Confidence,
        fail_on_exposure: Option<Exposure>,
    ) -> Vec<&Finding> {
        self.introduced
            .iter()
            .filter(|finding| fails_gate(finding, fail_on, min_confidence, fail_on_exposure))
            .collect()
    }

    /// Whether the turn should be refused.
    ///
    /// The gate is the same predicate `scan` uses, applied to a different set.
    /// That is the point: `turn` is not a second, laxer standard — it is the
    /// same standard asked of a smaller, newer set of findings.
    #[must_use]
    pub fn should_fail(
        &self,
        fail_on: Severity,
        min_confidence: Confidence,
        fail_on_exposure: Option<Exposure>,
    ) -> bool {
        !self
            .blocking(fail_on, min_confidence, fail_on_exposure)
            .is_empty()
    }
}

/// The verdict, as one word. Stable — CI and agents branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    /// Nothing introduced met the gate. Carried findings may still exist and
    /// are reported; they do not make a turn dirty.
    Clean,
    /// The turn introduced at least one finding at or above the gate.
    Blocked,
}

impl Verdict {
    /// The word used in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Blocked => "blocked",
        }
    }
}

/// The commit the turn was measured against.
///
/// Both fields are present in every record because "since HEAD" is not a fact
/// anyone can check six weeks later and `a1b2c3d` is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnBase {
    /// What the operator typed, or `HEAD`.
    pub reference: String,
    /// The commit it resolved to, when git could say. Absent outside a
    /// repository, in which case the turn has no anchor and says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// One finding named without its body.
///
/// `carried` and `fixed` are counted and listed, never rendered in full: the
/// whole argument of this command is that the reader's attention belongs on
/// what the turn introduced. A carried finding printed with a code frame and a
/// fix is the flat list this release exists to stop producing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingRef {
    /// Rule id.
    pub id: String,
    /// Severity, so a reader can tell a fixed `high` from a fixed `info`.
    pub severity: Severity,
    /// `path:line`, or the probed URL for an endpoint finding.
    pub at: String,
    /// The baseline fingerprint. What a later run matches on, and what makes a
    /// record checkable rather than merely readable.
    pub fingerprint: String,
}

impl FindingRef {
    /// Builds a reference from a finding and its already-computed fingerprint.
    #[must_use]
    pub fn new(finding: &Finding, fingerprint: String) -> Self {
        let at = match &finding.location {
            crate::finding::Location::Source(location) => {
                format!("{}:{}", location.path, location.line)
            }
            crate::finding::Location::Endpoint(location) => location.url.clone(),
        };
        Self {
            id: finding.id.to_string(),
            severity: finding.severity,
            at,
            fingerprint,
        }
    }
}

/// What the agent execution surface did during the turn.
///
/// The seal already answers this ([ADR 0027](../../../docs/adr/0027-workspace-seal.md));
/// the turn verdict carries the answer because *the agent added a hook* and
/// *the agent added a stack-trace leak* are the same question asked of two
/// surfaces, and reading them in two places is how one of them stops being read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnSurface {
    /// `sealed` / `unsealed` / `moved` / `unreadable`.
    pub state: String,
    /// Files on the protected surface.
    pub files: u32,
    /// Hook declarations found.
    pub hooks: u32,
    /// MCP servers declared.
    pub mcp_servers: u32,
    /// One sentence per change, when the surface moved. Empty otherwise.
    #[serde(default)]
    pub changes: Vec<String>,
}

/// The thresholds the verdict was reached under.
///
/// Recorded rather than assumed: a record that says `clean` without saying
/// *clean at what* is a record that means whatever the reader's defaults happen
/// to be today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnGate {
    /// Severity floor.
    pub fail_on: Severity,
    /// Confidence floor.
    pub min_confidence: Confidence,
    /// Exposure floor, when one was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on_exposure: Option<Exposure>,
}

/// Format version for the turn record. Independent of the scan report's
/// version: they change for different reasons.
pub const TURN_SCHEMA_VERSION: &str = "1.0";

/// One turn's verdict, and the JSON contract for it.
///
/// Deterministic by construction: every field is derived from the two reports
/// and the base, and the only clock-dependent field is
/// [`Self::recorded_at`]. Two runs of the same turn against the same base
/// produce the same bytes everywhere else, which is what makes a recorded
/// verdict something a reviewer can re-derive rather than merely trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnReport {
    /// Format version, see [`TURN_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Tool identity.
    pub tool: crate::report::ToolInfo,
    /// RFC 3339 UTC timestamp.
    pub recorded_at: String,
    /// Wall-clock cost of both scans and the diff.
    pub duration_ms: u64,
    /// What the turn was measured against.
    pub base: TurnBase,
    /// Files the turn touched, as git reported them.
    pub files_changed: u32,
    /// Thresholds in force.
    pub gate: TurnGate,
    /// The verdict.
    pub verdict: Verdict,
    /// Counts by state.
    pub counts: TurnCounts,
    /// How many of the introduced findings met the gate.
    ///
    /// Separate from `counts.introduced` because they are different numbers and
    /// conflating them produces the one sentence this command must never
    /// print: `clean` over a finding the turn just added. Everything introduced
    /// is reported; only this subset blocks.
    pub blocking: u32,
    /// The findings the turn introduced, in full. The only findings printed
    /// with a code frame and a fix, because they are the only ones whose
    /// author is still at the keyboard.
    pub introduced: Vec<Finding>,
    /// Findings that were already there, named but not rendered.
    #[serde(default)]
    pub carried: Vec<FindingRef>,
    /// Findings the turn removed.
    #[serde(default)]
    pub fixed: Vec<FindingRef>,
    /// The agent execution surface, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<TurnSurface>,
    /// Anything that stopped the turn from being fully answered — a base that
    /// would not resolve, a scan that failed. Present and empty rather than
    /// absent: a verdict reached over a broken input has to say so.
    #[serde(default)]
    pub notes: Vec<String>,
}

impl TurnReport {
    /// Assembles a record from a diff.
    ///
    /// The gate is applied here rather than by the caller so that the verdict
    /// and the counts can never disagree.
    #[must_use]
    pub fn new(
        diff: &TurnDiff,
        base: TurnBase,
        files_changed: u32,
        duration_ms: u64,
        gate: TurnGate,
    ) -> Self {
        let blocking = diff.blocking(gate.fail_on, gate.min_confidence, gate.fail_on_exposure);
        let blocking = u32::try_from(blocking.len()).unwrap_or(u32::MAX);
        let verdict = if blocking > 0 {
            Verdict::Blocked
        } else {
            Verdict::Clean
        };
        Self {
            schema_version: TURN_SCHEMA_VERSION.to_owned(),
            tool: crate::report::ToolInfo::default(),
            recorded_at: crate::report::now_rfc3339(),
            duration_ms,
            base,
            files_changed,
            gate,
            verdict,
            counts: diff.counts(),
            blocking,
            introduced: diff.introduced.clone(),
            carried: refs(&diff.carried),
            fixed: refs(&diff.fixed),
            surface: None,
            notes: Vec::new(),
        }
    }
}

/// Names a set of findings without their bodies.
fn refs(findings: &[Finding]) -> Vec<FindingRef> {
    let keys = fingerprints(findings);
    findings
        .iter()
        .zip(keys)
        .map(|(finding, key)| FindingRef::new(finding, key))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;
    use crate::finding::{ExposureEvidence, FindingContext, Location, RuleId, SourceLocation};

    fn at(rule: &'static str, path: &str, line: u32, evidence: &str) -> Finding {
        built(
            rule,
            path,
            line,
            evidence,
            Severity::High,
            Confidence::Likely,
        )
    }

    fn built(
        rule: &'static str,
        path: &str,
        line: u32,
        evidence: &str,
        severity: Severity,
        confidence: Confidence,
    ) -> Finding {
        Finding::builder(RuleId::new_static(rule), severity, "t")
            .confidence(confidence)
            .location(Location::Source(SourceLocation {
                path: path.to_owned(),
                line,
                col: 1,
            }))
            .context(FindingContext {
                evidence: Some(evidence.to_owned()),
                ..FindingContext::default()
            })
            .build()
    }

    #[test]
    fn a_finding_absent_from_the_base_is_introduced() {
        let before = vec![at("stack-trace-leak", "a.ts", 3, "err.stack")];
        let after = vec![
            at("stack-trace-leak", "a.ts", 3, "err.stack"),
            at("open-redirect", "b.ts", 9, "redirect(to)"),
        ];

        let diff = TurnDiff::between(&before, &after);
        assert_eq!(diff.counts().introduced, 1);
        assert_eq!(diff.counts().carried, 1);
        assert_eq!(diff.counts().fixed, 0);
        assert_eq!(diff.introduced[0].id.as_str(), "open-redirect");
    }

    #[test]
    fn reformatting_that_moves_a_line_is_not_a_regression() {
        // The failure this module exists to avoid: a key that includes the line
        // reports one finding fixed and one introduced when a fix above it
        // shifts everything down. Both sides here are the same finding.
        let before = vec![at("stack-trace-leak", "a.ts", 12, "{ error: err.stack }")];
        let after = vec![at(
            "stack-trace-leak",
            "a.ts",
            40,
            "{  error:  err.stack  }",
        )];

        let diff = TurnDiff::between(&before, &after);
        assert_eq!(
            diff.counts().carried,
            1,
            "same finding, moved and reindented"
        );
        assert_eq!(diff.counts().introduced, 0);
        assert_eq!(diff.counts().fixed, 0);
    }

    #[test]
    fn two_identical_findings_in_one_file_stay_two() {
        let before = vec![
            at("stack-trace-leak", "a.ts", 3, "err.stack"),
            at("stack-trace-leak", "a.ts", 9, "err.stack"),
        ];
        let after = vec![at("stack-trace-leak", "a.ts", 3, "err.stack")];

        let diff = TurnDiff::between(&before, &after);
        assert_eq!(
            diff.counts().fixed,
            1,
            "one of the two occurrences went away"
        );
        assert_eq!(diff.counts().carried, 1);
        assert_eq!(diff.counts().introduced, 0);
    }

    #[test]
    fn carried_findings_never_fail_a_turn() {
        // The load-bearing property. Twelve mediums of inherited debt, the
        // strictest gate that exists, and the turn still passes: a gate that
        // blocks on what the turn did not do is a gate that gets removed.
        let debt: Vec<Finding> = (0..12)
            .map(|index| at("insecure-cookie", "legacy.ts", index, "httpOnly: false"))
            .collect();
        let diff = TurnDiff::between(&debt, &debt);

        assert_eq!(diff.counts().carried, 12);
        assert!(!diff.should_fail(
            Severity::Info,
            Confidence::Possible,
            Some(Exposure::Internal)
        ));
        assert!(
            diff.blocking(Severity::Info, Confidence::Possible, None)
                .is_empty()
        );
    }

    #[test]
    fn the_turn_gate_is_the_scan_gate_applied_to_a_smaller_set() {
        // A `possible` finding never fails a scan, so it must never fail a
        // turn either. One predicate, one meaning.
        let guess = built(
            "ssrf",
            "a.ts",
            1,
            "fetch(url)",
            Severity::High,
            Confidence::Possible,
        );

        let diff = TurnDiff::between(&[], std::slice::from_ref(&guess));
        assert_eq!(diff.counts().introduced, 1, "still reported");
        assert!(
            !diff.should_fail(Severity::High, Confidence::Possible, None),
            "a guess must not block a turn any more than it blocks a build"
        );
    }

    #[test]
    fn the_exposure_gate_composes_on_introduced_findings() {
        let reachable =
            Finding::builder(RuleId::new_static("insecure-cookie"), Severity::Medium, "t")
                .confidence(Confidence::Likely)
                .location(Location::Source(SourceLocation {
                    path: "a.ts".to_owned(),
                    line: 1,
                    col: 1,
                }))
                .context(FindingContext {
                    evidence: Some("secure: false".to_owned()),
                    ..FindingContext::default()
                })
                .exposure(Exposure::Internet, ExposureEvidence::default())
                .build();

        let diff = TurnDiff::between(&[], std::slice::from_ref(&reachable));
        assert!(!diff.should_fail(Severity::High, Confidence::Possible, None));
        assert!(diff.should_fail(
            Severity::High,
            Confidence::Possible,
            Some(Exposure::Internet)
        ));
    }

    #[test]
    fn an_empty_turn_is_clean_and_says_nothing_happened() {
        let diff = TurnDiff::between(&[], &[]);
        assert_eq!(diff.counts(), TurnCounts::default());
        assert!(!diff.should_fail(Severity::Info, Confidence::Possible, None));
    }

    fn gate() -> TurnGate {
        TurnGate {
            fail_on: Severity::Medium,
            min_confidence: Confidence::Possible,
            fail_on_exposure: None,
        }
    }

    #[test]
    fn the_verdict_and_the_counts_cannot_disagree() {
        // Assembled in one place precisely so a record cannot say `clean` over
        // a non-zero blocking count.
        let after = vec![at("stack-trace-leak", "a.ts", 3, "err.stack")];
        let record = TurnReport::new(
            &TurnDiff::between(&[], &after),
            TurnBase::default(),
            1,
            0,
            gate(),
        );
        assert_eq!(record.verdict, Verdict::Blocked);
        assert_eq!(record.counts.introduced, 1);

        let carried = TurnReport::new(
            &TurnDiff::between(&after, &after),
            TurnBase::default(),
            1,
            0,
            gate(),
        );
        assert_eq!(carried.verdict, Verdict::Clean);
        assert_eq!(carried.counts.carried, 1);
        assert!(carried.introduced.is_empty());
    }

    #[test]
    fn something_introduced_below_the_bar_is_clean_but_not_silent() {
        // `clean` here means *clean at the threshold*, and the record has to
        // carry both numbers so the reporter can say which. A verdict that
        // collapsed them would print "nothing introduced" over a finding the
        // turn had just added.
        let after = vec![built(
            "insecure-cookie",
            "a.ts",
            4,
            "secure: false",
            Severity::Medium,
            Confidence::Likely,
        )];
        let record = TurnReport::new(
            &TurnDiff::between(&[], &after),
            TurnBase::default(),
            1,
            0,
            TurnGate {
                fail_on: Severity::High,
                min_confidence: Confidence::Possible,
                fail_on_exposure: None,
            },
        );
        assert_eq!(record.verdict, Verdict::Clean);
        assert_eq!(record.counts.introduced, 1);
        assert_eq!(record.blocking, 0);
        assert_eq!(
            record.introduced.len(),
            1,
            "still reported, just not blocking"
        );
    }

    #[test]
    fn a_record_is_byte_identical_apart_from_its_timestamp() {
        // The property that makes a recorded verdict re-derivable rather than
        // merely trusted: same inputs, same bytes.
        let before = vec![at("insecure-cookie", "a.ts", 4, "secure: false")];
        let after = vec![at("stack-trace-leak", "b.ts", 9, "err.stack")];
        let diff = TurnDiff::between(&before, &after);
        let base = TurnBase {
            reference: "HEAD".to_owned(),
            commit: Some("a1b2c3d".to_owned()),
        };

        let left = TurnReport::new(&diff, base.clone(), 2, 41, gate());
        let right = TurnReport::new(&diff, base, 2, 41, gate());

        let strip = |record: &TurnReport| {
            let mut value = serde_json::to_value(record).unwrap();
            value.as_object_mut().unwrap().remove("recordedAt");
            value
        };
        assert_eq!(strip(&left), strip(&right));
    }

    #[test]
    fn carried_and_fixed_are_named_but_not_rendered() {
        // A carried finding printed in full is the flat list this command
        // exists to stop producing.
        let before = vec![
            at("insecure-cookie", "a.ts", 4, "secure: false"),
            at("cors-permissive", "b.ts", 2, "origin: '*'"),
        ];
        let after = vec![at("insecure-cookie", "a.ts", 4, "secure: false")];
        let record = TurnReport::new(
            &TurnDiff::between(&before, &after),
            TurnBase::default(),
            2,
            0,
            gate(),
        );
        assert_eq!(record.carried.len(), 1);
        assert_eq!(record.fixed.len(), 1);
        assert_eq!(record.fixed[0].id, "cors-permissive");
        assert_eq!(record.fixed[0].at, "b.ts:2");
        assert!(!record.fixed[0].fingerprint.is_empty());
    }

    #[test]
    fn a_turn_that_only_fixes_things_is_clean() {
        let before = vec![at("stack-trace-leak", "a.ts", 3, "err.stack")];
        let diff = TurnDiff::between(&before, &[]);
        assert_eq!(diff.counts().fixed, 1);
        assert!(!diff.should_fail(Severity::Info, Confidence::Possible, None));
    }
}
