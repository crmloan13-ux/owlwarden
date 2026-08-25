//! `StaticEngine` — the [`Detector`] that owns the static rules.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use owlwarden_core::context::ScanContext;
use owlwarden_core::detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
use owlwarden_core::finding::{Confidence, Finding, RuleId, Severity};
use owlwarden_core::limits;
use owlwarden_core::surface::Surface;

use crate::project::Project;
use crate::rule::{FileRule, FindingSink, ProjectRule};

/// Skipped files remembered for the report. Enough to see the pattern, few
/// enough that a repository full of broken files does not produce a report
/// longer than the code.
const MAX_REMEMBERED_SKIPS: usize = 10;

/// What the last run actually did. Read by the runner to fill in the report
/// header and to surface files we could not analyse.
#[derive(Debug, Clone, Default)]
pub struct EngineStats {
    /// Files read and parsed successfully.
    pub files_scanned: u32,
    /// Files a rule wanted but which could not be read or parsed.
    pub files_skipped: u32,
    /// A sample of the skips, as `path: reason`.
    pub skip_examples: Vec<String>,
    /// True when a per-file or global findings cap dropped results.
    pub truncated: bool,
}

/// Runs every static rule over one project.
///
/// One engine is one [`Detector`] from the scheduler's point of view. Rule
/// identity travels on the findings; the engine's own id appears only if the
/// whole engine fails.
pub struct StaticEngine {
    file_rules: Vec<Arc<dyn FileRule>>,
    project_rules: Vec<Arc<dyn ProjectRule>>,
    stats: Mutex<EngineStats>,
}

impl StaticEngine {
    /// Builds an engine from a selected rule set — typically the rules a preset
    /// enabled.
    #[must_use]
    pub fn new(
        file_rules: Vec<Arc<dyn FileRule>>,
        project_rules: Vec<Arc<dyn ProjectRule>>,
    ) -> Self {
        Self {
            file_rules,
            project_rules,
            stats: Mutex::new(EngineStats::default()),
        }
    }

    /// Statistics from the most recent run.
    ///
    /// Returns the default when the lock is poisoned: a panicked rule should
    /// cost us the statistics, not the whole report.
    #[must_use]
    pub fn stats(&self) -> EngineStats {
        self.stats
            .lock()
            .map(|stats| stats.clone())
            .unwrap_or_default()
    }

    /// Number of rules that will run.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.file_rules.len() + self.project_rules.len()
    }

    /// Metadata for every rule in the engine, for `RULES.md` and `list_rules`.
    #[must_use]
    pub fn rule_metas(&self) -> Vec<DetectorMeta> {
        self.project_rules
            .iter()
            .map(|rule| rule.meta())
            .chain(self.file_rules.iter().map(|rule| rule.meta()))
            .collect()
    }

    /// Surfaces agent-workspace files that could not be read or parsed.
    ///
    /// Only when a rule that reads that surface is actually enabled: a
    /// `--preset owasp-top10` run has no business reporting on a malformed
    /// `.cursor/hooks.json` it never intended to look at.
    ///
    /// These go through the skip channel rather than becoming findings of their
    /// own, for two reasons. The rule count stays a count of *security rules*,
    /// which is what a reader compares between tools. And "we could not read
    /// this file" is a statement about the scan, not about the code — the same
    /// category as an unparseable source file, reported the same way, so a
    /// consumer already handling one handles both.
    fn note_unreadable_agent_config(&self, project: &Project<'_>) {
        if !self
            .project_rules
            .iter()
            .any(|rule| rule.meta().surface == Surface::AgentWorkspace)
        {
            return;
        }
        let workspace = project.agent_workspace();
        for unreadable in workspace.unreadable() {
            self.remember_skip(&unreadable.path, &unreadable.reason);
        }
        if workspace.truncated() {
            self.mark_truncated();
        }
    }

    /// Runs the project-wide rules.
    fn run_project_rules(&self, project: &Project<'_>, findings: &mut Vec<Finding>) {
        for rule in &self.project_rules {
            let mut sink = FindingSink::new();
            // A project rule that fails is recorded as a skip, not as a scan
            // failure: the other rules still have something useful to say.
            if let Err(error) = rule.check(project, &mut sink) {
                self.remember_skip(&rule.meta().id.to_string(), &error.to_string());
                continue;
            }
            let hit_cap = sink.truncated();
            findings.append(&mut sink.drain());
            if hit_cap {
                self.mark_truncated();
            }
        }
    }

    /// Runs the per-file rules, parsing each interested file exactly once.
    ///
    /// When `dirty_paths` is set, only those project-relative paths are parsed.
    fn run_file_rules(
        &self,
        project: &Project<'_>,
        findings: &mut Vec<Finding>,
        dirty_paths: Option<&HashSet<String>>,
    ) {
        let mut scanned = 0u32;

        for file in project.files().iter().take(limits::source::MAX_FILES) {
            if findings.len() >= limits::scan::MAX_FINDINGS {
                self.mark_truncated();
                break;
            }

            if let Some(dirty) = dirty_paths
                && !dirty.contains(file.path.as_str())
            {
                continue;
            }

            let interested: Vec<&Arc<dyn FileRule>> = self
                .file_rules
                .iter()
                .filter(|rule| rule.applies_to(&file.path))
                .collect();
            if interested.is_empty() {
                continue;
            }

            let parsed = project.with_parsed_file(file, |unit| {
                let mut sink = FindingSink::new();
                for rule in interested {
                    rule.check(unit, &mut sink);
                }
                let hit_cap = sink.truncated();
                (sink.drain(), hit_cap)
            });

            match parsed {
                Ok((mut produced, hit_cap)) => {
                    scanned = scanned.saturating_add(1);
                    findings.append(&mut produced);
                    if hit_cap {
                        self.mark_truncated();
                    }
                }
                Err(error) => self.remember_skip(file.path.as_str(), &error.to_string()),
            }
        }

        if let Ok(mut stats) = self.stats.lock() {
            stats.files_scanned = scanned;
        }
    }

    /// Records a file or rule we could not process.
    fn remember_skip(&self, subject: &str, reason: &str) {
        let Ok(mut stats) = self.stats.lock() else {
            return;
        };
        stats.files_skipped = stats.files_skipped.saturating_add(1);
        if stats.skip_examples.len() < MAX_REMEMBERED_SKIPS {
            stats.skip_examples.push(format!("{subject}: {reason}"));
        }
    }

    fn mark_truncated(&self) {
        if let Ok(mut stats) = self.stats.lock() {
            stats.truncated = true;
        }
    }
}

#[async_trait]
impl Detector for StaticEngine {
    fn meta(&self) -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static("static-engine"),
            title: "Static analysis engine".into(),
            severity: Severity::Info,
            // The engine itself never produces findings; its rules do, and each
            // carries its own ceiling.
            max_confidence: Confidence::Likely,
            owasp: None,
            asi: None,
            cwe: None,
            surface: Surface::WebApp,
            category: "engine".into(),
            description: "Parses project source with oxc and runs the enabled static rules.".into(),
        }
    }

    fn kind(&self) -> DetectorKind {
        DetectorKind::Static
    }

    fn capabilities(&self) -> Capabilities {
        // Reads source, touches nothing else. This is why a v0.0 scan is
        // passive by construction rather than by promise.
        Capabilities::source_only()
    }

    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        if let Ok(mut stats) = self.stats.lock() {
            *stats = EngineStats::default();
        }

        let project = Project::discover(ctx.source())?;
        let mut findings = Vec::new();

        let dirty_paths = ctx
            .settings()
            .dirty_paths
            .as_ref()
            .filter(|paths| !paths.is_empty())
            .map(|paths| paths.iter().cloned().collect::<HashSet<String>>());

        self.run_project_rules(&project, &mut findings);
        self.run_file_rules(&project, &mut findings, dirty_paths.as_ref());
        self.note_unreadable_agent_config(&project);

        // The scope ceiling is applied here rather than in each rule. Eleven
        // rules that had to remember it is eleven chances to forget, and the
        // failure mode — a fenced example in a tutorial reported like a live
        // config — is the one that gets a rule family switched off.
        for finding in &mut findings {
            finding.apply_runtime_scope_ceiling();
        }

        if findings.len() > limits::scan::MAX_FINDINGS {
            findings.truncate(limits::scan::MAX_FINDINGS);
            self.mark_truncated();
        }
        Ok(findings)
    }
}
