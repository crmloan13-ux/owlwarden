//! `Surface` — what kind of artefact a rule reads, and which profile set its
//! remediation table must therefore cover.
//!
//! # The invariant this exists to save
//!
//! From v0.0: *every rule ships remediation for every supported framework, and
//! the build fails otherwise.* That is the reason the framework column in
//! `RULES.md` cannot quietly drift to zero, and it is the most valuable
//! property the rule catalogue has.
//!
//! [ADR 0025](../../../docs/adr/0025-agent-surface-and-supply-chain.md) added
//! rules that read `.claude/settings.json`, where the invariant as written
//! makes no sense: the fix for a hostile `SessionStart` hook is identical
//! across all twelve web frameworks and different across agent hosts. Writing
//! the same paragraph twelve times would satisfy the test and make `RULES.md`
//! dishonest; exempting the new rules would put a hole in the invariant, which
//! is how an invariant dies.
//!
//! So the invariant is generalised rather than weakened. A rule declares its
//! surface; a surface owns a profile set; the matrix test asserts completeness
//! *per surface*. A rule still cannot ship without a concrete fix for every
//! environment it claims to serve — the change is only in what counts as an
//! environment.
//!
//! ```
//! # use owlwarden_core::surface::Surface;
//! assert_eq!(Surface::WebApp.profiles().len(), 16);
//! assert_eq!(Surface::AgentWorkspace.profiles().len(), 7);
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::finding::{AgentHost, Framework};

/// The frameworks every `WebApp` rule is expected to have remediation for.
///
/// Lives here rather than in the detector crate so that both profile sets sit
/// beside each other and neither can be extended without the other being
/// visible in the diff.
pub const SUPPORTED_FRAMEWORKS: &[Framework] = &[
    Framework::NEXT,
    Framework::NUXT,
    Framework::NEST,
    Framework::EXPRESS,
    Framework::FASTIFY,
    Framework::HONO,
    Framework::KOA,
    Framework::HAPI,
    Framework::SAILS,
    Framework::ASTRO,
    Framework::REMIX,
    Framework::GATSBY,
    // Added in 1.2 alongside the runtime overlay. These four are the frameworks
    // most likely to be on a non-Node runtime, so the overlay and the new
    // profiles exercise each other
    // ([ADR 0031](../../../docs/adr/0031-runtime-overlay.md) §5).
    Framework::SVELTEKIT,
    Framework::TANSTACK_START,
    Framework::SOLIDSTART,
    Framework::ELYSIA,
];

/// The agent hosts every `AgentWorkspace` rule is expected to have remediation
/// for.
///
/// `GENERIC` is in the set and is not a placeholder: it is the fix for a host
/// we have never heard of, and keeping it mandatory is what stops this family
/// from becoming an advertisement for the four vendors we happen to know.
pub const SUPPORTED_AGENT_HOSTS: &[AgentHost] = &[
    AgentHost::CLAUDE_CODE,
    AgentHost::CURSOR,
    AgentHost::VSCODE,
    AgentHost::COPILOT,
    AgentHost::CODEX,
    AgentHost::GEMINI_CLI,
    AgentHost::GENERIC,
];

/// What kind of artefact a rule reads.
///
/// Serialized in `DetectorMeta` and defaulting to [`Surface::WebApp`], so a
/// plugin manifest written against `schemaVersion: 1` — which predates this
/// type — keeps loading and keeps being checked against the twelve frameworks
/// ([ADR 0024](../../../docs/adr/0024-plugin-api-v1.md) §9).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum Surface {
    /// Application source. Profiles: [`SUPPORTED_FRAMEWORKS`].
    #[default]
    WebApp,
    /// Agent and editor configuration in the working tree. Profiles:
    /// [`SUPPORTED_AGENT_HOSTS`].
    AgentWorkspace,
}

impl Surface {
    /// Lowercase wire/CLI name (`"webApp"`, `"agentWorkspace"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebApp => "webApp",
            Self::AgentWorkspace => "agentWorkspace",
        }
    }

    /// Human-facing label for the generated catalogue and the coverage table.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WebApp => "web app",
            Self::AgentWorkspace => "agent workspace",
        }
    }

    /// Parses a wire value. Case-insensitive, and tolerant of the
    /// kebab-case spelling a CLI user is likely to type.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "webapp" => Some(Self::WebApp),
            "agentworkspace" => Some(Self::AgentWorkspace),
            _ => None,
        }
    }

    /// The profile set a rule on this surface must cover.
    ///
    /// This is the function the matrix test iterates. Adding a framework or a
    /// host is an edit here plus the remediation cells it makes missing —
    /// which the build then names, one by one.
    #[must_use]
    pub fn profiles(self) -> Vec<Profile> {
        match self {
            Self::WebApp => SUPPORTED_FRAMEWORKS
                .iter()
                .cloned()
                .map(Profile::Framework)
                .collect(),
            Self::AgentWorkspace => SUPPORTED_AGENT_HOSTS
                .iter()
                .cloned()
                .map(Profile::Host)
                .collect(),
        }
    }

    /// Whether this surface can ever produce
    /// [`Confidence::Confirmed`](crate::finding::Confidence::Confirmed).
    ///
    /// `Confirmed` means a static finding corroborated against a *running*
    /// target ([ADR 0014](../../../docs/adr/0014-passive-dynamic-and-correlation.md)).
    /// There is no running target for a config file, and inventing a second
    /// meaning for the word would break the one property this project sells.
    #[must_use]
    pub const fn can_confirm(self) -> bool {
        match self {
            Self::WebApp => true,
            Self::AgentWorkspace => false,
        }
    }
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One entry of a surface's profile set.
///
/// The matrix test, `owlwarden coverage`, and `RULES.md` all walk profiles
/// without caring which set they came from; only remediation lookup cares, and
/// it matches on this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// A web framework.
    Framework(Framework),
    /// An agent or editor host.
    Host(AgentHost),
}

impl Profile {
    /// The wire id, e.g. `"next"` or `"claude-code"`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Framework(framework) => framework.as_str(),
            Self::Host(host) => host.as_str(),
        }
    }

    /// The human-facing label, e.g. `"Next.js"` or `"Claude Code"`.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Framework(framework) => framework.label(),
            Self::Host(host) => host.label(),
        }
    }

    /// The surface this profile belongs to.
    #[must_use]
    pub const fn surface(&self) -> Surface {
        match self {
            Self::Framework(_) => Surface::WebApp,
            Self::Host(_) => Surface::AgentWorkspace,
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn each_surface_owns_a_non_empty_profile_set() {
        for surface in [Surface::WebApp, Surface::AgentWorkspace] {
            let profiles = surface.profiles();
            assert!(!profiles.is_empty(), "{surface} has no profiles");
            for profile in &profiles {
                assert_eq!(profile.surface(), surface);
                assert!(!profile.as_str().is_empty());
                assert!(!profile.label().is_empty());
            }
        }
    }

    #[test]
    fn profile_ids_are_unique_within_a_surface() {
        for surface in [Surface::WebApp, Surface::AgentWorkspace] {
            let mut ids: Vec<String> = surface
                .profiles()
                .iter()
                .map(|profile| profile.as_str().to_owned())
                .collect();
            let count = ids.len();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), count, "duplicate profile id on {surface}");
        }
    }

    #[test]
    fn the_generic_host_is_mandatory() {
        // Dropping it would make the agent family a list of four vendors.
        assert!(SUPPORTED_AGENT_HOSTS.contains(&AgentHost::GENERIC));
    }

    #[test]
    fn confirmed_is_unreachable_on_the_agent_surface() {
        assert!(Surface::WebApp.can_confirm());
        assert!(!Surface::AgentWorkspace.can_confirm());
    }

    #[test]
    fn the_wire_form_round_trips_and_a_typo_does_not_default() {
        for surface in [Surface::WebApp, Surface::AgentWorkspace] {
            assert_eq!(Surface::from_str_opt(surface.as_str()), Some(surface));
            let json = serde_json::to_string(&surface).expect("serializing cannot fail");
            assert_eq!(json, format!("\"{}\"", surface.as_str()));
        }
        assert_eq!(
            Surface::from_str_opt("agent-workspace"),
            Some(Surface::AgentWorkspace)
        );
        assert_eq!(Surface::from_str_opt("agent surface"), None);
    }

    #[test]
    fn an_absent_surface_deserializes_as_web_app() {
        // The plugin API compatibility promise: a manifest written before this
        // field existed still loads, and is still checked against the twelve
        // frameworks rather than against nothing.
        #[derive(serde::Deserialize)]
        struct Holder {
            #[serde(default)]
            surface: Surface,
        }
        let holder: Holder = serde_json::from_str("{}").expect("empty object");
        assert_eq!(holder.surface, Surface::WebApp);
    }
}
