//! The external taxonomies owlwarden maps findings onto, as data.
//!
//! Two things depend on this module existing rather than each rule inventing
//! its own category string.
//!
//! **Validation.** A rule declares `owasp: Some(OwaspRef::new_static("A05:2021"))`.
//! Without a catalogue that is an unchecked string: a typo produces a finding
//! that references a category nobody can look up, and a dead link in a security
//! report costs more than a missing one. [`category`] resolves the id, and a
//! test in this crate refuses any built-in rule whose reference does not
//! resolve.
//!
//! **Coverage.** "How much of the OWASP Top 10 does this tool actually check?"
//! is the first question a serious user asks, and the honest answer is a table
//! with gaps in it. [`coverage`] computes that table from the rules that are
//! actually compiled in, so it can never overstate what ships —
//! `docs/explanation/coverage.md` explains how to read it.
//!
//! Keeping the catalogue in `core` rather than in the detector crate means a
//! plugin's rules land in the same table as the built-ins.

use crate::detector::DetectorMeta;
use crate::finding::{OwaspRef, RuleId};

/// One OWASP Top 10 category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Category {
    /// Canonical id, e.g. `"A05:2021"`.
    pub id: &'static str,
    /// Official title, e.g. `"Security Misconfiguration"`.
    pub title: &'static str,
    /// URL slug on owasp.org.
    pub slug: &'static str,
    /// What the category covers, in the words we would use to explain it to
    /// someone who has just been handed a finding.
    pub summary: &'static str,
    /// Whether static source analysis can meaningfully see this category at
    /// all. Recorded so the coverage table can distinguish "we have not written
    /// this rule yet" from "no static rule can answer this" — see
    /// [`Reachability`].
    pub static_reachability: Reachability,
}

impl Category {
    /// The canonical URL for the category.
    #[must_use]
    pub fn url(&self) -> String {
        format!("https://owasp.org/Top10/{}/", self.slug)
    }
}

/// How much of a category a source-reading engine can hope to cover.
///
/// This exists so the coverage table cannot quietly imply that an empty
/// category is merely a backlog item. Some of the Top 10 are properties of a
/// deployment or of a design, and no amount of parsing will find them; saying
/// so is more useful than an ambitious roadmap entry that never lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// The category is largely visible in source. A missing rule here is a gap.
    Good,
    /// Parts are visible; the rest needs runtime, deployment, or design
    /// context.
    Partial,
    /// Essentially invisible to static analysis of application source.
    Poor,
}

impl Reachability {
    /// Short label for the generated catalogue.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Partial => "partial",
            Self::Poor => "poor",
        }
    }
}

/// The OWASP Top 10 (2021), in order.
///
/// 2021 rather than the newer list because rule ids and the `owasp` field are
/// public API: findings emitted today have to keep resolving. Moving to a newer
/// edition is a schema decision with an alias table, not a text edit.
pub const TOP_10_2021: &[Category] = &[
    Category {
        id: "A01:2021",
        title: "Broken Access Control",
        slug: "A01_2021-Broken_Access_Control",
        summary: "Users can act outside their permissions: reaching another tenant's records, \
                  calling an admin route, or changing an id in a URL and getting away with it.",
        // Whether a handler *should* be authorised is a property of the
        // application's intent. A rule can spot a route with no guard at all,
        // but not one with the wrong guard.
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A02:2021",
        title: "Cryptographic Failures",
        slug: "A02_2021-Cryptographic_Failures",
        summary: "Sensitive data is transmitted or stored without adequate protection: plaintext \
                  transport, weak or homemade algorithms, or keys handled as ordinary strings.",
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A03:2021",
        title: "Injection",
        slug: "A03_2021-Injection",
        summary: "Untrusted input reaches an interpreter as code: SQL, shell, template, or the \
                  DOM. The classic and still one of the most damaging classes.",
        // Injection is a source-to-sink question, which is exactly what an AST
        // is for.
        static_reachability: Reachability::Good,
    },
    Category {
        id: "A04:2021",
        title: "Insecure Design",
        slug: "A04_2021-Insecure_Design",
        summary: "The flaw is in what was built, not in how it was coded: a missing rate limit, \
                  a recovery flow that trusts an email address, a threat never considered.",
        // A design flaw is correct code implementing the wrong idea.
        static_reachability: Reachability::Poor,
    },
    Category {
        id: "A05:2021",
        title: "Security Misconfiguration",
        slug: "A05_2021-Security_Misconfiguration",
        summary: "The software is fine; the way it is set up is not. Default credentials, verbose \
                  errors, permissive CORS, missing headers, debug features left enabled.",
        static_reachability: Reachability::Good,
    },
    Category {
        id: "A06:2021",
        title: "Vulnerable and Outdated Components",
        slug: "A06_2021-Vulnerable_and_Outdated_Components",
        summary: "A dependency has a known vulnerability, or is too old to be receiving fixes.",
        // Visible in a lockfile, but answering it means shipping or fetching an
        // advisory database, which is a different tool with different update
        // guarantees. See `docs/explanation/coverage.md`.
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A07:2021",
        title: "Identification and Authentication Failures",
        slug: "A07_2021-Identification_and_Authentication_Failures",
        summary: "Identity can be assumed rather than proven: credentials in source, sessions \
                  that never expire, tokens signed with a guessable key.",
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A08:2021",
        title: "Software and Data Integrity Failures",
        slug: "A08_2021-Software_and_Data_Integrity_Failures",
        summary: "Code or data is trusted without verifying where it came from: unsigned updates, \
                  unpinned CI actions, deserialisation of attacker-controlled payloads.",
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A09:2021",
        title: "Security Logging and Monitoring Failures",
        slug: "A09_2021-Security_Logging_and_Monitoring_Failures",
        summary: "An attack leaves no trace, or the trace itself leaks: unlogged auth failures, \
                  and secrets written into logs.",
        static_reachability: Reachability::Partial,
    },
    Category {
        id: "A10:2021",
        title: "Server-Side Request Forgery (SSRF)",
        slug: "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
        summary: "The server fetches a URL the user chose, and can be pointed at internal \
                  services, cloud metadata endpoints, or the loopback interface.",
        static_reachability: Reachability::Good,
    },
];

/// Resolves a category id such as `"A05:2021"`.
///
/// Returns `None` for anything not in [`TOP_10_2021`]; callers must not
/// synthesise a URL from an unrecognised id.
#[must_use]
pub fn category(id: &str) -> Option<&'static Category> {
    TOP_10_2021.iter().find(|entry| entry.id == id)
}

/// Whether an [`OwaspRef`] names a category we can resolve.
#[must_use]
pub fn is_known(reference: &OwaspRef) -> bool {
    category(reference.as_str()).is_some()
}

/// Which rules cover one category.
#[derive(Debug, Clone)]
pub struct CategoryCoverage {
    /// The category.
    pub category: &'static Category,
    /// Ids of the rules that map to it, sorted. Empty means no coverage.
    pub rules: Vec<RuleId>,
}

impl CategoryCoverage {
    /// Whether any rule maps to this category.
    #[must_use]
    pub fn is_covered(&self) -> bool {
        !self.rules.is_empty()
    }
}

/// Builds the coverage table for a set of rules.
///
/// Every category appears, covered or not. A table that listed only what we
/// check would be an advertisement; the gaps are the useful part, because they
/// tell a reader what owlwarden is *not* looking at in their codebase.
///
/// Rules whose `owasp` field does not resolve are ignored here and caught by
/// the catalogue test instead — a coverage table is not the place to report a
/// bug in our own metadata.
#[must_use]
pub fn coverage(rules: &[DetectorMeta]) -> Vec<CategoryCoverage> {
    TOP_10_2021
        .iter()
        .map(|entry| {
            let mut ids: Vec<RuleId> = rules
                .iter()
                .filter(|meta| {
                    meta.owasp
                        .as_ref()
                        .is_some_and(|reference| reference.as_str() == entry.id)
                })
                .map(|meta| meta.id.clone())
                .collect();
            ids.sort();
            CategoryCoverage {
                category: entry,
                rules: ids,
            }
        })
        .collect()
}

/// How many of the ten categories have at least one rule.
#[must_use]
pub fn covered_count(table: &[CategoryCoverage]) -> usize {
    table.iter().filter(|entry| entry.is_covered()).count()
}

/// Titles for the CWE entries the built-in rules reference.
///
/// Not the full CWE corpus — that is a 900-entry XML download, and shipping it
/// to render one line of a report is not a trade worth making. Rules reference
/// a small, curated set, and [`cwe_title`] returning `None` for anything else
/// is the honest outcome: the report still carries the number and a working
/// link.
const CWE_TITLES: &[(u32, &str)] = &[
    (89, "SQL Injection"),
    (79, "Cross-site Scripting"),
    (78, "OS Command Injection"),
    (209, "Information Exposure Through an Error Message"),
    (532, "Insertion of Sensitive Information into Log File"),
    (614, "Sensitive Cookie Without 'Secure' Attribute"),
    (693, "Protection Mechanism Failure"),
    (798, "Use of Hard-coded Credentials"),
    (918, "Server-Side Request Forgery"),
    (942, "Permissive Cross-domain Policy"),
    (1004, "Sensitive Cookie Without 'HttpOnly' Flag"),
    (1275, "Sensitive Cookie with Improper SameSite Attribute"),
];

/// The short title for a CWE number, when we ship one.
#[must_use]
pub fn cwe_title(id: u32) -> Option<&'static str> {
    CWE_TITLES
        .iter()
        .find(|(number, _)| *number == id)
        .map(|(_, title)| *title)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::finding::{Confidence, Severity};

    fn meta(id: &'static str, owasp: Option<&'static str>) -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(id),
            title: "t",
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: owasp.map(OwaspRef::new_static),
            cwe: None,
            category: "c",
            description: "d",
        }
    }

    #[test]
    fn the_catalogue_is_the_whole_top_ten_in_order() {
        assert_eq!(TOP_10_2021.len(), 10);
        for (index, entry) in TOP_10_2021.iter().enumerate() {
            let expected = format!("A{:02}:2021", index + 1);
            assert_eq!(entry.id, expected, "categories must be in order");
            assert!(!entry.title.is_empty());
            assert!(!entry.summary.is_empty());
            assert!(entry.url().starts_with("https://owasp.org/Top10/"));
        }
    }

    #[test]
    fn an_unknown_category_does_not_resolve() {
        assert!(category("A11:2021").is_none());
        assert!(category("a05:2021").is_none(), "ids are case-sensitive");
        assert!(category("").is_none());
        assert!(!is_known(&OwaspRef::new_static("A05-2021")));
    }

    #[test]
    fn coverage_lists_every_category_including_the_empty_ones() {
        let table = coverage(&[meta("rule-a", Some("A03:2021"))]);
        assert_eq!(table.len(), 10);
        assert_eq!(covered_count(&table), 1);

        let injection = table
            .iter()
            .find(|entry| entry.category.id == "A03:2021")
            .expect("A03 is in the catalogue");
        assert_eq!(injection.rules.len(), 1);
        assert!(injection.is_covered());

        let access = table
            .iter()
            .find(|entry| entry.category.id == "A01:2021")
            .expect("A01 is in the catalogue");
        assert!(
            !access.is_covered(),
            "an uncovered category is still listed"
        );
    }

    #[test]
    fn rules_with_no_or_unknown_mapping_do_not_land_anywhere() {
        let table = coverage(&[meta("rule-a", None), meta("rule-b", Some("A99:2021"))]);
        assert_eq!(covered_count(&table), 0);
    }

    #[test]
    fn coverage_is_sorted_so_the_catalogue_diff_is_stable() {
        let table = coverage(&[
            meta("zeta", Some("A05:2021")),
            meta("alpha", Some("A05:2021")),
        ]);
        let misconfiguration = table
            .iter()
            .find(|entry| entry.category.id == "A05:2021")
            .expect("A05 is in the catalogue");
        let ids: Vec<&str> = misconfiguration.rules.iter().map(RuleId::as_str).collect();
        assert_eq!(ids, ["alpha", "zeta"]);
    }
}
