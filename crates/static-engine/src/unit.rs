//! `FileUnit` — one parsed file, as a rule sees it.
//!
//! Everything a rule needs to turn an AST node into a finding lives here: the
//! tree, the original text, the line index for code frames, and what the
//! project knows about the file — including the detected frameworks, which is
//! how a rule asks "is this a response object?" without hardcoding a name.

use std::sync::Arc;

use owlwarden_core::finding::{CodeFrame, FindingContext, Framework, Location, SourceLocation};
use owlwarden_core::source::RelPath;
use oxc_ast::ast::Program;
use oxc_span::Span;

use crate::framework::{FrameworkSet, RouteInfo};
use crate::line_index::LineIndex;

/// What the project knows about a file, independent of its contents.
#[derive(Debug, Clone)]
pub struct UnitMeta {
    /// Frameworks detected for the project.
    ///
    /// Shared rather than copied: one set is built per scan and every file
    /// points at it, so detection happens once no matter how many files a rule
    /// walks.
    pub frameworks: Arc<FrameworkSet>,
    /// Route the file serves, when the framework routes by file layout.
    pub route: Option<RouteInfo>,
}

impl UnitMeta {
    /// Metadata for a file in a project with no recognised framework.
    #[must_use]
    pub fn generic() -> Self {
        Self {
            frameworks: Arc::new(FrameworkSet::generic_only()),
            route: None,
        }
    }

    /// Metadata for a file in a project known to use one framework.
    ///
    /// Builds the set from the built-in registry and derives the route from the
    /// path, so a single file analysed on its own gets the same context it
    /// would get inside a full scan. That is what a per-file entry point needs
    /// — the editor and agent integrations check one file at a time and must
    /// not produce different findings than `scan` does.
    ///
    /// An unregistered framework id yields the generic profile rather than an
    /// error: analysing the file with baseline knowledge beats refusing.
    #[must_use]
    pub fn for_framework(framework: &Framework, path: &RelPath) -> Self {
        let registry = crate::framework::FrameworkRegistry::builtin();
        let set = registry
            .get(framework)
            .map_or_else(FrameworkSet::generic_only, |profile| {
                FrameworkSet::new(vec![profile], registry.generic())
            });
        let route = set.route(path.as_str());
        Self {
            frameworks: Arc::new(set),
            route,
        }
    }
}

/// One parsed source file.
pub struct FileUnit<'a> {
    /// Project-relative path.
    pub path: &'a RelPath,
    /// The file's text, exactly as read.
    pub source: &'a str,
    /// The parsed program.
    pub program: &'a Program<'a>,
    /// Line offsets, built once per file.
    pub(crate) line_index: LineIndex,
    /// Project-level facts.
    pub meta: UnitMeta,
}

impl FileUnit<'_> {
    /// The frameworks detected for this project.
    #[must_use]
    pub fn frameworks(&self) -> &FrameworkSet {
        &self.meta.frameworks
    }

    /// The framework remediation should be written for.
    #[must_use]
    pub fn framework(&self) -> &Framework {
        self.meta.frameworks.id()
    }

    /// The route this file serves, if the framework routes by file layout.
    #[must_use]
    pub fn route(&self) -> Option<&RouteInfo> {
        self.meta.route.as_ref()
    }

    /// The line index, for rules that need positions directly.
    #[must_use]
    pub fn line_index(&self) -> &LineIndex {
        &self.line_index
    }

    /// 1-based `(line, column)` of a byte offset.
    #[must_use]
    pub fn position(&self, offset: u32) -> (u32, u32) {
        self.line_index.position(self.source, offset)
    }

    /// The [`Location`] for a span.
    #[must_use]
    pub fn location(&self, span: Span) -> Location {
        let (line, col) = self.position(span.start);
        Location::Source(SourceLocation {
            path: self.path.to_string(),
            line,
            col,
        })
    }

    /// The code frame for a span, with the message shown under the underline.
    #[must_use]
    pub fn code_frame(&self, span: Span, label: impl Into<String>) -> CodeFrame {
        self.line_index.code_frame(
            self.source,
            self.path.as_str(),
            (span.start, span.end),
            Some(label.into()),
        )
    }

    /// The text a span covers, for use as finding evidence.
    ///
    /// Capped at `max_chars`, because a span can cover an entire function and
    /// evidence is meant to be a glance, not a listing.
    #[must_use]
    pub fn span_text(&self, span: Span, max_chars: usize) -> String {
        let start = usize::try_from(span.start).unwrap_or(0);
        let end = usize::try_from(span.end).unwrap_or(0);
        let slice = self.source.get(start..end.max(start)).unwrap_or("");
        let collapsed = slice.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.chars().count() <= max_chars {
            return collapsed;
        }
        collapsed.chars().take(max_chars).collect::<String>() + "…"
    }

    /// A [`FindingContext`] pre-filled from what the project knows.
    ///
    /// `method` prefers what the rule observed in the AST — the handler it was
    /// standing in — over the file name, because a Nitro file named
    /// `users.get.ts` states the method for the whole file while a rule may be
    /// inside a nested handler.
    #[must_use]
    pub fn context(&self, method: Option<String>, evidence: Option<String>) -> FindingContext {
        let route = self.meta.route.as_ref();
        FindingContext {
            framework: Some(self.framework().clone()),
            route: route.map(|route| route.path.clone()),
            method: method.or_else(|| route.and_then(|route| route.method.clone())),
            evidence,
        }
    }
}
