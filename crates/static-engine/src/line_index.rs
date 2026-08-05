//! Byte offsets in, human positions and code frames out.
//!
//! oxc reports spans as byte offsets. Users read line and column numbers, and
//! editors count columns in characters, not bytes — so a file with a Thai
//! comment or an emoji in a string must not shift the underline. Everything
//! here counts characters and is tested against multi-byte input.

use owlwarden_core::finding::{CodeFrame, Highlight};

/// Lines of context shown on each side of a finding. Two is enough to see the
/// surrounding statement without turning the report into a file listing.
const CONTEXT_LINES: u32 = 2;

/// Longest line a code frame will reproduce. A minified bundle on one 200 kB
/// line would otherwise be pasted whole into the report.
const MAX_FRAME_LINE_CHARS: usize = 400;

/// Start offsets of every line in a source file.
#[derive(Debug, Clone)]
pub struct LineIndex {
    /// Byte offset of the first character of each line.
    line_starts: Vec<u32>,
    /// Length of the source in bytes.
    source_len: u32,
}

impl LineIndex {
    /// Builds the index. O(n) once per file; every lookup after that is a
    /// binary search.
    #[must_use]
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0u32];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                // Saturating cast: files over 4 GiB are impossible here, the
                // source provider caps them at 2 MiB.
                let next = u32::try_from(offset + 1).unwrap_or(u32::MAX);
                line_starts.push(next);
            }
        }
        Self {
            line_starts,
            source_len: u32::try_from(source.len()).unwrap_or(u32::MAX),
        }
    }

    /// Number of lines. A file with no trailing newline still counts its last
    /// line.
    #[must_use]
    pub fn line_count(&self) -> u32 {
        u32::try_from(self.line_starts.len()).unwrap_or(u32::MAX)
    }

    /// 1-based line number containing `offset`.
    #[must_use]
    pub fn line_of(&self, offset: u32) -> u32 {
        match self.line_starts.binary_search(&offset) {
            // Exactly on a line start.
            Ok(index) => u32::try_from(index + 1).unwrap_or(u32::MAX),
            // Between starts: `index` is the insertion point, so the line is
            // the one before it.
            Err(index) => u32::try_from(index.max(1)).unwrap_or(u32::MAX),
        }
    }

    /// Byte offset where a 1-based line starts.
    #[must_use]
    pub fn line_start(&self, line: u32) -> u32 {
        let index = usize::try_from(line.saturating_sub(1)).unwrap_or(0);
        self.line_starts
            .get(index)
            .copied()
            .unwrap_or(self.source_len)
    }

    /// Byte offset just past the end of a 1-based line, excluding the newline.
    #[must_use]
    pub fn line_end(&self, line: u32) -> u32 {
        let index = usize::try_from(line).unwrap_or(usize::MAX);
        self.line_starts
            .get(index)
            .map_or(self.source_len, |next| next.saturating_sub(1))
    }

    /// 1-based `(line, column)` for a byte offset, with the column counted in
    /// characters.
    #[must_use]
    pub fn position(&self, source: &str, offset: u32) -> (u32, u32) {
        let line = self.line_of(offset);
        let start = self.line_start(line);
        let column = char_distance(source, start, offset).saturating_add(1);
        (line, column)
    }

    /// The text of a 1-based line, without its newline.
    #[must_use]
    pub fn line_text<'src>(&self, source: &'src str, line: u32) -> &'src str {
        let start = usize::try_from(self.line_start(line)).unwrap_or(0);
        let end = usize::try_from(self.line_end(line)).unwrap_or(0);
        source.get(start..end.max(start)).unwrap_or("")
    }

    /// Builds the code frame for a byte span.
    ///
    /// A span covering several lines is underlined only on its first line —
    /// the reader needs one place to look, and the following lines are shown as
    /// context anyway.
    #[must_use]
    pub fn code_frame(
        &self,
        source: &str,
        path: &str,
        span: (u32, u32),
        label: Option<String>,
    ) -> CodeFrame {
        let (start_offset, end_offset) = span;
        let (line, start_col) = self.position(source, start_offset);

        // Clamp the underline to the line the span starts on.
        let line_end = self.line_end(line);
        let clamped_end = end_offset.min(line_end).max(start_offset);
        let end_col = char_distance(source, self.line_start(line), clamped_end).saturating_add(1);

        let first = line.saturating_sub(CONTEXT_LINES).max(1);
        let last = line
            .saturating_add(CONTEXT_LINES)
            .min(self.line_count().max(1));

        let mut lines = Vec::new();
        for current in first..=last {
            lines.push(truncate_chars(
                self.line_text(source, current),
                MAX_FRAME_LINE_CHARS,
            ));
        }
        // A file ending in a newline has a final empty line. Showing it as
        // context is just a blank row under the finding, so drop trailing
        // blanks — but never past the highlighted line itself.
        let keep_at_least = usize::try_from(line.saturating_sub(first)).unwrap_or(0) + 1;
        while lines.len() > keep_at_least && lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }

        CodeFrame {
            path: path.to_owned(),
            start_line: first,
            lines,
            highlight: Highlight {
                line,
                start_col,
                // A zero-width span still underlines one character; an empty
                // `~` run reads as a rendering bug.
                end_col: end_col.max(start_col.saturating_add(1)),
                label,
            },
        }
    }
}

/// Characters between two byte offsets. Out-of-range offsets yield 0 rather
/// than panicking — a bad span from a parser must not take down a scan.
fn char_distance(source: &str, from: u32, to: u32) -> u32 {
    let from = usize::try_from(from).unwrap_or(0);
    let to = usize::try_from(to).unwrap_or(0);
    if to <= from {
        return 0;
    }
    let Some(slice) = source.get(from..to) else {
        return 0;
    };
    u32::try_from(slice.chars().count()).unwrap_or(u32::MAX)
}

/// Cuts a line to `max` characters, marking the cut so nobody reads a truncated
/// line as the whole line.
fn truncate_chars(line: &str, max: usize) -> String {
    if line.chars().count() <= max {
        return line.to_owned();
    }
    let kept: String = line.chars().take(max).collect();
    format!("{kept}… (line truncated)")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const SOURCE: &str = "const a = 1\nconst b = 2\nconst c = 3\n";

    #[test]
    fn positions_are_one_based() {
        let index = LineIndex::new(SOURCE);
        assert_eq!(index.position(SOURCE, 0), (1, 1));
        assert_eq!(index.position(SOURCE, 6), (1, 7));
        assert_eq!(index.position(SOURCE, 12), (2, 1));
        assert_eq!(index.position(SOURCE, 24), (3, 1));
    }

    #[test]
    fn columns_count_characters_not_bytes() {
        // "ปลอดภัย" is 21 bytes and 7 characters; the column after it must be 8,
        // or the underline lands in the wrong place in the user's editor.
        let source = "const ปลอดภัย = err.stack";
        let index = LineIndex::new(source);
        let offset = u32::try_from(source.find("err").unwrap()).unwrap();
        let (line, col) = index.position(source, offset);
        assert_eq!(line, 1);
        assert_eq!(
            col,
            u32::try_from("const ปลอดภัย = ".chars().count() + 1).unwrap()
        );
    }

    #[test]
    fn code_frame_shows_two_lines_of_context() {
        let index = LineIndex::new(SOURCE);
        let start = u32::try_from(SOURCE.find("const b").unwrap()).unwrap();
        let frame = index.code_frame(SOURCE, "a.ts", (start, start + 5), Some("here".into()));

        assert_eq!(frame.start_line, 1);
        assert_eq!(frame.lines.len(), 3, "3 lines exist, context is clamped");
        assert_eq!(frame.highlight.line, 2);
        assert_eq!(frame.highlight.start_col, 1);
        assert_eq!(frame.highlight.end_col, 6);
        assert_eq!(frame.highlight.label.as_deref(), Some("here"));
    }

    #[test]
    fn multiline_spans_underline_only_the_first_line() {
        let index = LineIndex::new(SOURCE);
        let frame = index.code_frame(SOURCE, "a.ts", (6, 30), None);
        assert_eq!(frame.highlight.line, 1);
        // Line 1 is 11 characters; the underline must stop there.
        assert_eq!(frame.highlight.end_col, 12);
    }

    #[test]
    fn a_very_long_line_is_truncated() {
        let long = format!("const a = '{}'\n", "x".repeat(5_000));
        let index = LineIndex::new(&long);
        let frame = index.code_frame(&long, "bundle.js", (0, 5), None);
        let first = frame.lines.first().unwrap();
        assert!(first.ends_with("(line truncated)"));
        assert!(first.chars().count() < 500);
    }

    #[test]
    fn out_of_range_offsets_do_not_panic() {
        let index = LineIndex::new(SOURCE);
        let frame = index.code_frame(SOURCE, "a.ts", (9_999, 10_005), None);
        assert!(frame.highlight.line >= 1);
    }

    #[test]
    fn empty_source_still_produces_a_position() {
        let index = LineIndex::new("");
        assert_eq!(index.position("", 0), (1, 1));
        assert_eq!(index.line_count(), 1);
    }
}
