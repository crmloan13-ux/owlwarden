//! Parsing a single file with oxc, and handing the AST to a closure.
//!
//! The AST lives in an arena that is dropped when this function returns, which
//! is why the API is "call me back" rather than "here is your AST". That is
//! also the reason [`SourceProvider::ast`](owlwarden_core::SourceProvider) does
//! not exist — see the note in `owlwarden_core::source`.

use std::path::Path;

use owlwarden_core::detector::DetectorError;
use owlwarden_core::limits;
use owlwarden_core::source::RelPath;
use oxc_allocator::Allocator;
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

use crate::line_index::LineIndex;
use crate::unit::{FileUnit, UnitMeta};

/// A file that could not be parsed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ParseFailure {
    /// Project-relative path.
    pub path: String,
    /// First parser diagnostic, or a description of the fatal failure.
    pub message: String,
}

impl From<ParseFailure> for DetectorError {
    fn from(failure: ParseFailure) -> Self {
        Self::Parse {
            path: failure.path,
            message: failure.message,
        }
    }
}

/// Bracket nesting a file may contain before we refuse to parse it.
///
/// See [`limits::source::MAX_NESTING_DEPTH`].
const MAX_NESTING_DEPTH: u32 = limits::source::MAX_NESTING_DEPTH;

/// Cheap upper bound on how deeply the file nests.
///
/// Walks with a small state machine so brackets inside strings and comments do
/// not cancel real nesting (`f(/*)*/` must not look shallow). Also counts
/// `<`/`>` so nested generics / JSX cannot bypass the guard — over-estimating
/// on a comparison-heavy file skips it (safe) rather than under-estimating and
/// letting oxc abort the process.
fn exceeds_nesting_limit(source: &str) -> bool {
    let mut bracket_depth: u32 = 0;
    let mut angle_depth: u32 = 0;
    let mut state = ScanState::Normal;
    let bytes = source.as_bytes();
    let mut index = 0usize;

    while let Some(&byte) = bytes.get(index) {
        match state {
            ScanState::Normal => match byte {
                b'/' if bytes.get(index + 1) == Some(&b'/') => {
                    state = ScanState::LineComment;
                    index = index.saturating_add(2);
                    continue;
                }
                b'/' if bytes.get(index + 1) == Some(&b'*') => {
                    state = ScanState::BlockComment;
                    index = index.saturating_add(2);
                    continue;
                }
                b'"' => state = ScanState::DoubleString,
                b'\'' => state = ScanState::SingleString,
                // Treat templates as opaque: brackets inside `${…}` are rare as
                // an attack shape compared with generics / comment tricks, and
                // re-entering Normal for `${` without a matching state for `}`
                // is how under-counts creep back in.
                b'`' => state = ScanState::Template,
                b'(' | b'[' | b'{' => {
                    bracket_depth = bracket_depth.saturating_add(1);
                    if bracket_depth.saturating_add(angle_depth) > MAX_NESTING_DEPTH {
                        return true;
                    }
                }
                b')' | b']' | b'}' => bracket_depth = bracket_depth.saturating_sub(1),
                // `<` only when it looks like generics/JSX (`Foo<`, `<div`, `<>`),
                // not comparisons (`a < b`) or shifts (`<<`, `<=`).
                b'<' if is_type_or_jsx_open(bytes, index) => {
                    angle_depth = angle_depth.saturating_add(1);
                    if bracket_depth.saturating_add(angle_depth) > MAX_NESTING_DEPTH {
                        return true;
                    }
                }
                // Only close an angle we opened — stray `>` from `a > b` / `=>`
                // must not cancel paren depth. Nested generics use `>>` / `>>>`
                // as consecutive closers, so each `>` decrements once.
                b'>' if angle_depth > 0 => {
                    angle_depth = angle_depth.saturating_sub(1);
                }
                _ => {}
            },
            ScanState::LineComment => {
                if byte == b'\n' {
                    state = ScanState::Normal;
                }
            }
            ScanState::BlockComment => {
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    state = ScanState::Normal;
                    index = index.saturating_add(2);
                    continue;
                }
            }
            ScanState::DoubleString => match byte {
                b'\\' => {
                    index = index.saturating_add(2);
                    continue;
                }
                b'"' => state = ScanState::Normal,
                _ => {}
            },
            ScanState::SingleString => match byte {
                b'\\' => {
                    index = index.saturating_add(2);
                    continue;
                }
                b'\'' => state = ScanState::Normal,
                _ => {}
            },
            ScanState::Template => match byte {
                b'\\' => {
                    index = index.saturating_add(2);
                    continue;
                }
                b'`' => state = ScanState::Normal,
                // Count brackets inside templates too. Leaving them opaque let
                // `${((((…` bypass the guard and reach oxc's recursive descent.
                b'(' | b'[' | b'{' => {
                    bracket_depth = bracket_depth.saturating_add(1);
                    if bracket_depth.saturating_add(angle_depth) > MAX_NESTING_DEPTH {
                        return true;
                    }
                }
                b')' | b']' | b'}' => bracket_depth = bracket_depth.saturating_sub(1),
                _ => {}
            },
        }
        index = index.saturating_add(1);
    }
    false
}

#[derive(Clone, Copy)]
enum ScanState {
    Normal,
    LineComment,
    BlockComment,
    DoubleString,
    SingleString,
    Template,
}

/// `Foo<Bar`, `<div`, `</div`, `<>` — not `a < b`, `<=`, `<<`.
fn is_type_or_jsx_open(bytes: &[u8], index: usize) -> bool {
    matches!(
        bytes.get(index + 1).copied(),
        Some(b'A'..=b'Z' | b'a'..=b'z' | b'_' | b'$' | b'/' | b'>')
    )
}

/// Parses `source` and runs `f` against the resulting AST.
///
/// A file with syntax errors is **not** analysed. Rules reason about shapes in
/// the tree, and oxc's error recovery produces a tree that is plausible rather
/// than true — running rules over it invents findings that are not in the
/// user's code. The user's own compiler will report the syntax error; we say
/// nothing about the file and record that we skipped it.
///
/// # Errors
/// [`ParseFailure`] when the file does not parse cleanly.
pub fn with_parsed<T>(
    path: &RelPath,
    source: &str,
    meta: UnitMeta,
    f: impl FnOnce(&FileUnit<'_>) -> T,
) -> Result<T, ParseFailure> {
    if exceeds_nesting_limit(source) {
        return Err(ParseFailure {
            path: path.to_string(),
            message: format!("nesting exceeds the {MAX_NESTING_DEPTH}-level parser limit"),
        });
    }

    let source_type = SourceType::from_path(Path::new(path.as_str())).unwrap_or_else(|_| {
        // Only reachable for an extension the engine should have filtered out
        // already; TSX is the most permissive superset, so it recovers the most.
        SourceType::tsx()
    });

    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            // We never inspect regex internals, and parsing them is a
            // measurable slice of total parse time.
            parse_regular_expression: false,
            ..ParseOptions::default()
        })
        .parse();

    if parsed.panicked {
        return Err(ParseFailure {
            path: path.to_string(),
            message: "parser could not recover".to_owned(),
        });
    }
    if let Some(first) = parsed.diagnostics.first() {
        return Err(ParseFailure {
            path: path.to_string(),
            message: first.to_string(),
        });
    }

    let unit = FileUnit {
        path,
        source,
        program: &parsed.program,
        line_index: LineIndex::new(source),
        meta,
    };
    Ok(f(&unit))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn rel(path: &str) -> RelPath {
        RelPath::new(Path::new(path)).unwrap()
    }

    fn meta() -> UnitMeta {
        UnitMeta::generic()
    }

    #[test]
    fn parses_typescript_with_types_and_decorators() {
        let path = rel("src/users.controller.ts");
        let source = r"
@Controller('users')
export class UsersController {
  @Get()
  findAll(): Promise<User[]> { return this.service.findAll() }
}
";
        let body_count =
            with_parsed(&path, source, meta(), |unit| unit.program.body.len()).unwrap();
        assert_eq!(body_count, 1);
    }

    #[test]
    fn parses_tsx() {
        let path = rel("app/page.tsx");
        let source = "export default function Page() { return <div>hi</div> }";
        assert!(with_parsed(&path, source, meta(), |_| ()).is_ok());
    }

    #[test]
    fn a_file_with_syntax_errors_is_refused_rather_than_guessed() {
        let path = rel("broken.ts");
        let failure = with_parsed(&path, "export function ( { {", meta(), |_| ()).unwrap_err();
        assert_eq!(failure.path, "broken.ts");
        assert!(!failure.message.is_empty());
    }

    #[test]
    fn deeply_nested_input_is_refused_before_it_can_overflow_the_stack() {
        // Without the guard this aborts the whole process, tests included.
        let path = rel("nested.ts");
        let source = format!("const a = {}1{};", "(".repeat(20_000), ")".repeat(20_000));
        let failure = with_parsed(&path, &source, meta(), |_| ()).unwrap_err();
        assert!(
            failure.message.contains("nesting"),
            "expected the depth guard, got: {}",
            failure.message
        );
    }

    #[test]
    fn nested_generics_are_refused() {
        let path = rel("generics.ts");
        let mut inner = String::new();
        for _ in 0..300 {
            inner.push_str("A<");
        }
        for _ in 0..300 {
            inner.push('>');
        }
        let source = format!("type T = {inner};");
        let failure = with_parsed(&path, &source, meta(), |_| ()).unwrap_err();
        assert!(failure.message.contains("nesting"));
    }

    #[test]
    fn closing_paren_inside_block_comment_does_not_cancel_nesting() {
        let path = rel("comment-nest.ts");
        let mut source = String::new();
        for _ in 0..300 {
            source.push_str("f(/*)*/");
        }
        source.push('1');
        for _ in 0..300 {
            source.push(')');
        }
        let failure = with_parsed(&path, &source, meta(), |_| ()).unwrap_err();
        assert!(failure.message.contains("nesting"));
    }

    #[test]
    fn ordinary_nesting_is_not_refused() {
        // Deeply-chained but realistic code must still be analysed.
        let path = rel("nested.ts");
        let source = format!("const a = {}1{};", "(".repeat(64), ")".repeat(64));
        assert!(with_parsed(&path, &source, meta(), |_| ()).is_ok());
    }

    #[test]
    fn empty_file_parses_to_an_empty_program() {
        let path = rel("empty.ts");
        let count = with_parsed(&path, "", meta(), |unit| unit.program.body.len()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn string_brackets_do_not_inflate_depth() {
        let source = format!("const s = \"{}\";", "(".repeat(300));
        assert!(!exceeds_nesting_limit(&source));
    }

    #[test]
    fn template_expression_brackets_are_counted() {
        let path = rel("template-nest.ts");
        let mut source = String::from("const x = `${");
        for _ in 0..300 {
            source.push('(');
        }
        source.push('1');
        for _ in 0..300 {
            source.push(')');
        }
        source.push_str("}`;");
        let failure = with_parsed(&path, &source, meta(), |_| ()).unwrap_err();
        assert!(
            failure.message.contains("nesting"),
            "expected the depth guard, got: {}",
            failure.message
        );
    }

    #[test]
    fn template_braces_and_brackets_are_counted() {
        // N2 regression: `{}` / `[]` inside `${…}` must deepen the guard, not
        // only `()`.
        let mut source = String::from("const x = `${");
        for _ in 0..300 {
            source.push('{');
        }
        source.push('1');
        for _ in 0..300 {
            source.push('}');
        }
        source.push_str("}`;");
        assert!(
            exceeds_nesting_limit(&source),
            "braces inside a template expression must count"
        );

        let mut source = String::from("const x = `${");
        for _ in 0..300 {
            source.push('[');
        }
        source.push('1');
        for _ in 0..300 {
            source.push(']');
        }
        source.push_str("}`;");
        assert!(
            exceeds_nesting_limit(&source),
            "brackets inside a template expression must count"
        );
    }

    #[test]
    fn deep_brackets_in_template_static_chunks_are_over_estimated() {
        // The guard counts every bracket while inside `` `…` ``, including the
        // static chunks. That over-skips comparison-heavy templates, which is
        // the safe side of ADR 0008 — under-counting is what we refuse.
        let source = format!("const s = `{}`;", "(".repeat(300));
        assert!(exceeds_nesting_limit(&source));
    }
}
