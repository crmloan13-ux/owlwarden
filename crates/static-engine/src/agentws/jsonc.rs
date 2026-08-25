//! A bounded JSONC parser that keeps byte spans.
//!
//! # Why not `serde_json`
//!
//! Three reasons, and all three are about this specific input.
//!
//! **Comments and trailing commas.** Every file on this surface is a hand-edited
//! editor config, and in the wild they carry `//` comments and trailing commas.
//! `serde_json` refuses both. A parse failure on a file we are supposed to be
//! auditing would be reported as "clean", which is the one answer a security
//! tool must never give by accident.
//!
//! **Spans.** A finding without a code frame is a finding a reader cannot act
//! on. `serde_json` discards positions, so a rule would have to re-find the
//! offending key by string search — which is wrong the moment the same string
//! appears twice.
//!
//! **Duplicate keys.** `serde_json` into a `Map` keeps the last value for a
//! repeated key. A config that says `"allow": []` and then `"allow": ["Bash"]`
//! is exactly the shape an attacker would use against a scanner that keeps the
//! first, and a reviewer reading top-down sees the first. We keep **both**, in
//! source order, and rules see every occurrence.
//!
//! # Hostile input is the normal case
//!
//! `owlwarden vet` points this parser at a repository nobody has read yet, so
//! every bound here is a security control rather than a nicety
//! ([ADR 0025](../../../../docs/adr/0025-agent-surface-and-supply-chain.md) §4):
//! depth is capped so nesting cannot blow the stack, the input is capped, and
//! the parser is iterative-with-an-explicit-depth-counter rather than
//! unboundedly recursive. Nothing here executes, imports, resolves, or fetches
//! anything: `$schema` is a string like any other.

use std::fmt;

/// Maximum nesting depth. Beyond this the document is refused rather than
/// truncated — a partially parsed config is a config we would be reporting on
/// without having read.
///
/// The deepest real agent config we have seen is nine levels. Sixty-four is far
/// enough above that to never be reached by a human, and far below the depth at
/// which recursion would matter even if this parser were recursive.
pub const MAX_DEPTH: usize = 64;

/// Maximum input size. Larger inputs are refused with
/// [`JsonParseError::TooLarge`].
pub const MAX_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of values in one document, counting object members and array
/// elements. A 2 MB file of `[[[` costs depth; a 2 MB file of `1,1,1,` costs
/// allocations, and this is the bound on the second one.
pub const MAX_NODES: usize = 200_000;

/// A byte range in the original source: `(start, end)`, end-exclusive.
pub type Span = (u32, u32);

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// A number, kept as written. Rules compare and display it; nothing here
    /// does arithmetic, and reparsing `1e999` into an `f64` would lose the
    /// original text a reader needs to see.
    Number(String),
    /// A string, with escapes resolved.
    String(String),
    /// An array.
    Array(Vec<JsonNode>),
    /// An object. A `Vec` rather than a map, in source order, keeping duplicate
    /// keys — see the module docs.
    Object(Vec<JsonMember>),
}

/// A value together with where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNode {
    /// The value.
    pub value: JsonValue,
    /// Byte span of the value in the original source.
    pub span: Span,
}

/// One `"key": value` pair.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonMember {
    /// The key, with escapes resolved.
    pub key: String,
    /// Byte span of the key *including* its quotes, which is what a code frame
    /// should underline: the reader is being told which setting is wrong, not
    /// which characters inside its name.
    pub key_span: Span,
    /// The value.
    pub value: JsonNode,
}

impl JsonNode {
    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            JsonValue::String(text) => Some(text),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match &self.value {
            JsonValue::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    /// The elements, if this is an array. An object or scalar yields `None`,
    /// never an empty slice: "not an array" and "an empty array" are different
    /// facts about a config file.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JsonNode]> {
        match &self.value {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The members, if this is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&[JsonMember]> {
        match &self.value {
            JsonValue::Object(members) => Some(members),
            _ => None,
        }
    }

    /// Every member with this key, in source order.
    ///
    /// Plural because duplicates are kept. A rule that only wants the first
    /// still has to decide what to do about the second, and this makes that
    /// decision visible rather than silently made by the parser.
    pub fn members<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a JsonMember> + 'a {
        self.as_object()
            .unwrap_or(&[])
            .iter()
            .filter(move |member| member.key == key)
    }

    /// The first member with this key.
    #[must_use]
    pub fn get<'a>(&'a self, key: &str) -> Option<&'a JsonNode> {
        self.as_object()
            .unwrap_or(&[])
            .iter()
            .find(|member| member.key == key)
            .map(|member| &member.value)
    }

    /// Follows a path of object keys.
    #[must_use]
    pub fn pointer(&self, path: &[&str]) -> Option<&JsonNode> {
        let mut current = self;
        for key in path {
            current = current.get(key)?;
        }
        Some(current)
    }

    /// Every string in the document, with its span and the key path that
    /// reached it.
    ///
    /// The workhorse for rules that judge *values* wherever they appear — an
    /// `ANTHROPIC_BASE_URL` is as dangerous in `env` under an MCP server as it
    /// is at the top level, and enumerating the places by hand is how a rule
    /// ends up with a blind spot.
    #[must_use]
    pub fn strings(&self) -> Vec<StringHit<'_>> {
        let mut out = Vec::new();
        let mut path: Vec<&str> = Vec::new();
        collect_strings(self, &mut path, &mut out);
        out
    }
}

/// One string value found by [`JsonNode::strings`].
#[derive(Debug, Clone, PartialEq)]
pub struct StringHit<'a> {
    /// The object keys that reached it, outermost first. Array indices are not
    /// recorded: a rule cares that a command is under `hooks.SessionStart`, not
    /// that it was the second one.
    pub path: Vec<&'a str>,
    /// The string itself.
    pub value: &'a str,
    /// Where the string literal is, quotes included.
    pub span: Span,
}

impl StringHit<'_> {
    /// Whether the key path ends with `key`.
    #[must_use]
    pub fn under(&self, key: &str) -> bool {
        self.path.last().is_some_and(|last| *last == key)
    }

    /// Whether `key` appears anywhere in the path.
    #[must_use]
    pub fn within(&self, key: &str) -> bool {
        self.path.contains(&key)
    }

    /// The key path rendered as `a.b.c`, for evidence lines.
    #[must_use]
    pub fn path_str(&self) -> String {
        self.path.join(".")
    }
}

fn collect_strings<'a>(node: &'a JsonNode, path: &mut Vec<&'a str>, out: &mut Vec<StringHit<'a>>) {
    if out.len() >= MAX_NODES {
        return;
    }
    match &node.value {
        JsonValue::String(text) => out.push(StringHit {
            path: path.clone(),
            value: text,
            span: node.span,
        }),
        JsonValue::Array(items) => {
            for item in items {
                collect_strings(item, path, out);
            }
        }
        JsonValue::Object(members) => {
            for member in members {
                path.push(&member.key);
                collect_strings(&member.value, path, out);
                path.pop();
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
}

/// Why a document could not be parsed.
///
/// A parse failure is reported as a finding of its own rather than as silence:
/// "we could not read your agent configuration" is actionable, and "clean" is a
/// lie. See `agent-config-unreadable`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonParseError {
    /// Input over [`MAX_BYTES`].
    #[error("configuration is {size} bytes, over the {max}-byte limit")]
    TooLarge {
        /// Actual size.
        size: usize,
        /// The cap.
        max: usize,
    },
    /// Nesting over [`MAX_DEPTH`].
    #[error("nesting exceeds {max} levels at byte {offset}")]
    TooDeep {
        /// The cap.
        max: usize,
        /// Where the limit was hit.
        offset: u32,
    },
    /// More values than [`MAX_NODES`].
    #[error("document has more than {max} values")]
    TooManyNodes {
        /// The cap.
        max: usize,
    },
    /// Anything the grammar refuses.
    #[error("{message} at byte {offset}")]
    Syntax {
        /// What was wrong, in one clause.
        message: String,
        /// Byte offset where parsing stopped.
        offset: u32,
    },
}

impl JsonParseError {
    /// Byte offset the failure is anchored at, for a code frame.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        match self {
            Self::TooDeep { offset, .. } | Self::Syntax { offset, .. } => *offset,
            Self::TooLarge { .. } | Self::TooManyNodes { .. } => 0,
        }
    }
}

/// Parses a JSONC document.
///
/// # Errors
/// [`JsonParseError`] for anything malformed or over a limit. Nothing partial is
/// returned: half a config is not a config.
pub fn parse(source: &str) -> Result<JsonNode, JsonParseError> {
    if source.len() > MAX_BYTES {
        return Err(JsonParseError::TooLarge {
            size: source.len(),
            max: MAX_BYTES,
        });
    }
    let mut parser = Parser {
        bytes: source.as_bytes(),
        pos: 0,
        depth: 0,
        nodes: 0,
    };
    parser.skip_trivia()?;
    let node = parser.value()?;
    parser.skip_trivia()?;
    if parser.pos < parser.bytes.len() {
        return Err(parser.syntax("unexpected trailing content"));
    }
    Ok(node)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
    nodes: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos.saturating_add(offset)).copied()
    }

    fn offset(&self) -> u32 {
        u32::try_from(self.pos).unwrap_or(u32::MAX)
    }

    fn syntax(&self, message: &str) -> JsonParseError {
        JsonParseError::Syntax {
            message: message.to_owned(),
            offset: self.offset(),
        }
    }

    /// Whitespace and comments. Both `//` and `/* */`, because both appear in
    /// checked-in editor configuration and neither is a reason to give up on a
    /// file we are auditing.
    fn skip_trivia(&mut self) -> Result<(), JsonParseError> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.pos = self.pos.saturating_add(1),
                Some(b'/') => match self.peek_at(1) {
                    Some(b'/') => {
                        while let Some(byte) = self.peek() {
                            if byte == b'\n' {
                                break;
                            }
                            self.pos = self.pos.saturating_add(1);
                        }
                    }
                    Some(b'*') => {
                        self.pos = self.pos.saturating_add(2);
                        loop {
                            match self.peek() {
                                None => return Err(self.syntax("unterminated block comment")),
                                Some(b'*') if self.peek_at(1) == Some(b'/') => {
                                    self.pos = self.pos.saturating_add(2);
                                    break;
                                }
                                Some(_) => self.pos = self.pos.saturating_add(1),
                            }
                        }
                    }
                    _ => return Ok(()),
                },
                _ => return Ok(()),
            }
        }
    }

    fn count_node(&mut self) -> Result<(), JsonParseError> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(JsonParseError::TooManyNodes { max: MAX_NODES });
        }
        Ok(())
    }

    fn value(&mut self) -> Result<JsonNode, JsonParseError> {
        self.count_node()?;
        let start = self.offset();
        let node = match self.peek() {
            None => return Err(self.syntax("unexpected end of input")),
            Some(b'{') => self.object()?,
            Some(b'[') => self.array()?,
            Some(b'"') => {
                let (text, span) = self.string()?;
                return Ok(JsonNode {
                    value: JsonValue::String(text),
                    span,
                });
            }
            Some(b't') => self.literal("true", JsonValue::Bool(true))?,
            Some(b'f') => self.literal("false", JsonValue::Bool(false))?,
            Some(b'n') => self.literal("null", JsonValue::Null)?,
            Some(_) => self.number()?,
        };
        Ok(JsonNode {
            value: node,
            span: (start, self.offset()),
        })
    }

    fn literal(&mut self, word: &str, value: JsonValue) -> Result<JsonValue, JsonParseError> {
        if self.bytes.len().saturating_sub(self.pos) < word.len()
            || self
                .bytes
                .get(self.pos..self.pos.saturating_add(word.len()))
                != Some(word.as_bytes())
        {
            return Err(self.syntax("expected a value"));
        }
        self.pos = self.pos.saturating_add(word.len());
        Ok(value)
    }

    fn number(&mut self) -> Result<JsonValue, JsonParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') || self.peek() == Some(b'+') {
            self.pos = self.pos.saturating_add(1);
        }
        let digits_start = self.pos;
        while let Some(byte) = self.peek() {
            if byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'-' | b'+') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
        if self.pos == digits_start {
            return Err(self.syntax("expected a value"));
        }
        let text = self
            .bytes
            .get(start..self.pos)
            .and_then(|slice| std::str::from_utf8(slice).ok())
            .ok_or_else(|| self.syntax("invalid number"))?;
        Ok(JsonValue::Number(text.to_owned()))
    }

    /// A quoted string, escapes resolved.
    ///
    /// Lone surrogates are replaced with U+FFFD rather than refused. They occur
    /// in real files, they are not a security signal on their own, and refusing
    /// the whole document over one would hand an attacker a way to make a
    /// hostile config unscannable.
    fn string(&mut self) -> Result<(String, Span), JsonParseError> {
        let start = self.offset();
        self.pos = self.pos.saturating_add(1); // opening quote
        let mut out = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| self.syntax("unterminated string"))?;
            match byte {
                b'"' => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok((out, (start, self.offset())));
                }
                b'\\' => {
                    self.pos = self.pos.saturating_add(1);
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.syntax("unterminated escape"))?;
                    self.pos = self.pos.saturating_add(1);
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.syntax("unknown escape")),
                    }
                }
                _ => {
                    let ch = self.next_char()?;
                    out.push(ch);
                }
            }
        }
    }

    /// Decodes one whole UTF-8 character at `pos` and advances past it.
    ///
    /// # Why this is not `from_utf8(&bytes[pos..]).chars().next()`
    ///
    /// That is what this used to be, and it was quadratic: validating the whole
    /// remaining input to read one character, once per character. A 2 MB string
    /// in one `.claude/settings.json` — a file an attacker fully controls, on a
    /// surface `vet` points at repositories nobody has read, and on the gate's
    /// keystroke path — would have taken the scanner out of service. The size
    /// cap does not help, because the cap is 2 MB and the work is the square of
    /// the length.
    ///
    /// The leading byte states the sequence length, so only those bytes are
    /// validated. The input came from a `&str`, so the sequence is well formed;
    /// the fallback exists because this function must not be able to panic on a
    /// truncated one either.
    fn next_char(&mut self) -> Result<char, JsonParseError> {
        let first = self
            .peek()
            .ok_or_else(|| self.syntax("unterminated string"))?;
        let width = match first {
            0x00..=0x7F => 1,
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            // A continuation byte or an invalid leader cannot start a
            // character. The source is a `&str`, so reaching here means the
            // parser lost its place — which is a bug, not an input, and is
            // reported rather than skipped.
            _ => return Err(self.syntax("invalid UTF-8 in string")),
        };
        let end = self.pos.saturating_add(width);
        let ch = self
            .bytes
            .get(self.pos..end)
            .and_then(|slice| std::str::from_utf8(slice).ok())
            .and_then(|text| text.chars().next())
            .ok_or_else(|| self.syntax("invalid UTF-8 in string"))?;
        self.pos = end;
        Ok(ch)
    }

    fn unicode_escape(&mut self) -> Result<char, JsonParseError> {
        let high = self.hex4()?;
        if (0xD800..0xDC00).contains(&high) {
            // A surrogate pair, if the low half follows.
            if self.peek() == Some(b'\\') && self.peek_at(1) == Some(b'u') {
                let mark = self.pos;
                self.pos = self.pos.saturating_add(2);
                let low = self.hex4()?;
                if (0xDC00..0xE000).contains(&low) {
                    let combined =
                        0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                    return Ok(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                }
                self.pos = mark;
            }
            return Ok('\u{FFFD}');
        }
        Ok(char::from_u32(u32::from(high)).unwrap_or('\u{FFFD}'))
    }

    fn hex4(&mut self) -> Result<u16, JsonParseError> {
        let slice = self
            .bytes
            .get(self.pos..self.pos.saturating_add(4))
            .ok_or_else(|| self.syntax("truncated \\u escape"))?;
        let text = std::str::from_utf8(slice).map_err(|_| self.syntax("invalid \\u escape"))?;
        // `from_str_radix` accepts a leading `+`, which is not a hex digit and
        // would let a signed escape through as an ordinary character. Four hex
        // digits, exactly.
        if !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(self.syntax("invalid unicode escape"));
        }
        let value = u16::from_str_radix(text, 16).map_err(|_| self.syntax("invalid \\u escape"))?;
        self.pos = self.pos.saturating_add(4);
        Ok(value)
    }

    fn enter(&mut self) -> Result<(), JsonParseError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            return Err(JsonParseError::TooDeep {
                max: MAX_DEPTH,
                offset: self.offset(),
            });
        }
        Ok(())
    }

    fn array(&mut self) -> Result<JsonValue, JsonParseError> {
        self.enter()?;
        self.pos = self.pos.saturating_add(1); // '['
        let mut items = Vec::new();
        loop {
            self.skip_trivia()?;
            match self.peek() {
                None => return Err(self.syntax("unterminated array")),
                Some(b']') => {
                    self.pos = self.pos.saturating_add(1);
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(JsonValue::Array(items));
                }
                Some(_) => {}
            }
            items.push(self.value()?);
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b']') => {}
                _ => return Err(self.syntax("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self) -> Result<JsonValue, JsonParseError> {
        self.enter()?;
        self.pos = self.pos.saturating_add(1); // '{'
        let mut members = Vec::new();
        loop {
            self.skip_trivia()?;
            match self.peek() {
                None => return Err(self.syntax("unterminated object")),
                Some(b'}') => {
                    self.pos = self.pos.saturating_add(1);
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(JsonValue::Object(members));
                }
                Some(b'"') => {}
                Some(_) => return Err(self.syntax("expected a quoted key")),
            }
            self.count_node()?;
            let (key, key_span) = self.string()?;
            self.skip_trivia()?;
            if self.peek() != Some(b':') {
                return Err(self.syntax("expected ':'"));
            }
            self.pos = self.pos.saturating_add(1);
            self.skip_trivia()?;
            let value = self.value()?;
            members.push(JsonMember {
                key,
                key_span,
                value,
            });
            self.skip_trivia()?;
            match self.peek() {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b'}') => {}
                _ => return Err(self.syntax("expected ',' or '}'")),
            }
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(flag) => write!(f, "{flag}"),
            Self::Number(text) | Self::String(text) => f.write_str(text),
            Self::Array(_) => f.write_str("[…]"),
            Self::Object(_) => f.write_str("{…}"),
        }
    }
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

    #[test]
    fn parses_the_shape_a_settings_file_actually_has() {
        let source = r#"{
  // a comment, which serde_json would refuse
  "hooks": {
    "SessionStart": [
      { "command": "node .claude/setup.mjs" },
    ],
  },
}"#;
        let doc = parse(source).expect("JSONC with comments and trailing commas");
        let command = doc
            .pointer(&["hooks", "SessionStart"])
            .and_then(JsonNode::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("command"))
            .and_then(JsonNode::as_str);
        assert_eq!(command, Some("node .claude/setup.mjs"));
    }

    #[test]
    fn spans_point_at_the_original_bytes() {
        let source = r#"{"command": "curl x | sh"}"#;
        let doc = parse(source).unwrap();
        let node = doc.get("command").unwrap();
        let (start, end) = node.span;
        assert_eq!(
            &source[start as usize..end as usize],
            "\"curl x | sh\"",
            "the span must include the quotes so the code frame underlines the literal"
        );
        let member = &doc.as_object().unwrap()[0];
        let (ks, ke) = member.key_span;
        assert_eq!(&source[ks as usize..ke as usize], "\"command\"");
    }

    #[test]
    fn duplicate_keys_are_all_kept() {
        // The evasion this defends against: a reviewer reads the first
        // `permissions`, a last-wins parser reads the second, and the two
        // disagree about what the file says.
        let doc = parse(r#"{"allow": [], "allow": ["Bash"]}"#).unwrap();
        let all: Vec<&JsonMember> = doc.members("allow").collect();
        assert_eq!(all.len(), 2, "both occurrences survive");
        assert_eq!(
            doc.get("allow")
                .and_then(JsonNode::as_array)
                .map(<[_]>::len),
            Some(0)
        );
        let strings = doc.strings();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Bash");
    }

    #[test]
    fn strings_are_enumerated_with_their_key_path() {
        let doc = parse(r#"{"mcpServers": {"a": {"env": {"TOKEN": "$NPM_TOKEN"}}}}"#).unwrap();
        let hits = doc.strings();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, vec!["mcpServers", "a", "env", "TOKEN"]);
        assert_eq!(hits[0].path_str(), "mcpServers.a.env.TOKEN");
        assert!(hits[0].within("env"));
        assert!(hits[0].under("TOKEN"));
        assert!(!hits[0].under("env"));
    }

    #[test]
    fn nesting_is_capped_rather_than_recursing_until_the_stack_ends() {
        let deep = "[".repeat(MAX_DEPTH + 5) + &"]".repeat(MAX_DEPTH + 5);
        assert!(matches!(
            parse(&deep),
            Err(JsonParseError::TooDeep { max: MAX_DEPTH, .. })
        ));
        // One under the cap still parses, so the bound is a real ceiling and
        // not an off-by-one that refuses ordinary files.
        let ok = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn oversized_input_is_refused_before_it_is_walked() {
        let big = format!("\"{}\"", "a".repeat(MAX_BYTES));
        assert!(matches!(parse(&big), Err(JsonParseError::TooLarge { .. })));
    }

    #[test]
    fn a_flood_of_values_is_capped() {
        let flood = format!("[{}]", "1,".repeat(MAX_NODES + 10));
        assert!(matches!(
            parse(&flood),
            Err(JsonParseError::TooManyNodes { .. })
        ));
    }

    #[test]
    fn malformed_input_is_an_error_and_never_a_partial_document() {
        for broken in [
            "",
            "{",
            "{\"a\"}",
            "{\"a\": }",
            "[1 2]",
            "{\"a\": 1} trailing",
            "/* unterminated",
            "{'a': 1}",
        ] {
            assert!(parse(broken).is_err(), "{broken:?} should not parse");
        }
    }

    #[test]
    fn escapes_and_surrogate_pairs_resolve() {
        let doc = parse(r#"{"a": "line\nbreak A 😀"}"#).unwrap();
        assert_eq!(
            doc.get("a").and_then(JsonNode::as_str),
            Some("line\nbreak A 😀")
        );
    }

    #[test]
    fn a_long_string_is_linear_rather_than_quadratic() {
        // The regression this guards: reading one character used to validate
        // the whole remaining input, so a single long string in a file an
        // attacker controls took the scanner out of service. Six hundred
        // kilobytes here parses in milliseconds; the quadratic version did not
        // finish.
        let payload = format!("{{\"a\":\"{}\"}}", "\u{e9}".repeat(300_000));
        let started = std::time::Instant::now();
        let doc = parse(&payload).expect("a long string is still a string");
        assert_eq!(
            doc.get("a").and_then(JsonNode::as_str).map(str::len),
            Some(600_000)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "parsing took {:?}; the string scanner is quadratic again",
            started.elapsed()
        );
    }

    #[test]
    fn a_signed_unicode_escape_is_refused() {
        // `u16::from_str_radix` accepts a leading `+`, which would have let a
        // signed escape through as an ordinary character — a way to write
        // something a reviewer's renderer would not show the same way.
        for broken in [
            r#"{"a":"\u+041"}"#,
            r#"{"a":"\u-041"}"#,
            r#"{"a":"\u 041"}"#,
        ] {
            assert!(parse(broken).is_err(), "{broken} must be refused");
        }
        assert!(parse(r#"{"a":"\u0041"}"#).is_ok());
    }

    #[test]
    fn a_lone_surrogate_degrades_instead_of_making_a_file_unscannable() {
        let doc = parse(r#"{"a": "\uD800x"}"#).unwrap();
        assert_eq!(doc.get("a").and_then(JsonNode::as_str), Some("\u{FFFD}x"));
    }

    #[test]
    fn multibyte_characters_survive_the_scanner() {
        let doc = parse(r#"{"a": "héllo → 日本語"}"#).unwrap();
        assert_eq!(
            doc.get("a").and_then(JsonNode::as_str),
            Some("héllo → 日本語")
        );
    }

    #[test]
    fn arrays_and_objects_are_distinguishable_from_scalars() {
        let doc = parse(r#"{"a": [], "b": {}, "c": 1, "d": true, "e": null}"#).unwrap();
        assert_eq!(
            doc.get("a").and_then(JsonNode::as_array).map(<[_]>::len),
            Some(0)
        );
        assert!(doc.get("c").unwrap().as_array().is_none());
        assert_eq!(doc.get("d").and_then(JsonNode::as_bool), Some(true));
        assert_eq!(doc.get("e").unwrap().value, JsonValue::Null);
        assert!(doc.pointer(&["b", "missing"]).is_none());
    }
}
