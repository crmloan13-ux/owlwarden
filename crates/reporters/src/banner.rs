//! owlwarden startup banner.
//!
//! Rules it has to obey:
//!   * The banner is decoration — it prints to STDERR, never STDOUT, so it can
//!     never corrupt `--format json` output that a tool is parsing.
//!   * It shows ONLY on an interactive TTY and only when not silenced. In CI,
//!     when piped, or with `--quiet` / `--format json` / `--ci`, it is
//!     suppressed.
//!   * Color respects `NO_COLOR` and a resolved `color` flag. Non-UTF terminals
//!     and `--ascii` get the plain fallback so nothing renders as mojibake.
//!
//! Colour is written through `anstream`, which translates ANSI into console
//! calls on Windows instead of printing escape codes at the user.

use std::io::{IsTerminal, Write};

use anstyle::{AnsiColor, Color, Style};

// ── art ──────────────────────────────────────────────────────────────────────
// Unicode owl (default). Eyes are the two ◉; head is ,___, ; feet are " " .
const OWL_UNICODE: &str = r#"
   ,___,
   (◉,◉)   owlwarden
   /)_)    keen-eyed security auditor
    " "
"#;

// Portable fallback for terminals without reliable UTF-8 / with `--ascii`.
const OWL_ASCII: &str = r#"
   ,___,
   (O,O)   owlwarden
   /)_)    keen-eyed security auditor
    " "
"#;

/// One-line mark for the scan header, e.g. `◉ᴥ◉ preset owasp-top10 ...`.
pub const OWL_MARK_UNICODE: &str = "◉ᴥ◉";
/// ASCII fallback for [`OWL_MARK_UNICODE`].
pub const OWL_MARK_ASCII: &str = "(o.o)";

/// What the caller has already resolved from flags and environment.
#[derive(Debug, Clone, Copy)]
pub struct BannerOpts {
    /// False if `NO_COLOR` is set, `--no-color` was passed, or the stream is
    /// not a colour TTY.
    pub color: bool,
    /// False with `--ascii` or a non-UTF locale.
    pub unicode: bool,
    /// True with `--quiet`, `--format json`, or `--ci` — suppress decoration.
    pub quiet: bool,
}

impl Default for BannerOpts {
    fn default() -> Self {
        Self {
            color: true,
            unicode: true,
            quiet: false,
        }
    }
}

/// Prints the welcome banner to stderr, honouring every suppression rule.
///
/// Returns without doing anything when it must stay silent. Write failures are
/// ignored on purpose: a broken pipe on a decorative banner must not fail a
/// scan.
pub fn print_banner(opts: &BannerOpts) {
    if opts.quiet || !std::io::stderr().is_terminal() {
        return;
    }
    let mut out = anstream::stderr();
    let _ = render_banner(&mut out, opts);
    let _ = out.flush();
}

/// Renders the banner into any writer. Split out from [`print_banner`] so it can
/// be snapshot-tested without a terminal.
///
/// # Errors
/// Propagates whatever the writer returns.
pub fn render_banner(out: &mut impl Write, opts: &BannerOpts) -> std::io::Result<()> {
    let art = if opts.unicode { OWL_UNICODE } else { OWL_ASCII };

    if !opts.color {
        return out.write_all(art.as_bytes());
    }

    // Eyes and "owl" amber, "warden" blue, the rest dim. Done line by line
    // rather than by string replacement so the styling cannot accidentally
    // match text inside the subtitle.
    let dim = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack)));
    let amber = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
    let blue = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlue)));

    for line in art.lines() {
        match line.split_once("owlwarden") {
            Some((prefix, suffix)) => writeln!(
                out,
                "{dim}{prefix}{dim:#}{amber}owl{amber:#}{blue}warden{blue:#}{dim}{suffix}{dim:#}"
            )?,
            None => writeln!(out, "{dim}{line}{dim:#}")?,
        }
    }
    Ok(())
}

/// The header mark used by the pretty reporter (`◉ᴥ◉`, or the ASCII fallback).
#[must_use]
pub fn owl_mark(unicode: bool) -> &'static str {
    if unicode {
        OWL_MARK_UNICODE
    } else {
        OWL_MARK_ASCII
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn plain_output_contains_no_escape_codes() {
        let mut buffer = Vec::new();
        render_banner(
            &mut buffer,
            &BannerOpts {
                color: false,
                unicode: true,
                quiet: false,
            },
        )
        .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("owlwarden"));
        assert!(!text.contains('\x1b'), "no ANSI without colour");
    }

    #[test]
    fn ascii_mode_is_pure_ascii() {
        let mut buffer = Vec::new();
        render_banner(
            &mut buffer,
            &BannerOpts {
                color: false,
                unicode: false,
                quiet: false,
            },
        )
        .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.is_ascii(),
            "the fallback must render on a non-UTF terminal: {text:?}"
        );
    }
}
