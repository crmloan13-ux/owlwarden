//! Colours and box-drawing, with the fallbacks that make Windows and CI
//! readable.

use anstyle::{AnsiColor, Color, Style};
use owlwarden_core::finding::{Confidence, Severity};

/// Characters used to draw the report.
///
/// Two sets rather than one: a terminal without reliable UTF-8 renders the
/// Unicode set as mojibake, and a report you cannot read is worse than a plain
/// one. `--ascii` selects the fallback explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Glyphs {
    /// Horizontal rule between findings.
    pub rule: char,
    /// Vertical bar between the gutter and source in a code frame.
    pub gutter: char,
    /// Character repeated to underline the offending span.
    pub underline: char,
    /// Marker before a remediation line.
    pub arrow: &'static str,
    /// Marker before a references line.
    pub info: &'static str,
}

impl Glyphs {
    /// The default set.
    #[must_use]
    pub const fn unicode() -> Self {
        Self {
            rule: '─',
            gutter: '│',
            underline: '~',
            arrow: "↳",
            info: "ⓘ",
        }
    }

    /// The portable set.
    #[must_use]
    pub const fn ascii() -> Self {
        Self {
            rule: '-',
            gutter: '|',
            underline: '~',
            arrow: "->",
            info: "i",
        }
    }

    /// Picks a set.
    #[must_use]
    pub const fn for_unicode(unicode: bool) -> Self {
        if unicode {
            Self::unicode()
        } else {
            Self::ascii()
        }
    }
}

/// Colour for a severity band.
///
/// Red for high, yellow for medium, blue for low, dim for info — the ordering
/// most terminal tools use, so the reader does not have to learn ours.
#[must_use]
pub fn severity_style(severity: Severity) -> Style {
    let colour = match severity {
        Severity::High => AnsiColor::Red,
        Severity::Medium => AnsiColor::Yellow,
        Severity::Low => AnsiColor::Blue,
        Severity::Info => AnsiColor::BrightBlack,
    };
    Style::new().fg_color(Some(Color::Ansi(colour))).bold()
}

/// Colour for a confidence label. Deliberately muted: confidence qualifies the
/// finding, it does not compete with the severity for attention.
#[must_use]
pub fn confidence_style(confidence: Confidence) -> Style {
    let colour = match confidence {
        Confidence::Confirmed => AnsiColor::Green,
        Confidence::Likely => AnsiColor::Cyan,
        Confidence::Possible => AnsiColor::BrightBlack,
    };
    Style::new().fg_color(Some(Color::Ansi(colour)))
}

/// Dimmed text: gutters, context lines, secondary labels.
#[must_use]
pub fn dim() -> Style {
    Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack)))
}

/// Emphasis without colour, for headings.
#[must_use]
pub fn bold() -> Style {
    Style::new().bold()
}

/// The style of the `~~~` underline and its message.
#[must_use]
pub fn underline_style() -> Style {
    Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)))
        .bold()
}
