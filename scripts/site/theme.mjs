/**
 * The palette, derived from the CLI rather than picked for a web page.
 *
 * The site and the terminal should be recognisably the same object. So these
 * are the colours `crates/reporters/src/theme.rs` actually emits — red for
 * high, yellow for medium, blue for low, dim for info; cyan for `likely`, green
 * for `confirmed` — resolved to the values a modern terminal renders them as,
 * and then used as the only accent system on the site.
 *
 * The severity ramp is already load-bearing in the product: a reader who has
 * seen one report knows what red means before they read a word. Adding a fourth
 * accent for the web would be inventing a second vocabulary for the same idea.
 *
 * Two neutrals, one ink, one paper, and the ramp. Nothing else.
 */

export const THEME = {
  // Two neutrals. Near-black rather than black: a true #000 next to a bright
  // accent reads as a screenshot of a terminal rather than as a page.
  ink: "#12141a",
  inkSoft: "#5b6272",
  paper: "#fbfaf8",
  paperDeep: "#eef0f3",
  rule: "rgba(18, 20, 26, 0.14)",

  // The severity ramp, straight from the reporter.
  high: "#c0362c",
  medium: "#a8720b",
  low: "#2f5fa8",
  info: "#6b7280",

  // Confidence, deliberately muted: it qualifies the finding, it does not
  // compete with the severity for attention.
  confirmed: "#2c7a52",
  likely: "#1f6f7a",
  possible: "#6b7280",
};

/**
 * Type: two faces, no more.
 *
 * The transcript *is* the display type on this site, so the mono is chosen
 * deliberately rather than inherited from a docs theme — and it is used for
 * headings too, which is what keeps the page and the terminal looking like one
 * object. The body face is a quiet, high-x-height sans.
 *
 * Both are system stacks. A security tool that pulls two font files from a CDN
 * on every page load has added a third party to a page whose entire argument is
 * that it has no third parties.
 */
export const FONTS = {
  mono: `"SFMono-Regular", "JetBrains Mono", "IBM Plex Mono", ui-monospace, Menlo, Consolas, "Liberation Mono", monospace`,
  sans: `"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`,
};
