import { THEME } from "./theme.mjs";
import { favicon } from "./icon.mjs";

/**
 * The social card, as an SVG.
 *
 * # Why a finding and not a logo on a gradient
 *
 * The most characteristic artefact in this project's world is a scan transcript,
 * and the most characteristic *thing about owlwarden* is which finding it shows:
 * a line of repository configuration that runs a command when anyone opens the
 * folder. Nobody else in this category puts that on a social card, because
 * nobody else reads that file.
 *
 * A centred wordmark on a gradient would be instantly forgettable and would say
 * nothing. This says the whole argument in one image.
 *
 * # Why this is not generated per page
 *
 * Per-page cards would be better and need a rasteriser: 200 PNGs at build time
 * means a headless browser or an image library, and neither is worth adding to
 * a repository whose dependency posture is a feature. Faking it with an SVG
 * `og:image` does not work — the platforms that matter do not render SVG in a
 * card. So there is one card, it is checked in, and `site/README.md` records the
 * command that produced it.
 */
export function ogCard() {
  const mono = "Menlo, Consolas, monospace";
  const mark = favicon()
    .replace(/^<svg[^>]*>/, "")
    .replace(/<\/svg>\s*$/, "")
    .replace(/<title>[\s\S]*?<\/title>/, "");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <rect width="1200" height="630" fill="${THEME.paper}"/>

  <g transform="translate(72 60) scale(1.05)">${mark}</g>
  <text x="152" y="106" font-family="${mono}" font-size="34" font-weight="600" fill="${THEME.ink}">owlwarden</text>
  <text x="152" y="136" font-family="${mono}" font-size="17" fill="${THEME.inkSoft}">offline security scanner · Node web apps · AI coding agents</text>

  <rect x="72" y="176" width="1056" height="286" rx="8" fill="${THEME.paperDeep}" stroke="${THEME.rule}"/>

  <!-- xml:space=preserve, because SVG collapses runs of spaces by default,
       which turns an aligned transcript into a paragraph and moves the
       underline away from the thing it underlines. -->
  <text font-family="${mono}" font-size="19" xml:space="preserve">
    <tspan x="104" y="216" fill="${THEME.high}" font-weight="700">HIGH</tspan><tspan fill="${THEME.likely}">  likely</tspan><tspan fill="${THEME.info}">  active</tspan><tspan fill="${THEME.ink}">  Repository config executes on open</tspan><tspan fill="${THEME.info}">   ASI05</tspan>
    <tspan x="104" y="248" fill="${THEME.info}">.claude/settings.json:4:24</tspan>
    <tspan x="104" y="296" fill="${THEME.info}">3 │</tspan><tspan fill="${THEME.ink}">   "hooks": {</tspan>
    <tspan x="104" y="324" fill="${THEME.info}">4 │</tspan><tspan fill="${THEME.ink}">     "SessionStart": [{ "command": "node .claude/setup.mjs" }]</tspan>
    <tspan x="104" y="352" fill="${THEME.info}">  │</tspan><tspan fill="${THEME.high}" font-weight="700">                                  ~~~~~~~~~~~~~~~~~~~~~~ runs on open</tspan>
    <tspan x="104" y="380" fill="${THEME.info}">5 │</tspan><tspan fill="${THEME.ink}">   }</tspan>
    <tspan x="104" y="428" fill="${THEME.inkSoft}">↳  fix (Claude Code)  Remove the SessionStart entry, or move the hook to</tspan>
  </text>

  <text x="72" y="524" font-family="${mono}" font-size="30" font-weight="600" fill="${THEME.ink}">Your dependency scanner does not read this file.</text>
  <text x="72" y="562" font-family="${mono}" font-size="19" fill="${THEME.inkSoft}">Not a dependency. Not source. Executed anyway.</text>
  <text x="72" y="596" font-family="${mono}" font-size="19" fill="${THEME.high}">npx owlwarden vet .</text>
</svg>
`;
}
