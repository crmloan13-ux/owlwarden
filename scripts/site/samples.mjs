import { fileURLToPath } from "node:url";

/**
 * Real vulnerable code for every (rule, profile) cell, harvested by scanning
 * the fixtures.
 *
 * # Why this is scanned rather than written
 *
 * A page saying "here is the vulnerable pattern in Fastify" is worth reading
 * only if the pattern is one the scanner actually fires on. Writing the
 * examples by hand would produce 200 snippets nobody verifies, drifting away
 * from the rules one release at a time — which is the failure mode
 * programmatic SEO is famous for, and the reason most of it is worthless.
 *
 * So the build scans the vulnerable fixture of every framework and every agent
 * host, and takes the code frames the engine produced. Every snippet on the site is a
 * finding the test suite already asserts. If a rule stops firing, its pages
 * lose their sample and the build says so, rather than the site quietly
 * describing behaviour the tool no longer has.
 *
 * # Why an empty cell publishes nothing
 *
 * Thin pages at scale is the one way this tactic backfires. A cell with no
 * sample from its own fixture has nothing the rule page does not already say,
 * so it is not generated at all and the rule page does not link to it.
 */

/** The twelve framework fixtures, in the order `RULES.md` lists them. */
const FRAMEWORK_FIXTURES = {
  next: "vulnerable/next-api",
  nuxt: "vulnerable/nuxt-api",
  nest: "vulnerable/nest-api",
  express: "vulnerable/express-api",
  fastify: "vulnerable/fastify-api",
  hono: "vulnerable/hono-api",
  koa: "vulnerable/koa-api",
  hapi: "vulnerable/hapi-api",
  sails: "vulnerable/sails-api",
  astro: "vulnerable/astro-api",
  remix: "vulnerable/remix-api",
  gatsby: "vulnerable/gatsby-api",
};

/** The seven agent-host fixtures. */
const HOST_FIXTURES = {
  "claude-code": "agent/claude-code/vulnerable",
  cursor: "agent/cursor/vulnerable",
  vscode: "agent/vscode/vulnerable",
  copilot: "agent/copilot/vulnerable",
  codex: "agent/codex/vulnerable",
  "gemini-cli": "agent/gemini-cli/vulnerable",
  generic: "agent/generic/vulnerable",
};

function fixturePath(relative) {
  return fileURLToPath(new URL(`../../fixtures/${relative}`, import.meta.url));
}

/**
 * Scans every fixture once and indexes the findings by rule and profile.
 *
 * @returns {Promise<Map<string, Map<string, object>>>} `rule -> profile -> finding`
 */
export async function harvestSamples(native) {
  const byRule = new Map();

  const record = (ruleId, profile, finding) => {
    if (!byRule.has(ruleId)) byRule.set(ruleId, new Map());
    const perProfile = byRule.get(ruleId);
    // First finding wins. The fixtures are ordered so the first occurrence of a
    // rule is its clearest example — the one the rule's own test asserts on.
    if (!perProfile.has(profile)) perProfile.set(profile, finding);
  };

  for (const [profile, relative] of Object.entries(FRAMEWORK_FIXTURES)) {
    for (const finding of await scanFixture(native, relative)) {
      if (!finding.snippet) continue;
      record(finding.id, profile, finding);
    }
  }

  for (const [profile, relative] of Object.entries(HOST_FIXTURES)) {
    for (const finding of await scanFixture(native, relative)) {
      if (!finding.snippet) continue;
      record(finding.id, profile, finding);
    }
  }

  return byRule;
}

async function scanFixture(native, relative) {
  const envelope = JSON.parse(
    await native.scan(
      JSON.stringify({
        projectRoot: fixturePath(relative),
        preset: "deep",
        minConfidence: "possible",
      }),
    ),
  );
  if (!envelope.ok || !envelope.report) {
    throw new Error(
      `scanning ${relative} failed: ${envelope.error?.message ?? "no report and no reason"}`,
    );
  }
  return envelope.report.findings;
}

/**
 * Renders a finding's code frame as the transcript block the site uses.
 *
 * The same shape the terminal prints, because a reader who has seen one report
 * should recognise the page — and because the underline is the part that makes
 * the example legible without reading the prose around it.
 */
export function renderFrame(finding, esc) {
  const frame = finding.snippet;
  if (!frame) return "";

  const gutterWidth = String(frame.startLine + frame.lines.length).length;
  const rows = frame.lines.map((line, offset) => {
    const number = frame.startLine + offset;
    const gutter = String(number).padStart(gutterWidth, " ");
    const highlighted = number === frame.highlight.line;
    const row = `<span class="dim">${gutter} │</span> ${esc(line)}`;
    if (!highlighted) return row;

    const start = Math.max(0, frame.highlight.startCol - 1);
    const width = Math.max(1, frame.highlight.endCol - frame.highlight.startCol);
    const pad = " ".repeat(gutterWidth) + " │ " + line.slice(0, start).replace(/[^\t]/g, " ");
    const marks = "~".repeat(width);
    const label = frame.highlight.label ? ` ${frame.highlight.label}` : "";
    return `${row}\n<span class="dim">${esc(pad.slice(0, gutterWidth + 3))}</span>${esc(pad.slice(gutterWidth + 3))}<span class="mark">${esc(marks + label)}</span>`;
  });

  const severityClass = `sev-${finding.severity}`;
  const scope = finding.runtimeScope ? `  <span class="dim">${esc(finding.runtimeScope)}</span>` : "";
  const taxonomy = finding.owasp ?? finding.asi ?? "";
  const header =
    `<span class="${severityClass}">${esc(finding.severity.toUpperCase())}</span>  ` +
    `<span class="conf">${esc(finding.confidence)}</span>${scope}  ` +
    `${esc(finding.title)}` +
    (taxonomy ? `  <span class="dim">${esc(taxonomy)}</span>` : "");

  const where = finding.location.path
    ? `${finding.location.path}:${finding.location.line}:${finding.location.col}`
    : `${finding.location.method ?? ""} ${finding.location.url ?? ""}`.trim();

  return `<div class="transcript">${header}\n<span class="dim">${esc(where)}</span>\n\n${rows.join("\n")}</div>`;
}
