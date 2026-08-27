/**
 * `sitemap.xml`, `robots.txt`, and `llms.txt`.
 *
 * All three are generated from the page list rather than maintained beside it,
 * because the failure mode of a hand-written sitemap is silent: pages get added
 * and never submitted, and nobody notices for a quarter.
 */

/** XML-escapes a URL for the sitemap. */
function xml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

/**
 * The sitemap.
 *
 * `lastmod` is the latest dated changelog release, not a per-page git
 * timestamp and not the clock. A per-page date would be more useful and would
 * also be a lie here: these pages are generated from the rule catalogue, so a
 * rule's write-up changing means every one of its pages changed, and the git
 * history of the HTML file says nothing about that. The clock is worse: it
 * makes `site:check` fail the next morning with no content change.
 */
export function sitemap(paths, site, isoDate) {
  const entries = paths
    .map((path) => {
      const depth = path.split("/").filter(Boolean).length;
      // The homepage, then the hubs, then the long tail. Priority is a hint and
      // a weak one, but a flat sitemap tells a crawler nothing at all.
      const priority = path === "" ? "1.0" : depth >= 3 ? "0.5" : "0.8";
      return [
        "  <url>",
        `    <loc>${xml(`${site}/${path}`)}</loc>`,
        `    <lastmod>${xml(isoDate)}</lastmod>`,
        `    <priority>${priority}</priority>`,
        "  </url>",
      ].join("\n");
    })
    .join("\n");

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    entries,
    "</urlset>",
    "",
  ].join("\n");
}

/** `robots.txt`. Nothing is blocked except the 404 page. */
export function robots(site) {
  return `# owlwarden: https://github.com/suthat/owlwarden
User-agent: *
Allow: /
Disallow: /404.html

Sitemap: ${site}/sitemap.xml
`;
}

/**
 * `llms.txt` — a plain-text index for model crawlers.
 *
 * Cheap, and for a developer tool a meaningful share of "how do I fix X"
 * traffic arrives through a model rather than a browser. The format is a
 * headed list of links with one line of context each: enough for a retrieval
 * step to pick the right page, short enough to be read whole.
 */
export function llms({ site, version, rules, coverage, extra }) {
  const line = (path, note) => `- [${note.title}](${site}/${path}): ${note.blurb}`;

  const webRules = rules.filter((rule) => (rule.surface ?? "webApp") === "webApp");
  const agentRules = rules.filter((rule) => rule.surface === "agentWorkspace");

  return `# owlwarden

> Offline security scanner for Node web apps and AI coding agents. ${rules.length} rules
> with framework-specific fixes for 12 stacks and 7 agent hosts, plus scanning of
> the \`.claude/\`, \`.cursor/\`, and \`.vscode/\` configuration a lockfile does not
> record. Runs entirely on the developer's machine: no account, no telemetry, no
> network unless asked. Version ${version}. MIT OR Apache-2.0.

Install: \`npm i -D owlwarden\` / Scan: \`npx owlwarden scan\` / Vet a repo you did
not write: \`npx owlwarden vet .\`

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 could not run.

## Start here

${[
  ["", { title: "owlwarden", blurb: "What it is, what it does not look at, and how to run it." }],
  ["rules/", { title: "All rules", blurb: `${rules.length} rules: ${webRules.length} on application source, ${agentRules.length} on agent configuration.` }],
  ["agent-config-security/", { title: "Agent config security", blurb: "Hooks, MCP servers, instructions, and editor tasks loaded from the repository." }],
  ["vet/", { title: "owlwarden vet", blurb: "Scanning a repository you did not write, with the target's own suppressions treated as evidence." }],
  ["offline/", { title: "Offline by default", blurb: "What stays local and which two flags enable network access." }],
  ["changelog/", { title: "Changelog", blurb: "Release notes and rule-id compatibility notes. Atom feed at /changelog/feed.xml." }],
]
  .map(([path, note]) => line(path, note))
  .join("\n")}

## Coverage

${[
  ["owasp/", { title: "OWASP Top 10 (2021)", blurb: `${coverage.categoriesCovered} of 10 categories, with the gaps and the reason each one is empty.` }],
  ["asi/", { title: `OWASP ASI ${coverage.asiEdition}`, blurb: `${coverage.asiCategoriesCovered} of 10 agentic categories, kept as a separate table from the Top 10.` }],
]
  .map(([path, note]) => line(path, note))
  .join("\n")}

## In an agent or in CI

${[
  ["claude-code/", { title: "Claude Code", blurb: "Hooks on edit, before a shell command, and at the turn boundary; plus MCP." }],
  ["cursor/", { title: "Cursor", blurb: "Hooks in .cursor/hooks.json, an MCP entry, and a rules file." }],
  ["mcp/", { title: "MCP server", blurb: "Four read-only static-analysis tools over stdio." }],
  ["ci/", { title: "CI", blurb: "SARIF, JUnit, Markdown, and exit codes for clean, findings, and scan errors." }],
]
  .map(([path, note]) => line(path, note))
  .join("\n")}

## Comparisons

${[
  ["vs/semgrep/", { title: "vs Semgrep", blurb: "Rule and language coverage, local defaults, and agent config." }],
  ["vs/snyk/", { title: "vs Snyk", blurb: "Dependency analysis and repository-controlled agent config." }],
  ["vs/claude-security/", { title: "vs model-based review", blurb: "Repeatable static checks and review that needs judgement." }],
  ["vs/eslint-plugin-security/", { title: "vs eslint-plugin-security", blurb: "Lint patterns and framework-aware checks with confidence levels." }],
]
  .map(([path, note]) => line(path, note))
  .join("\n")}

## Rules

Each rule page carries the pattern, why it is dangerous, a verified vulnerable
example, the corrected code for each supported framework or agent host, the CWE
and OWASP or ASI mapping, and one command to check a repository.

${rules
  .map(
    (rule) =>
      `- [${rule.id}](${site}/rules/${rule.id}/): ${rule.severity}, max confidence ${rule.maxConfidence}. ${rule.title}.`,
  )
  .join("\n")}

${extra ?? ""}`;
}
