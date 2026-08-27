import { esc } from "./layout.mjs";
import { renderFrame } from "./samples.mjs";

/**
 * The structured hero used by the shared page shell.
 *
 * @typedef {object} MarketingHero
 * @property {string} kicker Short category label above the page heading.
 * @property {string} summary Trusted, site-authored HTML explaining the value in one paragraph.
 * @property {Array<{label: string, href: string, kind?: "primary" | "secondary"}>} actions
 * @property {string} visual Accessible HTML that shows the product or workflow being described.
 */

/**
 * Returns the hero content for one hand-written product page.
 *
 * Keeping page summaries here leaves the long-form pages focused on reference
 * material and keeps labels, actions, and visuals consistent.
 * Unknown paths deliberately return `null`, so reference and generated pages
 * keep their compact article treatment.
 *
 * @param {string} path Site-relative directory path.
 * @param {object} context Generated rule, coverage, and fixture data.
 * @returns {MarketingHero | null}
 */
export function marketingHero(path, context) {
  const build = HEROES[path];
  return build ? build(context) : null;
}

/**
 * Renders a bounded product-workflow visual from structured content.
 *
 * @param {object} input
 * @param {string} input.label Accessible name and window label.
 * @param {string} input.title Short product claim.
 * @param {string} [input.status]
 * @param {string} [input.tone]
 * @param {Array<{tag: string, title: string, detail: string}>} input.items
 * @param {string} input.footer
 * @returns {string}
 */
export function productVisual({ label, title, status = "local", tone = "default", items, footer }) {
  const rows = items.slice(0, 4).map(visualRow).join("\n");
  return `<figure class="product-visual product-visual-${esc(tone)}" aria-label="${esc(label)}">
  ${visualChrome(label, status)}
  <div class="visual-body">
    <p class="visual-title">${esc(title)}</p>
    <ol class="visual-list">${rows}</ol>
  </div>
  <figcaption>${esc(footer)}</figcaption>
</figure>`;
}

function visualRow(item) {
  return `<li>
  <span class="visual-tag">${esc(item.tag)}</span>
  <span><strong>${esc(item.title)}</strong><small>${esc(item.detail)}</small></span>
</li>`;
}

function visualChrome(label, status) {
  return `<div class="visual-chrome" aria-hidden="true">
  <span class="window-dots"><i></i><i></i><i></i></span>
  <span>${esc(label)}</span>
  <span class="visual-status"><i></i>${esc(status)}</span>
</div>`;
}

function findingVisual(frames) {
  return `<figure class="product-visual finding-visual" aria-label="Two owlwarden findings from one local scan">
  ${visualChrome("owlwarden scan", "offline")}
  <div class="finding-stack">${frames.filter(Boolean).slice(0, 2).join("\n")}</div>
  <figcaption>Application source and agent workspace in one local scan</figcaption>
</figure>`;
}

function comparisonVisual(other, rows) {
  return `<figure class="product-visual comparison-visual" aria-label="owlwarden compared with ${esc(other)}">
  ${visualChrome(`compare / ${other}`, "local")}
  <div class="compare-grid compare-head"><span>Capability</span><strong>${esc(other)}</strong><strong>owlwarden</strong></div>
  ${rows
    .slice(0, 4)
    .map(
      ([label, theirs, ours]) =>
        `<div class="compare-grid"><span>${esc(label)}</span><span>${esc(theirs)}</span><strong>${esc(ours)}</strong></div>`,
    )
    .join("\n")}
  <figcaption>Scope and defaults differ. Run both when you need both sets of checks.</figcaption>
</figure>`;
}

const HEROES = {
  "": ({ rules, webRules, agentRules, leak, hook }) => ({
    kicker: "Node and agent config security",
    summary: `<strong>${webRules.length} checks cover Node application code and ${agentRules.length} cover coding-agent config.</strong> Each finding includes the line, confidence, and a fix for the detected framework or host.`,
    actions: [
      { label: "Install", href: "https://www.npmjs.com/package/owlwarden", kind: "primary" },
      { label: `Read ${rules.length} rules`, href: "./rules/", kind: "secondary" },
    ],
    visual: findingVisual([
      leak ? renderFrame(leak, esc) : "",
      hook ? renderFrame(hook, esc) : "",
    ]),
  }),
  "agent-config-security/": ({ agentRules, hook }) => ({
    kicker: "Agent config",
    summary: `<strong>Repository config can run commands and load tools.</strong> owlwarden checks hooks, MCP servers, instruction files, and editor tasks before an agent uses them.`,
    actions: [
      { label: "Vet a repository", href: "../vet/", kind: "primary" },
      { label: `See ${agentRules.length} agent rules`, href: "#agent-rules", kind: "secondary" },
    ],
    visual: hook
      ? findingVisual([renderFrame(hook, esc)])
      : productVisual({
          label: "agent surface",
          title: "Config that can affect an agent session",
          items: agentSurfaceItems(),
          footer: "Fixed path list, bounded reads, target policy ignored",
          tone: "risk",
        }),
  }),
  "vet/": () => ({
    kicker: "For repositories you did not write",
    summary: `<strong><code>owlwarden vet</code> checks agent config before you open the folder.</strong> It does not load the target's settings, baseline, plugins, or suppressions.`,
    actions: [
      { label: "Install owlwarden", href: "https://www.npmjs.com/package/owlwarden", kind: "primary" },
      { label: "Understand the surface", href: "../agent-config-security/", kind: "secondary" },
    ],
    visual: productVisual({
      label: "owlwarden vet ./candidate",
      title: "Check the config before opening the folder",
      items: [
        { tag: "01", title: "Clone", detail: "Clone without opening the folder in an agent." },
        { tag: "02", title: "Run vet", detail: "Scan agent config with target policy disabled." },
        { tag: "03", title: "Review", detail: "Read the finding and fix before opening the folder." },
      ],
      footer: "No network, no plugins, no target suppressions",
      tone: "safe",
    }),
  }),
  "claude-code/": () => lifecycleHero("Claude Code", "../agent-config-security/", [
    ["PostToolUse", "Scan the file after Edit, Write, or MultiEdit"],
    ["PreToolUse", "Fail closed before a Bash command executes"],
    ["Stop", "Check everything changed before the turn ends"],
  ]),
  "cursor/": () => lifecycleHero("Cursor", "../agent-config-security/", [
    ["afterFileEdit", "Scan the file Cursor just changed"],
    ["beforeShellExecution", "Decide before the command runs"],
    ["stop", "Close the loop on the whole turn"],
  ]),
  "mcp/": () => ({
    kicker: "MCP server",
    summary: `<strong>The MCP server exposes four read-only tools.</strong> It can scan files and explain rules, but it cannot write files or make network requests. Hooks handle enforcement.`,
    actions: [
      { label: "Set up a host", href: "../claude-code/", kind: "primary" },
      { label: "Read the rules", href: "../rules/", kind: "secondary" },
    ],
    visual: productVisual({
      label: "owlwarden mcp",
      title: "Four read-only tools",
      items: [
        { tag: "01", title: "scan_project", detail: "Check the bounded workspace tree." },
        { tag: "02", title: "scan_file", detail: "Inspect one path under the workspace root." },
        { tag: "03", title: "explain_rule", detail: "Return the rule and its inline fix." },
        { tag: "04", title: "list_rules", detail: "Expose the compiled-in catalogue." },
      ],
      footer: "stdio, static analysis, workspace paths only",
      tone: "safe",
    }),
  }),
  "offline/": () => ({
    kicker: "Local by default",
    summary: `<strong>A normal scan does not create a network client.</strong> Source files stay on the machine. Network access is available only when you explicitly enable an active or OSV check.`,
    actions: [
      { label: "Run a local scan", href: "https://www.npmjs.com/package/owlwarden", kind: "primary" },
      { label: "Review CI options", href: "../ci/", kind: "secondary" },
    ],
    visual: productVisual({
      label: "default scan",
      title: "Local input, local report",
      items: [
        { tag: "IN", title: "Repository files", detail: "Bounded reads below the project root." },
        { tag: "CPU", title: "Local Rust engine", detail: "Static rules run on your machine." },
        { tag: "OUT", title: "Actionable finding", detail: "Line, confidence, and framework-specific fix." },
      ],
      footer: "No outbound requests, telemetry, or account",
      tone: "safe",
    }),
  }),
  "owasp/": ({ coverage, webRules }) => coverageHero(
    "OWASP Top 10 (2021)",
    coverage.categoriesCovered,
    webRules.length,
    "../asi/",
  ),
  "asi/": ({ coverage, agentRules }) => coverageHero(
    `OWASP ASI ${coverage.asiEdition}`,
    coverage.asiCategoriesCovered,
    agentRules.length,
    "../owasp/",
  ),
  "ci/": () => ({
    kicker: "CI",
    summary: `<strong>Exit 0 means clean, 1 means findings, and 2 means the scan failed.</strong> The same run can write SARIF, JUnit, JSON, or Markdown.`,
    actions: [
      { label: "Browse the GitHub Action", href: "https://github.com/suthat/owlwarden/tree/main/action", kind: "primary" },
      { label: "Review coverage", href: "../owasp/", kind: "secondary" },
    ],
    visual: productVisual({
      label: "pull request / security gate",
      title: "One scan, several report formats",
      items: [
        { tag: "SARIF", title: "Code scanning", detail: "Findings land on the exact source line." },
        { tag: "JUNIT", title: "Test UI", detail: "Security results sit beside the test suite." },
        { tag: "MD", title: "Review summary", detail: "A compact report fits the pull request." },
      ],
      footer: "exit 0 clean, exit 1 findings, exit 2 scan error",
      tone: "safe",
    }),
  }),
  "vs/semgrep/": () => compareHero("Semgrep", [
    ["Rule breadth", "Thousands", "Focused"],
    ["Languages", "Many", "JS / TS"],
    ["Agent config", "No", "Yes"],
    ["Default run", "Varies", "Offline"],
  ]),
  "vs/snyk/": () => compareHero("Snyk", [
    ["Dependencies", "Deep", "OSV opt-in"],
    ["Agent config", "No", "Yes"],
    ["Account", "Product tier", "None"],
    ["Best together", "SCA", "Source + config"],
  ]),
  "vs/claude-security/": () => compareHero("model review", [
    ["Novel bugs", "Strong", "Rule-bound"],
    ["Same answer twice", "No", "Yes"],
    ["Always runs", "When asked", "Host gate"],
    ["Cost per scan", "Tokens", "None"],
  ]),
  "vs/eslint-plugin-security/": () => compareHero("ESLint security", [
    ["Setup", "Already in lint", "One command"],
    ["Framework context", "Syntax", "Profiles"],
    ["Confidence", "No", "Explicit"],
    ["Agent config", "No", "Yes"],
  ]),
};

function lifecycleHero(host, surfaceHref, events) {
  return {
    kicker: `${host} hooks`,
    summary: `<strong>Run checks from the host lifecycle instead of relying on a prompt.</strong> Hooks scan edits, inspect shell commands, and check the completed turn.`,
    actions: [
      { label: `Set up ${host}`, href: "https://www.npmjs.com/package/owlwarden", kind: "primary" },
      { label: "See what gets scanned", href: surfaceHref, kind: "secondary" },
    ],
    visual: productVisual({
      label: `${host} lifecycle`,
      title: "Checks attached to host events",
      items: events.map(([title, detail], index) => ({ tag: `0${index + 1}`, title, detail })),
      footer: "host event, local check, finding or clean result",
      tone: "safe",
    }),
  };
}

function coverageHero(label, covered, ruleCount, otherHref) {
  return {
    kicker: `${label} mapping`,
    summary: `<strong>${ruleCount} rules map to ${covered} of 10 categories.</strong> The table also shows categories that static source or configuration checks cannot cover.`,
    actions: [
      { label: "Read the rules", href: "../rules/", kind: "primary" },
      { label: "Compare taxonomies", href: otherHref, kind: "secondary" },
    ],
    visual: productVisual({
      label,
      title: `${covered} of 10 categories have compiled-in coverage`,
      items: [
        { tag: String(covered).padStart(2, "0"), title: "Categories covered", detail: "Backed by rules in the engine." },
        { tag: String(ruleCount).padStart(2, "0"), title: "Rules mapped", detail: "Each mapping is published and inspectable." },
        { tag: "ALL", title: "Unmapped categories", detail: "Empty categories remain visible in the table." },
      ],
      footer: "Generated from rule metadata in the installed engine",
    }),
  };
}

function compareHero(other, rows) {
  return {
    kicker: `owlwarden and ${esc(other)}`,
    summary: `<strong>The tools cover different jobs.</strong> The table compares scope and default behavior so you can decide whether to run one or both.`,
    actions: [
      { label: "See owlwarden rules", href: "../../rules/", kind: "primary" },
      { label: "Review the gaps", href: "../../owasp/", kind: "secondary" },
    ],
    visual: comparisonVisual(other, rows),
  };
}

function agentSurfaceItems() {
  return [
    { tag: "HOOK", title: "Lifecycle commands", detail: "Can run when a workspace opens." },
    { tag: "MCP", title: "Tool servers", detail: "May resolve executable code at run time." },
    { tag: "TEXT", title: "Agent instructions", detail: "Can hide reviewer-invisible directives." },
  ];
}
