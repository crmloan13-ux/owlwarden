import { chip, code, esc } from "./layout.mjs";
import { marketingHero } from "./marketing.mjs";
import { renderFrame } from "./samples.mjs";

/**
 * The pages that are written rather than generated.
 *
 * Each page answers one developer question:
 *
 * - the homepage explains what gets scanned and how to run it;
 * - hub pages document a product surface;
 * - comparison pages state scope and trade-offs.
 *
 * They live in a module rather than in HTML files so that the header, the
 * footer, the JSON-LD, and the canonical tag have one definition — and so a
 * domain change is one file rather than fourteen.
 */

const CROSS = (up = "") => `
<h2>Keep reading</h2>
<ul class="cards">
  <li><a href="${up}rules/"><span class="name">Rules</span><span class="blurb">Trigger, confidence, and framework-specific fix.</span></a></li>
  <li><a href="${up}agent-config-security/"><span class="name">Agent config</span><span class="blurb">Hooks, MCP servers, instructions, and editor tasks.</span></a></li>
  <li><a href="${up}vet/"><span class="name">owlwarden vet</span><span class="blurb">Check a repository before you open it.</span></a></li>
  <li><a href="${up}owasp/"><span class="name">Coverage</span><span class="blurb">Mapped rules and categories static analysis cannot cover.</span></a></li>
</ul>`;

export function staticPages({ rules, coverage, samples, version }) {
  const agentRules = rules.filter((rule) => rule.surface === "agentWorkspace");
  const webRules = rules.filter((rule) => (rule.surface ?? "webApp") === "webApp");

  const leak = samples.get("stack-trace-leak")?.get("next");
  const hook = samples.get("agent-hook-autoexec")?.get("claude-code");

  const pages = [
    { path: "", page: home({ rules, webRules, agentRules, coverage, leak, hook, version }) },
    { path: "agent-config-security/", page: agentConfigSecurity({ agentRules, hook }) },
    { path: "vet/", page: vet({ agentRules }) },
    { path: "claude-code/", page: claudeCode() },
    { path: "cursor/", page: cursor() },
    { path: "mcp/", page: mcp() },
    { path: "offline/", page: offline() },
    { path: "owasp/", page: owasp({ coverage, webRules }) },
    { path: "asi/", page: asi({ coverage, agentRules }) },
    { path: "ci/", page: ci() },
    { path: "vs/semgrep/", page: vsSemgrep() },
    { path: "vs/snyk/", page: vsSnyk() },
    { path: "vs/claude-security/", page: vsModelReviewers() },
    { path: "vs/eslint-plugin-security/", page: vsEslint() },
  ];

  const heroContext = { rules, webRules, agentRules, coverage, leak, hook };
  return pages.map(({ path, page }) => ({
    path,
    page: { ...page, hero: marketingHero(path, heroContext) },
  }));
}

// ---------------------------------------------------------------------------

function home({ rules, webRules, agentRules, coverage, version }) {
  return {
    title: "owlwarden: local security scanner for Node and coding agents",
    heading: "Security checks for Node apps and coding-agent config",
    description:
      "Local security scanner for Node apps and coding agents. OWASP checks with framework fixes, " +
      "plus .claude, .cursor, and .vscode configuration.",
    ogType: "website",
    breadcrumbs: [{ label: "owlwarden", href: "" }],
    schema: [
      {
        "@type": "SoftwareApplication",
        name: "owlwarden",
        applicationCategory: "DeveloperApplication",
        applicationSubCategory: "Security Scanner",
        operatingSystem: "macOS, Linux, Windows",
        softwareVersion: version,
        downloadUrl: "https://www.npmjs.com/package/owlwarden",
        codeRepository: "https://github.com/suthat/owlwarden",
        license: "https://spdx.org/licenses/MIT.html",
        programmingLanguage: ["Rust", "TypeScript"],
        offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
        description:
          "Offline security scanner for Node web apps and AI coding agents.",
      },
      {
        "@type": "FAQPage",
        mainEntity: [
          faq(
            "Does owlwarden send my code anywhere?",
            "No. There is no telemetry and no opt-in switch, because there is nothing to switch on. " +
              "The only network traffic is what you ask for explicitly: --osv looks up advisories by " +
              "package name and version, and --target probes a URL you name.",
          ),
          faq(
            "Is owlwarden free?",
            "Yes. MIT OR Apache-2.0, at your option. No account, no seat count, no hosted tier.",
          ),
          faq(
            "Does it work with Claude Code?",
            "Yes. `owlwarden init --claude-code` wires the gate into the host's lifecycle events, " +
              "and `owlwarden mcp` exposes a read-only, static-only MCP server. Cursor and any " +
              "hook-capable host are supported too.",
          ),
          faq(
            "How is it different from a cloud SAST?",
            `It runs locally and checks agent and editor configuration as well as application ` +
              `source. It has ${rules.length} focused rules. Run it with a broader scanner when ` +
              "you need more language or rule coverage.",
          ),
        ],
      },
    ],
    body: `
${code("bash", "npx owlwarden scan          # your app\nnpx owlwarden vet .         # your agent's config")}

<h2>Known limits</h2>
<p>
  Read these before treating a clean result as a clean repository.
</p>
<div class="table-wrap">
<table>
  <thead><tr><th>Limit</th><th>Why</th></tr></thead>
  <tbody>
    <tr><td>${coverage.categoriesCovered} of 10 OWASP categories</td><td>A04 (Insecure Design) needs design context. <a href="./owasp/">See the full mapping</a>.</td></tr>
    <tr><td>Origin tracking is one hop</td><td>Not a full taint engine. Injection-shaped rules cap their confidence instead of guessing.</td></tr>
    <tr><td>Agent rules cap at <code>likely</code></td><td><code>confirmed</code> means corroborated against a running target, and a config file has none.</td></tr>
    <tr><td>${rules.length} rules, not thousands</td><td>Node web applications and agent configuration. <a href="./vs/semgrep/">Run Semgrep too</a>.</td></tr>
  </tbody>
</table>
</div>

<h2>What gets scanned</h2>
<p>
  <strong>${webRules.length} rules read application code. ${agentRules.length} read agent config.</strong>
  Agent rules cover files loaded from the working tree, including
  <code>.claude/settings.json</code>,
  <code>.vscode/tasks.json</code>, <code>.cursor/hooks.json</code>,
  and <code>CLAUDE.md</code>. These files are not recorded in the lockfile.
</p>
<p>
  Each finding includes a fix for the detected framework or agent host.
  <a href="./rules/">The rule catalogue</a> shows the tested examples.
</p>

<h2>Run it from agent hooks</h2>
<p>
  <code>owlwarden gate</code> runs from host lifecycle events after edits,
  before shell commands, and at the end of a turn. The agent does not need to
  remember to call it.
</p>
${code("bash", "owlwarden init --claude-code   # hooks + MCP entry\nowlwarden init --cursor\nowlwarden init --generic       # any host that can run a process")}
<p>
  <a href="./claude-code/">Claude Code</a> · <a href="./cursor/">Cursor</a> ·
  <a href="./mcp/">MCP</a> · <a href="./ci/">CI</a> ·
  <a href="./vet/">vet</a> · <a href="./changelog/">Changelog</a>
</p>

<h2>Common questions</h2>
<details>
<summary>Does owlwarden send my code anywhere?</summary>
<p>
  No. There is no telemetry and no opt-in switch, because there is nothing to
  switch on. <a href="./offline/">The threat model is on its own page</a>.
</p>
</details>
<details>
<summary>Is it free?</summary>
<p>MIT OR Apache-2.0, at your option. No account, no seat count, no hosted tier.</p>
</details>
<details>
<summary>Does it replace my existing scanner?</summary>
<p>
  No. Compare its scope with <a href="./vs/semgrep/">Semgrep</a>,
  <a href="./vs/snyk/">Snyk</a>,
  <a href="./vs/claude-security/">model-based review</a>, and
  <a href="./vs/eslint-plugin-security/">eslint-plugin-security</a>.
</p>
</details>
<details>
<summary>What changed in the last release?</summary>
<p>
  Read the <a href="./changelog/">changelog</a> or subscribe to its
  <a href="./changelog/feed.xml">Atom feed</a>.
</p>
</details>
`,
  };
}

function faq(question, answer) {
  return {
    "@type": "Question",
    name: question,
    acceptedAnswer: { "@type": "Answer", text: answer },
  };
}

// ---------------------------------------------------------------------------

function agentConfigSecurity({ agentRules, hook }) {
  return {
    title: "Scan agent and editor configuration",
    heading: "Scan agent config before it runs",
    description:
      "Agent and editor configuration is executable, is read from the working tree, and is not in " +
      "your lockfile. What lives there, and how to check your repo.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Agent config security", href: "agent-config-security/" },
    ],
    schema: [
      {
        "@type": "TechArticle",
        headline: "Agent and editor configuration is a second attack surface",
        proficiencyLevel: "Beginner",
        about: [
          { "@type": "Thing", name: "CWE-829", url: "https://cwe.mitre.org/data/definitions/829.html" },
          { "@type": "Thing", name: "OWASP ASI 2026", url: "https://genai.owasp.org/" },
        ],
      },
    ],
    body: `
<p>
  Hooks, MCP declarations, instruction files, and editor tasks are checked into
  the repository but are not dependencies or application source. Many scanners
  do not read them.
</p>

<h2>How the August 2026 npm worm persisted</h2>
<p>
  Dependency tooling found the poisoned package versions. The payload also
  wrote files under
  <code>.claude/settings.json</code>, <code>.claude/setup.mjs</code>,
  <code>.vscode/tasks.json</code>, and <code>.vscode/setup.mjs</code>, and used
  stolen credentials to commit them to other repositories.
</p>
<p>
  Removing the package or regenerating the lockfile does not remove those
  files. Opening the folder in an editor or agent can run them again.
</p>

${hook ? `<h2>What that looks like in a scan</h2>${renderFrame(hook, esc)}` : ""}

<h2 id="agent-rules">${agentRules.length} agent-config rules</h2>
<ul class="cards">
${agentRules
  .map(
    (rule) => `  <li><a href="../rules/${esc(rule.id)}/">
    <span class="name">${esc(rule.id)}</span>
    <span class="blurb">${chip(rule.severity)} ${esc(rule.title)}</span>
  </a></li>`,
  )
  .join("\n")}
</ul>

<h2>Which files are in scope</h2>
<p>
  owlwarden scans a fixed list of paths at the repository root and below package
  directories. It does not scan agent config inside <code>node_modules</code>.
</p>
${code(
  "text",
  [
    ".claude/settings.json          .cursor/mcp.json           .vscode/tasks.json",
    ".claude/settings.local.json    .cursor/hooks.json         .vscode/settings.json",
    ".claude/hooks/**               .cursor/hooks/**           .vscode/extensions.json",
    ".claude/agents/**              .cursor/rules/**           .vscode/*.{js,mjs,ts,sh,py}",
    ".claude/skills/**              .cursorrules               .devcontainer/devcontainer.json",
    ".claude/*.{js,mjs,ts,sh,py}    .gemini/**                 .github/copilot-instructions.md",
    ".claude-plugin/**              .codex/**                  .mcp.json  mcp.json",
    "CLAUDE.md                      AGENTS.md",
  ].join("\n"),
)}
<p>
  <code>.claude/settings.local.json</code> is conventionally gitignored. It is
  also used for workspace hooks, so agent-config scans include it even when it
  is ignored. Path containment, symlink checks, and size limits still apply.
</p>

<h2>Check your own repository</h2>
${code("bash", "npx owlwarden scan --preset agent-surface   # your own repo\nnpx owlwarden vet ./cloned-repo             # someone else's")}
<p>
  <a href="../vet/"><code>vet</code> is the one to use on a repository you did
  not write</a>. It ignores target policy and reports target suppressions.
  <a href="../asi/">The ASI table</a> shows the category mapping.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function vet({ agentRules }) {
  return {
    title: "owlwarden vet: check a repo before opening it",
    heading: "Check a repository before you open it in an agent",
    description:
      "owlwarden vet scans a repository you did not write: agent rules only, offline, no plugins, " +
      "and the target's own suppressions counted rather than honoured.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "vet", href: "vet/" },
    ],
    schema: [
      {
        "@type": "HowTo",
        name: "Check a cloned repository before opening it in an agent",
        totalTime: "PT1M",
        step: [
          { "@type": "HowToStep", name: "Clone without opening", text: "git clone <url> ./candidate" },
          { "@type": "HowToStep", name: "Vet it", text: "npx owlwarden vet ./candidate" },
          {
            "@type": "HowToStep",
            name: "Read the exit code",
            text: "0 means nothing at or above high; 1 means findings; 2 means the scan could not run.",
          },
        ],
      },
    ],
    body: `
${code("bash", "git clone https://github.com/someone/thing ./candidate\nnpx owlwarden vet ./candidate")}

<h2>What makes it different from <code>scan</code></h2>
<p>
  <code>scan</code> reads your config, honours your baseline, and applies your
  inline suppressions. Those options are useful on a repository you maintain.
</p>
<p>
  On an unfamiliar repository, its own policy can hide findings. <code>vet</code>
  therefore uses fixed settings:
</p>
<div class="table-wrap">
<table>
  <thead><tr><th>Setting</th><th>Under <code>vet</code></th></tr></thead>
  <tbody>
    <tr><td>Preset</td><td><code>agent-surface</code>, the ${agentRules.length} rules that read configuration</td></tr>
    <tr><td>Network</td><td>None. No OSV, no <code>--target</code>, no exceptions</td></tr>
    <tr><td>Plugins</td><td>Not loaded, even signed ones, even with a trust root configured</td></tr>
    <tr><td>The target's config</td><td>Not read</td></tr>
    <tr><td>The target's baseline</td><td>Not applied</td></tr>
    <tr><td>Inline suppressions</td><td>Counted and reported, never honoured</td></tr>
  </tbody>
</table>
</div>
<p>
  Passing <code>--plugin</code>, <code>--target</code>, <code>--baseline</code>,
  or <code>--allow-suppressions</code> to <code>vet</code> is an error rather
  than a no-op.
</p>

<h2>Suppression count</h2>
<p>
  The summary reports how many inline suppressions it found and confirms that
  none were applied.
</p>

<h2>Then what</h2>
<p>
  <code>vet</code> tells you what is in the configuration. It does not sandbox
  execution. Open a suspicious repository in a
  sandboxed runtime. <a href="../agent-config-security/">What the rules look
  for</a> · <a href="../rules/">the full catalogue</a> ·
  <a href="../offline/">why none of this needs a network</a>.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function claudeCode() {
  return {
    title: "owlwarden for Claude Code: hooks, MCP, and vet",
    heading: "Security scanning inside Claude Code",
    description:
      "Wire owlwarden into Claude Code's lifecycle: a gate after every edit and at the turn " +
      "boundary, a read-only MCP server, and a scan of the .claude config itself.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Claude Code", href: "claude-code/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "owlwarden and Claude Code", proficiencyLevel: "Beginner" }],
    body: `
${code("bash", "npm i -D owlwarden\nnpx owlwarden init --claude-code")}

<h2>What that writes</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Event</th><th>Scope</th><th>Verdict</th></tr></thead>
  <tbody>
    <tr><td><code>PostToolUse</code> (Edit, Write, MultiEdit)</td><td>the file that was written</td><td>blocks with the rule, the line, and the fix</td></tr>
    <tr><td><code>PreToolUse</code> (Bash)</td><td>the command string</td><td>blocks the command when the check fails</td></tr>
    <tr><td><code>Stop</code></td><td>everything changed since the turn began</td><td>checks the completed turn</td></tr>
  </tbody>
</table>
</div>

<h2>No repository <code>SessionStart</code> hook</h2>
<p>
  The generated config does not add a <code>SessionStart</code> entry.
  <a href="../rules/agent-hook-autoexec/"><code>agent-hook-autoexec</code></a>
  reports repository configuration that runs when the workspace is opened, at
  high severity, because anyone who clones the repository and opens it runs that
  command. <code>owlwarden scan</code> would report a generated repository hook
  of that shape.
</p>
<p>
  The session digest belongs in <em>user</em> settings,
  which a cloned repository cannot write. The same reasoning is why the MCP
  entry is <code>node_modules/.bin/owlwarden</code> rather than
  <code>npx -y owlwarden</code>:
  <a href="../rules/agent-mcp-unpinned-remote/">that shape is a finding too</a>.
</p>

<h2>MCP for manual scans</h2>
<p>
  Hooks run checks automatically. <a href="../mcp/">MCP</a> handles prompted
  requests such as <em>explain this rule</em> or <em>scan
  <code>packages/api</code></em>. The server is read-only and static-only.
</p>

<h2>Before you open an unfamiliar repository</h2>
${code("bash", "npx owlwarden vet ./cloned-repo")}
<p>
  <a href="../vet/">What <code>vet</code> refuses to trust</a> ·
  <a href="../agent-config-security/">what lives in <code>.claude/</code></a> ·
  <a href="../rules/">every rule</a>.
</p>
${CROSS("../")}
`,
  };
}

function cursor() {
  return {
    title: "owlwarden for Cursor: hooks, MCP, and rules",
    heading: "Security scanning inside Cursor",
    description:
      "Wire owlwarden into Cursor's hooks: a gate after every edit, before a shell command, and at " +
      "the turn boundary, plus a rules file the model reads first.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Cursor", href: "cursor/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "owlwarden and Cursor", proficiencyLevel: "Beginner" }],
    body: `
${code("bash", "npm i -D owlwarden\nnpx owlwarden init --cursor")}

<h2>What that writes</h2>
<ul>
  <li><code>.cursor/hooks.json</code> with <code>afterFileEdit</code>, <code>beforeShellExecution</code>, and <code>stop</code>.</li>
  <li><code>.cursor/mcp.json</code> with the read-only server pinned to the installed binary.</li>
  <li><code>.cursor/rules/owlwarden.mdc</code> with the rule summary used by the hooks.</li>
</ul>

<h2>The rules file is not the control</h2>
<p>
  Rules reduce avoidable findings, but they remain prompt context. Hooks are the
  part that runs independently of the model's decision.
</p>

<h2>Cursor's own configuration is a scan surface</h2>
<p>
  <code>.cursor/mcp.json</code>, <code>.cursor/hooks.json</code>,
  <code>.cursorrules</code>, and <code>.cursor/rules/**</code> are read by the
  <a href="../agent-config-security/">agent-config rules</a>. They check unpinned MCP
  server, a hook that pipes a fetch into a shell, a rules file with characters a
  reviewer cannot see. Cursor is one <code>git pull</code> away from any of them.
</p>

${code("bash", "npx owlwarden vet .")}
${CROSS("../")}
`,
  };
}

function mcp() {
  return {
    title: "owlwarden MCP server: read-only and local",
    heading: "The owlwarden MCP server",
    description:
      "A stdio MCP server exposing scan_project, scan_file, explain_rule, and list_rules. " +
      "Read-only, static-only, and it never touches the network.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "MCP", href: "mcp/" },
    ],
    schema: [
      {
        "@type": "SoftwareApplication",
        name: "owlwarden MCP server",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "macOS, Linux, Windows",
        offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
      },
    ],
    body: `
${code("bash", "npx owlwarden mcp")}

<h2>When to use it</h2>
<p>
  It is the right surface for the prompted, exploratory case: <em>what does this
  rule mean</em>, <em>show me everything in <code>packages/api</code></em>.
</p>
<p>
  MCP calls are optional because the model decides when to make them. Use
  <a href="../claude-code/">hooks</a> for checks that must run after edits or
  before commands.
</p>

<h2>Configuration</h2>
<p>
  <code>owlwarden init</code> writes this for you:
  <a href="../claude-code/">Claude Code</a>, <a href="../cursor/">Cursor</a>, or
  <a href="../vet/">check a repository first</a>.
</p>
${code(
  "json",
  `{
  "mcpServers": {
    "owlwarden": {
      "command": "node_modules/.bin/owlwarden",
      "args": ["mcp"]
    }
  }
}`,
)}
<p>
  Invoked by path rather than <code>npx -y owlwarden</code>, because
  <a href="../rules/agent-mcp-unpinned-remote/">a server resolved at run time is
  a finding</a>. The generated config uses the installed binary instead.
</p>

<h2>On a terminal</h2>
<p>
  Run without a host and it prints a short how-to on stderr, then waits.
  Silence means it is waiting for a host, not that it hung.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function offline() {
  return {
    title: "Offline by default: no account or telemetry",
    heading: "Local scans with no account or telemetry",
    description:
      "owlwarden scans on your machine without an account or telemetry. Network access is used " +
      "only for explicitly enabled OSV lookups or target probes.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "Offline", href: "offline/" },
    ],
    schema: [
      {
        "@type": "FAQPage",
        mainEntity: [
          faq(
            "Does owlwarden send my code anywhere?",
            "No. There is no telemetry and no opt-in switch. The only network traffic is what you " +
              "ask for: --osv sends package names and versions, never source; --target probes a " +
              "URL you name, scoped deny-by-default.",
          ),
          faq(
            "Can I run it with no network at all?",
            "Yes. That is the default. For advisory lookups in an air-gapped pipeline, build a " +
              "cached index with `owlwarden osv update` and pass --osv-db --offline.",
          ),
        ],
      },
    ],
    body: `
<h2>What the default run does</h2>
<p>
  The default command reads files below the project root, parses them, and
  prints a report. It does not create a network transport. The request budget is
  zero and the scope resolver denies every destination.
</p>

<h2>The two ways to opt in</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Flag</th><th>What leaves the machine</th></tr></thead>
  <tbody>
    <tr><td><code>--osv</code></td><td>Package names and versions from your lockfile, to <code>api.osv.dev</code>. Never source, never file paths.</td></tr>
    <tr><td><code>--target URL</code></td><td>HTTP requests to the URL you name, and only to its origin unless you widen <code>--scope</code>. Passive methods unless you also pass <code>--allow-active</code>.</td></tr>
  </tbody>
</table>
</div>
<p>
  For an air-gapped pipeline: <code>owlwarden osv update</code> builds a cached
  index once, and <code>--osv-db path --offline</code> fails closed if the cache
  is missing rather than quietly reaching for the network.
</p>

<h2>What "no telemetry" means here</h2>
<p>
  There is no analytics code, crash reporter, or version check. This site also
  loads no font CDN, analytics script, or tag manager. The site build checks the
  external-host allowlist.
</p>

<h2>Where it runs</h2>
<p>
  A Rust engine behind a Node CLI, plus a standalone binary that needs no
  JavaScript toolchain at all. Both read the same rules and print the same
  report. <a href="../ci/">In CI</a>, the exit code is the gate and nothing is
  uploaded unless you upload it.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function coverageTable(entries, emptyLabel) {
  return `<div class="table-wrap">
<table>
  <thead><tr><th>Category</th><th>Reach</th><th>Rules</th></tr></thead>
  <tbody>
${entries
  .map((entry) => {
    const rules =
      entry.rules.length > 0
        ? entry.rules
            .map((id) => `<a href="../rules/${esc(id)}/"><code>${esc(id)}</code></a>`)
            .join(", ")
        : `<em>${entry.reachability === "poor" ? emptyLabel : "none yet"}</em>`;
    return `    <tr><td><strong>${esc(entry.id)}</strong> ${esc(entry.title)}</td><td>${esc(entry.reachability)}</td><td>${rules}</td></tr>`;
  })
  .join("\n")}
  </tbody>
</table>
</div>`;
}

function owasp({ coverage, webRules }) {
  return {
    title: "OWASP Top 10 coverage for Node",
    heading: `OWASP Top 10 (2021): ${coverage.categoriesCovered} of 10 categories`,
    description:
      `owlwarden maps ${webRules.length} rules onto the OWASP Top 10 (2021). This table lists every ` +
      `category, including the ones with no rule and the ones no source scanner can reach.`,
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "OWASP coverage", href: "owasp/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "OWASP Top 10 (2021) coverage", proficiencyLevel: "Beginner" }],
    body: `
<p>
  <strong>Reach</strong> describes how much of a category static source analysis
  can see. Categories marked <code>poor</code> need runtime data or design
  review.
</p>

${coverageTable(coverage.owasp, "not reachable from source")}

<h2>Why A04 has no rules</h2>
<p>
  Insecure Design covers choices such as a missing rate limit or an unsafe
  recovery flow. Those problems do not have a reliable AST pattern and need
  design review or runtime evidence.
</p>

<h2>The other taxonomy</h2>
<p>
  Rules that read agent configuration map to
  <a href="../asi/">OWASP ASI ${esc(coverage.asiEdition)}</a> instead, and that
  table is separate because agent-config findings do not increase application
  Top 10 coverage.
</p>

${code("bash", "npx owlwarden coverage      # printed from the engine you have installed")}
${CROSS("../")}
`,
  };
}

function asi({ coverage, agentRules }) {
  return {
    title: `OWASP ASI ${coverage.asiEdition} coverage for agent config`,
    heading: `OWASP ASI ${coverage.asiEdition} coverage: ${coverage.asiCategoriesCovered} of 10`,
    description:
      `owlwarden maps ${agentRules.length} agent-surface rules onto the OWASP Top 10 for Agentic ` +
      `Applications. Every category is listed, including the ones configuration cannot show.`,
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "ASI coverage", href: "asi/" },
    ],
    schema: [{ "@type": "TechArticle", headline: `OWASP ASI ${coverage.asiEdition} coverage`, proficiencyLevel: "Beginner" }],
    body: `
${coverageTable(coverage.asi, "needs the agent's run-time behaviour, not its configuration")}

<h2>What a configuration scanner can and cannot see</h2>
<p>
  Instruction files, hooks, permissions, and tool declarations are checked into
  the repository, so they are visible. Memory poisoning, tool misuse at run
  time, and multi-agent orchestration need runtime data. Parsing
  <code>.claude/settings.json</code> cannot detect them.
</p>

<h2>Why CWE is the primary mapping</h2>
<p>
  CWE ids are stable across decades. The agentic list is new and will be
  renumbered, so every rule in this family declares a CWE and carries the ASI
  reference as additional context. Existing baselines therefore continue to
  use the stable CWE mapping if ASI numbering changes.
</p>

<p>
  <a href="../agent-config-security/">What this surface is</a> ·
  <a href="../vet/">how to check a repository you did not write</a> ·
  <a href="../owasp/">the OWASP Top 10 table</a>.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function ci() {
  return {
    title: "owlwarden in CI: SARIF, JUnit, and exit codes",
    heading: "Run owlwarden in CI",
    description:
      "SARIF 2.1.0 for code scanning, JUnit for test UIs, Markdown for PR comments, and an exit " +
      "code contract that refuses to go green on a partial scan.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "CI", href: "ci/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "owlwarden in CI", proficiencyLevel: "Intermediate" }],
    body: `
${code(
  "yaml",
  `- uses: suthat/owlwarden/action@v1
  with:
    fail-on: medium
    format: sarif
    since: \${{ github.event.pull_request.base.sha }}`,
)}

<h2>The exit-code contract</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Code</th><th>Means</th></tr></thead>
  <tbody>
    <tr><td><code>0</code></td><td>Scanned, nothing at or above <code>--fail-on</code></td></tr>
    <tr><td><code>1</code></td><td>Findings at or above the threshold</td></tr>
    <tr><td><code>2</code></td><td>Could not run because of a bad flag, unreadable tree, or missing engine</td></tr>
  </tbody>
</table>
</div>
<p>
  Exit code <code>2</code> keeps a scan error separate from a finding. CI should
  fail in both cases but can report them differently.
</p>

<h2>What <code>--ci</code> refuses</h2>
<p>
  Under <code>--ci</code>, project configuration cannot set the gate knobs, and
  inline suppressions and <code>--baseline</code> are ignored unless the
  operator opts in explicitly. A pull request cannot weaken the check by editing
  repository config.
</p>

<h2>A truncated report is not a clean report</h2>
<p>
  If the engine hits its finding cap it says so, and the run fails even with no
  retained findings above the threshold. Exiting <code>0</code> would hide
  whatever it did not get to.
</p>

<h2>Only what changed</h2>
${code("bash", "owlwarden scan --since origin/main --fail-on medium\nowlwarden scan --staged            # a pre-commit hook")}
<p>
  A diff-scoped scan states its scope in every format, so a clean result can
  never be mistaken for a clean repository. Project-scope rules still run when
  <em>their own</em> declared inputs changed — a commit touching only
  <code>package.json</code> still fires the dependency rules.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function comparison({ path, slug, title, heading, description, body, questions }) {
  return {
    path,
    page: {
      title,
      heading,
      description,
      breadcrumbs: [
        { label: "owlwarden", href: "" },
        { label: "Compare", href: "vs/semgrep/" },
        { label: slug, href: path },
      ],
      schema: [
        { "@type": "TechArticle", headline: heading, proficiencyLevel: "Beginner" },
        // "owlwarden vs X" is a question someone types, and the answer is
        // already on the page. A padded FAQ is worse than none, so these are
        // the two real questions each comparison actually answers.
        ...(questions ? [{ "@type": "FAQPage", mainEntity: questions.map(([q, a]) => faq(q, a)) }] : []),
      ],
      body: `${body}
<h2>Other comparisons</h2>
<ul class="cards">
  <li><a href="../semgrep/"><span class="name">vs Semgrep</span><span class="blurb">Rule and language coverage, local defaults, and agent config.</span></a></li>
  <li><a href="../snyk/"><span class="name">vs Snyk</span><span class="blurb">Dependency analysis and repository-controlled agent config.</span></a></li>
  <li><a href="../claude-security/"><span class="name">vs model-based review</span><span class="blurb">Static checks and review that needs judgement.</span></a></li>
  <li><a href="../eslint-plugin-security/"><span class="name">vs eslint-plugin-security</span><span class="blurb">Lint patterns and framework-aware checks.</span></a></li>
</ul>
<p><a href="../../rules/">All rules</a> · <a href="../../owasp/">Coverage, gaps included</a> · <a href="../../offline/">Offline</a></p>`,
    },
  };
}

function vsSemgrep() {
  return comparison({
    questions: [
      [
        "Should I use owlwarden instead of Semgrep?",
        "Usually not. Semgrep has thousands of rules across many languages; owlwarden has 25, " +
          "runs offline with no account, gives a fix written for your framework, and reads the " +
          "agent and editor configuration Semgrep does not.",
      ],
      [
        "Does owlwarden need an account or a cloud service?",
        "No. It runs entirely on your machine and constructs no network transport at all unless " +
          "you pass --osv or --target.",
      ],
    ],
    path: "vs/semgrep/",
    slug: "Semgrep",
    title: "owlwarden vs Semgrep: scope and trade-offs",
    heading: "owlwarden vs Semgrep",
    description:
      "Semgrep has thousands of rules across many languages. owlwarden has 25, runs offline with " +
      "no account, and reads agent config. Compare their scope and defaults.",
    body: `
<h2>What Semgrep covers</h2>
<ul>
  <li><strong>Rule breadth.</strong> Thousands of rules across many languages. owlwarden has 25 rules for Node applications and agent config.</li>
  <li><strong>Custom rules.</strong> A mature pattern language with a large public registry. owlwarden's plugin tier is source-only WASM with a fixed v1 API.</li>
  <li><strong>Language coverage.</strong> Python, Go, Java, C#. owlwarden is JavaScript and TypeScript.</li>
</ul>

<h2>What owlwarden adds</h2>
<ul>
  <li><strong>Agent configuration.</strong> <code>.claude/settings.json</code>, <code>.vscode/tasks.json</code>, and <code>.cursor/hooks.json</code>.</li>
  <li><strong>Offline with no account.</strong> No login, no upload, no policy service. The default run constructs no transport at all.</li>
  <li><strong>Framework-specific fixes.</strong> Findings include corrected code for the detected API.</li>
  <li><strong>Agent hooks.</strong> <a href="../../claude-code/">Host events run checks automatically</a>.</li>
</ul>

<h2>Running both</h2>
${code("bash", "semgrep --config auto        # broad rule coverage\nowlwarden scan --since origin/main   # Node and agent config")}
<p>
  Both emit SARIF, so both land in the same code-scanning view.
  <a href="../../ci/">The exit-code contract is here.</a>
</p>`,
  }).page;
}

function vsSnyk() {
  return comparison({
    questions: [
      [
        "Does owlwarden replace Snyk?",
        "No. Snyk's dependency database and reachability analysis are better than anything " +
          "owlwarden does with a lockfile. owlwarden covers the half a lockfile does not record: " +
          "the agent and editor configuration a compromised package writes into your repository.",
      ],
      [
        "Why does removing a poisoned package not remove the problem?",
        "Because the persistence lives in files a lockfile does not record. A hook written into " +
          ".claude/settings.json survives the package rollback, and opening the folder runs it again.",
      ],
    ],
    path: "vs/snyk/",
    slug: "Snyk",
    title: "owlwarden vs Snyk: dependencies and agent config",
    heading: "owlwarden vs Snyk",
    description:
      "Snyk covers dependencies. owlwarden checks application source and agent configuration that " +
      "lockfiles do not record. Compare their scope and defaults.",
    body: `
<h2>What Snyk covers</h2>
<ul>
  <li><strong>Dependency intelligence.</strong> A curated database, reachability, and fix pull requests. owlwarden's <code>--osv</code> is an opt-in lookup against a public database and nothing more.</li>
  <li><strong>Breadth and ecosystem.</strong> Many languages, container and IaC scanning, an organisation-wide policy plane.</li>
  <li><strong>Reporting for a security team.</strong> Dashboards, ownership, trend lines. owlwarden prints a report and sets an exit code.</li>
</ul>

<h2>What owlwarden adds</h2>
<ul>
  <li><strong>The persistence half of a supply-chain incident.</strong> Pulling a poisoned package version does not remove a hook someone wrote into <code>.claude/settings.json</code>. Regenerating the lockfile does not either. <a href="../../agent-config-security/">That file is not a dependency</a>.</li>
  <li><strong>No account, no upload.</strong> Nothing leaves the machine unless you pass a flag that says so.</li>
  <li><strong>Local static checks.</strong> Same input, same output, no seat count.</li>
</ul>

<h2>Running both</h2>
<p>
  Snyk for the dependency tree, owlwarden for the source and the agent
  configuration next to it. One <code>--fail-on</code> each, both in the same
  pipeline. <a href="../../ci/">CI setup</a> ·
  <a href="../../vet/">checking a repository before you open it</a>.
</p>`,
  }).page;
}

function vsModelReviewers() {
  return comparison({
    questions: [
      [
        "Can a model replace static analysis for security review?",
        "Not as a gate. A model answers differently between runs, which a baseline, a suppression, " +
          "and a CI threshold cannot use reliably. Use model review for authorisation, business " +
          "rules, and other work that needs judgement.",
      ],
      [
        "How much do local static checks cost per run?",
        "Nothing per token. --format agent puts the report on a budget of about 1500 tokens so the " +
          "checks a parser can answer stop being asked of a frontier model.",
      ],
    ],
    path: "vs/claude-security/",
    slug: "Model-based review",
    title: "Static analysis vs model-based code review",
    heading: "owlwarden vs a model reviewing your code",
    description:
      "A model can review design and business logic. Static rules give repeatable results for " +
      "known patterns. Compare where each approach fits.",
    body: `
<h2>Use model review for</h2>
<ul>
  <li><strong>Judgement.</strong> Authorisation logic, business rules, whether this particular endpoint should be public. No AST shape exists for any of it.</li>
  <li><strong>Novelty.</strong> A bug nobody wrote a rule for.</li>
  <li><strong>Context.</strong> It can read the ticket, the tests, and the migration in one pass.</li>
</ul>

<h2>Use static rules for</h2>
<ul>
  <li><strong>It gives the same answer twice.</strong> A baseline, a suppression, and a CI gate all require that. A reviewer that changes its mind between runs cannot be a gate.</li>
  <li><strong>It always runs.</strong> <a href="../../claude-code/">A hook fires on the host's event</a>; a model reviews when it is asked, and mid-refactor it often is not.</li>
  <li><strong>Low-cost repeated checks.</strong> A parser can check the same known pattern after every edit without using tokens.</li>
  <li><strong>Checks outside the prompt.</strong> Host hooks run independently of model instructions.</li>
</ul>

<h2>Run both</h2>
<p>
  Run static checks locally, then use model review for architecture,
  authorisation, payments, and data handling. <code>--format agent</code> keeps
  the static report within a token budget.
</p>
${code("bash", "owlwarden scan --format agent --budget 1500")}`,
  }).page;
}

function vsEslint() {
  return comparison({
    questions: [
      [
        "Is owlwarden a replacement for eslint-plugin-security?",
        "Not necessarily. owlwarden adds framework and route context plus an explicit confidence " +
          "field. Keeping both is reasonable when their rule sets differ.",
      ],
      [
        "Why do lint security rules produce so many false positives?",
        "Because they match syntax without knowing what a response, a cookie, or a request is in " +
          "your framework. owlwarden asks the detected framework's profile instead.",
      ],
    ],
    path: "vs/eslint-plugin-security/",
    slug: "eslint-plugin-security",
    title: "owlwarden vs eslint-plugin-security",
    heading: "owlwarden vs eslint-plugin-security",
    description:
      "eslint-plugin-security is lint heuristics with a known false-positive rate. owlwarden is " +
      "framework-aware, route-aware, and states the confidence its method earns.",
    body: `
<h2>What the ESLint plugin provides</h2>
<ul>
  <li><strong>Zero marginal setup.</strong> It is an ESLint plugin, and you already run ESLint.</li>
  <li><strong>Editor integration for free.</strong> Squiggles where you type, with no second process.</li>
</ul>

<h2>What owlwarden adds</h2>
<ul>
  <li><strong>It knows what a response is.</strong> <code>reply.send</code> in Fastify, <code>NextResponse.json</code> in Next.js, <code>ctx.body</code> in Koa. A lint rule matching <code>.stack</code> fires on <code>res.json({ stack: project.stack })</code> too.</li>
  <li><strong>Confidence is a field.</strong> <code>possible</code> findings are shown and do not fail CI on their own.</li>
  <li><strong>The fix is in the finding.</strong> Written for your framework, with the corrected code.</li>
  <li><strong>It reads your agent configuration.</strong> <a href="../../agent-config-security/">No lint rule does.</a></li>
</ul>

<h2>How precision is tested</h2>
<p>
  Each rule has a vulnerable fixture, a clean twin that must stay
  silent, and on the agent surface a <em>tempting</em> fixture: a legitimate
  configuration that shares surface features with the vulnerable one, whose
  silence is the assertion. <a href="../../rules/">Rules and tested
  examples</a>.
</p>`,
  }).page;
}
