import { chip, code, esc } from "./layout.mjs";
import { renderFrame } from "./samples.mjs";

/**
 * The pages that are written rather than generated.
 *
 * Each one has a job, and each one serves exactly one:
 *
 * - the homepage converts a reader into `npx owlwarden scan`;
 * - the hub pages answer a specific question well enough to be worth linking to;
 * - the comparison pages exist because without them the reader builds a worse
 *   comparison in their head, and ours is allowed to say where we lose.
 *
 * They live in a module rather than in HTML files so that the header, the
 * footer, the JSON-LD, and the canonical tag have one definition — and so a
 * domain change is one file rather than fourteen.
 */

const CROSS = (up = "") => `
<h2>Keep reading</h2>
<ul class="cards">
  <li><a href="${up}rules/"><span class="name">All rules</span><span class="blurb">The pattern, the fix for your stack, the CWE.</span></a></li>
  <li><a href="${up}agent-config-security/"><span class="name">Agent config security</span><span class="blurb">The files your agent executes and nothing scans.</span></a></li>
  <li><a href="${up}vet/"><span class="name">owlwarden vet</span><span class="blurb">Check a repository before you open it.</span></a></li>
  <li><a href="${up}owasp/"><span class="name">Coverage, gaps included</span><span class="blurb">What it checks, and what no parser can.</span></a></li>
</ul>`;

export function staticPages({ rules, coverage, samples, version }) {
  const agentRules = rules.filter((rule) => rule.surface === "agentWorkspace");
  const webRules = rules.filter((rule) => (rule.surface ?? "webApp") === "webApp");

  const leak = samples.get("stack-trace-leak")?.get("next");
  const hook = samples.get("agent-hook-autoexec")?.get("claude-code");

  return [
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
}

// ---------------------------------------------------------------------------

function home({ rules, webRules, agentRules, coverage, leak, hook, version }) {
  return {
    title: "owlwarden — offline security scanner for Node and AI agents",
    heading: "The deterministic security floor for code your agent just wrote",
    description:
      "Offline security scanner for Node web apps and AI coding agents. OWASP rules with " +
      "framework-specific fixes, plus the .claude and .vscode config nothing else reads.",
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
            "It runs offline with no account, it is deterministic, and it scans your agent and " +
              "editor configuration as well as your source. It has 25 rules, not thousands — run " +
              "both if you want breadth.",
          ),
        ],
      },
    ],
    body: `
<div class="hero-transcript">
${leak ? renderFrame(leak, esc) : ""}
${hook ? renderFrame(hook, esc) : ""}
</div>

<p class="lede">
  Two findings from one scan: an application bug, and a line of configuration
  that runs a command when anyone opens the folder. Most tools see the first.
  <a href="./agent-config-security/">Nothing sees the second</a>, because it is
  not a dependency and it is not source.
</p>

${code("bash", "npx owlwarden scan          # your app\nnpx owlwarden vet .         # your agent's config")}

<h2>What it does not look at</h2>
<p>
  This is the part most scanners leave out, so it goes above the feature list. A
  clean report you cannot calibrate is worse than no report.
</p>
<div class="table-wrap">
<table>
  <thead><tr><th>Limit</th><th>Why</th></tr></thead>
  <tbody>
    <tr><td>${coverage.categoriesCovered} of 10 OWASP categories</td><td>A04 (Insecure Design) is out of reach from source, on purpose — <a href="./owasp/">no parser finds a design flaw</a>.</td></tr>
    <tr><td>Origin tracking is one hop</td><td>Not a full taint engine. Injection-shaped rules cap their confidence instead of guessing.</td></tr>
    <tr><td>Agent rules cap at <code>likely</code></td><td><code>confirmed</code> means corroborated against a running target, and a config file has none.</td></tr>
    <tr><td>${rules.length} rules, not thousands</td><td>Node web applications and agent configuration. <a href="./vs/semgrep/">Run Semgrep too</a>.</td></tr>
  </tbody>
</table>
</div>

<h2>Two surfaces, one exit code</h2>
<p>
  ${webRules.length} rules read the code in your repository.
  ${agentRules.length} read the files your agent loads out of the working tree
  and executes — <code>.claude/settings.json</code>,
  <code>.vscode/tasks.json</code>, <code>.cursor/hooks.json</code>,
  <code>CLAUDE.md</code>. Your lockfile does not record those. Your SCA tool
  does not read them. Your review treats them like a <code>.prettierrc</code>.
</p>
<p>
  Every rule carries a fix written for your framework, or for your agent host.
  A rule cannot ship without one: <a href="./rules/">the build fails on an empty
  cell</a>.
</p>

<h2>A control, not a suggestion</h2>
<p>
  A tool the model <em>may</em> call is not a control that <em>always</em> runs.
  <code>owlwarden gate</code> attaches to the host's lifecycle — after every
  edit, before a shell command, at the turn boundary — and returns a verdict the
  prompt cannot reach, because the prompt is not its input.
</p>
${code("bash", "owlwarden init --claude-code   # hooks + MCP entry\nowlwarden init --cursor\nowlwarden init --generic       # any host that can run a process")}
<p>
  <a href="./claude-code/">Claude Code</a> · <a href="./cursor/">Cursor</a> ·
  <a href="./mcp/">MCP</a> · <a href="./ci/">CI</a> ·
  <a href="./vet/">vet</a> · <a href="./changelog/">Changelog</a>
</p>

<h2>Common questions</h2>
<h3>Does owlwarden send my code anywhere?</h3>
<p>
  No. There is no telemetry and no opt-in switch, because there is nothing to
  switch on. <a href="./offline/">The threat model is on its own page</a>.
</p>
<h3>Is it free?</h3>
<p>MIT OR Apache-2.0, at your option. No account, no seat count, no hosted tier.</p>
<h3>Does it replace my existing scanner?</h3>
<p>
  No, and it does not try to. <a href="./vs/semgrep/">Here is where it loses</a>,
  and the same page for <a href="./vs/snyk/">Snyk</a>,
  <a href="./vs/claude-security/">model-based review</a>, and
  <a href="./vs/eslint-plugin-security/">eslint-plugin-security</a>.
</p>

<h3>What changed in the last release?</h3>
<p>
  <a href="./changelog/">The changelog</a> lists every user-visible change with
  the security notes spelled out, and carries an
  <a href="./changelog/feed.xml">Atom feed</a> — no account, no mailing list.
</p>
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
    title: "Agent config security — the files nothing scans",
    heading: "Your dependency scanner does not read .claude/settings.json",
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
<p class="lede">
  The property that makes this class of file dangerous is simple and general:
  <strong>agent and editor configuration is executable, is read from the working
  tree, and is not read by any software composition analysis tool.</strong>
</p>

<p>
  It is not a dependency, so no lockfile records it. It is not application
  source, so no SAST rule parses it. It is checked in, so review passes over it
  the way review passes over a <code>.prettierrc</code>.
</p>

<h2>What the August 2026 npm worm actually did</h2>
<p>
  The dependency half of that incident was within reach of ordinary tooling:
  poisoned package versions, pulled within hours. The half that was not is the
  persistence mechanism. The payload wrote itself into
  <code>.claude/settings.json</code>, <code>.claude/setup.mjs</code>,
  <code>.vscode/tasks.json</code>, and <code>.vscode/setup.mjs</code>, and used
  stolen credentials to commit those files into every repository it could reach.
</p>
<p>
  Removing the poisoned package version does not remove that foothold.
  Regenerating the lockfile does not remove it. The next developer who opens the
  folder in an editor, or starts an agent session in it, re-executes the
  dropper.
</p>

${hook ? `<h2>What that looks like in a scan</h2>${renderFrame(hook, esc)}` : ""}

<h2>The ${agentRules.length} rules that read this surface</h2>
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
  A closed list, matched at the repository root and under any prefix. A path not
  on it is not scanned — including agent configuration inside
  <code>node_modules</code>, which is a real vector and a very large scan, and
  is named as out of scope rather than left unsaid.
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
  also where a workspace-scoped hook configuration vulnerability lived, so this
  surface deliberately overrides <code>.gitignore</code> — and only that.
  Containment, symlink refusal, and the size caps all still hold.
</p>

<h2>Check your own repository</h2>
${code("bash", "npx owlwarden scan --preset agent-surface   # your own repo\nnpx owlwarden vet ./cloned-repo             # someone else's")}
<p>
  <a href="../vet/"><code>vet</code> is the one to use on a repository you did
  not write</a>: it treats the target's own suppressions as evidence rather than
  as instruction. <a href="../asi/">The ASI coverage table</a> lists the agentic
  categories this reaches and the ones it does not.
</p>
${CROSS("../")}
`,
  };
}

// ---------------------------------------------------------------------------

function vet({ agentRules }) {
  return {
    title: "owlwarden vet — check a repo before you open it",
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
<p class="lede">
  Cloning a repository is safe. Opening it in an editor or an agent is not:
  that is the moment the configuration in it starts being executed.
</p>

${code("bash", "git clone https://github.com/someone/thing ./candidate\nnpx owlwarden vet ./candidate")}

<h2>What makes it different from <code>scan</code></h2>
<p>
  <code>scan</code> reads your config, honours your baseline, and applies your
  inline suppressions. Every one of those mechanisms exists to make adoption
  realistic on a legacy repository, and on your own repository that trade is
  correct and deliberate.
</p>
<p>
  On someone else's repository it is not a trade at all. In the hands of the
  repository's author, each of them is a way to hide a finding. So <code>vet</code>
  fixes the posture:
</p>
<div class="table-wrap">
<table>
  <thead><tr><th>Setting</th><th>Under <code>vet</code></th></tr></thead>
  <tbody>
    <tr><td>Preset</td><td><code>agent-surface</code> — the ${agentRules.length} rules that read configuration</td></tr>
    <tr><td>Network</td><td>None. No OSV, no <code>--target</code>, no exceptions</td></tr>
    <tr><td>Plugins</td><td>Not loaded, even signed ones, even with a trust root configured</td></tr>
    <tr><td>The target's config</td><td>Not read at all — not "read and partly ignored"</td></tr>
    <tr><td>The target's baseline</td><td>Not applied</td></tr>
    <tr><td>Inline suppressions</td><td>Counted and reported, never honoured</td></tr>
  </tbody>
</table>
</div>
<p>
  Passing <code>--plugin</code>, <code>--target</code>, <code>--baseline</code>,
  or <code>--allow-suppressions</code> to <code>vet</code> is an error rather
  than a no-op. A flag that appears to work and does not is worse than one that
  is rejected.
</p>

<h2>The line worth reading</h2>
<p>
  A non-zero suppression count is printed on the summary line. "This repository
  carries four inline suppressions, which vet counted and did not honour" is the
  single most useful sentence <code>vet</code> can produce about a tree you have
  not read.
</p>

<h2>Then what</h2>
<p>
  <code>vet</code> tells you what is in the configuration. It does not sandbox
  anything: a repository hostile enough to matter should be opened in a
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
    title: "owlwarden for Claude Code — hooks, MCP, and vet",
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
<p class="lede">
  One command wires the deterministic checks into the events Claude Code
  already fires, so they run because the host ran them — not because the model
  chose to.
</p>

${code("bash", "npm i -D owlwarden\nnpx owlwarden init --claude-code")}

<h2>What that writes</h2>
<div class="table-wrap">
<table>
  <thead><tr><th>Event</th><th>Scope</th><th>Verdict</th></tr></thead>
  <tbody>
    <tr><td><code>PostToolUse</code> (Edit, Write, MultiEdit)</td><td>the file that was written</td><td>blocks with the rule, the line, and the fix</td></tr>
    <tr><td><code>PreToolUse</code> (Bash)</td><td>the command string</td><td>the only event before execution — it fails closed</td></tr>
    <tr><td><code>Stop</code></td><td>everything changed since the turn began</td><td>the loop-closer: work, then no declaring victory over code that does not pass</td></tr>
  </tbody>
</table>
</div>

<h2>The hook it deliberately does not write</h2>
<p>
  There is no <code>SessionStart</code> entry, and that omission is the point.
  <a href="../rules/agent-hook-autoexec/"><code>agent-hook-autoexec</code></a>
  reports repository configuration that runs when the workspace is opened, at
  high severity, because anyone who clones the repository and opens it runs that
  command. A tool that ships that rule and then writes exactly that entry into
  your settings would be indefensible — <code>owlwarden scan</code> would report
  its own output.
</p>
<p>
  The session digest is a real feature and belongs in <em>user</em> settings,
  which a cloned repository cannot write. The same reasoning is why the MCP
  entry is <code>node_modules/.bin/owlwarden</code> rather than
  <code>npx -y owlwarden</code>:
  <a href="../rules/agent-mcp-unpinned-remote/">that shape is a finding too</a>.
</p>

<h2>MCP as well, for the exploratory case</h2>
<p>
  A hook is the control. <a href="../mcp/">MCP</a> is the right surface for the
  prompted question — <em>what does this rule mean, show me everything in
  <code>packages/api</code></em> — and it stays read-only and static-only.
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
    title: "owlwarden for Cursor — hooks, MCP, and rules",
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
<p class="lede">
  Cursor runs hooks declared in <code>.cursor/hooks.json</code>. owlwarden
  attaches to the three that matter and returns a verdict the prompt cannot
  argue with.
</p>

${code("bash", "npm i -D owlwarden\nnpx owlwarden init --cursor")}

<h2>What that writes</h2>
<ul>
  <li><code>.cursor/hooks.json</code> — <code>afterFileEdit</code>, <code>beforeShellExecution</code>, and <code>stop</code>.</li>
  <li><code>.cursor/mcp.json</code> — the read-only MCP server, pinned to the binary the lockfile already installed.</li>
  <li><code>.cursor/rules/owlwarden.mdc</code> — what the gate blocks on, so the model prefers the shapes it will not flag.</li>
</ul>

<h2>The rules file is not the control</h2>
<p>
  It is worth having: a model told "never return <code>err.stack</code>" writes
  fewer of them. But a sentence in a rules file is an instruction competing with
  every other instruction in the context window, and losing to whichever one the
  model weighted higher this turn. The hook is what always runs.
</p>

<h2>Cursor's own configuration is a scan surface</h2>
<p>
  <code>.cursor/mcp.json</code>, <code>.cursor/hooks.json</code>,
  <code>.cursorrules</code>, and <code>.cursor/rules/**</code> are read by the
  <a href="../agent-config-security/">agent-surface rules</a> — an unpinned MCP
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
    title: "owlwarden MCP server — read-only, static, offline",
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
<p class="lede">
  Four tools, all read-only: <code>scan_project</code>, <code>scan_file</code>,
  <code>explain_rule</code>, <code>list_rules</code>. No live target, no file
  writes, and every path stays under the workspace root.
</p>

${code("bash", "npx owlwarden mcp")}

<h2>What it is for, and what it is not</h2>
<p>
  It is the right surface for the prompted, exploratory case: <em>what does this
  rule mean</em>, <em>show me everything in <code>packages/api</code></em>.
</p>
<p>
  It is not the enforcement story, and this page will not pretend otherwise.
  An MCP tool is called when the model decides the task warrants it, and
  mid-refactor it often does not. Every commercial scanner shipped an MCP server
  in 2026; that is not a differentiator, and leading with it invites the
  comparison we lose. <a href="../claude-code/">The gate is the control</a>.
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
  a finding</a> — and generating the shape we report would be indefensible.
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
    title: "Offline by default — no account, no telemetry",
    heading: "A security scanner that never sends your code anywhere",
    description:
      "owlwarden runs entirely on your machine. No account, no telemetry, no opt-in switch — " +
      "there is nothing to switch on. The threat model, not the marketing.",
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
<p class="lede">
  Most scanners answer "is my code private?" with a policy page. The useful
  answer is a description of what the process actually does, and what would have
  to be true for that to be wrong.
</p>

<h2>What the default run does</h2>
<p>
  Reads files under the project root, parses them, prints a report. No
  transport object is constructed at all, so there is nothing for a rule to send
  a request through — <em>passive by construction, not by promise</em>. The
  scope resolver denies everything as a second line of defence, and the request
  budget is zero.
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
  There is no analytics code, no crash reporter, no version check, and no
  configuration key to disable any of them — because none exists to disable.
  This site loads no third-party resource either: no font CDN, no analytics, no
  tag manager. A check in the build refuses any external host, because that is
  the kind of thing that gets added later "just for a week".
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
    title: "OWASP Top 10 coverage for Node — with the gaps",
    heading: `OWASP Top 10 (2021) coverage: ${coverage.categoriesCovered} of 10, gaps included`,
    description:
      `owlwarden maps ${webRules.length} rules onto the OWASP Top 10 (2021). This table lists every ` +
      `category, including the ones with no rule and the ones no source scanner can reach.`,
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "OWASP coverage", href: "owasp/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "OWASP Top 10 (2021) coverage", proficiencyLevel: "Beginner" }],
    body: `
<p class="lede">
  A coverage table with no holes in it is an advertisement. What a reader needs
  is what the tool is <em>not</em> looking at, so a clean report is read
  correctly.
</p>

<p>
  <strong>Reach</strong> says whether source analysis can see the category at
  all. A category with no rules and <code>poor</code> reach is a limit of the
  method, not a backlog item — no parser finds a design flaw. Those need the
  dynamic engine, or a human.
</p>

${coverageTable(coverage.owasp, "not reachable from source")}

<h2>Why A04 is empty on purpose</h2>
<p>
  Insecure Design is correct code implementing the wrong idea: a missing rate
  limit, a recovery flow that trusts an email address, a threat nobody
  considered. There is no AST shape for it. Listing it as "0 rules" next to
  categories we simply have not covered yet would invite you to wait for a
  release that is never coming.
</p>

<h2>The other taxonomy</h2>
<p>
  Rules that read agent configuration map to
  <a href="../asi/">OWASP ASI ${esc(coverage.asiEdition)}</a> instead, and that
  table is kept separate on purpose. Merging them would let an agent rule appear
  to raise Top 10 coverage, and the <code>owasp-top10</code> preset would stop
  meaning anything.
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
<p class="lede">
  The Top 10 (2021) is about the web application in your repository. This list
  is about the agent that works in it — goal hijack, privilege abuse, supply
  chain, unexpected execution.
</p>

${coverageTable(coverage.asi, "needs the agent's run-time behaviour, not its configuration")}

<h2>What a configuration scanner can and cannot see</h2>
<p>
  Instruction files, hooks, permissions, and tool declarations are checked into
  the repository, so they are visible. Memory poisoning, tool misuse at run
  time, and multi-agent orchestration are properties of a running agent; no
  amount of parsing <code>.claude/settings.json</code> will reach them, and this
  table says so rather than leaving the rows looking like a backlog.
</p>

<h2>Why CWE is the primary mapping</h2>
<p>
  CWE ids are stable across decades. The agentic list is new and will be
  renumbered, so every rule in this family declares a CWE and carries the ASI
  reference as additional context. A renumbering then costs a table edit rather
  than invalidating the taxonomy on findings already in someone's baseline.
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
    title: "owlwarden in CI — SARIF, exit codes, no greenwashing",
    heading: "Running owlwarden in CI without greenwashing the build",
    description:
      "SARIF 2.1.0 for code scanning, JUnit for test UIs, Markdown for PR comments, and an exit " +
      "code contract that refuses to go green on a partial scan.",
    breadcrumbs: [
      { label: "owlwarden", href: "" },
      { label: "CI", href: "ci/" },
    ],
    schema: [{ "@type": "TechArticle", headline: "owlwarden in CI", proficiencyLevel: "Intermediate" }],
    body: `
<p class="lede">
  One command, three output formats from one scan, and an exit code that means
  the same thing every time.
</p>

${code(
  "yaml",
  `- uses: suthat/owlwarden@v1
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
    <tr><td><code>2</code></td><td>Could not run — a bad flag, an unreadable tree, a missing engine</td></tr>
  </tbody>
</table>
</div>
<p>
  <code>2</code> is distinct from <code>1</code> on purpose. A pipeline that
  treats "the scanner broke" as "the scanner found nothing" is a pipeline with
  no scanner in it, and nobody notices for months.
</p>

<h2>What <code>--ci</code> refuses</h2>
<p>
  Under <code>--ci</code>, project configuration cannot set the gate knobs, and
  inline suppressions and <code>--baseline</code> are ignored unless the
  operator opts in explicitly. Otherwise a hostile pull request silences the
  build by adding a JSON file, and the diff looks like configuration.
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
  <li><a href="../semgrep/"><span class="name">vs Semgrep</span><span class="blurb">Rule breadth against determinism and offline.</span></a></li>
  <li><a href="../snyk/"><span class="name">vs Snyk</span><span class="blurb">Dependencies against the config nothing scans.</span></a></li>
  <li><a href="../claude-security/"><span class="name">vs model-based review</span><span class="blurb">Judgement against a floor that always runs.</span></a></li>
  <li><a href="../eslint-plugin-security/"><span class="name">vs eslint-plugin-security</span><span class="blurb">Lint heuristics against routed, framework-aware rules.</span></a></li>
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
        "No — run both. Semgrep has thousands of rules across many languages; owlwarden has 25, " +
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
    title: "owlwarden vs Semgrep — where each one wins",
    heading: "owlwarden vs Semgrep",
    description:
      "Semgrep has thousands of rules across many languages. owlwarden has 25, runs offline with " +
      "no account, and reads agent config. Where each one loses.",
    body: `
<p class="lede">
  These are not the same tool, and the honest recommendation is to run both.
</p>

<h2>Where Semgrep wins</h2>
<ul>
  <li><strong>Rule breadth.</strong> Thousands of rules, many languages. owlwarden has 25 and covers Node web applications. That fight cannot be won and this page will not pretend it can.</li>
  <li><strong>Custom rules.</strong> A mature pattern language with a large public registry. owlwarden's plugin tier is source-only WASM with a frozen v1 API — deliberately smaller.</li>
  <li><strong>Language coverage.</strong> Python, Go, Java, C#. owlwarden is JavaScript and TypeScript.</li>
</ul>

<h2>Where owlwarden wins</h2>
<ul>
  <li><strong>It scans your agent's configuration.</strong> <code>.claude/settings.json</code>, <code>.vscode/tasks.json</code>, <code>.cursor/hooks.json</code>. <a href="../../agent-config-security/">Nothing else in this comparison reads those files.</a></li>
  <li><strong>Offline with no account.</strong> No login, no upload, no policy service. The default run constructs no transport at all.</li>
  <li><strong>The fix is in the finding, per framework.</strong> Not a generic message and a documentation link — the corrected code for the API your project actually uses, enforced by a build that fails on an empty cell.</li>
  <li><strong>It runs in the agent loop.</strong> <a href="../../claude-code/">A hook that always runs</a>, with a report on a token budget.</li>
</ul>

<h2>Running both</h2>
${code("bash", "semgrep --config auto        # breadth\nowlwarden scan --since origin/main   # the floor, and the agent surface")}
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
    title: "owlwarden vs Snyk — dependencies and the config gap",
    heading: "owlwarden vs Snyk",
    description:
      "Snyk is strongest on dependencies. owlwarden reads the agent and editor configuration a " +
      "lockfile does not record — the gap a 2026 npm worm used for persistence.",
    body: `
<p class="lede">
  Snyk's dependency database and reachability analysis are better than anything
  owlwarden does with a lockfile, and owlwarden does not try to compete there.
</p>

<h2>Where Snyk wins</h2>
<ul>
  <li><strong>Dependency intelligence.</strong> A curated database, reachability, and fix pull requests. owlwarden's <code>--osv</code> is an opt-in lookup against a public database and nothing more.</li>
  <li><strong>Breadth and ecosystem.</strong> Many languages, container and IaC scanning, an organisation-wide policy plane.</li>
  <li><strong>Reporting for a security team.</strong> Dashboards, ownership, trend lines. owlwarden prints a report and sets an exit code.</li>
</ul>

<h2>Where owlwarden wins</h2>
<ul>
  <li><strong>The persistence half of a supply-chain incident.</strong> Pulling a poisoned package version does not remove a hook someone wrote into <code>.claude/settings.json</code>. Regenerating the lockfile does not either. <a href="../../agent-config-security/">That file is not a dependency</a>.</li>
  <li><strong>No account, no upload.</strong> Nothing leaves the machine unless you pass a flag that says so.</li>
  <li><strong>Deterministic and free.</strong> Same input, same output, no seat count.</li>
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
          "and a CI threshold all depend on it not doing. Use it for judgement — authorisation, " +
          "business rules — on top of a deterministic floor.",
      ],
      [
        "How much does a deterministic floor cost per run?",
        "Nothing per token. --format agent puts the report on a budget of about 1500 tokens so the " +
          "checks a parser can answer stop being asked of a frontier model.",
      ],
    ],
    path: "vs/claude-security/",
    slug: "Model-based review",
    title: "Static analysis vs model-based code review",
    heading: "owlwarden vs a model reviewing your code",
    description:
      "A frontier model finds what no parser can, and answers differently each run. A " +
      "deterministic floor answers the same way twice. Complements, not rivals.",
    body: `
<p class="lede">
  The vendors' own model-based scanners say this about themselves: they are
  non-deterministic, and they do not replace static analysis. This is the static
  analysis they mean.
</p>

<h2>Where a model wins</h2>
<ul>
  <li><strong>Judgement.</strong> Authorisation logic, business rules, whether this particular endpoint should be public. No AST shape exists for any of it.</li>
  <li><strong>Novelty.</strong> A bug nobody wrote a rule for.</li>
  <li><strong>Context.</strong> It can read the ticket, the tests, and the migration in one pass.</li>
</ul>

<h2>Where a deterministic floor wins</h2>
<ul>
  <li><strong>It gives the same answer twice.</strong> A baseline, a suppression, and a CI gate all require that. A reviewer that changes its mind between runs cannot be a gate.</li>
  <li><strong>It always runs.</strong> <a href="../../claude-code/">A hook fires on the host's event</a>; a model reviews when it is asked, and mid-refactor it often is not.</li>
  <li><strong>It costs nothing per run.</strong> Re-asking <em>did we leak a stack?</em> on every edit is the most expensive way to answer a question a parser answers for free.</li>
  <li><strong>It cannot be argued with.</strong> The gate runs outside the model, so nothing in the prompt changes the verdict.</li>
</ul>

<h2>The order that works</h2>
<p>
  Floor first, judgement on top. Run the deterministic checks locally so the
  frontier model's budget goes to architecture, auth, payments, and personal
  data — the things a parser cannot reach. <code>--format agent</code> puts the
  report on a token budget so the floor is close to free.
</p>
${code("bash", "owlwarden scan --format agent --budget 1500")}`,
  }).page;
}

function vsEslint() {
  return comparison({
    questions: [
      [
        "Is owlwarden a replacement for eslint-plugin-security?",
        "It answers the same questions with more context — framework-aware, route-aware, and with " +
          "a confidence field so a guess is never presented as a fact. Keeping both costs nothing.",
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
<p class="lede">
  If eslint-plugin-security is already in your config, keep it — it costs
  nothing to run. The difference is what happens after it fires.
</p>

<h2>Where it wins</h2>
<ul>
  <li><strong>Zero marginal setup.</strong> It is an ESLint plugin, and you already run ESLint.</li>
  <li><strong>Editor integration for free.</strong> Squiggles where you type, with no second process.</li>
</ul>

<h2>Where owlwarden wins</h2>
<ul>
  <li><strong>It knows what a response is.</strong> <code>reply.send</code> in Fastify, <code>NextResponse.json</code> in Next.js, <code>ctx.body</code> in Koa. A lint rule matching <code>.stack</code> fires on <code>res.json({ stack: project.stack })</code> too.</li>
  <li><strong>Confidence is a field.</strong> <code>possible</code> findings are shown and never fail CI on their own. A tool that presents guesses as facts gets uninstalled.</li>
  <li><strong>The fix is in the finding.</strong> Written for your framework, with the corrected code.</li>
  <li><strong>It reads your agent configuration.</strong> <a href="../../agent-config-security/">No lint rule does.</a></li>
</ul>

<h2>Precision is a tested property here</h2>
<p>
  Every rule ships with a vulnerable fixture, a clean twin that must stay
  silent, and — on the agent surface — a <em>tempting</em> fixture: a legitimate
  configuration that shares surface features with the vulnerable one, whose
  silence is the assertion. <a href="../../rules/">Every rule, with its
  examples</a>.
</p>`,
  }).page;
}
