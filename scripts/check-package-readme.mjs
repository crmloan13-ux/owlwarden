/**
 * The contract for both READMEs.
 *
 * There are two, deliberately, and most of this file exists to keep them from
 * being merged back into one by someone who notices the duplication. They are
 * different documents for different readers, rendered by registries with
 * different rules, and the checks below are different too.
 *
 * The npm page is often the first and only document a prospective user reads,
 * and it is rendered by a registry with different rules from GitHub's. So this
 * checks two separate things:
 *
 * 1. **It renders correctly on npmjs.com.** Relative links resolve against the
 *    registry, not the repository, so every link has to be absolute. Anchors do
 *    not work at all. `<details>` renders inconsistently. Each of these is a
 *    silent failure — the page looks fine in review and is broken in public.
 *
 * 2. **It says the things that are contract.** The limits, the exit codes, the
 *    absence of telemetry. A missing safety limit on the page someone reads
 *    before installing is a contract failure too, not a documentation gap.
 *
 * It deliberately does *not* mirror the GitHub README. They are different
 * documents for different readers, and a check that forced them together would
 * be enforcing the wrong thing.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const readmeUrl = new URL("packages/cli/README.md", root);

const [readme, packageJsonText, siteUrl] = await Promise.all([
  readFile(readmeUrl, "utf8"),
  readFile(new URL("packages/cli/package.json", root), "utf8"),
  readFile(new URL("site.url", root), "utf8").then((text) => text.trim()),
]);
const packageJson = JSON.parse(packageJsonText);

// --- 1. It has to render on npmjs.com -------------------------------------

assert.doesNotMatch(
  readme,
  /\]\((?!https:\/\/)/,
  "npm resolves relative links against the registry: every link must be absolute",
);
assert.doesNotMatch(readme, /\]\(#/, "anchor links do not work on npmjs.com");
assert.doesNotMatch(readme, /<details>/, "<details> renders inconsistently on npm");
assert.doesNotMatch(readme, /<div align=/, "npm strips alignment; it reads as a stray tag");

const badgeCount = (readme.match(/!\[[^\]]*\]\(https:\/\/img\.shields\.io/g) ?? []).length;
assert(
  badgeCount <= 1,
  `a badge row pushes the value proposition below the fold on mobile; found ${badgeCount}`,
);

// The first paragraph is what npm shows in search snippets, and what an LLM
// summarising the package will quote. It is load-bearing.
const firstParagraph = readme.split("\n\n").find((block) => block.startsWith("Security scanner"));
assert(firstParagraph, "the first prose paragraph must lead with what the tool is");
const leadWords = firstParagraph.split(/\s+/).length;
assert(leadWords >= 40 && leadWords <= 110, `the lead is ${leadWords} words; aim for 40-110`);

const size = (await stat(readmeUrl)).size;
assert(size < 16_000, `npm README is ${size} bytes; a reader deciding whether to install wants less`);

// --- 2. The things that are contract --------------------------------------

for (const heading of ["Install", "Why", "What it finds", "Usage", "In the agent loop", "In CI", "Config", "Limits", "Links", "Licence"]) {
  assert.match(readme, new RegExp(`^## ${heading}$`, "m"), `missing section: ${heading}`);
}

for (const framework of [
  "Next.js", "Nuxt", "NestJS", "Express", "Fastify", "Hono",
  "Koa", "Hapi", "Sails.js", "Astro", "Remix", "Gatsby",
]) {
  assert(readme.includes(framework), `npm README is missing ${framework}`);
}

for (const [pattern, why] of [
  [/npx owlwarden scan/, "the first command"],
  [/npx owlwarden vet/, "the command nothing else has"],
  [/owlwarden gate --host/, "the deterministic control"],
  [/owlwarden verify --patch/, "the fix-verification loop"],
  [/No telemetry|no telemetry/, "the promise people check first"],
  [/Node 20\+/, "the runtime floor"],
  [/npm provenance/, "the supply-chain signal, post-ChainDrop"],
  [/`0` clean · `1` findings.*`2` could not run/s, "the exit-code contract"],
  [/A04 \(Insecure Design\)/, "the OWASP category we cannot reach"],
  [/one hop, not a full taint engine/, "the limit of the origin model"],
  [/`confirmed` means confirmed/, "the word nothing else in the tool uses"],
  [/cap at `likely` and carry a `runtime_scope`/, "why a tutorial is not a live config"],
  [/--allow-active/, "active probing is opt-in"],
  [/never writes a `SessionStart` hook/, "the rule we refuse to break in our own output"],
  [/--format agent/, "the token budget"],
  [/--since|--staged/, "diff scoping"],
  [/OWASP ASI 2026/, "the agent-surface taxonomy"],
] ) {
  assert.match(readme, pattern, `npm README must state: ${why}`);
}

// The catalogue link has to exist for every rule the page implies.
assert.match(readme, /https:\/\/github\.com\/suthat\/owlwarden\/blob\/main\/RULES\.md/);
assert(readme.includes(`${siteUrl}/`), `the docs link must use site.url (${siteUrl})`);

// --- 3. The manifest npm reads alongside it -------------------------------

assert.equal(packageJson.homepage, siteUrl, "homepage must match site.url");
assert.equal(packageJson.license, "(MIT OR Apache-2.0)", "SPDX expressions need the parentheses");
assert.equal(packageJson.publishConfig?.provenance, true, "provenance in the manifest, not only the CI flag");
assert(packageJson.funding, "funding is a free line in `npm install` output and on the package page");
assert(
  packageJson.description.length <= 200,
  `description is ${packageJson.description.length} chars; the first 60 are what survives on mobile`,
);
assert.match(packageJson.description, /^Offline security scanner for Node web apps and AI coding agents/);

const keywords = packageJson.keywords ?? [];
assert(keywords.length >= 20 && keywords.length <= 40, `${keywords.length} keywords; aim for 20-35`);
for (const required of [
  // Tier three is where a package with no downloads actually gets found.
  "claude-code", "cursor", "mcp-server", "agent-security", "prompt-injection",
  // ...and tier one is what someone searches when they do not know we exist.
  "security-scanner", "sast", "owasp", "nodejs", "sarif",
]) {
  assert(keywords.includes(required), `keywords must include ${required}`);
}
assert.equal(new Set(keywords).size, keywords.length, "duplicate keyword");

// --- 4. The README GitHub renders ----------------------------------------
//
// A different reader with a different question. Someone on npm is deciding
// whether to `npm i`; someone on GitHub is deciding whether to trust the
// project. So this one is allowed to be longer, may use relative links and
// `<details>`, and is checked for the things a sceptical reader looks for.

const githubReadme = await readFile(new URL("README.md", root), "utf8");

// The first screen is the highest-traffic content the project owns. It has to
// state a problem before it states a feature list: a category does not get
// starred, and "local security scanner for Node" is a category.
const firstScreen = githubReadme.slice(0, 2_400);
assert.match(firstScreen, /npx owlwarden vet/, "the first screen must show the command nothing else has");
assert.match(firstScreen, /## Why this exists/, "the first heading after the badges is the problem, not the features");
assert.doesNotMatch(
  firstScreen,
  /^## (Install|Usage|Features)/m,
  "installation before motivation reads as a feature list",
);

for (const [pattern, why] of [
  [/## Limits, stated up front/, "the most distinctive section in the repository, and it stays near the top"],
  [/## How it compares/, "without one, the reader builds a worse comparison in their head"],
  [/A tool the model \*may\* call is not a control that \*always\* runs/, "the agent-loop thesis"],
  [/not trying to out-rule Semgrep/, "the honest position on rule count"],
  [/never writes a `SessionStart` hook/, "the rule we refuse to break in our own output"],
  [/no\s+parser finds a design flaw/, "why A04 is absent on purpose"],
  [/#!\[forbid\(unsafe_code\)\]/, "the memory-safety posture"],
  [/best bug report is a false positive/, "what CONTRIBUTING actually asks for"],
]) {
  assert.match(githubReadme, pattern, `GitHub README must state: ${why}`);
}

// Limits come before the feature tour. A reader who has to scroll past three
// screens of capability to find the caveats has already formed a view.
assert(
  githubReadme.indexOf("## Limits, stated up front") < githubReadme.indexOf("## Install"),
  "the limits belong above the install instructions",
);
assert(
  githubReadme.indexOf("## Why this exists") < githubReadme.indexOf("## How it compares"),
  "the problem comes before the comparison",
);

// Every relative link has to resolve to something in the repository. A README
// full of dead links is the same failure as a report full of them.
const relativeLinks = [...githubReadme.matchAll(/\]\((?!https?:\/\/|#)([^)]+)\)/g)].map(
  (match) => match[1],
);
assert(relativeLinks.length > 0, "the GitHub README should link into the repository");
for (const link of relativeLinks) {
  const target = new URL(link.replace(/#.*$/, ""), root);
  await stat(target).catch(() => {
    throw new Error(`GitHub README links to ${link}, which does not exist`);
  });
}

assert(
  githubReadme.includes(`${siteUrl}/`),
  `the GitHub README's docs link must use site.url (${siteUrl})`,
);

// --- 5. Every documented Action input exists ------------------------------
//
// This section exists because both READMEs shipped a snippet using `since:`,
// which the Action did not have, pointed at `suthat/owlwarden@v1`, where there
// is no `action.yml`. Neither is a typo a reader can recover from: the first
// input GitHub does not recognise fails the workflow, and the wrong path fails
// before the job starts. Copy-pasteable is the whole point of those snippets,
// so what they contain is checked against the Action itself.

const actionYaml = await readFile(new URL("action/action.yml", root), "utf8");

const inputsBlock = actionYaml.slice(
  actionYaml.indexOf("\ninputs:\n"),
  actionYaml.indexOf("\noutputs:\n"),
);
const actionInputs = new Set(
  [...inputsBlock.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)].map((match) => match[1]),
);
assert(actionInputs.size >= 8, `parsed only ${actionInputs.size} Action inputs; the block moved`);

const DOCUMENTS = [
  ["README.md", githubReadme],
  ["packages/cli/README.md", readme],
  ["docs/how-to/ci.md", await readFile(new URL("docs/how-to/ci.md", root), "utf8")],
  ["scripts/site/pages.mjs", await readFile(new URL("scripts/site/pages.mjs", root), "utf8")],
];

let snippetsChecked = 0;
for (const [name, text] of DOCUMENTS) {
  for (const match of text.matchAll(/uses: ([\w.-]+\/[\w./-]+)@[\w.-]+\n((?:.*\n)*?)(?=\n|```)/g)) {
    const [, action, body] = match;
    if (!action.startsWith("suthat/owlwarden")) continue;
    snippetsChecked += 1;

    assert.equal(
      action,
      "suthat/owlwarden/action",
      `${name} references ${action}; the Action lives in action/, not at the repository root`,
    );

    // `with:` keys are one indent deeper than `with:` itself, whatever the
    // snippet's base indent is — the READMEs and ci.md do not agree on it.
    const withIndex = body.indexOf("with:");
    if (withIndex === -1) continue;
    const indent = " ".repeat(body.slice(0, withIndex).match(/[^\n]*$/)[0].length + 2);
    for (const key of body.matchAll(new RegExp(`^${indent}([a-z][a-z0-9-]*):`, "gm"))) {
      assert(
        actionInputs.has(key[1]),
        `${name} passes \`${key[1]}\` to the Action, which has no such input`,
      );
    }
  }
}
assert(snippetsChecked >= 3, `found only ${snippetsChecked} Action snippets; expected one per document`);

console.log(
  `README contracts passed (npm: ${size} bytes, ${keywords.length} keywords; ` +
    `GitHub: ${githubReadme.length} bytes, ${relativeLinks.length} repository links; ` +
    `${snippetsChecked} Action snippets against ${actionInputs.size} inputs)`,
);
