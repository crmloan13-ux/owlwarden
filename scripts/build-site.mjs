#!/usr/bin/env node
/**
 * Generates the whole site from the engine.
 *
 *   node scripts/build-site.mjs           # write site/
 *   node scripts/build-site.mjs --check   # fail if the committed site is stale
 *
 * # Why generated
 *
 * The rule catalogue already generates `RULES.md`, and a rule that ships
 * without a fix for a supported framework already fails the build. That
 * invariant is worth more than a documentation site: it means a few hundred
 * pages can exist without any of them being filler, because every one of them
 * carries something the others do not — the vulnerable code for *that*
 * framework or host, taken from a fixture the test suite asserts on, and the
 * fix written for it.
 *
 * Hand-writing those pages would produce two hundred snippets nobody verifies,
 * drifting away from the rules one release at a time. That is what makes most
 * programmatic SEO worthless, and it is avoidable here for free.
 *
 * # Why the whole site, not just the rules
 *
 * The header, the footer, the canonical tag, the breadcrumbs, and the JSON-LD
 * are the same shape on every page. Fourteen hand-written pages would be
 * fourteen copies of a head block and fourteen chances for a stale domain.
 * `site.url` is the switch; this is what reads it.
 */

import { createRequire } from "node:module";
import { mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

import { problems, renderPage } from "./site/layout.mjs";
import { changelogFeed, changelogPage } from "./site/changelog.mjs";
import { llms, robots, sitemap } from "./site/feeds.mjs";
import { staticPages } from "./site/pages.mjs";
import { rulePages } from "./site/rules.mjs";
import { harvestSamples } from "./site/samples.mjs";
import { favicon } from "./site/icon.mjs";
import { stylesheet } from "./site/styles.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const siteDir = join(root, "site");
const check = process.argv.includes("--check");

const require = createRequire(import.meta.url);
const native = require("@dointhai/owlwarden-core-native");

const site = (await readFile(join(root, "site.url"), "utf8")).trim();
if (!site.startsWith("https://") || site.endsWith("/")) {
  throw new Error(`site.url must be an absolute https origin with no trailing slash, got ${site}`);
}

const version = native.engineVersion();
const rules = JSON.parse(native.listRules());
const coverage = JSON.parse(native.coverage());
const explain = new Map(
  rules.map((rule) => [rule.id, JSON.parse(native.explainRule(rule.id) ?? "null")]),
);

process.stdout.write(`scanning fixtures for verified examples…\n`);
const samples = await harvestSamples(native);

const changelogSource = await readFile(join(root, "CHANGELOG.md"), "utf8");

const pages = [
  ...staticPages({ rules, coverage, samples, version }),
  { path: "changelog/", page: changelogPage(changelogSource, version) },
  ...rulePages({ rules, explain, samples, coverage }),
];

// A duplicate path would silently overwrite a page and drop it from the
// sitemap; better to say so.
const seen = new Set();
for (const { path } of pages) {
  if (seen.has(path)) throw new Error(`two pages claim the path ${path || "/"}`);
  seen.add(path);
}

/** Everything the site is, as `path -> contents`. */
const files = new Map();

for (const { path, page } of pages) {
  files.set(join(path, "index.html"), renderPage({ ...page, path }, site, version));
}

files.set("styles.css", stylesheet());
files.set("favicon.svg", favicon());
files.set("robots.txt", robots(site));
files.set(
  "sitemap.xml",
  sitemap(
    [...pages.map(({ path }) => path)].sort(),
    site,
    new Date().toISOString().slice(0, 10),
  ),
);
files.set("llms.txt", llms({ site, version, rules, coverage }));
files.set(join("changelog", "feed.xml"), changelogFeed(changelogSource, site));
files.set("404.html", renderPage(notFound(), site, version));

// Every page has been rendered, so every problem is known. Reporting them
// together is the difference between one fix-up pass and fourteen.
if (problems.length > 0) {
  process.stderr.write(
    `${problems.length} page(s) fail the head-tag contract:\n\n` +
      problems.map((problem) => `  ${problem}`).join("\n\n") +
      "\n",
  );
  process.exit(1);
}

// --- write, or compare -----------------------------------------------------

if (check) {
  const stale = [];
  for (const [path, contents] of files) {
    const current = await readFile(join(siteDir, path), "utf8").catch(() => undefined);
    if (current !== contents) stale.push(path);
  }
  const extra = (await listGenerated(siteDir)).filter((path) => !files.has(path));
  if (stale.length > 0 || extra.length > 0) {
    process.stderr.write(
      "site/ is out of date. Run `pnpm site:build`.\n" +
        (stale.length > 0 ? `  stale: ${stale.slice(0, 8).join(", ")}${stale.length > 8 ? ` (+${stale.length - 8})` : ""}\n` : "") +
        (extra.length > 0 ? `  orphaned: ${extra.slice(0, 8).join(", ")}${extra.length > 8 ? ` (+${extra.length - 8})` : ""}\n` : ""),
    );
    process.exitCode = 1;
  } else {
    process.stdout.write(`site/ is current (${files.size} files)\n`);
  }
} else {
  // Remove generated output first so a renamed rule does not leave an orphan
  // page behind — a URL nothing links to, still in the sitemap, still indexed.
  for (const path of await listGenerated(siteDir)) {
    await rm(join(siteDir, path), { force: true });
  }
  for (const [path, contents] of files) {
    const full = join(siteDir, path);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, contents);
  }
  await pruneEmptyDirectories(siteDir);
  process.stdout.write(
    `wrote ${files.size} files to site/ (${pages.length} pages, canonical ${site})\n`,
  );
}

// ---------------------------------------------------------------------------

/**
 * Files this script owns.
 *
 * Everything except the binary assets that are not generated: the favicon, the
 * social image, and the site's own README. Listing what we own rather than what
 * we do not is what makes the orphan check possible.
 */
async function listGenerated(directory) {
  const keep = new Set(["favicon.png", "og.png", "og.svg", "README.md", "CNAME", ".nojekyll"]);
  const out = [];

  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      const path = relative(directory, full);
      if (!keep.has(path)) out.push(path);
    }
  }

  await stat(directory).then(
    () => walk(directory),
    () => undefined,
  );
  return out;
}

async function pruneEmptyDirectories(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const full = join(directory, entry.name);
    await pruneEmptyDirectories(full);
    const remaining = await readdir(full);
    if (remaining.length === 0) await rm(full, { recursive: true, force: true });
  }
}

function notFound() {
  return {
    path: "404.html",
    title: "Page not found — owlwarden",
    heading: "That page is not here",
    description:
      "The page you were looking for does not exist on owlwarden.dev. Every rule has a page, " +
      "every rule has a page per framework, and both are listed on the rules index.",
    ogType: "website",
    breadcrumbs: [{ label: "owlwarden", href: "" }],
    schema: [],
    body: `
<p class="lede">
  Nothing is here. The most likely reason is a rule id that changed, or a
  framework variant that has no verified example — those pages are not published
  rather than published thin.
</p>
<ul class="cards">
  <li><a href="./rules/"><span class="name">All rules</span><span class="blurb">Every rule, and every framework and host variant that exists.</span></a></li>
  <li><a href="./agent-config-security/"><span class="name">Agent config security</span><span class="blurb">The files your agent executes and nothing else scans.</span></a></li>
  <li><a href="./owasp/"><span class="name">Coverage</span><span class="blurb">What it checks, and what no parser can.</span></a></li>
  <li><a href="./"><span class="name">Home</span><span class="blurb">Start again.</span></a></li>
</ul>
<p>
  Or run it and see for yourself: <code>npx owlwarden scan</code>.
  <code>npx owlwarden explain &lt;rule-id&gt;</code> prints any rule's whole
  write-up in your terminal, offline.
</p>
`,
  };
}
