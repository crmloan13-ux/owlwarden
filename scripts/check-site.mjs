#!/usr/bin/env node
/**
 * Validates the committed site.
 *
 * Deliberately independent of the generator: it reads the HTML on disk and
 * checks the properties a reader, a crawler, and a model actually depend on. A
 * check that called the same functions the build called would only prove the
 * build ran.
 *
 * It also runs **without the native addon**, because it runs in the Pages
 * workflow, which deploys the committed directory and does not build Rust. The
 * freshness check — "is the committed site what the current rules would
 * generate?" — is a different question and lives in `build-site.mjs --check`,
 * which does need the engine.
 *
 * The check that earns its keep here is the link graph. Two hundred pages
 * cross-linking along two axes is exactly the shape where a renamed rule leaves
 * a dozen dead links that nobody clicks until a reader does.
 */

import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize, relative } from "node:path";

const root = fileURLToPath(new URL("../", import.meta.url));
const siteDir = join(root, "site");
const site = (await readFile(join(root, "site.url"), "utf8")).trim();

/** Hosts a page may link to. Anything else is a supply-chain decision. */
const ALLOWED_HOSTS = new Set([
  "github.com",
  "www.npmjs.com",
  "owasp.org",
  "genai.owasp.org",
  "cwe.mitre.org",
  "img.shields.io",
  "spdx.org",
  "api.osv.dev",
  new URL(site).host,
]);

const pages = await collect(siteDir, ".html");
assert(pages.length > 50, `expected the generated site, found ${pages.length} pages`);

/** Every file the site actually contains, for the link check. */
const present = new Set(await collectPaths(siteDir));
const known = new Set(pages.map((page) => page.path));

/** How many *other* pages link to each page. Orphans do not get crawled. */
const inbound = new Map(pages.map((page) => [page.path, 0]));
const problems = [];

function fail(where, message) {
  problems.push(`${where}: ${message}`);
}

for (const page of pages) {
  const { path, html } = page;
  const canonicalPath = path.replace(/index\.html$/, "");

  // --- head ---------------------------------------------------------------
  const title = one(html, /<title>([^<]*)<\/title>/);
  if (!title) fail(path, "no <title>");
  else if (title.length > 62) fail(path, `title is ${title.length} chars`);

  const description = one(html, /<meta name="description" content="([^"]*)"/);
  if (!description) fail(path, "no meta description");
  else if (description.length < 100 || description.length > 175) {
    fail(path, `description is ${description.length} chars`);
  }

  const canonical = one(html, /<link rel="canonical" href="([^"]*)"/);
  if (!canonical) fail(path, "no canonical");
  else if (path === "404.html") {
    // The 404 is the one page that must not claim to be a real URL.
  } else if (canonical !== `${site}/${canonicalPath}`) {
    fail(path, `canonical is ${canonical}, expected ${site}/${canonicalPath}`);
  }

  for (const tag of [
    'property="og:title"',
    'property="og:description"',
    'property="og:url"',
    'property="og:image"',
    'name="twitter:card"',
  ]) {
    if (!html.includes(tag)) fail(path, `missing ${tag}`);
  }

  // --- structure ----------------------------------------------------------
  const headings = [...html.matchAll(/<h([123])[\s>]/g)].map((match) => Number(match[1]));
  const h1Count = headings.filter((level) => level === 1).length;
  if (h1Count !== 1) fail(path, `${h1Count} <h1> elements, expected exactly 1`);
  let previous = 1;
  for (const level of headings) {
    if (level > previous + 1) fail(path, `heading level jumps from h${previous} to h${level}`);
    previous = level;
  }

  if (!html.includes('<main id="main-content">')) fail(path, "no <main id=main-content>");
  if (!html.includes('class="skip-link"')) fail(path, "no skip link");
  if (!html.includes('aria-label="Breadcrumb"')) fail(path, "no breadcrumb nav");

  // --- structured data ----------------------------------------------------
  const ld = one(html, /<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
  if (!ld) fail(path, "no JSON-LD");
  else {
    try {
      const parsed = JSON.parse(ld);
      assert.equal(parsed["@context"], "https://schema.org");
      assert(Array.isArray(parsed["@graph"]) && parsed["@graph"].length > 0);
      assert(
        parsed["@graph"].some((node) => node["@type"] === "BreadcrumbList"),
        "breadcrumbs must be in the graph as well as the markup",
      );
    } catch (error) {
      fail(path, `JSON-LD is not valid: ${error.message}`);
    }
  }

  // --- links --------------------------------------------------------------
  const body = html.slice(html.indexOf("<main"), html.indexOf("</main>"));
  const links = [...html.matchAll(/<a[^>]+href="([^"]+)"/g)].map((match) => match[1]);
  const bodyLinks = [...body.matchAll(/<a[^>]+href="([^"]+)"/g)].map((match) => match[1]);

  if (bodyLinks.length < 3) {
    fail(path, `${bodyLinks.length} links in <main>; a page nobody links out of is a dead end`);
  }

  for (const href of links) {
    if (href.startsWith("#")) continue;
    if (/^https?:\/\//.test(href)) {
      const host = new URL(href).host;
      if (!ALLOWED_HOSTS.has(host)) fail(path, `links to an unexpected host: ${host}`);
      continue;
    }
    const target = normalize(join(dirname(path), href));
    const resolved = target.endsWith("/") || target === "" ? join(target, "index.html") : target;
    const candidates = [resolved, join(target, "index.html"), target];
    const hit = candidates.find((candidate) => known.has(candidate));
    if (hit === undefined && !candidates.some((candidate) => present.has(candidate))) {
      fail(path, `dead link: ${href}`);
      continue;
    }
    // Links from the shared header and footer do not count: every page has
    // them, so counting them would make every page look well-linked and the
    // check would find nothing.
    if (hit !== undefined && hit !== path && bodyLinks.includes(href)) {
      inbound.set(hit, (inbound.get(hit) ?? 0) + 1);
    }
  }

  // --- the promises this site makes about itself --------------------------
  if (/<script\b(?![^>]*type="application\/ld\+json")/.test(html)) {
    fail(path, "a script tag: this site ships no JavaScript");
  }
  if (/<img(?![^>]+(?:width|height)=)/.test(html)) {
    fail(path, "an <img> without dimensions shifts the layout as it loads");
  }
  if (/target="_blank"(?![^>]+rel="[^"]*noopener)/.test(html)) {
    fail(path, "target=_blank without rel=noopener");
  }
}

// --- the link graph --------------------------------------------------------
//
// A page nothing links to is a page a crawler reaches only through the sitemap,
// which is the weakest signal there is. Two inbound links from the *body* of
// other pages is the floor; the header and footer do not count, because they
// are on every page and would make every page look well-connected.

for (const page of pages) {
  if (page.path === "404.html" || page.path === "index.html") continue;
  const count = inbound.get(page.path) ?? 0;
  if (count < 2) {
    fail(page.path, `${count} inbound body link(s); a page nothing links to is an orphan`);
  }
}

// --- feeds -----------------------------------------------------------------

const sitemap = await readFile(join(siteDir, "sitemap.xml"), "utf8");
const listed = new Set([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]));
for (const page of pages) {
  if (page.path === "404.html") {
    assert(
      !listed.has(`${site}/404.html`),
      "the 404 page must not be in the sitemap",
    );
    continue;
  }
  const url = `${site}/${page.path.replace(/index\.html$/, "")}`;
  if (!listed.has(url)) fail("sitemap.xml", `does not list ${url}`);
}
assert.equal(
  listed.size,
  pages.length - 1,
  `sitemap lists ${listed.size} URLs for ${pages.length - 1} indexable pages`,
);

const robots = await readFile(join(siteDir, "robots.txt"), "utf8");
assert.match(robots, new RegExp(`Sitemap: ${escapeRegExp(site)}/sitemap.xml`));
assert.match(robots, /^User-agent: \*$/m);
assert.match(robots, /^Allow: \/$/m);

const feed = await readFile(join(siteDir, "changelog", "feed.xml"), "utf8");
assert.match(feed, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
assert.match(feed, /<feed xmlns="http:\/\/www\.w3\.org\/2005\/Atom">/);
assert(feed.includes(`${site}/changelog/feed.xml`), "the feed must name its own URL");
assert(
  (feed.match(/<entry>/g) ?? []).length >= 2,
  "the feed should carry the release history, not just the newest",
);
for (const page of pages) {
  if (!page.html.includes('type="application/atom+xml"')) {
    fail(page.path, "does not advertise the feed in <head>");
  }
}

const llms = await readFile(join(siteDir, "llms.txt"), "utf8");
assert.match(llms, /^# owlwarden$/m);
assert(llms.includes(`${site}/rules/`), "llms.txt must point at the rule index");
for (const page of pages) {
  const match = /^rules\/([^/]+)\/index\.html$/.exec(page.path);
  if (match && !llms.includes(`${site}/rules/${match[1]}`)) {
    fail("llms.txt", `does not list the rule ${match[1]}`);
  }
}

// A missing social image is a silent failure: the card renders blank and
// nobody finds out until a link is shared.
for (const asset of ["og.png", "og.svg", "favicon.svg", "favicon.png"]) {
  assert(present.has(asset), `site/${asset} is missing`);
}
for (const page of pages) {
  if (!page.html.includes("/og.png")) fail(page.path, "og:image does not point at og.png");
}

const styles = await readFile(join(siteDir, "styles.css"), "utf8");
assert(!/@import|url\(https?:/.test(styles), "the stylesheet must not fetch anything");
assert(styles.includes("prefers-reduced-motion"), "the one animation must respect the preference");

// --- report ----------------------------------------------------------------

if (problems.length > 0) {
  process.stderr.write(
    `${problems.length} site problem(s):\n\n` +
      problems.slice(0, 40).map((problem) => `  ${problem}`).join("\n") +
      (problems.length > 40 ? `\n  … and ${problems.length - 40} more` : "") +
      "\n",
  );
  process.exit(1);
}

process.stdout.write(
  `site contract passed (${pages.length} pages, ${listed.size} in the sitemap, canonical ${site})\n`,
);

// ---------------------------------------------------------------------------

function one(html, pattern) {
  return pattern.exec(html)?.[1];
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Every file under `directory`, as site-relative paths. */
async function collectPaths(directory) {
  const out = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else out.push(relative(directory, full));
    }
  }
  await walk(directory);
  return out;
}

async function collect(directory, extension) {
  const out = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      if (!entry.name.endsWith(extension)) continue;
      out.push({ path: relative(directory, full), html: await readFile(full, "utf8") });
    }
  }
  await stat(directory);
  await walk(directory);
  return out;
}
