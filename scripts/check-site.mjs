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
import { Buffer } from "node:buffer";
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

// These are the pages that introduce or sell a product surface. Their visual
// is part of the content contract, not decoration: each must show the product,
// workflow, or comparison it describes before the long-form explanation.
const PRODUCT_PAGES = new Set([
  "index.html",
  "agent-config-security/index.html",
  "vet/index.html",
  "claude-code/index.html",
  "cursor/index.html",
  "mcp/index.html",
  "offline/index.html",
  "owasp/index.html",
  "asi/index.html",
  "ci/index.html",
  "vs/semgrep/index.html",
  "vs/snyk/index.html",
  "vs/claude-security/index.html",
  "vs/eslint-plugin-security/index.html",
]);

// Navigation is part of the site contract, not page content. Every generated
// page must expose the same destinations in the same order; only the current
// section marker may vary. Keeping this assertion independent of the renderer
// catches a stale committed page as well as an accidental layout fork.
const PRIMARY_NAV = [
  { label: "Rules", href: `${site}/rules/` },
  { label: "Agent config", href: `${site}/agent-config-security/` },
  { label: "vet", href: `${site}/vet/` },
  { label: "Offline", href: `${site}/offline/` },
  { label: "Coverage", href: `${site}/owasp/` },
  { label: "GitHub ↗", href: "https://github.com/suthat/owlwarden" },
];

// Site copy should read like one developer explaining a tool to another.
// These separators and stock marketing phrases made the generated pages sound
// synthetic, so keep them out of both visible copy and metadata.
const BANNED_COPY = [
  /[·—–]/,
  /deterministic (?:security )?floor/i,
  /the overlooked attack surface/i,
  /trust the repository after you check it/i,
  /coverage you can calibrate/i,
  /an honest comparison/i,
  /one source of truth/i,
  /privacy by design/i,
  /passive by construction/i,
];

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
  if (!html.includes('name="twitter:image:alt"')) fail(path, "missing twitter:image:alt");
  if (!html.includes('rel="manifest"')) fail(path, "missing web app manifest");
  const stylesheetHref = one(html, /<link rel="stylesheet" href="([^"]*)"/);
  if (!/styles\.css\?v=[a-f0-9]{12}$/.test(stylesheetHref ?? "")) {
    fail(path, "stylesheet cache key is not content-addressed");
  }

  const robotsMeta = one(html, /<meta name="robots" content="([^"]*)"/);
  if (path === "404.html") {
    if (robotsMeta !== "noindex,follow") fail(path, "404 page must be noindex,follow");
  } else if (!robotsMeta?.startsWith("index,follow")) {
    fail(path, "indexable page must opt into index,follow");
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

  if (!/<main id="main-content"(?:\s[^>]*)?>/.test(html)) fail(path, "no <main id=main-content>");
  if (!html.includes('class="skip-link"')) fail(path, "no skip link");
  if (!html.includes('aria-label="Breadcrumb"')) fail(path, "no breadcrumb nav");
  checkPrimaryNavigation(path, html);
  for (const pattern of BANNED_COPY) {
    if (pattern.test(html)) fail(path, `contains banned copy: ${pattern}`);
  }
  if (PRODUCT_PAGES.has(path)) {
    if (!html.includes('class="page-hero"')) fail(path, "no shared product hero");
    if (!html.includes('class="product-visual')) fail(path, "no product visual in hero");
  }

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

// Public text assets bypass the HTML layout normalizer, so protect them with
// the same plain-punctuation contract as the pages themselves.
for (const asset of [
  "changelog/feed.xml",
  "favicon.svg",
  "llms.txt",
  "manifest.webmanifest",
  "og.svg",
  "robots.txt",
]) {
  const content = await readFile(join(siteDir, asset), "utf8");
  assert(!/[·—–]/.test(content), `site/${asset} must use plain punctuation`);
}

// A missing social image is a silent failure: the card renders blank and
// nobody finds out until a link is shared.
for (const asset of [
  "og.png",
  "og.svg",
  "favicon.svg",
  "favicon.png",
  "apple-touch-icon.png",
  "icon-512.png",
  "manifest.webmanifest",
]) {
  assert(present.has(asset), `site/${asset} is missing`);
}
for (const page of pages) {
  if (!page.html.includes("/og.png")) fail(page.path, "og:image does not point at og.png");
}

const brandMark = await readFile(join(siteDir, "favicon.svg"), "utf8");
assert(
  brandMark.includes('data-brand="owlwarden-guardian"'),
  "the favicon must use the guardian owl brand mark",
);
for (const part of ["owl-head", "owl-face", "owl-eyes", "owl-beak"]) {
  if (part === "owl-beak") {
    assert(!brandMark.includes(`id="${part}"`), "the guardian owl must not have a beak shape");
  } else {
    assert(brandMark.includes(`id="${part}"`), `the brand mark is missing ${part}`);
  }
}
assert(
  brandMark.includes('shape-rendering="geometricPrecision"'),
  "the vector mark must favour precise edge rendering",
);
const brandBuilder = await readFile(join(root, "scripts", "build-og.mjs"), "utf8");
assert(
  brandBuilder.includes("const ICON_OVERSAMPLE = 4;"),
  "raster brand assets must use 4x supersampling",
);

const styles = await readFile(join(siteDir, "styles.css"), "utf8");
assert(!/@import|url\(https?:/.test(styles), "the stylesheet must not fetch anything");
assert(styles.includes("prefers-reduced-motion"), "the one animation must respect the preference");
assert(
  styles.includes(".page-hero + .code"),
  "only a code block directly after the hero may overlap the hero boundary",
);
assert(
  !styles.includes(".with-hero > .code:first-of-type"),
  "the first later code block must not be pulled into its section heading",
);
assert(
  styles.includes(".chip-medium { background: #8a5a00; color: #fff; }"),
  "the medium badge needs the high-contrast white-on-ochre treatment",
);
assert(Buffer.byteLength(styles) < 32 * 1024, "the stylesheet must stay under 32 KiB");

const manifest = JSON.parse(await readFile(join(siteDir, "manifest.webmanifest"), "utf8"));
assert.equal(manifest.name, "owlwarden");
assert.equal(manifest.start_url, "./");
assert.deepEqual(
  manifest.icons.map((icon) => icon.src),
  ["./favicon.svg", "./favicon.png", "./icon-512.png"],
  "the install icons must come from the same owlwarden mark",
);

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

/** Checks the shared top navigation and its page-aware current marker. */
function checkPrimaryNavigation(path, html) {
  const header = one(html, /<header class="site-header">([\s\S]*?)<\/header>/);
  if (!header) {
    fail(path, "no shared site header");
    return;
  }
  const nav = one(header, /<nav aria-label="Primary">([\s\S]*?)<\/nav>/);
  if (!nav) {
    fail(path, "no primary navigation in the site header");
    return;
  }

  const pageUrl = `${site}/${path.replace(/index\.html$/, "")}`;
  const actual = [...nav.matchAll(/<a([^>]*)href="([^"]+)"([^>]*)>([\s\S]*?)<\/a>/g)].map(
    (match) => ({
      label: match[4].replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim(),
      href: new URL(match[2], pageUrl).href,
      current: `${match[1]} ${match[3]}`.includes('aria-current="page"'),
    }),
  );

  if (actual.length !== PRIMARY_NAV.length) {
    fail(path, `primary navigation has ${actual.length} links, expected ${PRIMARY_NAV.length}`);
    return;
  }
  for (const [index, expected] of PRIMARY_NAV.entries()) {
    if (actual[index].label !== expected.label || actual[index].href !== expected.href) {
      fail(
        path,
        `primary link ${index + 1} is ${actual[index].label} (${actual[index].href}), expected ${expected.label} (${expected.href})`,
      );
    }
  }

  const expectedCurrent = primarySection(path);
  const current = actual.filter((link) => link.current);
  if (expectedCurrent === undefined && current.length > 0) {
    fail(path, `marks ${current.map((link) => link.label).join(", ")} current outside a primary section`);
  } else if (expectedCurrent !== undefined && (current.length !== 1 || current[0].label !== expectedCurrent)) {
    fail(path, `current primary link is ${current[0]?.label ?? "missing"}, expected ${expectedCurrent}`);
  }
}

/** Maps a generated page to the primary product section readers are in. */
function primarySection(path) {
  if (path.startsWith("rules/")) return "Rules";
  if (
    path.startsWith("agent-config-security/") ||
    path.startsWith("claude-code/") ||
    path.startsWith("cursor/") ||
    path.startsWith("mcp/")
  ) return "Agent config";
  if (path.startsWith("vet/")) return "vet";
  if (path.startsWith("offline/")) return "Offline";
  if (path.startsWith("owasp/") || path.startsWith("asi/")) return "Coverage";
  return undefined;
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
