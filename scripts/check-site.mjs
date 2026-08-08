import assert from "node:assert/strict";
import { access, readFile, stat } from "node:fs/promises";

const root = new URL("../site/", import.meta.url);
const canonical = "https://suthat.github.io/owlwarden/";

async function text(path) {
  return readFile(new URL(path, root), "utf8");
}

async function bytes(path) {
  return (await stat(new URL(path, root))).size;
}

function occurrences(source, pattern) {
  return source.match(pattern)?.length ?? 0;
}

const [html, robots, sitemap, llms] = await Promise.all([
  text("index.html"),
  text("robots.txt"),
  text("sitemap.xml"),
  text("llms.txt"),
]);

assert.match(html, /<html lang="en">/);
assert.equal(occurrences(html, /<h1(?:\s|>)/g), 1, "the page needs exactly one h1");
assert.match(html, /<main id="main-content">/);
assert.match(html, /<a class="skip-link" href="#main-content">/);
assert.match(html, new RegExp(`<link rel="canonical" href="${canonical}"`));
assert.match(html, /name="description" content="[^"]{120,165}"/);
assert.match(html, /property="og:image" content="https:\/\/suthat\.github\.io\/owlwarden\/og\.jpg"/);
assert.match(html, /<meta name="twitter:card" content="summary_large_image">/);
assert.match(html, /<script type="application\/ld\+json">/);
assert.match(html, /"@type":\s*"SoftwareApplication"/);
assert.match(html, /"applicationCategory":\s*"SecurityApplication"/);
assert.match(html, /npx owlwarden scan/);
assert.match(html, /Next\.js/);
assert.match(html, /Gatsby/);
assert.match(html, /9 of 10/);
assert.match(html, /twelve rules/i);
assert.match(html, /No telemetry/i);
assert.match(html, /Insecure Design/);
assert.doesNotMatch(html, /<img(?![^>]+(?:width|height)=)/);
assert.doesNotMatch(html, /https:\/\/(?:fonts|use\.typekit|cdn\.)/);
assert.doesNotMatch(html, /target="_blank"(?![^>]+rel="[^"]*noopener)/);

const jsonLdMatch = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
assert(jsonLdMatch, "JSON-LD is required");
JSON.parse(jsonLdMatch[1]);

for (const path of ["og.jpg", "favicon.png"]) {
  await access(new URL(path, root));
}

assert.match(robots, /Allow: \/owlwarden\//);
assert.match(robots, /Sitemap: https:\/\/suthat\.github\.io\/owlwarden\/sitemap\.xml/);
assert.match(sitemap, new RegExp(`<loc>${canonical}</loc>`));
assert.match(llms, /^# Owlwarden/m);
assert.match(llms, /https:\/\/github\.com\/suthat\/owlwarden\/blob\/main\/RULES\.md/);

assert((await bytes("index.html")) < 38_000, "HTML exceeds the 38 KB budget");
assert((await bytes("styles.css")) < 28_000, "CSS exceeds the 28 KB budget");
assert((await bytes("site.js")) < 2_500, "JavaScript exceeds the 2.5 KB budget");
assert((await bytes("og.jpg")) < 350_000, "social image exceeds the 350 KB budget");

console.log("site contract passed");
