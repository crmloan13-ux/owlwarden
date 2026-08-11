/**
 * Keeps the README published with the `owlwarden` npm package aligned with the
 * compiled v0.5 surface. The npm page is often the first and only document a
 * prospective user reads, so missing safety limits are contract failures too.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const readmeUrl = new URL("packages/cli/README.md", root);
const [readme, packageJsonText] = await Promise.all([
  readFile(readmeUrl, "utf8"),
  readFile(new URL("packages/cli/package.json", root), "utf8"),
]);
const packageJson = JSON.parse(packageJsonText);
const rules = [
  "ci-unpinned-action",
  "cors-permissive",
  "csrf-cross-origin-post",
  "hardcoded-secret",
  "insecure-cookie",
  "known-vulnerable-dependency",
  "open-redirect",
  "security-headers-missing",
  "sensitive-data-logged",
  "sql-injection",
  "ssrf",
  "stack-trace-leak",
  "unpinned-dependency",
  "weak-crypto",
];
const frameworks = [
  "Next.js",
  "Nuxt",
  "NestJS",
  "Express",
  "Fastify",
  "Hono",
  "Koa",
  "Hapi",
  "Sails.js",
  "Astro",
  "Remix",
  "Gatsby",
];

for (const heading of [
  "Why Owlwarden",
  "One finding, the whole answer",
  "What it catches",
  "Framework support",
  "Coding agents and MCP",
  "CI without greenwashing",
  "Configuration",
  "Adopting it in an existing codebase",
  "Optional runtime confirmation",
  "Incremental watch",
  "Source-only WASM plugins",
  "Safety model",
  "Honest limits",
]) {
  assert.match(readme, new RegExp(`^## ${heading}$`, "m"), `missing ${heading}`);
}

for (const value of [...rules, ...frameworks]) {
  assert(readme.includes(value), `npm README is missing ${value}`);
}

assert.match(readme, /npx owlwarden scan/);
assert.match(readme, /npx owlwarden mcp/);
assert.match(readme, /confirmed.*likely.*possible/is);
assert.match(readme, /No telemetry/i);
assert.match(readme, /static-only, read-only/i);
assert.match(readme, /A04:2021.*Insecure Design/is);
assert.match(readme, /`--fix` applies only/i);
assert.match(readme, /`--osv`/i);
assert.match(readme, /--osv-db/i);
assert.match(readme, /--require-signed-plugins/i);
assert.match(readme, /plugin inspect/i);
assert.match(readme, /no hosted plugin store/i);
assert.match(readme, /sarif/i);
assert.match(readme, /junit/i);
assert.match(readme, /Version 0\.5\.0/);
assert.match(readme, /fourteen rules/i);
assert.match(readme, /12 rules × 12 frameworks|12 × 12/i);
assert.match(readme, /osv update/i);
assert.match(readme, /https:\/\/suthat\.github\.io\/owlwarden\//);
assert.match(readme, /Save tokens first/i);
assert.match(readme, /frontier model/i);
assert.match(readme, /Silence means/i);
assert.doesNotMatch(readme, /\]\((?!https:\/\/|#)/, "npm links must be absolute or local anchors");
assert((await stat(readmeUrl)).size < 32_000, "npm README exceeds the 32 KB budget");
assert.equal(packageJson.homepage, "https://suthat.github.io/owlwarden/");
assert.match(packageJson.description, /Local security scanner.*coding agents.*framework-specific fixes/i);
assert(packageJson.keywords.includes("static-analysis"));
assert(packageJson.keywords.includes("web-security"));

console.log("npm README contract passed");
