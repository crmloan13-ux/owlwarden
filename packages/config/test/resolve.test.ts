import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { formatConfigError, resolveConfig } from "../src/index.js";

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "owlwarden-config-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("resolveConfig", () => {
  it("returns defaults when there is no config at all", async () => {
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source.kind).toBe("defaults");
    expect(result.config).toEqual({
      preset: "quick",
      rules: {},
      failOn: "info",
      minConfidence: "possible",
      format: "pretty",
    });
  });

  it("reads a JSON config", async () => {
    await writeFile(join(dir, "owlwarden.config.json"), JSON.stringify({ preset: "deep" }));
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("deep");
    // Unspecified keys still get their defaults, so the rest of the CLI never
    // has to deal with a partially populated config.
    expect(result.config.failOn).toBe("info");
  });

  it("reads an ESM config's default export", async () => {
    await writeFile(
      join(dir, "owlwarden.config.mjs"),
      "export default { preset: 'owasp-top10', failOn: 'medium' };\n",
    );
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("owasp-top10");
    expect(result.config.failOn).toBe("medium");
  });

  it("falls back to the owlwarden key in package.json", async () => {
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ name: "app", owlwarden: { failOn: "high" } }),
    );
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source.kind).toBe("package.json");
    expect(result.config.failOn).toBe("high");
  });

  it("prefers a config file over the package.json key", async () => {
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({ owlwarden: { preset: "deep" } }),
    );
    await writeFile(join(dir, "owlwarden.config.json"), JSON.stringify({ preset: "quick" }));
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("quick");
  });

  it("still scans a project whose package.json is malformed", async () => {
    // A broken package.json is the project's problem, not a reason to refuse to
    // look for vulnerabilities in it.
    await writeFile(join(dir, "package.json"), "{ not json");
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
  });

  it("names the offending key when a value is invalid", async () => {
    await writeFile(join(dir, "owlwarden.config.json"), JSON.stringify({ failOn: "critical" }));
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("invalid");
    const message = formatConfigError(result.error);
    expect(message).toContain("failOn");
    expect(message).toContain("owlwarden.config.json");
  });

  it("reports unparseable JSON instead of silently using defaults", async () => {
    await writeFile(join(dir, "owlwarden.config.json"), "{{{");
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("unreadable");
  });

  it("ignores a config directory that is above the project", async () => {
    // Config outside the scanned project must not change what a scan does.
    await writeFile(join(dir, "owlwarden.config.json"), JSON.stringify({ preset: "deep" }));
    const nested = join(dir, "packages", "app");
    await writeFile(join(dir, "marker"), "");
    const result = await resolveConfig(nested);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source.kind).toBe("defaults");
  });
});
