import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { MAX_CONFIG_BYTES, formatConfigError, resolveConfig } from "../src/index.js";

/**
 * Config resolution against a tree written by someone else.
 *
 * `owlwarden.config.json` sits in the repository under scan, which means an
 * attacker who can open a pull request can write it. Everything it can reach
 * has to be either harmless or refused, and — this is the half that is easy to
 * miss — anything refused has to be *said*. A config that is quietly ignored
 * and a config that is quietly honoured fail in opposite directions, and both
 * of them look identical from the terminal.
 *
 * The other reader of this file is the person who wrote the config for their
 * own project and made a typo. Their failure mode is the same shape: a knob
 * that reads as if it tightens the scan and does nothing.
 */

let dir: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "owlwarden-hostile-config-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function write(name: string, contents: unknown): Promise<void> {
  await writeFile(
    join(dir, name),
    typeof contents === "string" ? contents : JSON.stringify(contents),
  );
}

describe("a key that does not exist is refused, not dropped", () => {
  // zod strips unknown keys by default, which meant `failon: "high"` parsed
  // cleanly and the scan used the default `info`. The user reads their config,
  // believes it, and is wrong — with no output anywhere that says so.
  it.each([
    ["failon", "failOn"],
    ["failOn ", "failOn"],
    ["FailOn", "failOn"],
    ["fail_on", "failOn"],
    ["minconfidence", "minConfidence"],
    ["minConfidance", "minConfidence"],
    ["Preset", "preset"],
    ["formats", "format"],
  ])("names %s as a near miss for %s", async (typo, intended) => {
    await write("owlwarden.config.json", { [typo]: "high" });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(formatConfigError(result.error)).toContain(`did you mean "${intended}"`);
  });

  it.each([
    ["plugins", "a config-file route to loading code"],
    ["target", "a config-file route to network egress"],
    ["allowActive", "a config-file route to active probing"],
    ["baseline", "a config-file route to a mute switch"],
    ["honorSuppressions", "the same, spelled the American way"],
  ])("refuses %s outright (%s)", async (key) => {
    await write("owlwarden.config.json", { [key]: true });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const message = formatConfigError(result.error);
    expect(message).toContain(`unknown key "${key}"`);
    // No near-miss claim for a key that is not near anything: telling someone
    // `plugins` might have meant `preset` sends them somewhere wrong.
    expect(message).not.toContain("did you mean");
    expect(message).toContain("known keys are");
  });

  it("refuses an unknown key inside a rule override", async () => {
    await write("owlwarden.config.json", { rules: { "weak-crypto": { enable: false } } });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const message = formatConfigError(result.error);
    expect(message).toContain("rules.weak-crypto");
    expect(message).toContain('did you mean "enabled"');
  });

  it("reports every unknown key at once, not the first", async () => {
    await write("owlwarden.config.json", { failon: "high", minconfidence: "likely" });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    const message = formatConfigError(result.error);
    expect(message).toContain("failon");
    expect(message).toContain("minconfidence");
  });

  it("still accepts a config that is entirely correct", async () => {
    await write("owlwarden.config.json", {
      preset: "deep",
      failOn: "high",
      minConfidence: "likely",
      format: "sarif",
      rules: { "weak-crypto": { enabled: false, severity: "low" } },
    });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.failOn).toBe("high");
    expect(result.config.rules["weak-crypto"]?.enabled).toBe(false);
  });

  it("does not spend real time on a pathological key", async () => {
    // The near-miss search compares the config's key against each schema key.
    // Only one of the two is attacker-controlled, and the bound has to hold
    // regardless of how long that one is.
    await write("owlwarden.config.json", { [`x${"y".repeat(200_000)}`]: 1 });

    const started = performance.now();
    const result = await resolveConfig(dir);
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(result.ok).toBe(false);
  });
});

describe("a config that is present but not read says so", () => {
  it("names a symlinked JSON config rather than falling through in silence", async () => {
    await write("elsewhere.json", { preset: "deep", failOn: "high" });
    await symlink(join(dir, "elsewhere.json"), join(dir, "owlwarden.config.json"));

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Still not followed — that is the security half and it has not moved.
    expect(result.source.kind).toBe("defaults");
    expect(result.config.preset).toBe("quick");
    // ...and now the reporting half.
    expect(result.skippedSymlink).toBe(join(dir, "owlwarden.config.json"));
  });

  it("names a symlinked executable config under --allow-config-js", async () => {
    await write("elsewhere.mjs", "export default { preset: 'deep' };");
    await symlink(join(dir, "elsewhere.mjs"), join(dir, "owlwarden.config.mjs"));

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source.kind).toBe("defaults");
    expect(result.skippedSymlink).toBe(join(dir, "owlwarden.config.mjs"));
  });

  it("loads a real config sitting beside a symlinked one, and reports both facts", async () => {
    // A symlinked `.ts` earlier in the lookup order must not stop the real
    // `.mjs` behind it from loading. The old loop `continue`d past anything
    // `exists()` called false, which happened to get this right by accident;
    // this pins the behaviour now that the two cases are distinguished.
    await write("elsewhere.ts", "export default { preset: 'deep' };");
    await symlink(join(dir, "elsewhere.ts"), join(dir, "owlwarden.config.ts"));
    await write("owlwarden.config.mjs", "export default { preset: 'owasp-top10' };");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("owasp-top10");
    expect(result.skippedSymlink).toBe(join(dir, "owlwarden.config.ts"));
  });

  it("does not read config through a directory named like one", async () => {
    await mkdir(join(dir, "owlwarden.config.json"));
    await write("package.json", { owlwarden: { preset: "deep" } });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // A directory is "present but not a file" — the package.json key still wins.
    expect(result.config.preset).toBe("deep");
    expect(result.skippedSymlink).toBe(join(dir, "owlwarden.config.json"));
  });

  it("does not read a package.json that is a symlink", async () => {
    await write("elsewhere.json", { owlwarden: { preset: "deep" } });
    await symlink(join(dir, "elsewhere.json"), join(dir, "package.json"));

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("quick");
  });

  it("still reports a skipped executable config alongside the JSON it loaded", async () => {
    await write("owlwarden.config.js", "export default { preset: 'deep' };");
    await write("owlwarden.config.json", { preset: "owasp-top10" });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("owasp-top10");
    expect(result.skippedExecutable).toBe(join(dir, "owlwarden.config.js"));
  });
});

describe("values a hostile config can put in a valid key", () => {
  it.each([
    ["a prototype pollution attempt", '{"__proto__":{"failOn":"high"},"preset":"quick"}'],
    ["a constructor key", '{"constructor":{"prototype":{"x":1}}}'],
  ])("refuses %s", async (_label, raw) => {
    await write("owlwarden.config.json", raw);

    const result = await resolveConfig(dir);
    // Either shape is acceptable — what is not acceptable is Object.prototype
    // acquiring a property.
    expect(({} as Record<string, unknown>).failOn).toBeUndefined();
    if (result.ok) {
      expect(Object.hasOwn(result.config, "failOn")).toBe(true);
      expect(result.config.failOn).toBe("info");
    }
  });

  it("refuses a severity that is not one of the five", async () => {
    await write("owlwarden.config.json", { failOn: "critical" });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(formatConfigError(result.error)).toContain("failOn");
  });

  it("refuses a config whose root is an array", async () => {
    await write("owlwarden.config.json", ["preset", "deep"]);

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
  });

  it("refuses a config whose root is a string", async () => {
    await write("owlwarden.config.json", '"deep"');

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
  });

  it("treats a null config as invalid rather than as absent", async () => {
    await write("owlwarden.config.json", "null");

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
  });

  it("refuses a rule id mapped to a non-object", async () => {
    await write("owlwarden.config.json", { rules: { "weak-crypto": false } });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
  });

  it("carries an unusual rule id through untouched", async () => {
    // Rule ids are the config's only free-form keys. They are looked up, never
    // interpreted, so a strange one must be a miss rather than an error.
    const id = "../../etc/passwd";
    await write("owlwarden.config.json", { rules: { [id]: { enabled: false } } });

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.rules[id]?.enabled).toBe(false);
  });
});

describe("size and shape limits", () => {
  it("refuses a config larger than the cap without parsing it", async () => {
    // Padding inside a string value: the file is oversized but the JSON is
    // valid, so a size check that ran after parsing would already have paid.
    await write("owlwarden.config.json", `{"preset":"${"q".repeat(MAX_CONFIG_BYTES)}"}`);

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("too-large");
    expect(formatConfigError(result.error)).toContain("maximum is");
  });

  it("does not let an oversized package.json block the scan", async () => {
    await write("package.json", `{"name":"x","description":"${"y".repeat(MAX_CONFIG_BYTES)}"}`);

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.source.kind).toBe("defaults");
  });

  it("does not let deeply nested JSON take the process down", async () => {
    const depth = 20_000;
    await write("owlwarden.config.json", "[".repeat(depth) + "]".repeat(depth));

    // JSON.parse throws RangeError on this rather than overflowing; what
    // matters is that it arrives as a typed error and not as a crash.
    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(["unreadable", "invalid"]).toContain(result.error.kind);
  });

  it("reports a truncated config rather than using defaults", async () => {
    await write("owlwarden.config.json", '{"preset":"deep"');

    const result = await resolveConfig(dir);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("unreadable");
  });
});

describe("executable config stays opt-in", () => {
  it.each(["owlwarden.config.js", "owlwarden.config.mjs", "owlwarden.config.ts", "owlwarden.config.mts"])(
    "does not import %s without the flag",
    async (name) => {
      // If this ever regresses the module runs, so the assertion is the
      // side effect, not the return value.
      await write(name, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(join(dir, "EXECUTED"))}, "");\nexport default { preset: "deep" };\n`);

      const result = await resolveConfig(dir);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.config.preset).toBe("quick");
      expect(result.skippedExecutable).toBe(join(dir, name));

      const { existsSync } = await import("node:fs");
      expect(existsSync(join(dir, "EXECUTED"))).toBe(false);
    },
  );

  it("validates an executable config's export as strictly as a JSON one", async () => {
    await write("owlwarden.config.mjs", "export default { failon: 'high' };");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(formatConfigError(result.error)).toContain('did you mean "failOn"');
  });

  it("reports a module that throws instead of crashing the scan", async () => {
    await write("owlwarden.config.mjs", "throw new Error('boom');");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.kind).toBe("unreadable");
    expect(formatConfigError(result.error)).toContain("boom");
  });

  it("validates the namespace when a module has no default export", async () => {
    await write("owlwarden.config.mjs", "export const preset = 'deep';");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.preset).toBe("deep");
  });

  it("refuses a named export the schema does not know", async () => {
    // The leniency above is bounded by the same strict schema: named exports
    // work, but a name nobody recognises is still a refusal rather than a
    // silent no-op.
    await write("owlwarden.config.mjs", "export const failon = 'high';");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(formatConfigError(result.error)).toContain('did you mean "failOn"');
  });

  it("refuses a module whose default export is not an object", async () => {
    await write("owlwarden.config.mjs", "export default 'deep';");

    const result = await resolveConfig(dir, { allowConfigJs: true });
    expect(result.ok).toBe(false);
  });
});
