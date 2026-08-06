import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";

import { reportSchema } from "@dointhai/owlwarden-sdk";
import { describe, expect, it } from "vitest";

import { EXIT } from "../src/exit.js";
import { run } from "../src/run.js";

/**
 * End-to-end through the real engine.
 *
 * These need `pnpm build:native` to have run — the point is to exercise the
 * path a user takes, and mocking the addon would test the mock. If the addon is
 * missing, the failure says so clearly rather than looking like a logic bug.
 */

function fixture(name: string): string {
  return fileURLToPath(new URL(`../../../fixtures/${name}`, import.meta.url));
}

/** A writable that keeps what was written. */
function capture(): Writable & { text(): string } {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(chunk.toString());
      callback();
    },
  });
  return Object.assign(stream, { text: () => chunks.join("") });
}

async function cli(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const stdout = capture();
  const stderr = capture();
  const code = await run(argv, { stdout, stderr });
  return { code, out: stdout.text(), err: stderr.text() };
}

describe("owlwarden scan", () => {
  it("finds both fixture issues and exits 1", async () => {
    const { code, out } = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--format",
      "json",
      "--quiet",
    ]);

    expect(code).toBe(EXIT.FINDINGS);
    const report = reportSchema.parse(JSON.parse(out));
    expect(report.findings.map((finding) => finding.id).sort()).toEqual([
      "ci-unpinned-action",
      "security-headers-missing",
      "sensitive-data-logged",
      "stack-trace-leak",
      "unpinned-dependency",
    ]);
  });

  it("exits 0 on the false-positive corpus", async () => {
    // If this ever goes red, the tool has started crying wolf, which is the
    // failure that gets a scanner uninstalled.
    for (const name of ["should-not-fire/next-api-clean", "should-not-fire/tempting"]) {
      const { code, out } = await cli(["scan", fixture(name), "--format", "json", "--quiet"]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings, `${name} should be silent`).toEqual([]);
      expect(code).toBe(EXIT.CLEAN);
    }
  });

  it("does not fail the run when --fail-on is above what was found", async () => {
    const { code } = await cli([
      "scan",
      fixture("vulnerable/nest-api"),
      "--fail-on",
      "high",
      "--min-confidence",
      "confirmed",
      "--format",
      "json",
      "--quiet",
    ]);
    // Nothing reaches `confirmed` without a dynamic run, so a static-only scan
    // configured this strictly must pass.
    expect(code).toBe(EXIT.CLEAN);
  });

  it("prints a code frame in pretty output", async () => {
    const { out } = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--no-color",
      "--ascii",
      "--quiet",
    ]);
    expect(out).toContain("err.stack");
    expect(out).toContain("leaks internal stack trace to the client");
    expect(out).toContain("app/api/users/route.ts");
    expect(out).not.toContain("\u001b[");
  });

  it("reports an unreadable project instead of pretending it scanned", async () => {
    const { code, err } = await cli(["scan", fixture("does-not-exist"), "--quiet"]);
    expect(code).toBe(EXIT.ERROR);
    expect(err).toMatch(/error:/);
  });

  it("writes a baseline and then hides those findings on the next scan", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-baseline-"));
    const baselinePath = join(dir, "baseline.json");
    try {
      const write = await cli([
        "scan",
        fixture("vulnerable/next-api"),
        "--format",
        "json",
        "--quiet",
        "--write-baseline",
        baselinePath,
      ]);
      expect(write.code).toBe(EXIT.FINDINGS);
      const written = JSON.parse(await readFile(baselinePath, "utf8")) as {
        entries: unknown[];
      };
      expect(written.entries.length).toBeGreaterThan(0);

      const filtered = await cli([
        "scan",
        fixture("vulnerable/next-api"),
        "--format",
        "json",
        "--quiet",
        "--baseline",
        baselinePath,
      ]);
      const report = reportSchema.parse(JSON.parse(filtered.out));
      expect(report.findings).toEqual([]);
      expect(report.baselineHiddenCount).toBeGreaterThan(0);
      expect(filtered.code).toBe(EXIT.CLEAN);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("honours a next-line suppression with a reason", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-suppress-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "suppress-fixture", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak -- fixture: prove reason works",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const { code, out, err } = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--report-suppressions",
      ]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(false);
      expect(report.suppressedCount).toBeGreaterThanOrEqual(1);
      expect(err).toContain("stack-trace-leak");
      expect(err).toContain("[active]");
      expect(code).toBe(EXIT.FINDINGS); // security-headers-missing still fires
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("labels a missing-reason directive without calling it active", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-suppress-bad-"));
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "suppress-bad", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const { out, err } = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--report-suppressions",
      ]);
      const report = reportSchema.parse(JSON.parse(out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(true);
      expect(report.suppressedCount ?? 0).toBe(0);
      expect(err).toContain("[missing-reason]");
      expect(err).not.toContain("[active]");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("write-baseline captures the post-suppression view", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-baseline-suppress-"));
    const baselinePath = join(dir, ".owlwarden-baseline.json");
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "baseline-suppress", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "route.ts"),
        [
          "import { NextResponse } from 'next/server'",
          "export async function GET() {",
          "  try {",
          "    return NextResponse.json({ ok: true })",
          "  } catch (err) {",
          "    // owlwarden-disable-next-line stack-trace-leak -- accepted locally",
          "    return NextResponse.json({ error: (err as Error).stack })",
          "  }",
          "}",
          "",
        ].join("\n"),
      );

      const written = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--write-baseline",
        baselinePath,
      ]);
      expect(written.code).toBe(EXIT.FINDINGS);
      const baseline = JSON.parse(await readFile(baselinePath, "utf8")) as {
        entries: { id: string }[];
      };
      expect(baseline.entries.some((entry) => entry.id === "stack-trace-leak")).toBe(false);

      const filtered = await cli([
        "scan",
        dir,
        "--format",
        "json",
        "--quiet",
        "--baseline",
        baselinePath,
      ]);
      const report = reportSchema.parse(JSON.parse(filtered.out));
      expect(report.findings.some((finding) => finding.id === "stack-trace-leak")).toBe(false);
      expect(report.suppressedCount).toBeGreaterThanOrEqual(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("CI security posture", () => {
  it("does not execute owlwarden.config.mjs under --ci", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-ci-config-"));
    const marker = join(dir, "pwned.marker");
    try {
      await writeFile(
        join(dir, "package.json"),
        JSON.stringify({ name: "ci-config", dependencies: { next: "^14.2.0" } }),
      );
      await writeFile(
        join(dir, "owlwarden.config.mjs"),
        `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(marker)}, 'pwned');\nexport default { failOn: 'high' };\n`,
      );
      await writeFile(join(dir, "route.ts"), "export const GET = () => null\n");

      const { code } = await cli(["scan", dir, "--ci"]);
      // Scan still runs (findings or clean); the marker must never appear.
      expect([EXIT.CLEAN, EXIT.FINDINGS]).toContain(code);
      await expect(readFile(marker, "utf8")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("redacts hardcoded-secret values from CI JSON snippets", async () => {
    const { code, out } = await cli([
      "scan",
      fixture("vulnerable/express-api"),
      "--ci",
      "--fail-on",
      "info",
    ]);
    expect(code).toBe(EXIT.FINDINGS);
    const report = reportSchema.parse(JSON.parse(out));
    const secretFinding = report.findings.find((finding) => finding.id === "hardcoded-secret");
    expect(secretFinding).toBeDefined();
    const blob = JSON.stringify(secretFinding);
    expect(blob).not.toContain("sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx");
    expect(blob).toContain("sk_l***");
  });

  it("--ci still exits 1 on findings and 0 on clean fixtures", async () => {
    const dirty = await cli([
      "scan",
      fixture("vulnerable/next-api"),
      "--ci",
      "--fail-on",
      "medium",
    ]);
    expect(dirty.code).toBe(EXIT.FINDINGS);
    reportSchema.parse(JSON.parse(dirty.out));

    const clean = await cli([
      "scan",
      fixture("should-not-fire/next-api-clean"),
      "--ci",
      "--fail-on",
      "info",
    ]);
    expect(clean.code).toBe(EXIT.CLEAN);
    const report = reportSchema.parse(JSON.parse(clean.out));
    expect(report.findings).toEqual([]);
  });
});

describe("owlwarden rules / explain", () => {
  it("lists rules as JSON", async () => {
    const { code, out } = await cli(["rules", "--json"]);
    expect(code).toBe(EXIT.CLEAN);
    expect((JSON.parse(out) as unknown[]).length).toBeGreaterThan(0);
  });

  it("explains a rule completely offline", async () => {
    const { code, out } = await cli(["explain", "stack-trace-leak"]);
    expect(code).toBe(EXIT.CLEAN);
    expect(out).toContain("CWE-209");
    // An agent reading this has no browser: the fix has to be in the output.
    expect(out).toContain("FIXES");
    expect(out).toContain("NextResponse.json");
  });

  it("does not invent an answer for an unknown rule", async () => {
    const { code, err } = await cli(["explain", "no-such-rule"]);
    expect(code).toBe(EXIT.ERROR);
    expect(err).toContain("owlwarden rules");
  });
});
