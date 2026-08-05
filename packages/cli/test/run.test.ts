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
      "security-headers-missing",
      "stack-trace-leak",
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
