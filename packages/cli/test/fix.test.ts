import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Finding, Report } from "@dointhai/owlwarden-sdk";
import { describe, expect, it } from "vitest";

import {
  applyFixPlans,
  planFixes,
  resolveFindingPath,
  selectFix,
} from "../src/fix.js";

function finding(overrides: Partial<Finding> & Pick<Finding, "id">): Finding {
  return {
    severity: "high",
    confidence: "likely",
    title: "t",
    why: "w",
    location: { path: "src/a.ts", line: 2, col: 10 },
    snippet: {
      path: "src/a.ts",
      startLine: 1,
      lines: ["const x = 1", "  return err.stack", "}"],
      highlight: { line: 2, startCol: 10, endCol: 19 },
    },
    remediation: [
      {
        summary: "generic string",
        patch: "'Internal Server Error'",
        safety: "safe",
      },
    ],
    references: [],
    ...overrides,
  };
}

function report(findings: Finding[]): Report {
  return {
    schemaVersion: "1.0.0",
    tool: { name: "owlwarden", version: "0.0.0" },
    scannedAt: "1970-01-01T00:00:00Z",
    durationMs: 1,
    target: {
      project: ".",
      scope: [],
      filesScanned: 1,
      routesProbed: 0,
      preset: "quick",
    },
    summary: { high: findings.length, medium: 0, low: 0, info: 0 },
    findings,
    suppressedCount: 0,
    suppressions: [],
    baselineHiddenCount: 0,
    truncated: false,
    errors: [],
  };
}

describe("selectFix", () => {
  it("picks a Safe single-line patch and skips Possible", () => {
    const ok = selectFix(finding({ id: "stack-trace-leak" }), false);
    expect(ok?.fix.patch).toBe("'Internal Server Error'");
    expect(selectFix(finding({ id: "x", confidence: "possible" }), false)).toBeUndefined();
  });

  it("skips Manual and multi-line patches", () => {
    expect(
      selectFix(
        finding({
          id: "x",
          remediation: [
            {
              summary: "rewrite handler",
              patch: "console.error(err)\nreturn null",
              safety: "manual",
            },
          ],
        }),
        false,
      ),
    ).toBeUndefined();
  });

  it("requires --fix-unsafe for Unsafe", () => {
    const f = finding({
      id: "x",
      remediation: [{ summary: "u", patch: "safeish()", safety: "unsafe" }],
    });
    expect(selectFix(f, false)).toBeUndefined();
    expect(selectFix(f, true)?.fix.safety).toBe("unsafe");
  });
});

describe("applyFixPlans", () => {
  it("replaces the highlight and dry-run does not write", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-fix-"));
    const file = join(dir, "src", "a.ts");
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(file, "const x = 1\n  return err.stack\n}\n", "utf8");

    const planned = planFixes(dir, report([finding({ id: "stack-trace-leak" })]), false);
    expect(planned.plans).toHaveLength(1);

    const dry = await applyFixPlans(planned.plans, {
      dryRun: true,
      stderr: { write: () => true } as unknown as NodeJS.WritableStream,
    });
    expect(dry.applied).toBe(1);
    expect(dry.written).toHaveLength(0);
    const afterDry = await import("node:fs/promises").then((fs) =>
      fs.readFile(file, "utf8"),
    );
    expect(afterDry).toContain("err.stack");

    const wet = await applyFixPlans(planned.plans, {
      dryRun: false,
      stderr: { write: () => true } as unknown as NodeJS.WritableStream,
    });
    expect(wet.applied).toBe(1);
    const after = await import("node:fs/promises").then((fs) => fs.readFile(file, "utf8"));
    expect(after).toContain("'Internal Server Error'");
    expect(after).not.toContain("err.stack");
  });

  it("refuses paths that escape the project root", () => {
    expect(() => resolveFindingPath("/tmp/proj", "../etc/passwd")).toThrow(/escapes/);
  });

  it("refuses to apply when the highlight text no longer matches", async () => {
    const dir = await mkdtemp(join(tmpdir(), "owlwarden-fix-drift-"));
    const file = join(dir, "src", "a.ts");
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(file, "const x = 1\n  return something.else\n}\n", "utf8");

    const planned = planFixes(dir, report([finding({ id: "stack-trace-leak" })]), false);
    const result = await applyFixPlans(planned.plans, {
      dryRun: false,
      stderr: { write: () => true } as unknown as NodeJS.WritableStream,
    });
    expect(result.applied).toBe(0);
    expect(result.errors.some((message) => /highlight text changed/.test(message))).toBe(true);
  });
});
