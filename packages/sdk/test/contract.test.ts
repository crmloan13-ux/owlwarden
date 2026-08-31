import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  coverageReportSchema,
  reportSchema,
  ruleMetaListSchema,
  shouldFail,
  turnReportSchema,
  type Confidence,
  type Severity,
} from "../src/index.js";

/**
 * The other half of the cross-language contract.
 *
 * `crates/reporters/tests/ts_contract.rs` writes these files from the real
 * engine. If a field is renamed in Rust and not here, this test fails; if the
 * zod schema drifts from what the engine emits, this test fails. Neither side
 * can move alone.
 */

function golden(name: string): unknown {
  const path = fileURLToPath(new URL(`../../../fixtures/golden/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("report schema", () => {
  it("accepts a report produced by the Rust engine", () => {
    const parsed = reportSchema.safeParse(golden("report.json"));
    if (!parsed.success) {
      // The default zod error is unreadable at this size; show the paths.
      throw new Error(
        `the engine's report does not match the zod schema:\n${parsed.error.issues
          .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
          .join("\n")}`,
      );
    }
    expect(parsed.data.schemaVersion).toBe("1.0");
    expect(parsed.data.findings.length).toBeGreaterThan(0);
  });

  it("keeps every field the engine emits", () => {
    // zod strips unknown keys, so a field the schema does not know about
    // survives the round trip only if the schema declares it. Comparing the key
    // sets is what turns "parsed fine" into "parsed completely".
    const raw = golden("report.json") as Record<string, unknown>;
    const parsed = reportSchema.parse(raw) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(raw).sort());
  });

  it("accepts the rule catalogue", () => {
    const rules = ruleMetaListSchema.parse(golden("rules.json"));
    expect(rules.length).toBeGreaterThan(0);
    // Sorted by id, because the CLI, the docs, and this test all rely on a
    // stable order rather than sorting it themselves.
    expect(rules.map((rule) => rule.id)).toEqual([...rules.map((rule) => rule.id)].sort());
  });
});

describe("coverage schema", () => {
  it("accepts the coverage table produced by the Rust engine", () => {
    const parsed = coverageReportSchema.safeParse(golden("coverage.json"));
    if (!parsed.success) {
      throw new Error(
        `the engine's coverage table does not match the zod schema:\n${parsed.error.issues
          .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
          .join("\n")}`,
      );
    }
    expect(parsed.data.owasp).toHaveLength(10);
  });

  it("reports gaps rather than omitting them", () => {
    // A table that listed only what we check would be an advertisement. If this
    // ever stops finding an empty category, verify that each rule earning its
    // category is real before deleting the assertion.
    const coverage = coverageReportSchema.parse(golden("coverage.json"));
    const empty = coverage.owasp.filter((entry) => entry.rules.length === 0);
    expect(empty.length).toBeGreaterThan(0);
    expect(coverage.categoriesCovered).toBe(coverage.owasp.length - empty.length);
  });

  it("distinguishes a gap from something static analysis cannot see", () => {
    // Collapsing these two would tell a reader to expect a rule that is never
    // coming.
    const coverage = coverageReportSchema.parse(golden("coverage.json"));
    const reachabilities = new Set(coverage.owasp.map((entry) => entry.reachability));
    expect(reachabilities.size).toBeGreaterThan(1);
  });

  it("gives every supported framework specific remediation", () => {
    const coverage = coverageReportSchema.parse(golden("coverage.json"));
    expect(coverage.frameworks.map((framework) => framework.id).sort()).toEqual([
      "astro",
      "elysia",
      "express",
      "fastify",
      "gatsby",
      "hapi",
      "hono",
      "koa",
      "nest",
      "next",
      "nuxt",
      "remix",
      "sails",
      // Added in 1.2 alongside the runtime overlay: the four frameworks most
      // likely to be on a non-Node runtime, so the overlay and the new profiles
      // exercise each other (ADR 0031 §5).
      "solidstart",
      "sveltekit",
      "tanstack-start",
    ]);
    for (const framework of coverage.frameworks) {
      expect(framework.rulesFallingBack, `${framework.id} falls back`).toBe(0);
    }
  });
});

describe("shouldFail", () => {
  it("agrees with the Rust implementation on every threshold", () => {
    const report = reportSchema.parse(golden("report.json"));
    const matrix = golden("should-fail.json") as {
      failOn: Severity;
      minConfidence: Confidence;
      fails: boolean;
    }[];

    expect(matrix.length).toBe(12);
    for (const row of matrix) {
      expect(
        shouldFail(report, row.failOn, row.minConfidence),
        `failOn=${row.failOn} minConfidence=${row.minConfidence}`,
      ).toBe(row.fails);
    }
  });
});

describe("turn record schema", () => {
  it("accepts a turn record produced by the Rust engine", () => {
    const parsed = turnReportSchema.safeParse(golden("turn.json"));
    if (!parsed.success) {
      throw new Error(
        `the engine's turn record does not match the zod schema:\n${parsed.error.issues
          .map((issue) => `  ${issue.path.join(".")}: ${issue.message}`)
          .join("\n")}`,
      );
    }
    expect(parsed.data.schemaVersion).toBe("1.0");
  });

  it("keeps every field the engine emits", () => {
    const raw = golden("turn.json") as Record<string, unknown>;
    const parsed = turnReportSchema.parse(raw) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(Object.keys(raw).sort());
  });

  it("exercises all three states, so none of them can drift unnoticed", () => {
    const record = turnReportSchema.parse(golden("turn.json"));
    expect(record.counts.introduced).toBeGreaterThan(0);
    expect(record.counts.carried).toBeGreaterThan(0);
    expect(record.counts.fixed).toBeGreaterThan(0);
  });

  it("renders carried and fixed findings by reference only", () => {
    // The shape enforces the argument: a carried finding cannot arrive with a
    // code frame and a fix, because the schema has nowhere to put them.
    const record = turnReportSchema.parse(golden("turn.json"));
    expect(record.carried.length).toBe(record.counts.carried);
    for (const entry of [...record.carried, ...record.fixed]) {
      expect(Object.keys(entry).sort()).toEqual(["at", "fingerprint", "id", "severity"]);
    }
  });

  it("never says clean while something introduced met the gate", () => {
    const record = turnReportSchema.parse(golden("turn.json"));
    expect(record.blocking).toBeLessThanOrEqual(record.counts.introduced);
    expect(record.verdict === "blocked").toBe(record.blocking > 0);
  });
});
