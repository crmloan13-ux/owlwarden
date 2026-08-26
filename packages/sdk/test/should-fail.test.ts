import { describe, expect, it } from "vitest";

import { shouldFail, type Finding, type Report } from "../src/index.js";

function finding(severity: Finding["severity"], confidence: Finding["confidence"]): Finding {
  return {
    id: "stack-trace-leak",
    title: "t",
    why: "t",
    severity,
    confidence,
    location: { path: "a.ts", line: 1, col: 1 },
    remediation: [],
    references: [],
  };
}

function reportOf(findings: Finding[], truncated = false): Report {
  return {
    schemaVersion: "1.0",
    tool: { name: "owlwarden", version: "0.0.0" },
    scannedAt: "1970-01-01T00:00:00Z",
    durationMs: 0,
    target: {
      project: ".",
      scope: [],
      filesScanned: 0,
    configFilesScanned: 0,
      routesProbed: 0,
      preset: "quick",
    },
    summary: { high: 0, medium: 0, low: 0, info: 0 },
    findings,
    suppressedCount: 0,
    suppressions: [],
    baselineHiddenCount: 0,
    truncated,
    errors: [],
  };
}

describe("shouldFail security contract", () => {
  it("fails when the report is truncated even with no findings", () => {
    expect(shouldFail(reportOf([], true), "high", "confirmed")).toBe(true);
  });

  it("never fails CI on possible-confidence findings alone", () => {
    expect(shouldFail(reportOf([finding("high", "possible")]), "info", "possible")).toBe(false);
  });

  it("fails on likely findings at or above the gate", () => {
    expect(shouldFail(reportOf([finding("medium", "likely")]), "medium", "likely")).toBe(true);
  });

  it("does not fail when severity is below the gate", () => {
    expect(shouldFail(reportOf([finding("low", "confirmed")]), "high", "possible")).toBe(false);
  });
});
