import { z } from "zod";

/**
 * The report schema, mirroring the Rust `Report` in `crates/core/src/report.rs`.
 *
 * Two definitions of one format will drift, so this one is held to the other by
 * a contract test: `packages/sdk/test/contract.test.ts` parses a report emitted
 * by the Rust engine with these schemas. Rename a field in Rust and that test
 * goes red, which is the only reliable way to keep the two in step.
 *
 * Unknown keys are stripped rather than rejected, on purpose. A newer engine
 * adding a field must not break an older CLI — additive changes are compatible,
 * renames and removals are not, and only the latter should fail. The practical
 * consequence: pass the *original* JSON string to `render()`, never a
 * re-serialised parse result, or you will silently drop fields you did not know
 * about.
 */

/** How much damage the issue can do. */
export const severitySchema = z.enum(["high", "medium", "low", "info"]);

/**
 * How sure the engine is. `confirmed` means it was observed at runtime;
 * `likely` means the code says so; `possible` means it is worth a look.
 */
export const confidenceSchema = z.enum(["confirmed", "likely", "possible"]);

/**
 * A framework identifier, e.g. `"next"`, `"fastify"`, `"generic"`.
 *
 * A string rather than an enum, mirroring the open `Framework` type in the
 * engine. A plugin may register a framework this SDK version has never heard
 * of, and rejecting its findings at the schema boundary would make the plugin
 * system unusable — the consumer would see a parse error instead of a real
 * vulnerability. The constraint is on the *shape* of the id, which is what the
 * engine also validates.
 *
 * {@link BUILTIN_FRAMEWORKS} lists the ones that ship, for callers that want to
 * branch on them; treat anything else as valid and unknown, not as an error.
 */
export const frameworkSchema = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[a-z][a-z0-9-]*$/, "a framework id is lowercase, digits, and hyphens");

/**
 * The frameworks that ship with the engine.
 *
 * For display and autocompletion only. Do not use it to validate — see
 * {@link frameworkSchema}.
 */
export const BUILTIN_FRAMEWORKS = [
  "next",
  "nuxt",
  "nest",
  "express",
  "fastify",
  "generic",
] as const;

/** Whether a fix can be applied automatically. */
export const fixSafetySchema = z.enum(["safe", "unsafe", "manual"]);

/**
 * Where the finding is.
 *
 * A static finding has `path`/`line`/`col`; a dynamic one has `url`/`method`.
 * The variants are distinguished by which keys are present rather than by a tag,
 * so the common case reads as `{ path, line, col }` with no ceremony.
 */
export const locationSchema = z.union([
  z.object({
    path: z.string(),
    line: z.number().int().positive(),
    col: z.number().int().positive(),
  }),
  z.object({
    url: z.string(),
    method: z.string().optional(),
  }),
]);

/** The underlined span within a code frame. */
export const highlightSchema = z.object({
  line: z.number().int().positive(),
  startCol: z.number().int().positive(),
  endCol: z.number().int().positive(),
  label: z.string().optional(),
});

/** The lines of source shown with the finding, plus what to underline. */
export const codeFrameSchema = z.object({
  path: z.string(),
  startLine: z.number().int().positive(),
  lines: z.array(z.string()),
  highlight: highlightSchema.optional(),
});

/** What the engine knew about the code around the finding. */
export const findingContextSchema = z.object({
  framework: frameworkSchema.optional(),
  route: z.string().optional(),
  method: z.string().optional(),
  evidence: z.string().optional(),
});

/** One way to fix the finding. Later entries are more generic than earlier ones. */
export const fixSchema = z.object({
  framework: frameworkSchema.optional(),
  summary: z.string(),
  patch: z.string().optional(),
  safety: fixSafetySchema,
});

/** A pointer to the wider literature: OWASP, CWE, or our own rule page. */
export const referenceSchema = z.object({
  kind: z.enum(["owasp", "cwe", "docs"]),
  id: z.string(),
  url: z.string(),
});

/** One issue, with everything needed to understand and fix it offline. */
export const findingSchema = z.object({
  /** The rule id. Stable public API — suppressions and agent rules cite it. */
  id: z.string(),
  severity: severitySchema,
  confidence: confidenceSchema,
  owasp: z.string().optional(),
  cwe: z.number().int().optional(),
  title: z.string(),
  why: z.string(),
  location: locationSchema,
  snippet: codeFrameSchema.optional(),
  context: findingContextSchema.optional(),
  remediation: z.array(fixSchema),
  references: z.array(referenceSchema),
});

/** A rule that could not run. The scan continues; the failure is reported. */
export const detectorFailureSchema = z.object({
  rule: z.string(),
  message: z.string(),
});

/** Counts by severity, for the one-line summary. */
export const reportSummarySchema = z.object({
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});

/** What was scanned. */
export const scanTargetSchema = z.object({
  project: z.string(),
  scope: z.array(z.string()),
  filesScanned: z.number().int().nonnegative(),
  routesProbed: z.number().int().nonnegative(),
  preset: z.string(),
});

/** The whole result of one scan. */
export const reportSchema = z.object({
  /** Bumped when the format changes incompatibly. Check it before trusting the rest. */
  schemaVersion: z.string(),
  tool: z.object({ name: z.string(), version: z.string() }),
  scannedAt: z.string(),
  durationMs: z.number().int().nonnegative(),
  target: scanTargetSchema,
  summary: reportSummarySchema,
  findings: z.array(findingSchema),
  /**
   * Findings hidden by a suppression. Present so that "0 findings" is never
   * mistaken for "0 problems" (`AGENTS.md` §5).
   */
  suppressedCount: z.number().int().nonnegative(),
  /** True when the engine hit its finding cap and stopped collecting. */
  truncated: z.boolean(),
  errors: z.array(detectorFailureSchema),
});

/** Metadata for one rule, as returned by `listRules()`. */
export const ruleMetaSchema = z.object({
  id: z.string(),
  title: z.string(),
  severity: severitySchema,
  maxConfidence: confidenceSchema,
  owasp: z.string().optional(),
  cwe: z.number().int().optional(),
  category: z.string(),
  description: z.string(),
});

/** One named bundle of rules. */
export const presetInfoSchema = z.object({
  name: z.string(),
  description: z.string(),
  rules: z.array(z.string()),
});

/** Everything `owlwarden explain <id>` prints, gathered offline. */
export const ruleExplanationSchema = z.object({
  meta: ruleMetaSchema,
  /** Every framework's fix, not only the one detected in this project. */
  fixes: z.array(fixSchema),
  references: z.array(referenceSchema),
});

/**
 * How much of an OWASP category static analysis can reach at all.
 *
 * `poor` is not a to-do. Some of the Top 10 describe a deployment or a design,
 * and no parser will ever see them; a consumer rendering this table must not
 * present those rows as work in progress.
 */
export const reachabilitySchema = z.enum(["good", "partial", "poor"]);

/** One OWASP category and the rules that map to it. */
export const categoryCoverageSchema = z.object({
  id: z.string(),
  title: z.string(),
  /** Empty means no coverage. Read it together with `reachability`. */
  rules: z.array(z.string()),
  reachability: reachabilitySchema,
  summary: z.string(),
});

/** One framework and how well the rules speak its dialect. */
export const frameworkCoverageSchema = z.object({
  id: z.string(),
  rulesWithSpecificFix: z.number().int().nonnegative(),
  rulesFallingBack: z.number().int().nonnegative(),
});

/**
 * What the installed engine covers, as returned by `coverage()`.
 *
 * Computed from the rules compiled into the binary, so it describes the engine
 * the caller actually has rather than the one the documentation was written
 * against.
 */
export const coverageReportSchema = z.object({
  version: z.string(),
  owasp: z.array(categoryCoverageSchema),
  frameworks: z.array(frameworkCoverageSchema),
  ruleCount: z.number().int().nonnegative(),
  categoriesCovered: z.number().int().nonnegative(),
});

// Collection schemas, so callers do not need zod as a direct dependency just to
// wrap these in `z.array`.
export const ruleMetaListSchema = z.array(ruleMetaSchema);
export const presetInfoListSchema = z.array(presetInfoSchema);

export type Severity = z.infer<typeof severitySchema>;
export type Confidence = z.infer<typeof confidenceSchema>;
export type Framework = z.infer<typeof frameworkSchema>;
export type FixSafety = z.infer<typeof fixSafetySchema>;
export type Location = z.infer<typeof locationSchema>;
export type Highlight = z.infer<typeof highlightSchema>;
export type CodeFrame = z.infer<typeof codeFrameSchema>;
export type FindingContext = z.infer<typeof findingContextSchema>;
export type Fix = z.infer<typeof fixSchema>;
export type Reference = z.infer<typeof referenceSchema>;
export type Finding = z.infer<typeof findingSchema>;
export type DetectorFailure = z.infer<typeof detectorFailureSchema>;
export type ReportSummary = z.infer<typeof reportSummarySchema>;
export type ScanTarget = z.infer<typeof scanTargetSchema>;
export type Report = z.infer<typeof reportSchema>;
export type RuleMeta = z.infer<typeof ruleMetaSchema>;
export type PresetInfo = z.infer<typeof presetInfoSchema>;
export type RuleExplanation = z.infer<typeof ruleExplanationSchema>;
export type Reachability = z.infer<typeof reachabilitySchema>;
export type CategoryCoverage = z.infer<typeof categoryCoverageSchema>;
export type FrameworkCoverage = z.infer<typeof frameworkCoverageSchema>;
export type CoverageReport = z.infer<typeof coverageReportSchema>;

/** Severities in the order the CLI ranks them; index 0 is the worst. */
export const SEVERITY_ORDER: readonly Severity[] = ["high", "medium", "low", "info"];

/** Confidences from most to least certain. */
export const CONFIDENCE_ORDER: readonly Confidence[] = ["confirmed", "likely", "possible"];

/** True when `severity` is at least as bad as `threshold`. */
export function severityAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf(threshold);
}

/** True when `confidence` is at least as certain as `threshold`. */
export function confidenceAtLeast(confidence: Confidence, threshold: Confidence): boolean {
  return CONFIDENCE_ORDER.indexOf(confidence) <= CONFIDENCE_ORDER.indexOf(threshold);
}

/**
 * Whether a report should fail the run.
 *
 * Mirrors `Report::should_fail` in the engine. Both sides implement it because
 * the CLI decides the exit code and the engine decides `--ci` behaviour; the
 * contract test pins them to the same answer.
 */
export function shouldFail(
  report: Report,
  failOn: Severity,
  minConfidence: Confidence,
): boolean {
  return report.findings.some(
    (finding) =>
      severityAtLeast(finding.severity, failOn) &&
      confidenceAtLeast(finding.confidence, minConfidence),
  );
}
