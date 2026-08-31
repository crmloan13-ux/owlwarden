import { z } from "zod";

import { confidenceSchema, exposureSchema, findingSchema, severitySchema } from "./report.js";

/**
 * The turn record: what one turn introduced, carried, and fixed.
 *
 * Declared here in zod and in `crates/core/src/turn.rs` in Rust, and held
 * together by `fixtures/golden/turn.json` the same way the scan report is — see
 * `packages/sdk/test/contract.test.ts`. Neither declaration can move alone.
 *
 * Versioned independently of the scan report. The two change for different
 * reasons, and tying them together would mean a turn-record field forcing a
 * major bump on a consumer that only reads reports.
 */

/** Where one finding stands relative to the base. */
export const turnStateSchema = z.enum(["introduced", "carried", "fixed"]);

/**
 * The verdict, as one word.
 *
 * `clean` is a statement about what the turn *introduced*, never about the
 * repository: a clean turn can sit on top of twelve carried findings, and the
 * record says so on the same line.
 */
export const verdictSchema = z.enum(["clean", "blocked"]);

/** The commit the turn was measured against. */
export const turnBaseSchema = z.object({
  /** What the operator asked for, usually `HEAD`. */
  reference: z.string(),
  /**
   * What it resolved to. Absent outside a git repository, where the turn has
   * no anchor — stated rather than defaulted, because a verdict with no base is
   * a verdict about nothing.
   */
  commit: z.string().optional(),
});

/** Counts by state. Present even at zero, so a consumer never special-cases. */
export const turnCountsSchema = z.object({
  introduced: z.number().int().nonnegative(),
  carried: z.number().int().nonnegative(),
  fixed: z.number().int().nonnegative(),
});

/**
 * One finding named without its body.
 *
 * Carried and fixed findings appear only in this form. Rendering them in full
 * would put the reader back in front of the flat list the turn verdict exists
 * to replace.
 */
export const findingRefSchema = z.object({
  id: z.string(),
  severity: severitySchema,
  /** `path:line`, or the probed URL. */
  at: z.string(),
  /** The baseline fingerprint — what a later run matches on. */
  fingerprint: z.string(),
});

/** What the agent execution surface did during the turn. */
export const turnSurfaceSchema = z.object({
  /** `sealed` / `unsealed` / `unchanged` / `moved` / `unreadable`. */
  state: z.string(),
  files: z.number().int().nonnegative(),
  hooks: z.number().int().nonnegative(),
  mcpServers: z.number().int().nonnegative(),
  /** One sentence per semantic change. Empty when the surface held still. */
  changes: z.array(z.string()).default([]),
});

/** The thresholds the verdict was reached under. */
export const turnGateSchema = z.object({
  failOn: severitySchema,
  minConfidence: confidenceSchema,
  failOnExposure: exposureSchema.optional(),
});

/** One turn's verdict. */
export const turnReportSchema = z.object({
  schemaVersion: z.string(),
  tool: z.object({ name: z.string(), version: z.string() }),
  recordedAt: z.string(),
  durationMs: z.number().int().nonnegative(),
  base: turnBaseSchema,
  filesChanged: z.number().int().nonnegative(),
  gate: turnGateSchema,
  verdict: verdictSchema,
  counts: turnCountsSchema,
  /**
   * How many introduced findings met the gate. Never conflated with
   * `counts.introduced`: everything introduced is reported, only this subset
   * blocks, and a `clean` verdict over a non-zero `counts.introduced` is a
   * turn that added something below the threshold.
   */
  blocking: z.number().int().nonnegative(),
  /** The only findings carried in full. */
  introduced: z.array(findingSchema),
  carried: z.array(findingRefSchema).default([]),
  fixed: z.array(findingRefSchema).default([]),
  surface: turnSurfaceSchema.optional(),
  /**
   * Anything that stopped the turn being fully answered. Present and empty
   * rather than absent: a verdict reached over a broken input has to say so.
   */
  notes: z.array(z.string()).default([]),
});

export type TurnState = z.infer<typeof turnStateSchema>;
export type Verdict = z.infer<typeof verdictSchema>;
export type TurnBase = z.infer<typeof turnBaseSchema>;
export type TurnCounts = z.infer<typeof turnCountsSchema>;
export type FindingRef = z.infer<typeof findingRefSchema>;
export type TurnSurface = z.infer<typeof turnSurfaceSchema>;
export type TurnGate = z.infer<typeof turnGateSchema>;
export type TurnReport = z.infer<typeof turnReportSchema>;
