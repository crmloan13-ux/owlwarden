import { confidenceSchema, severitySchema } from "@dointhai/owlwarden-sdk";
import { z } from "zod";

/**
 * The config file schema.
 *
 * Only options the engine actually reads are here. It would be easy to add
 * `target`, `auth`, and `rules[].options` now because the docs describe them,
 * but a key that parses and then does nothing is worse than a missing key: the
 * user configures it, believes it, and is wrong. They arrive with the features.
 *
 * # Why every object here is strict
 *
 * The same argument applies to a key the user *invented*, and it used to fail
 * the other way: zod strips unknown keys by default, so `failon: "high"` parsed
 * cleanly and the run used the default `info`. A config that reads as if it
 * tightens the gate and does not is the one mistake in this file with a
 * security consequence, and it is invisible — there is no output to notice.
 *
 * Strict turns each of those into a refusal at load time, with the near-miss
 * named. The cost is that a config written for a newer owlwarden fails on an
 * older one instead of degrading, which is the right way round: a scanner
 * silently ignoring half its instructions is worse than one that stops.
 */

/** Per-rule overrides. */
export const ruleOverrideSchema = z.strictObject({
  /** Turn the rule off entirely. */
  enabled: z.boolean().optional(),
  /** Report at a different severity than the rule's default. */
  severity: severitySchema.optional(),
});

export const configSchema = z.strictObject({
  /**
   * Rule bundle to run. Unknown names are an error rather than a fallback —
   * a typo silently scanning with fewer rules is the failure mode we care about.
   */
  preset: z.string().default("quick"),

  /** Per-rule overrides, keyed by rule id. */
  rules: z.record(z.string(), ruleOverrideSchema).default({}),

  /** Severity at which findings fail the run. */
  failOn: severitySchema.default("info"),

  /**
   * Findings below this confidence are reported but never fail the run.
   * `likely` is the sensible CI setting; `possible` findings are for a human.
   */
  minConfidence: confidenceSchema.default("possible"),

  /** Default output format. `--format` overrides it. */
  format: z.enum(["pretty", "json", "sarif", "junit", "md"]).default("pretty"),
});

/** The config as written by the user: everything optional. */
export type OwlwardenConfigInput = z.input<typeof configSchema>;

/** The config after defaults are applied. */
export type OwlwardenConfig = z.output<typeof configSchema>;

/**
 * Identity function that gives editors the config type.
 *
 * ```ts
 * // owlwarden.config.ts
 * import { defineConfig } from "@dointhai/owlwarden-config";
 * export default defineConfig({ preset: "owasp-top10", failOn: "medium" });
 * ```
 */
export function defineConfig(config: OwlwardenConfigInput): OwlwardenConfigInput {
  return config;
}
