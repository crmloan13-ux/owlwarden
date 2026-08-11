import { confidenceSchema, severitySchema } from "@dointhai/owlwarden-sdk";
import { z } from "zod";

/**
 * The config file schema.
 *
 * Only options the engine actually reads are here. It would be easy to add
 * `target`, `auth`, and `rules[].options` now because the docs describe them,
 * but a key that parses and then does nothing is worse than a missing key: the
 * user configures it, believes it, and is wrong. They arrive with the features.
 */

/** Per-rule overrides. */
export const ruleOverrideSchema = z.object({
  /** Turn the rule off entirely. */
  enabled: z.boolean().optional(),
  /** Report at a different severity than the rule's default. */
  severity: severitySchema.optional(),
});

export const configSchema = z.object({
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
  format: z.enum(["pretty", "json", "sarif", "junit"]).default("pretty"),
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
