/**
 * Plugin authoring schemas for the WASM detector host (v0.2).
 *
 * These describe `owlwarden.plugin.json`. They do not load or run plugins —
 * that is `crates/plugin-host`. Validate a manifest here before you ship a
 * `.wasm`, so a typo fails in the author's CI rather than at scan time.
 */

import { z } from "zod";

import { severitySchema } from "./report.js";

/**
 * Capability flags a plugin may declare.
 *
 * Defaults: `source` true (v0.2 is source-only), `network` / `active` false
 * (omitted = not granted). Declaring `network` or `active` fails validation.
 */
export const pluginCapabilitiesSchema = z
  .object({
    source: z.boolean().default(true),
    network: z.boolean().default(false),
    active: z.boolean().default(false),
  })
  .strict();

/** One rule the plugin contributes. */
export const pluginRuleMetaSchema = z
  .object({
    id: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z][a-z0-9-]*$/, "rule id is lowercase, digits, hyphens"),
    title: z.string().min(1).max(200),
    severity: severitySchema,
    /** Source-only plugins cannot declare `confirmed`. */
    maxConfidence: z.enum(["likely", "possible"]),
    owasp: z.string().max(32).optional(),
    cwe: z.number().int().positive().optional(),
    category: z.string().min(1).max(64),
    description: z.string().min(1).max(4_000),
  })
  .strict();

/** Optional pinned WASM artifact digest (ADR 0021). */
export const pluginArtifactSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .max(256)
      .refine(
        (value) => !value.includes("..") && !value.startsWith("/") && !value.includes("\\"),
        "artifact.path must be a relative path without '..'",
      ),
    sha256: z
      .string()
      .length(64)
      .regex(/^[0-9a-fA-F]+$/, "artifact.sha256 must be 64 hex characters"),
  })
  .strict();

/** The manifest that sits next to `plugin.wasm`. */
export const pluginManifestSchema = z
  .object({
    /** Matches `crates/plugin-host` `SCHEMA_VERSION` (integer, not a semver). */
    schemaVersion: z.literal(1),
    id: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z][a-z0-9-]*$/, "plugin id is lowercase, digits, hyphens"),
    version: z.string().min(1).max(64),
    license: z.string().max(64).optional(),
    artifact: pluginArtifactSchema.optional(),
    capabilities: pluginCapabilitiesSchema,
    rules: z.array(pluginRuleMetaSchema).min(1).max(64),
  })
  .strict()
  .superRefine((manifest, ctx) => {
    // v0.2 host is source-only. Catch over-declared capabilities at author time.
    if (manifest.capabilities.network || manifest.capabilities.active) {
      ctx.addIssue({
        code: "custom",
        message:
          "v0.2 plugin-host is source-only; set capabilities.network and capabilities.active to false",
        path: ["capabilities"],
      });
    }
    const prefix = `${manifest.id}-`;
    for (const [index, rule] of manifest.rules.entries()) {
      if (!rule.id.startsWith(prefix)) {
        ctx.addIssue({
          code: "custom",
          message: `rule id must start with "${prefix}" so it cannot collide with built-in rules`,
          path: ["rules", index, "id"],
        });
      }
    }
  });

export type PluginManifest = z.infer<typeof pluginManifestSchema>;
export type PluginArtifact = z.infer<typeof pluginArtifactSchema>;
export type PluginRuleMeta = z.infer<typeof pluginRuleMetaSchema>;
export type PluginCapabilities = z.infer<typeof pluginCapabilitiesSchema>;
