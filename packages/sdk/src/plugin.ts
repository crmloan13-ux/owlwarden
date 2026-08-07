/**
 * Plugin authoring schemas for the WASM detector host (v0.2).
 *
 * These describe `owlwarden.plugin.json`. They do not load or run plugins —
 * that is `crates/plugin-host`. Validate a manifest here before you ship a
 * `.wasm`, so a typo fails in the author's CI rather than at scan time.
 */

import { z } from "zod";

import { confidenceSchema, severitySchema } from "./report.js";

/** Capability flags a plugin may declare. Undeclared = not granted. */
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
    maxConfidence: confidenceSchema,
    owasp: z.string().max(32).optional(),
    cwe: z.number().int().positive().optional(),
    category: z.string().min(1).max(64),
    description: z.string().min(1).max(4_000),
  })
  .strict();

/** The manifest that sits next to `plugin.wasm`. */
export const pluginManifestSchema = z
  .object({
    schemaVersion: z.literal("0.1"),
    id: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[a-z][a-z0-9-]*$/, "plugin id is lowercase, digits, hyphens"),
    version: z.string().min(1).max(64),
    license: z.string().max(64).optional(),
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
  });

export type PluginManifest = z.infer<typeof pluginManifestSchema>;
export type PluginRuleMeta = z.infer<typeof pluginRuleMetaSchema>;
export type PluginCapabilities = z.infer<typeof pluginCapabilitiesSchema>;
