import { describe, expect, it } from "vitest";

import { pluginManifestSchema } from "../src/plugin.js";

describe("pluginManifestSchema", () => {
  it("accepts a source-only manifest with namespaced rules", () => {
    const parsed = pluginManifestSchema.parse({
      schemaVersion: 1,
      id: "acme-extra",
      version: "0.1.0",
      capabilities: { source: true, network: false, active: false },
      rules: [
        {
          id: "acme-extra-no-eval",
          title: "eval is forbidden",
          severity: "high",
          maxConfidence: "likely",
          category: "injection",
          description: "Direct eval of caller input.",
        },
      ],
    });
    expect(parsed.id).toBe("acme-extra");
  });

  it("accepts optional artifact digest metadata", () => {
    const parsed = pluginManifestSchema.parse({
      schemaVersion: 1,
      id: "acme-extra",
      version: "0.1.0",
      artifact: {
        path: "plugin.wasm",
        sha256: "a".repeat(64),
      },
      capabilities: { source: true, network: false, active: false },
      rules: [
        {
          id: "acme-extra-no-eval",
          title: "eval is forbidden",
          severity: "high",
          maxConfidence: "likely",
          category: "injection",
          description: "Direct eval of caller input.",
        },
      ],
    });
    expect(parsed.artifact?.path).toBe("plugin.wasm");
  });

  it("rejects network or active capabilities in v0.2", () => {
    const result = pluginManifestSchema.safeParse({
      schemaVersion: 1,
      id: "acme-net",
      version: "0.1.0",
      capabilities: { source: true, network: true, active: false },
      rules: [
        {
          id: "acme-net-ping",
          title: "ping",
          severity: "low",
          maxConfidence: "possible",
          category: "other",
          description: "Would need the network.",
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it("rejects a rule id that is not namespaced under the plugin id", () => {
    const result = pluginManifestSchema.safeParse({
      schemaVersion: 1,
      id: "acme-extra",
      version: "0.1.0",
      capabilities: { source: true, network: false, active: false },
      rules: [
        {
          id: "stack-trace-leak",
          title: "spoof",
          severity: "high",
          maxConfidence: "likely",
          category: "spoof",
          description: "Must not collide with a built-in id.",
        },
      ],
    });
    expect(result.success).toBe(false);
  });

  it("rejects confirmed maxConfidence for source-only plugins", () => {
    const result = pluginManifestSchema.safeParse({
      schemaVersion: 1,
      id: "acme-extra",
      version: "0.1.0",
      capabilities: { source: true, network: false, active: false },
      rules: [
        {
          id: "acme-extra-thing",
          title: "thing",
          severity: "low",
          maxConfidence: "confirmed",
          category: "other",
          description: "Cannot be confirmed without a live probe.",
        },
      ],
    });
    expect(result.success).toBe(false);
  });
});
