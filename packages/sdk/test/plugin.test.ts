import { describe, expect, it } from "vitest";

import { pluginManifestSchema } from "../src/plugin.js";

describe("pluginManifestSchema", () => {
  it("accepts a source-only manifest", () => {
    const parsed = pluginManifestSchema.parse({
      schemaVersion: "0.1",
      id: "acme-extra",
      version: "0.1.0",
      capabilities: { source: true, network: false, active: false },
      rules: [
        {
          id: "acme-no-eval",
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

  it("rejects network or active capabilities in v0.2", () => {
    const result = pluginManifestSchema.safeParse({
      schemaVersion: "0.1",
      id: "acme-net",
      version: "0.1.0",
      capabilities: { source: true, network: true, active: false },
      rules: [
        {
          id: "acme-ping",
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
});
