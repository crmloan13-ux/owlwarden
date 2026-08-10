import { describe, expect, it } from "vitest";

import { writeMcpBanner } from "../src/mcp/banner.js";

describe("writeMcpBanner", () => {
  it("prints an interactive how-to on a TTY and never looks like JSON-RPC", () => {
    const lines: string[] = [];
    writeMcpBanner({
      version: "0.2.1",
      workspaceRoot: "/tmp/project",
      tools: ["scan_project", "list_rules"],
      isTty: true,
      write: (line) => lines.push(line),
    });
    const text = lines.join("\n");
    expect(text).toContain("Silence on the terminal is normal");
    expect(text).toContain("mcpServers");
    expect(text).toContain("Press Ctrl+C to stop");
    expect(text).toContain("/tmp/project");
    expect(text).not.toMatch(/^\s*\{/);
    expect(text).not.toContain("jsonrpc");
  });

  it("prints a one-line ready notice for non-TTY hosts", () => {
    const lines: string[] = [];
    writeMcpBanner({
      version: "0.2.1",
      workspaceRoot: "/tmp/project",
      tools: ["scan_project"],
      isTty: false,
      write: (line) => lines.push(line),
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("ready (stdio)");
    expect(lines[0]).toContain("scan_project");
    expect(lines[0]).not.toContain("jsonrpc");
  });
});
