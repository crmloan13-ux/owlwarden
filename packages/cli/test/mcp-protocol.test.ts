import { Readable, Writable } from "node:stream";

import { describe, expect, it } from "vitest";

import { serveMcp } from "../src/mcp/protocol.js";

/** Drive serveMcp with a scripted stdin and capture stdout lines. */
async function exchange(
  lines: string[],
  handlers: Parameters<typeof serveMcp>[0]["handlers"] = {},
): Promise<unknown[]> {
  const stdin = Readable.from(lines.map((l) => `${l}\n`));
  const out: string[] = [];
  const stdout = new Writable({
    write(chunk: Buffer | string, _enc, cb) {
      out.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
      cb();
    },
  });

  await serveMcp({
    name: "owlwarden-test",
    version: "0.0.0",
    tools: [
      {
        name: "ping_tool",
        description: "test",
        inputSchema: { type: "object", properties: {} },
      },
    ],
    handlers: {
      ping_tool: () =>
        Promise.resolve({
          content: [{ type: "text" as const, text: "pong" }],
        }),
      ...handlers,
    },
    stdin,
    stdout,
  });

  return out
    .join("")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as unknown);
}

describe("serveMcp", () => {
  it("answers initialize and lists tools", async () => {
    const replies = await exchange([
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {},
      }),
      JSON.stringify({
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    ]);

    expect(replies).toHaveLength(2);
    const init = replies[0] as {
      result: { serverInfo: { name: string }; protocolVersion: string };
    };
    expect(init.result.serverInfo.name).toBe("owlwarden-test");
    expect(init.result.protocolVersion).toBe("2024-11-05");

    const list = replies[1] as { result: { tools: Array<{ name: string }> } };
    expect(list.result.tools.map((t) => t.name)).toContain("ping_tool");
  });

  it("calls a tool and returns its content", async () => {
    const replies = await exchange([
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "ping_tool", arguments: {} },
      }),
    ]);
    const call = replies[0] as {
      result: { content: Array<{ text: string }> };
    };
    expect(call.result.content[0]?.text).toBe("pong");
  });

  it("errors on an unknown tool without crashing the loop", async () => {
    const replies = await exchange([
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "nope" },
      }),
      JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
    ]);
    const err = replies[0] as { error: { message: string } };
    expect(err.error.message).toMatch(/unknown tool/);
    expect(replies[1]).toMatchObject({ id: 2, result: {} });
  });
});
