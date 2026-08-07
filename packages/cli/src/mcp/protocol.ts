/**
 * A tiny MCP (Model Context Protocol) subset over stdio.
 *
 * Only what owlwarden needs: `initialize`, `tools/list`, `tools/call`, and the
 * `notifications/initialized` handshake. Hand-written on purpose — a security
 * CLI should not pull a large protocol SDK to expose four read-only tools
 * (ADR 0009). The wire format matches the MCP JSON-RPC shape hosts expect.
 *
 * stdout is the protocol channel. Log only to stderr.
 */

import { createInterface } from "node:readline";

/**
 * Largest JSON-RPC line accepted on stdin. An MCP host that floods gigabyte
 * lines must not take the owlwarden process down with it (NASA Power of 10:
 * bound every loop / allocation over external data).
 */
export const MAX_MCP_LINE_BYTES = 4 * 1024 * 1024;

/** A JSON-RPC 2.0 request from the host. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

/** One MCP tool descriptor. */
export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

/** Result of a tool call. */
export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

type ToolHandler = (args: Record<string, unknown>) => Promise<ToolResult>;

/**
 * Serves MCP tools over stdin/stdout until the stream closes.
 *
 * Unknown methods get a JSON-RPC error. Notifications (no `id`) are answered
 * with silence.
 */
export async function serveMcp(options: {
  name: string;
  version: string;
  tools: McpTool[];
  handlers: Record<string, ToolHandler>;
  stdin?: NodeJS.ReadableStream;
  stdout?: NodeJS.WritableStream;
}): Promise<void> {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;
  const rl = createInterface({ input: stdin, crlfDelay: Infinity });

  const write = (message: unknown): void => {
    stdout.write(`${JSON.stringify(message)}\n`);
  };

  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    if (Buffer.byteLength(trimmed, "utf8") > MAX_MCP_LINE_BYTES) {
      write({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: `parse error: line exceeds ${MAX_MCP_LINE_BYTES} bytes`,
        },
      });
      continue;
    }

    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      write({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "parse error" },
      });
      continue;
    }

    if (request.jsonrpc !== "2.0" || typeof request.method !== "string") {
      if (request.id !== undefined && request.id !== null) {
        write({
          jsonrpc: "2.0",
          id: request.id,
          error: { code: -32600, message: "invalid request" },
        });
      }
      continue;
    }

    // Notifications have no id — acknowledge by doing the work, no reply.
    const isNotification = request.id === undefined || request.id === null;

    try {
      const result = await dispatch(request, options);
      if (!isNotification) {
        write({ jsonrpc: "2.0", id: request.id, result });
      }
    } catch (error) {
      if (!isNotification) {
        write({
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32000,
            message: error instanceof Error ? error.message : String(error),
          },
        });
      }
    }
  }
}

async function dispatch(
  request: JsonRpcRequest,
  options: {
    name: string;
    version: string;
    tools: McpTool[];
    handlers: Record<string, ToolHandler>;
  },
): Promise<unknown> {
  switch (request.method) {
    case "initialize":
      return {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: options.name, version: options.version },
      };
    case "notifications/initialized":
    case "initialized":
      return {};
    case "ping":
      return {};
    case "tools/list":
      return { tools: options.tools };
    case "tools/call": {
      const params = (request.params ?? {}) as {
        name?: string;
        arguments?: Record<string, unknown>;
      };
      const name = params.name;
      if (!name || typeof name !== "string") {
        throw new Error("tools/call requires params.name");
      }
      const handler = options.handlers[name];
      if (!handler) {
        throw new Error(`unknown tool: ${name}`);
      }
      const args =
        params.arguments && typeof params.arguments === "object"
          ? params.arguments
          : {};
      return handler(args);
    }
    default:
      throw new Error(`method not found: ${request.method}`);
  }
}
