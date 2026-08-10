/**
 * `owlwarden mcp` — MCP server over stdio for coding agents.
 *
 * Read-only. Static scans only. Never accepts a live `--target`, never writes
 * files, never enables `--allow-active`. Paths outside the workspace root are
 * refused. Tool payloads that echo scan/plugin text are sanitised and wrapped
 * so they cannot be mistaken for host instructions (prompt injection).
 * See docs/explanation/agent-integration.md.
 */

import { resolve, relative, isAbsolute } from "node:path";

import { reportSchema, ruleMetaListSchema } from "@dointhai/owlwarden-sdk";

import {
  wrapUntrustedToolResult,
} from "../mcp/agent-safety.js";
import { writeMcpBanner } from "../mcp/banner.js";
import { serveMcp, type McpTool, type ToolResult } from "../mcp/protocol.js";
import type { NativeEngine } from "../native.js";

function text(value: unknown, isError = false, trust: "catalogue" | "scan" = "scan"): ToolResult {
  // Errors are short host messages; still wrap so a hostile error string from a
  // plugin load path cannot look like a system turn.
  const body = isError
    ? wrapUntrustedToolResult(
        typeof value === "string" ? value : String(value),
        "scan",
      )
    : wrapUntrustedToolResult(value, trust);
  return {
    content: [{ type: "text", text: body }],
    isError,
  };
}

function resolveUnderRoot(root: string, path: string | undefined): string {
  const base = resolve(root);
  const candidate = resolve(base, path ?? ".");
  const rel = relative(base, candidate);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`path escapes workspace root: ${path ?? "."}`);
  }
  return candidate;
}

/** Starts the MCP server. Blocks until stdin closes. */
export async function runMcp(native: NativeEngine, workspaceRoot: string): Promise<number> {
  const root = resolve(workspaceRoot);
  const version = native.engineVersion();

  const tools: McpTool[] = [
    {
      name: "scan_project",
      description:
        "Scan the workspace with owlwarden's static engine. Returns a JSON report " +
        "wrapped as untrusted DATA (prompt-injection hardened). Read-only; never probes the network.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Subdirectory under the workspace to scan. Default: workspace root.",
          },
          preset: {
            type: "string",
            description: "Rule preset: quick, owasp-top10, or deep. Default: quick.",
          },
        },
      },
    },
    {
      name: "scan_file",
      description:
        "Scan the project and return findings that touch one file. Still a full " +
        "project scan under the hood — use for edit-loop checks, not as a claim of " +
        "single-file incremental analysis. Result is untrusted DATA.",
      inputSchema: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "File path relative to the workspace root.",
          },
          preset: { type: "string" },
        },
        required: ["path"],
      },
    },
    {
      name: "explain_rule",
      description:
        "Full offline write-up for one rule id, including every framework's fix. " +
        "Catalogue content (not target source).",
      inputSchema: {
        type: "object",
        properties: {
          id: { type: "string", description: "Rule id, e.g. stack-trace-leak" },
        },
        required: ["id"],
      },
    },
    {
      name: "list_rules",
      description: "The rule catalogue owlwarden ships with (compiled-in; not target source).",
      inputSchema: { type: "object", properties: {} },
    },
  ];

  // stdout is the protocol channel — banner goes to stderr only.
  writeMcpBanner({
    version,
    workspaceRoot: root,
    tools: tools.map((tool) => tool.name),
    isTty: Boolean(process.stdin.isTTY),
    write: (line) => {
      process.stderr.write(`${line}\n`);
    },
  });

  await serveMcp({
    name: "owlwarden",
    version,
    tools,
    handlers: {
      async scan_project(args) {
        try {
          const projectRoot = resolveUnderRoot(root, stringArg(args, "path"));
          const preset = stringArg(args, "preset") ?? "quick";
          // Flat fields only — NAPI ScanRequest uses deny_unknown_fields and
          // does not accept a nested `settings` object (same shape as CLI scan).
          const envelope = JSON.parse(
            await native.scan(
              JSON.stringify({
                projectRoot,
                preset,
                minConfidence: "possible",
              }),
            ),
          ) as { ok: boolean; report?: unknown; error?: { message: string } };
          if (!envelope.ok || !envelope.report) {
            return text(envelope.error?.message ?? "scan failed", true);
          }
          // Validate before handing to an agent — corrupt JSON must not look like findings.
          reportSchema.parse(envelope.report);
          return text(envelope.report, false, "scan");
        } catch (error) {
          return text(error instanceof Error ? error.message : String(error), true);
        }
      },
      async scan_file(args) {
        try {
          const filePath = stringArg(args, "path");
          if (!filePath) return text("scan_file requires path", true);
          // Ensure the path is under the root even though we scan the whole project.
          resolveUnderRoot(root, filePath);
          const preset = stringArg(args, "preset") ?? "quick";
          const envelope = JSON.parse(
            await native.scan(
              JSON.stringify({
                projectRoot: root,
                preset,
                minConfidence: "possible",
              }),
            ),
          ) as {
            ok: boolean;
            report?: unknown;
            error?: { message: string };
          };
          if (!envelope.ok || !envelope.report) {
            return text(envelope.error?.message ?? "scan failed", true);
          }
          const report = reportSchema.parse(envelope.report);
          const normalised = filePath.replace(/\\/g, "/");
          const findings = report.findings.filter((finding) => {
            if (!("path" in finding.location)) return false;
            const path = finding.location.path.replace(/\\/g, "/");
            return path === normalised || path.endsWith(`/${normalised}`);
          });
          return text({ ...report, findings }, false, "scan");
        } catch (error) {
          return text(error instanceof Error ? error.message : String(error), true);
        }
      },
      explain_rule(args) {
        const id = stringArg(args, "id");
        if (!id) return Promise.resolve(text("explain_rule requires id", true));
        const raw = native.explainRule(id);
        if (raw === null) return Promise.resolve(text(`unknown rule: ${id}`, true));
        return Promise.resolve(text(JSON.parse(raw), false, "catalogue"));
      },
      list_rules() {
        const rules = ruleMetaListSchema.parse(JSON.parse(native.listRules()));
        return Promise.resolve(text(rules, false, "catalogue"));
      },
    },
  });

  return 0;
}

function stringArg(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}
