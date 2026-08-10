/**
 * Startup messages for `owlwarden mcp`.
 *
 * stdout is the JSON-RPC channel — never write prose there. Humans who run
 * the command on a TTY need a how-to on stderr; MCP hosts get a one-line ready
 * notice so logs show the server actually started.
 */

export interface McpBannerOptions {
  version: string;
  workspaceRoot: string;
  tools: string[];
  /** When true, print the interactive how-to (human ran it in a terminal). */
  isTty: boolean;
  write: (line: string) => void;
}

/** Writes the MCP startup banner to the supplied sink (normally stderr). */
export function writeMcpBanner(options: McpBannerOptions): void {
  const { version, workspaceRoot, tools, isTty, write } = options;
  const toolList = tools.join(", ");

  if (isTty) {
    write(`owlwarden mcp ${version}`);
    write(`workspace: ${workspaceRoot}`);
    write(`tools: ${toolList}`);
    write("");
    write("This process speaks MCP over stdio. Silence on the terminal is normal —");
    write("it is waiting for an MCP host (Cursor, Claude Code, etc.), not hung.");
    write("");
    write("Wire it into a host, for example:");
    write("");
    write("  {");
    write('    "mcpServers": {');
    write('      "owlwarden": {');
    write('        "command": "npx",');
    write('        "args": ["owlwarden", "mcp", "."]');
    write("      }");
    write("    }");
    write("  }");
    write("");
    write("Then call tools: scan_project, scan_file, explain_rule, list_rules.");
    write("Static and read-only — no --target, no file writes.");
    write("Press Ctrl+C to stop.");
    return;
  }

  write(
    `owlwarden mcp ${version} ready (stdio) workspace=${workspaceRoot} tools=${toolList}`,
  );
}
