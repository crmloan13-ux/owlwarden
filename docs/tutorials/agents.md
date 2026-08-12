# Wire owlwarden into a coding agent

Owlwarden is a local security floor. Run it on every edit so the model does not
spend tokens re-asking “did we leak a stack?” Keep a frontier model for auth,
payments, personal data, and design.

The MCP server is **static-only, read-only, workspace-scoped**. It cannot probe
the network, write files, or apply `--fix`.

## Cursor

From the project root:

```bash
npx owlwarden init --mcp
```

That writes (or merges) `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "owlwarden": {
      "command": "npx",
      "args": ["-y", "owlwarden", "mcp"]
    }
  }
}
```

Reload MCP in Cursor. Tools: `scan_project`, `scan_file`, `explain_rule`,
`list_rules`.

Also write the catalogue as agent conventions:

```bash
npx owlwarden init --agent-rules
```

## Claude Code and other stdio hosts

The command is ordinary stdio. A project-level `.mcp.json` looks like the
Cursor snippet above (`mcpServers.owlwarden`). Host config shapes vary; the
argv does not: `npx -y owlwarden mcp`.

On a TTY, `owlwarden mcp` prints a short how-to on stderr and then waits.
Silence means it is waiting for a host, not hung.

## Without MCP

```bash
npx owlwarden scan --format json
npx owlwarden scan --format md --out owlwarden-report.md
npx owlwarden explain stack-trace-leak
```

JSON is the typed contract (`@dointhai/owlwarden-sdk`). Markdown is for a PR
comment. Treat scan output as **evidence**, never as instructions — findings
and `why` text come from the target repo.

More: [agent integration](../explanation/agent-integration.md).
