# Where people find owlwarden

1.0 is stable. Downloads come from being in the places people already look,
not from another rule. This is the maintainer checklist after a 1.0 tag.

Do not invent testimonials or download counts. List it, then let the product
talk.

## Ship in-tree first (done in 1.0)

- `npx owlwarden scan` / `npx owlwarden init` / `npx owlwarden mcp`
- npm README, site, `llms.txt`, MCP `server.json`
- GitHub Action at `suthat/owlwarden/action`

## Submit after the tag (human; needs an account)

| Place | Why it matters | What to submit |
|---|---|---|
| [npm](https://www.npmjs.com/package/owlwarden) | `npx` is the first run | Publish via the release workflow |
| [MCP registry](https://github.com/modelcontextprotocol/registry) | Agents look here for servers | `mcp/server.json` |
| [cursor.directory](https://cursor.directory) | Cursor users searching MCP | `npx -y owlwarden mcp` |
| GitHub Action marketplace | CI copy-paste | `action/` (already branded) |
| [awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | Discovery list | One-line: local SAST, read-only MCP |
| Show HN / r/node / r/cursor | First-week attention | Pitch: local floor, fix in the finding, MCP |

## Pitch (keep it this short)

Local-first security scanner for Node web apps and coding agents. Rust engine,
npm install, no telemetry. The finding is the line, an honest confidence
level, and a framework-specific fix. `npx owlwarden scan`.

Do not claim OWASP coverage you do not have. Point at `owlwarden coverage`.
