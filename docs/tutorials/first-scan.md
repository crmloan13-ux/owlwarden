# First scan in five minutes

You have a Node web app. You want to know whether owlwarden finds anything,
without wiring CI or an editor yet.

## 1. Run it

From the project root:

```bash
npx owlwarden@1 scan
```

No account. No upload. The default scan reads the tree and does not touch the
network. Node 20+ is enough; you do not need a Rust compiler.

## 2. Read one finding

A finding is the line, how sure owlwarden is, why it matters, and a fix written
for the framework it detected. You should not need another tab.

- **Severity** is impact if the finding is real (`high` / `medium` / `low`).
- **Confidence** is how strong the evidence is (`confirmed` / `likely` /
  `possible`). Static analysis cannot claim `confirmed`. `possible` stays
  visible and does not fail CI on its own.

If the output is empty, that means nothing in the catalogue fired. It does not
mean the app is secure. Run `npx owlwarden coverage` to see the published gaps.

## 3. Keep it

```bash
npm i -D owlwarden
npx owlwarden init
```

`init` with no flags writes three files:

| File | Why |
|---|---|
| `.owlwarden/agent-rules.md` | Catalogue as conventions an agent can load |
| `.github/workflows/owlwarden.yml` | PR gate (SARIF → GitHub code scanning) |
| `.cursor/mcp.json` | Cursor MCP entry (`npx owlwarden mcp`) |

Existing files that owlwarden did not generate are left alone. Pass `--force`
only when you intend to replace them.

Next: [wire it into an agent](agents.md), or
[CI](../how-to/ci.md).
