# Upgrade to 1.0

1.0 freezes the plugin API and the report schema. Rule ids, exit codes, and
`--format json` are unchanged from 0.5.

## Install

```bash
npm i -D owlwarden@1
```

Pin the GitHub Action to a 1.x tag:

```yaml
- uses: suthat/owlwarden/action@v1.0.0
```

Re-generate generated files so they match this engine:

```bash
npx owlwarden init --force
```

`--force` replaces owlwarden-generated files **and** a user-owned workflow /
MCP entry with the same path. Diff before you commit.

## What 1.0 adds

- `owlwarden init` with no flags writes the adoption kit (agent-rules, GitHub
  Action workflow, Cursor MCP config). `--agent-rules` still works alone.
- `--format md` — Markdown for PR comments. Repeatable with other formats.
- Plugin API v1 is frozen. `schemaVersion: 1` stays 1; breaking changes go
  through an [RFC](../rfc/README.md).

## What did not break

- Report JSON `schemaVersion` remains `"1.0"`.
- Exit codes remain 0 / 1 / 2.
- Rule ids are not renamed.
- MCP tools are still `scan_project`, `scan_file`, `explain_rule`, `list_rules`.
- Plugins remain source-only WASM. Manifests that already load on 0.5 load on
  1.0.

## Config

`format` in `owlwarden.config.json` may now be `md`. Other keys are unchanged.
`--target` / `--scope` are still never read from project config.
