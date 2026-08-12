# Documentation

| I want to… | Read |
|---|---|
| install it and run a first scan | [tutorials/first-scan.md](tutorials/first-scan.md) |
| wire it into Cursor / Claude / MCP | [tutorials/agents.md](tutorials/agents.md) |
| know what it can find | [RULES.md](../RULES.md), or `owlwarden rules` |
| know what it **cannot** find | [explanation/coverage.md](explanation/coverage.md), or `owlwarden coverage` |
| decide if it replaces another scanner | [explanation/compared.md](explanation/compared.md) |
| add a framework, a rule, or a plugin | [how-to/extend.md](how-to/extend.md), [how-to/plugins.md](how-to/plugins.md) |
| look up a flag | [reference/cli.md](reference/cli.md) |
| target plugin API v1 | [reference/plugin-api.md](reference/plugin-api.md) |
| upgrade from 0.x | [how-to/upgrade.md](how-to/upgrade.md) |
| wire it into CI (Action, SARIF, exit codes) | [how-to/ci.md](how-to/ci.md) |
| measure cold-scan performance | [how-to/performance.md](how-to/performance.md) |
| probe a running app (`--target`) | [how-to/dynamic.md](how-to/dynamic.md) |
| look up known vulns in lockfiles (`--osv`) | [how-to/osv.md](how-to/osv.md) |
| apply Safe autofixes (`--fix`) | [how-to/fix.md](how-to/fix.md) |
| suppress a finding or adopt with a baseline | [how-to/suppressions.md](how-to/suppressions.md) |
| decode an engine error code | [reference/errors.md](reference/errors.md) |
| understand why a finding says "possible" | [explanation/false-positives.md](explanation/false-positives.md) |
| use owlwarden from an AI agent | [explanation/agent-integration.md](explanation/agent-integration.md) |
| list it where people look | [how-to/discover.md](how-to/discover.md) |
| know what a given output format guarantees | [REPORTERS.md](../REPORTERS.md) |
| know how the engine is put together | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| know why a decision was made | [adr/](adr/), or [REVIEW.md](../REVIEW.md) for the ones made before v0.0 |
| report a vulnerability | [SECURITY.md](../SECURITY.md) |
| contribute | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| contribute as an AI coding agent | [AGENTS.md](../AGENTS.md) |

The rule catalogue is generated from the engine
(`node scripts/generate-rules-md.mjs`), so it cannot describe a rule that does
not exist. Everything else here is written by hand.
