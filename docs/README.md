# Documentation

| I want to… | Read |
|---|---|
| install it and run a first scan | [README](../README.md) |
| know what it can find | [RULES.md](../RULES.md), or `owlwarden rules` |
| know what it **cannot** find | [explanation/coverage.md](explanation/coverage.md), or `owlwarden coverage` |
| add a framework, a rule, or a plugin | [how-to/extend.md](how-to/extend.md) |
| wire it into CI | [how-to/ci.md](how-to/ci.md) |
| probe a running app (`--target`) | [how-to/dynamic.md](how-to/dynamic.md) |
| look up known vulns in lockfiles (`--osv`) | [how-to/osv.md](how-to/osv.md) |
| apply Safe autofixes (`--fix`) | [how-to/fix.md](how-to/fix.md) |
| suppress a finding or adopt with a baseline | [how-to/suppressions.md](how-to/suppressions.md) |
| decode an engine error code | [reference/errors.md](reference/errors.md) |
| understand why a finding says "possible" | [explanation/false-positives.md](explanation/false-positives.md) |
| use owlwarden from an AI agent | [explanation/agent-integration.md](explanation/agent-integration.md) |
| know what a given output format guarantees | [REPORTERS.md](../REPORTERS.md) |
| know how the engine is put together | [ARCHITECTURE.md](../ARCHITECTURE.md) |
| know why a decision was made | [adr/](adr/), or [REVIEW.md](../REVIEW.md) for the ones made before v0.0 |
| report a vulnerability | [SECURITY.md](../SECURITY.md) |
| contribute | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| contribute as an AI coding agent | [AGENTS.md](../AGENTS.md) |

The rule catalogue is generated from the engine
(`node scripts/generate-rules-md.mjs`), so it cannot describe a rule that does
not exist. Everything else here is written by hand.
