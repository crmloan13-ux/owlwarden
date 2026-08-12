# Compared with other scanners

Owlwarden is a **local security floor for Node web apps and coding agents**.
It is not a replacement for a design review, a pentest, or a commercial AppSec
platform. Use this page to decide whether it is the right floor, not to rank
tools in the abstract.

| | Owlwarden | ESLint security plugins | Semgrep | npm audit / OSV-only | Cloud AppSec (Snyk, etc.) |
|---|---|---|---|---|---|
| Runs offline by default | Yes | Yes | Yes (engine) | Needs a database | No |
| Telemetry / account | None | None | Optional cloud | Registry | Account |
| Framework-specific fix in the finding | Yes (12 Node stacks) | Rarely | Sometimes | No | Varies |
| Confidence separate from severity | Yes | No | Partial | No | Varies |
| MCP for agents | First-class, read-only | No | Separate | No | Vendor-specific |
| Languages | JS/TS web apps | JS | Many | Lockfile | Many |
| OWASP coverage claim | Published gaps (`coverage`) | Plugin-dependent | Rule-pack dependent | A06-shaped | Marketing-dependent |

## When to use owlwarden

- You ship Next.js, Nuxt, Nest, Express, Fastify, Hono, or another named
  stack, and you want the fix for *that* stack in the finding.
- An agent is in the edit loop and must not treat guesses as facts.
- CI must stay local: SARIF/JUnit, exit 0/1/2, no SaaS mute switch.

## When to use something else (as well)

- **Polyglot monorepo** — Semgrep or a commercial SAST for the non-JS sides.
- **Lockfile CVEs only** — `npm audit` or owlwarden's own `--osv` / `--osv-db`.
- **Authenticated, business-logic, or design flaws** — humans. Owlwarden marks
  OWASP A04 out of reach on purpose.

Running two floors is fine. Owlwarden is built to be the one you do not turn
off because it shouted.
