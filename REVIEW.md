# Design review, before implementation

An adversarial read of the original design documents, done before any code was
written. The question asked of every claim was: *could a team actually build
this, and would the result be worth installing?*

It is kept in the repository because the answer to the first item was **no** —
the architecture as specified could not produce the output the same documents
promised — and the reasoning behind that reversal explains the shape of the code
better than the finished design does. A record of what was wrong is more useful
than a document that only ever describes what is right.

Each item below is followed by where it ended up. Where a review conclusion was
itself later revised by implementation, that is recorded too.

---

## B1 — The architecture could not produce its own flagship output

**Blocking.** The architecture described a purely *dynamic* scanner: a
`Transport` port, a scope allowlist, routes, HTTP requests. The output
specification, meanwhile, showed a source code frame:

```
 app/api/users/route.ts:15
  15 │       { error: err.stack },
     │               ~~~~~~~~~ leaks internal stack trace to the client
```

Nothing in the described core can produce that. An HTTP response tells you a
stack trace leaked; it does not tell you the file, the line, or the expression
responsible. Those come from reading source. The design specified a dynamic
engine and a static user experience.

**Resolution — the dual-engine model.** Two analysis engines over one finding
model:

| Engine | Input | Answers |
|---|---|---|
| Static | source files and their AST | where in my code the problem is |
| Dynamic | live HTTP responses | what the server actually does |
| Correlated | both | confirmed at runtime, with the line that causes it |

Correlation is what makes "runtime-confirmed, and here is the line to change"
possible, and it is where `Confirmed` confidence comes from. Static analysis is
passive by definition, so the static engine ships first and carries no scanning
risk.

Parsing uses [oxc](https://oxc.rs) rather than a hand-written parser.

→ [ADR 0001](docs/adr/0001-dual-engine.md). Built in v0.0 (static half).

**Later revised.** This review proposed adding a `SourceProvider` port with an
`ast()` method next to `Transport`:

```rust
pub trait SourceProvider: Send + Sync {
    fn files(&self, glob: &Glob) -> Result<Vec<SourceFile>, SourceError>;
    fn ast(&self, file: &SourceFile) -> Result<Ast, ParseError>;   // ← unbuildable
}
```

Implementation showed `ast()` cannot exist. oxc allocates its AST in an arena
and every node borrows from it, so returning one across a trait boundary means
either a self-referential type or a lifetime parameter that spreads through
everything it touches — and it would re-parse each file once per detector. The
port now serves bytes, and parsing lives in the static engine, which parses each
file once and fans the result out to every interested rule.

→ [ADR 0004](docs/adr/0004-source-provider-has-no-ast.md).

## H1 — No strategy for false positives

**High.** The design had no confidence model, no suppression mechanism, and
mentioned baselines only in passing. A tool that flags correct code gets
switched off, and everything it would have caught goes with it. Three additions:

- **`Finding.confidence`** — `Confirmed | Likely | Possible`. Reporters show it,
  `--min-confidence` filters on it, and a `Possible` finding never fails a build
  on its own. Never present a guess as a fact.
- **Inline suppression with a required reason.** The reason is what stops
  suppression from becoming a silent blanket, because it is what a reviewer
  reads in the diff. `--report-suppressions` lists them and flags stale ones.
- **Baseline moved forward** from much later. Adopting the tool on an
  existing codebase without it is not realistic.
- **A false-positive corpus in CI** — a tree of *correct* code under
  `fixtures/should-not-fire/`. Anything that fires there fails the build.
  Precision becomes a tested property rather than a hope.

→ Confidence shipped in v0.0 ([ADR 0006](docs/adr/0006-confidence-in-the-model.md)),
along with the corpus. Suppression and baseline shipped in 0.0.2
([ADR 0013](docs/adr/0013-suppressions-and-baseline.md)); the dynamic half of
v0.1 (runtime confirmation) is still ahead.

## H2 — Nothing addressed AI-generated code

**High.** A stated goal was raising the security bar for code written with AI
assistance, but nothing in the design served that case. An agent reads a report
and edits; a human reads a report, thinks, and edits. Those want different
output.

The practical requirements that fell out: machine-readable output with the fix
inline, honest confidence (an agent has no prior with which to doubt a
confident-sounding report), single-file scans fast enough for an edit loop, and
an MCP surface that is read-only and cannot trigger network probes as a side
effect.

→ [docs/explanation/agent-integration.md](docs/explanation/agent-integration.md).
JSON output and `explain` shipped in v0.0; the MCP server is v0.2.

## H3 — The design stopped at the CLI

**High.** There was no account of how anyone other than the original author
would use or contribute to the project: no README plan, no contribution guide,
no documented threat model, no statement on telemetry.

For an open-source security tool these are not decoration. Someone deciding
whether to run this against their codebase needs to know what it does to their
machine, what it sends anywhere, and how to report it if they find a hole.

→ README, [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
the Diátaxis structure under `docs/`. Telemetry: none, not
off-by-default-but-present.

## M1 — Rule ids were load-bearing with no stability policy

**Medium.** Baselines, suppressions, SARIF output, and `--fail-on` all key off
the rule id. Renaming one silently invalidates every downstream baseline.

**Policy:** rule ids are permanent public API. A rename requires an alias
retained for two minor versions. `RULES.md` is generated from source and checked
in CI, so an accidental rename fails the build.

→ Enforced by `pnpm rules:check`. The generated catalogue is [RULES.md](RULES.md).

## M2 — "Rust-fast" was unfalsifiable

**Medium.** A performance claim with no number attached cannot be wrong, which
means it cannot be right either. Budgets:

| Metric | Budget |
|---|---|
| Static scan, 1k-file Next.js project, cold | < 5 s |
| Incremental re-scan of one file | < 300 ms |
| Peak memory, same project | < 300 MB |

The 300 ms figure is the load-bearing one: it is what fits inside an editor save
and an agent's edit loop, and it is the reason the engine parses each file once
rather than once per rule.

→ [ARCHITECTURE.md](ARCHITECTURE.md) §12. Benchmarks in CI are still to do.

## M3 — Licensing was never decided

**Medium.** **Dual MIT OR Apache-2.0** — the Rust ecosystem norm, and Apache-2.0
grants an explicit patent licence, which organisations check for. Plugins may
carry any licence.

DCO sign-off rather than a CLA. A CLA discourages drive-by contributions, which
are exactly what an early project needs.

→ `LICENSE-MIT`, `LICENSE-APACHE`, and the sign-off requirement in
[CONTRIBUTING.md](CONTRIBUTING.md).

## M4 — The testing strategy skipped the hardest cases

**Medium.** Missing: the false-positive corpus from H1; a **sandbox-escape
suite** in which a deliberately malicious plugin proves containment; and
snapshot tests on every reporter, so output format cannot drift silently.

→ Corpus and reporter snapshots shipped in v0.0. The sandbox-escape suite
arrives with the plugin host in v0.2, and is a condition of that release rather
than a follow-up.

## L1 — Smaller corrections

- **`--profile` versus `--preset`.** Both names were used for the same idea.
  Kept `--preset`; `--profile` does not exist.
- **`explain` must work offline.** Remediation content ships in the binary.
  The link to the generated `RULES.md` entry is an enhancement, not a
  dependency.
- **`watch` is static-only** by default. Re-issuing HTTP probes on every
  keystroke is hostile to the developer's own server.
- **Windows is a day-one target.** Code frames, ANSI handling, and path
  normalisation are the usual breakages, so all three platforms are in CI from
  v0.0 rather than ported later.
- **Language.** CLI output stays English — it ends up in issue reports and gets
  grepped. Translating the documentation is a separate, deliberate decision.

---

## What the review changed about the plan

The net effect was to pull safety-critical and precision-critical work earlier,
and push everything that depends on the network later:

| Phase | Before the review | After |
|---|---|---|
| v0.0 | napi bridge, HTTP transport, two dynamic detectors | **static engine first** (oxc), static rules, code frames, `pretty` + `json`, **confidence** |
| v0.1 | broader passive coverage | + dynamic engine, correlation, **baseline**, **suppression** |
| v0.2 | plugins | plugins + the **agent surface** |
| v0.3 | active mode | unchanged, still gated behind `--allow-active` |
| v0.4 | CI/CD integration | + autofix, plugin registry |

## Questions the review left open, and how they were settled

**How broad should static analysis be at v1?** TypeScript and JavaScript only,
rather than a generic AST layer from the start. A generic layer designed before
there is a second language to test it against would be designed wrong.

The review framed this as depth in two frameworks versus shallow support for
six, and v0.0 ended up with five. That is not a reversal: the constraint that
mattered was one *language*, not two frameworks. Within one language the cost of
a framework turned out to be a `FrameworkProfile` rather than a fork of every
rule, so the trade the question assumed was not the trade on offer. See
[ADR 0011](docs/adr/0011-framework-profiles.md).

**Should there be a hosted component?** No — not before v1.0, and there is no
plan for one. owlwarden is a local-first tool. A results dashboard is another
server to secure, and a security tool that leaks its customers' findings has
failed at the only thing it does.

**Telemetry?** None. The original recommendation was opt-in and off by default;
the decision went further, because "off by default" still means the code to
collect and transmit is present and has to be trusted. There is nothing to opt
out of.
