# Architecture

How owlwarden is put together, and the constraints that shape it. Decisions with
their rationale live as ADRs under [`docs/adr/`](docs/adr/); this document
describes the result.

Sections marked **planned** describe designs that are settled but not built.
They are here because the code that exists was shaped to accommodate them, not
as a promise about dates — see [ROADMAP.md](ROADMAP.md) for that.

---

## 1. Goals and non-goals

**Goals**

- A scanning engine fast enough to run on every save, driven from an npm CLI.
- Extensible through plugins that are safe by construction, not by convention.
- Useful with no configuration; configurable when that stops being enough.
- Held to the standard it enforces. A security tool that opens holes while
  finding them is worse than no tool.

**Non-goals**

- Not an exploitation toolkit. No payload damages, persists, or exfiltrates.
- Not a GUI product and not an HTTP proxy.
- Not every language at once. TypeScript web frameworks first — Next.js, Nuxt,
  NestJS, Express, and Fastify — and generalise from there.

## 2. The dual-engine model

owlwarden runs two analysis engines over one finding model.

| Engine | Input | Answers | Network |
|---|---|---|---|
| **Static** | source files and their AST, via [oxc](https://oxc.rs) | where in my code the problem is | none |
| **Dynamic** (planned) | live HTTP responses | what the server actually does | yes, within a declared scope |
| **Correlated** (planned) | both | confirmed at runtime, with the line that causes it | yes |

Each on its own is unsatisfying. A static analyser cannot tell you whether the
vulnerable path is reachable in production — a header set by an ingress
controller is invisible to it. A dynamic scanner can tell you the server is
wrong but not which file to open.

Static analysis is passive by definition, so the static engine carries no
scanning risk. That is why it ships first. See
[ADR 0001](docs/adr/0001-dual-engine.md).

## 3. Layered architecture

The core depends only on abstractions; concrete implementations are injected.
This keeps the core pure, testable, and free of I/O.

```
        adapters (concrete, I/O)                core (pure, abstractions)
  ┌────────────────────────────────┐      ┌──────────────────────────────────┐
  │ FsSourceProvider     (files)   │─impl▶│ trait SourceProvider             │
  │ StaticEngine         (oxc)     │─impl▶│ trait Detector                   │
  │ PrettyReporter / JsonReporter  │─impl▶│ trait Reporter                   │
  │ ReqwestTransport     (planned) │─impl▶│ trait Transport                  │
  │ WasmDetector         (planned) │─impl▶│ trait Detector                   │
  └────────────────────────────────┘      │ struct Scheduler  (orchestrates) │
                                          │ struct Finding / Severity / …    │
                                          └──────────────────────────────────┘
```

**The rule:** nothing in `crates/core` imports `reqwest`, `wasmtime`, `oxc`, or
`napi`. Those belong to adapter crates. Core is `#![forbid(unsafe_code)]`.

### Crate layout

| Crate | Responsibility |
|---|---|
| `core` | Ports (traits), the finding model, the scheduler, resource limits. No I/O. |
| `static-engine` | Sandboxed filesystem provider, oxc parsing, rule plumbing, framework profiles, shared AST and request-origin analysis. |
| `detectors` | The rules themselves, with their remediation content. |
| `reporters` | `pretty` and `json` output, and the banner. |
| `napi` | The Node bridge. |
| `cli-native` | Standalone binary — the same engine without Node. |

| Package | Responsibility |
|---|---|
| `@owlwarden/sdk` | Report types and zod schemas, checked against the engine in CI. |
| `@owlwarden/config` | Config schema and resolution. |
| `owlwarden` | The CLI. |

`plugin-host` and `transport` are planned crates. They do not exist yet, and
empty placeholder crates would only be noise.

## 4. Core interfaces

These are the load-bearing abstractions. They are small on purpose, and they
become public API at v1.0.

```rust
/// A unit of analysis. Pure with respect to I/O: it asks the context to act
/// on its behalf, so scope, sandboxing, and limits are unbypassable rather
/// than merely conventional.
#[async_trait]
pub trait Detector: Send + Sync {
    fn meta(&self) -> DetectorMeta;          // stable id, OWASP/CWE, severity
    fn kind(&self) -> DetectorKind;          // Static | Dynamic | Correlated
    fn capabilities(&self) -> Capabilities;  // {source, network, active}
    async fn run(&self, ctx: &ScanContext) -> Result<Vec<Finding>, DetectorError>;
}

/// Read-only access to project source, rooted at the project directory.
/// Resolves symlinks and refuses anything that escapes; respects .gitignore.
pub trait SourceProvider: Send + Sync {
    fn root(&self) -> &Path;
    fn files(&self, selector: &FileSelector) -> Result<Vec<SourceFile>, SourceError>;
    fn read(&self, file: &SourceFile) -> Result<Arc<str>, SourceError>;
}

/// The only way a detector reaches the network. Enforces scope and limits
/// centrally rather than trusting each detector to do it.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, req: BoundedRequest) -> Result<BoundedResponse, TransportError>;
}

/// Turns a report into output.
pub trait Reporter {
    fn name(&self) -> &'static str;
    fn emit(&mut self, report: &Report) -> Result<(), ReportError>;
}

/// Decides whether a URL is in scope. Deny-by-default.
pub trait ScopeResolver: Send + Sync {
    fn in_scope(&self, target: &Target) -> ScopeDecision;  // Allow | Deny(reason)
}
```

`ScanContext` is the mediator handed to every detector. It exposes `source()`,
`transport()`, `scope()`, the settings, and a `budget` of remaining requests and
time. A detector cannot construct its own transport or open a file directly.

### Why `SourceProvider` does not return an AST

An earlier draft of this document gave `SourceProvider` an `ast()` method. It
cannot be implemented: oxc allocates its AST in an arena and every node borrows
from it, so returning one across a trait boundary means either a self-referential
type or a lifetime parameter that infects everything it touches. It would also
re-parse each file once per detector.

Instead the static engine parses each file exactly once, hands the resulting
`FileUnit` to every rule interested in that file, and drops the arena when the
file is done. Rules see `&FileUnit<'_>` inside a callback and the lifetime never
escapes. [ADR 0004](docs/adr/0004-source-provider-has-no-ast.md).

### Static rules

Because their signatures mention the AST, the two rule traits live in
`static-engine` rather than in `core`:

```rust
/// Sees one parsed file.
pub trait FileRule: Send + Sync {
    fn meta(&self) -> DetectorMeta;
    fn applies_to(&self, path: &RelPath) -> bool;   // checked before parsing
    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink);
}

/// Sees the whole project — needed to detect the *absence* of something.
pub trait ProjectRule: Send + Sync {
    fn meta(&self) -> DetectorMeta;
    fn check(&self, project: &Project<'_>, sink: &mut FindingSink)
        -> Result<(), DetectorError>;
}
```

`StaticEngine` implements `Detector` and runs both kinds. From the scheduler's
point of view the entire static engine is one detector; from a rule author's
point of view there is one file to parse and one place to put findings.

### Framework knowledge is infrastructure, not rule content

A rule never matches a framework by name. `res.json`, `reply.send`,
`setCookie(event, ...)`, and `NextResponse.json` are the same idea spelled five
ways, and a rule that knows one of those spellings works on one framework and
silently does nothing on the rest.

Instead each framework has a `FrameworkProfile` in `static-engine` describing
how to detect it, where its configuration lives, how it declares routes, and its
HTTP vocabulary. Rules ask questions — `is_response_sink`, `is_cookie_setter`,
`is_cors_enabler` — and the profile answers.

`Framework` is an open type rather than an enum, so a plugin can register a
profile without a core change. Detection returns a *set*, because a NestJS
project genuinely is an Express project underneath, and a `specificity` field
resolves which one owns the remediation.

Remediation follows the same shape: a declarative `Remediation` table keyed by
framework, with `framework_coverage()` reporting every rule that lacks specific
advice for a supported framework. A test fails the build when that list is
non-empty, so a rule cannot ship serving four frameworks and neglecting the
fifth. [ADR 0011](docs/adr/0011-framework-profiles.md);
[docs/how-to/extend.md](docs/how-to/extend.md) is the practical guide.

### Request origin is shared, and deliberately shallow

Injection-shaped rules all ask "did this value come from the caller?", and the
answer sets the finding's confidence. `RequestOrigin` in
`static-engine/src/taint.rs` answers it once for every rule: a **one-hop,
intra-procedural, flow-insensitive** check that understands the three ways the
supported frameworks expose the request.

It is not a taint engine and does not aspire to be one. A real one needs type
resolution and a call graph, and — the deciding argument — it implies a
completeness claim we could not honour. So the contract is narrow: origin
decides `Likely` versus `Possible`, never whether to report. A miss costs a
confidence level, not a finding. [ADR 0012](docs/adr/0012-request-origin-not-taint.md).

### Coverage is computed, not written down

`owlwarden coverage` builds its table from the rules compiled into the binary:
which OWASP categories have rules, which do not, and — separately — which are
beyond static analysis entirely. The distinction between "no rule yet" and "no
rule is coming" is the load-bearing part; collapsing them would tell a reader to
wait for a release that will never arrive.
[docs/explanation/coverage.md](docs/explanation/coverage.md).

## 5. Trust and noise control

A security tool that cries wolf gets uninstalled, and that failure is caused by
presenting a guess and a fact at the same volume rather than by missing rules.
Three mechanisms address it. The first ships today; the other two are v0.1.

**Confidence.** Every finding carries `Confirmed | Likely | Possible`.

- `Confirmed` — corroborated by both engines: runtime behaviour plus the source
  that causes it. A static rule cannot reach it.
- `Likely` — a single engine with a strong signal.
- `Possible` — heuristic. Shown, but never fails CI on its own.

Each rule declares its ceiling in `DetectorMeta::max_confidence`, so the limit is
documented rather than implied. `--min-confidence` filters, and `--fail-on`
respects it. [ADR 0006](docs/adr/0006-confidence-in-the-model.md) and
[docs/explanation/false-positives.md](docs/explanation/false-positives.md).

**Suppression with a mandatory reason** (planned). The reason is what stops
suppression from becoming a silent blanket, because it is what a reviewer reads
in the diff:

```ts
// owlwarden-disable-next-line stack-trace-leak -- dev-only route, gated by NODE_ENV
```

`--report-suppressions` will list every suppression and flag stale ones, so the
annotations cannot rot. `suppressedCount` is already in the report schema, so
`findings: []` is never mistaken for a clean project.

**Baseline** (planned). `--baseline .owlwarden-baseline.json` fails only on
findings new since the baseline — the only realistic way to adopt the tool on an
existing codebase. Entries key on a fingerprint of rule id, normalised location,
and code hash, so they survive reformatting.

**Rule ids are permanent public API.** Baselines, suppressions, SARIF output,
and agent rules files all key off them. A rename requires an alias retained for
two minor versions. `RULES.md` is generated from source and checked in CI, so an
accidental rename fails the build.

## 6. Plugin system (planned)

Two tiers, distinguished by how much they are trusted.

| Tier | Language | Runs in | For | Trust |
|---|---|---|---|---|
| **Recipe** | TS/JS | the CLI process | presets, custom reporters, glue | the user's own code |
| **Detector** | any → WASM/WASI | `plugin-host` (wasmtime) | scanning logic | untrusted, sandboxed |

- **Capability model.** A plugin manifest declares what it needs — `network`,
  `active`. At load time the host wires only the granted host functions. No
  declaration means no capability. `active` additionally requires the run to
  pass `--allow-active` and the target to be in scope.
- **No ambient authority.** A WASM detector gets no clock, randomness,
  filesystem, or network except through host functions the runner provides.
  This is the whole reason a security tool can run third-party detectors.
- **Bounded.** Each invocation gets a fuel and time budget and a memory cap. A
  misbehaving plugin is starved; the host is not.

## 7. Configuration

Resolved in order: `owlwarden.config.ts` → `.mts` → `.mjs` → `.js` → `.json` →
an `owlwarden` key in `package.json` → built-in defaults. Flags override the
config file. Zero configuration produces a useful passive scan.

Resolution never walks above the directory being scanned. A config file two
levels up — possibly outside the repository — changing what a scan does is the
kind of surprise a security tool cannot afford.

The schema is declared in zod (TypeScript) and serde (Rust). Those two
declarations are held together by golden files generated from the engine and
parsed by the TypeScript tests; see
[ADR 0010](docs/adr/0010-cross-language-contract.md).

```ts
// owlwarden.config.ts
import { defineConfig } from "@owlwarden/config";

export default defineConfig({
  preset: "owasp-top10",
  failOn: "medium",
  minConfidence: "likely",
});
```

Every error carries a code, one human-readable line, and somewhere to read more.
Errors are a UX surface, not a stack trace.

`owasp-top10` is a preset name referencing a public standard. The product itself
is never branded with the OWASP mark.

## 8. Execution modes

| Command | Status | What it does |
|---|---|---|
| `scan` | shipped | One-shot scan. `--ci` gives JSON and meaningful exit codes. |
| `rules` | shipped | The rule catalogue. |
| `coverage` | shipped | Which OWASP categories the rules reach, and which they do not. |
| `explain <id>` | shipped | The full write-up for a rule, entirely offline. |
| `watch` | planned | Re-scan on change during development. |
| `report` | planned | Re-render a saved JSON result in another format. |
| `mcp` | planned | An MCP server, so an agent can call owlwarden as a tool. |

Exit codes are a contract: `0` clean, `1` findings at or above `--fail-on`, `2`
the scan could not run.

There is no network-listening daemon, and there will not be one in v1. It is
attack surface with no corresponding benefit.

## 9. Self-security

Three adversaries, and what is done about each. The full version is in
[SECURITY.md](SECURITY.md).

1. **A hostile target.** A scanned repository or server tries to harm the
   scanner. Hard caps on response body size, decompression ratio, redirects, and
   timeouts; bounded concurrency; deeply nested source rejected before it reaches
   the parser ([ADR 0008](docs/adr/0008-bound-parser-recursion.md)).
2. **A hostile plugin.** WASM sandbox, capability-gated host calls, memory and
   fuel limits, no ambient authority. Planned with the plugin host.
3. **A hostile supply chain.** `cargo-deny` and `cargo-audit` in CI, committed
   lockfiles, an explicit allowlist for npm install scripts, npm provenance, and
   signed releases with an SBOM.

Invariants throughout: scope is deny-by-default; secrets are redacted from
output; `unsafe` will be confined to `plugin-host` and audited line by line; the
standalone binary and the Node addon share one reviewed core.

## 10. Coding standards

An adaptation of NASA's "Power of Ten" rules for safety-critical C. CI enforces
what can be mechanised; review enforces the rest.

| # | Original rule | Here | Enforced by |
|---|---|---|---|
| 1 | Simple control flow, no `goto` or recursion | No unbounded recursion; bound it or make it iterative | review, clippy |
| 2 | Fixed loop bounds | Every loop over external data has an explicit cap | review, tests |
| 3 | No dynamic allocation after init | Not possible in Rust — instead, every allocation driven by untrusted input is clamped first | review, `limits.rs` |
| 4 | Functions ≤ 60 lines | Same. Extract beyond that | review |
| 5 | ≥ 2 assertions per function | ≥ 1 boundary check validating each external input; `debug_assert!` for invariants; zod at the TypeScript boundary | review |
| 6 | Smallest possible data scope | Ownership handles most of it; prefer immutability, no needless `pub` | clippy, review |
| 7 | Check every return value | No `unwrap`, `expect`, or `panic!` in library paths; typed errors via `thiserror`; no floating promises in TypeScript | clippy, eslint |
| 8 | Limited preprocessor use | Minimal macros, no `cfg` spaghetti, documented feature flags | review |
| 9 | Restricted pointer use | `#![forbid(unsafe_code)]` everywhere except `plugin-host` | the attribute itself |
| 10 | All warnings on, zero warnings | `clippy -- -D warnings`, `tsc` clean, `eslint` clean | CI gate |

Baseline lint configuration at the top of each crate:

```rust
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, missing_docs)]
```

`deny(warnings)` is deliberately *not* in the source. A new compiler release
would then break every local build the day it lands. `-D warnings` belongs in
CI, where it is a gate rather than an ambush.

## 11. Resource limits

Defaults, all overridable in configuration but never unbounded. They live in one
file, `crates/core/src/limits.rs`, so there is a single place to audit.

| Area | Cap |
|---|---|
| HTTP | 15 s timeout, 8 MiB body, 5 redirects, 20× decompression ratio |
| Scan | Request and wall-clock budget, concurrency ≤ 16, per-detector time slice |
| Source | Per-file size cap, total bytes cap, file count cap, nesting depth 256 |
| Findings | Per-file and per-run caps; the report says when it truncated |
| Plugins | 64 MiB memory, a fuel and time budget per invocation |

Any path that turns an attacker-controlled size into an allocation clamps first.

## 12. Testing

- **Unit tests per rule**, including at least one malicious or oversized input.
- **Vulnerable fixtures** (`fixtures/vulnerable/`) — one project per supported
  framework, driven from a declared matrix of which rule must fire how many
  times in which project. Adding a framework without wiring its fixtures in
  fails the build rather than quietly reducing coverage.
- **False-positive corpus** (`fixtures/should-not-fire/`) — a corrected twin of
  every vulnerable project, plus the tempting cases a naive implementation would
  flag. Anything that fires here fails the build. Precision is a tested
  property, not a hope.
- **Catalogue tests** — every rule has a section in the generated `RULES.md`
  and no section describes a rule that no longer exists, so the reference every
  finding prints cannot become a dead link.
- **Reporter snapshots** — golden output per format, so the terminal layout and
  the JSON contract cannot drift silently.
- **Cross-language contract** — golden files generated by the Rust engine and
  parsed by the TypeScript schemas, including the full exit-code truth table.
- **Sandbox-escape suite** (planned) — a deliberately malicious sample plugin;
  the test asserts containment. Will run on every PR touching `plugin-host`.
- **Property and fuzz testing** (planned) — `proptest` for parsers and bounds,
  `cargo-fuzz` on the response-handling and AST boundaries.

### Performance budget

| Metric | Budget |
|---|---|
| Static scan, 1k-file Next.js project, cold | < 5 s |
| Incremental re-scan of one file | < 300 ms |
| Peak memory, same project | < 300 MB |

The 300 ms figure is not arbitrary: it is what fits inside an editor save and an
agent's edit loop. Benchmarks against a large fixture repository are planned for
CI, failing on a regression over 20%.

### Platforms

Linux, macOS, and Windows are first-class from v0.0. Path normalisation, ANSI
handling, and line endings are the usual Windows breakages, and all three are
covered in CI rather than discovered later.
