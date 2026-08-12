# Output specification

What owlwarden prints, and the contract each format keeps. Output is a product
surface: for a human it is the only part of the tool they see, and for a CI
pipeline or an agent it is the entire API.

Formats marked **planned** are designed but not built. See
[ROADMAP.md](ROADMAP.md).

---

## 1. One model, many renderings

Every reporter implements one trait, and no reporter derives facts of its own.
If the terminal shows a reason, that reason is a field on the finding — which is
what stops the terminal and the JSON from disagreeing.

```rust
pub trait Reporter {
    /// The name used by `--format` and in config, e.g. `"pretty"`.
    fn name(&self) -> &'static str;
    fn emit(&mut self, report: &Report) -> Result<(), ReportError>;
}
```

The shared model:

```rust
pub struct Finding {
    pub id: RuleId,                  // stable, e.g. "stack-trace-leak"
    pub severity: Severity,          // High | Medium | Low | Info
    pub confidence: Confidence,      // Confirmed | Likely | Possible
    pub owasp: Option<OwaspRef>,     // e.g. A05:2021
    pub cwe: Option<u32>,            // e.g. 209
    pub title: String,               // one line, sentence case
    pub why: String,                 // why it matters, in plain language
    pub location: Location,          // file:line:col, or a URL for dynamic findings
    pub snippet: Option<CodeFrame>,  // lines around the issue, and the span to underline
    pub context: FindingContext,     // framework, route, method, evidence
    pub remediation: Vec<Fix>,       // one per applicable framework, most specific first
    pub references: Vec<Reference>,  // 1–3 curated links
}

pub struct CodeFrame {
    pub path: String,
    pub start_line: u32,
    pub lines: Vec<String>,
    pub highlight: Option<Highlight>,   // line, start_col, end_col, and its label
}

pub struct Fix {
    pub framework: Option<Framework>,
    pub summary: String,
    pub patch: Option<String>,          // ready to paste
    pub safety: FixSafety,              // Safe | Unsafe | Manual — gates `--fix`
}
```

`severity` and `confidence` answer different questions. Severity is how bad the
problem is if it is real; confidence is how sure owlwarden is that it is real.
Collapsing them into one number is how a scanner ends up shouting — see
[docs/explanation/false-positives.md](docs/explanation/false-positives.md).

**Shipped:** `pretty`, `json`, `sarif`, `junit`, `md`.

**Stackable reporters** (ADR 0022): repeat `--format` to render several outputs
from one scan. With one machine format, `--out` is the destination file; with
several, `--out` is a prefix (`results` → `results.json`, `results.sarif`, …)
or a directory (`./reports/` → `./reports/report.json`, …). `pretty` goes to
stdout when it is the only format, otherwise stderr so machine stdout stays one
parseable document.

## 2. Terminal reporter — `pretty`

Read once, understand, fix. The layout follows the Rust compiler and miette
diagnostic style, because that is a shape working developers already read
fluently.

```
◉ᴥ◉ 2 files · quick · 0.31s
2 findings (1 high, 1 medium)

────────────────────────────────────────────────────────────────────────
HIGH  likely  Stack trace leaked in error response  A05:2021
────────────────────────────────────────────────────────────────────────
 app/api/users/route.ts:13:16  (GET /api/users)

  11 │   } catch (err) {
  12 │     return NextResponse.json(
  13 │       { error: err.stack },
     │                ~~~~~~~~~ leaks internal stack trace to the client
  14 │       { status: 500 }
  15 │     )

 ↳ fix (Next.js)  Return a generic message; log the error server-side.
                  console.error(err)
                  return NextResponse.json(
                    { error: 'Internal Server Error' },
                    { status: 500 },
                  )
 ↳ why            Stack traces expose absolute file paths, dependency
                  versions, and internal call structure — enough to
                  fingerprint the stack and locate other weaknesses.
 ⓘ  ref            OWASP A05:2021 · CWE-209 ·
                   RULES.md#stack-trace-leak

Run `owlwarden explain stack-trace-leak` for the full write-up.
```

Rules the layout keeps:

- **Summary first.** Counts by severity, then details. Findings sort by severity
  descending, then by file and line, so two runs over unchanged code produce
  byte-identical output.
- **Code frames.** Two lines of context on each side. The offending span is
  underlined with `~` and carries a one-line label. Columns are counted in
  characters, not bytes, so a Thai comment or an emoji earlier in the line does
  not shift the underline. Long lines are truncated rather than wrapped.
- **Confidence next to severity.** `HIGH likely` reads as one phrase and gives
  the reader the right prior before they read the finding.
- **Colour, with fallbacks.** ANSI when the terminal supports it; `NO_COLOR`,
  `--no-color`, and a non-TTY stdout all disable it. Unicode box drawing with an
  `--ascii` fallback for terminals without reliable UTF-8. Colour is written
  through `anstream`, which converts escapes into console calls on Windows
  rather than printing them at the user.
- **Copy-paste fixes.** The patch is shown ready to paste, for the detected
  framework. The other frameworks' fixes are one `explain` away.
- **Decoration goes to stderr.** The banner never touches stdout, so
  `--format json` stays a single parseable object no matter what else prints.
- **Hyperlinks are opt-in.** `--hyperlinks` emits OSC-8 links. Terminal support
  is uneven enough that it is not the default.

**Planned:** a progress indicator during long scans, erased on completion so it
never reaches piped output.

## 3. JSON reporter — `json`

Machine-first, versioned, one object on stdout. `--out` writes it to a file
instead, indented.

```json
{
  "schemaVersion": "1.0",
  "tool": { "name": "owlwarden", "version": "0.1.0" },
  "scannedAt": "2026-08-05T11:09:03Z",
  "durationMs": 7,
  "target": {
    "project": "fixtures/vulnerable/next-api",
    "scope": [],
    "filesScanned": 2,
    "routesProbed": 0,
    "preset": "quick"
  },
  "summary": { "high": 1, "medium": 1, "low": 0, "info": 0 },
  "findings": [
    {
      "id": "stack-trace-leak",
      "severity": "high",
      "confidence": "likely",
      "owasp": "A05:2021",
      "cwe": 209,
      "title": "Stack trace leaked in error response",
      "why": "Stack traces expose absolute file paths, dependency versions, and internal call structure — enough to fingerprint the stack and locate other weaknesses.",
      "location": { "path": "app/api/users/route.ts", "line": 13, "col": 16 },
      "snippet": {
        "path": "app/api/users/route.ts",
        "startLine": 11,
        "lines": [
          "  } catch (err) {",
          "    return NextResponse.json(",
          "      { error: err.stack },",
          "      { status: 500 }",
          "    )"
        ],
        "highlight": { "line": 13, "startCol": 16, "endCol": 25, "label": "leaks internal stack trace to the client" }
      },
      "context": { "framework": "next", "route": "/api/users", "method": "GET", "evidence": "err.stack" },
      "remediation": [
        {
          "framework": "next",
          "summary": "Return a generic message; log the error server-side.",
          "patch": "console.error(err)\nreturn NextResponse.json(\n  { error: 'Internal Server Error' },\n  { status: 500 },\n)",
          "safety": "manual"
        }
      ],
      "references": [
        { "kind": "owasp", "id": "A05:2021", "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
        { "kind": "cwe", "id": "CWE-209", "url": "https://cwe.mitre.org/data/definitions/209.html" }
      ]
    }
  ],
  "suppressedCount": 0,
  "suppressions": [],
  "baselineHiddenCount": 0,
  "truncated": false,
  "errors": []
}
```

Top-level fields that exist so the output cannot mislead by omission:

| Field | Why it is there |
|---|---|
| `suppressedCount` | `findings: []` with a non-zero count is not a clean project. |
| `suppressions` | Every inline directive, including stale and missing-reason ones. |
| `baselineHiddenCount` | Findings the baseline already accepted — distinct from suppressions. |
| `truncated` | The engine hit its finding cap and stopped collecting. |
| `errors` | Rules that failed and files that were skipped. A scan that could not read half a project still exits 0 if the half it read was clean. |

`@dointhai/owlwarden-sdk` publishes zod schemas for this shape. They are checked against
the Rust engine on every CI run through golden files, so the types cannot
describe a format the tool does not emit —
[ADR 0010](docs/adr/0010-cross-language-contract.md).

### Exit codes

Canonical contract: [docs/how-to/ci.md](docs/how-to/ci.md) (ADR 0017).

| Code | Meaning |
|---|---|
| 0 | Nothing at or above `--fail-on` (after `--min-confidence`) |
| 1 | Findings at or above `--fail-on`, **or** `truncated` |
| 2 | The scan could not run |

A `Possible`-confidence finding never produces exit 1 on its own. `truncated`
always fails. `2` is deliberately distinct from `1`.

## 4. Markdown reporter — `md` (shipped in v1.0)

For pasting into a pull request or an issue. Grouped by severity, each finding
carrying the fix for the detected framework.

````markdown
# owlwarden report — apps/api
_2 files · 0.31s · 1 high · 1 medium_

## High

### Stack trace leaked in error response · A05:2021 · CWE-209
**Where:** `app/api/users/route.ts:13` (route `GET /api/users`, Next.js)
**Confidence:** likely
````

```bash
owlwarden scan --format md --out owlwarden-report.md
owlwarden scan --format pretty --format md --out owlwarden-report
```

`--md-group-by` / `--md-collapse` remain later. The default grouping is
severity, which is what a PR comment needs.

## 4b. SARIF reporter — `sarif` (shipped in v0.4)

SARIF 2.1.0 rendering of the same `Report` (ADR 0017). Severity maps to SARIF
`level`: High → `error`, Medium → `warning`, Low → `note`, Info → `none`.
Confidence, OWASP, and CWE sit in `result.properties`.

```bash
owlwarden scan --ci --format sarif --out owlwarden-results.sarif
```

Upload with a SHA-pinned `github/codeql-action/upload-sarif` — see
[docs/how-to/ci.md](docs/how-to/ci.md).

## 4c. JUnit reporter — `junit` (shipped in v0.4)

One `<testcase>` failure per finding. A clean scan is a single passing case.
JUnit does not redefine exit codes — pipelines still read the CLI's 0 / 1 / 2.

```bash
owlwarden scan --ci --format junit --out owlwarden-results.xml
```

## 5. Context-aware remediation

A finding is not "you have a problem" — it is "here is the fix for your stack".
Every rule attaches a `FindingContext` (framework, route, method, evidence) and
returns one `Fix` per applicable framework.

- **Framework detection selects the fix.** The same underlying issue produces
  different patches: missing security headers gets a `headers()` block for
  Next.js, `routeRules` for Nuxt, `app.use(helmet())` for NestJS and Express,
  `@fastify/helmet` for Fastify, and the raw header list when the framework is
  unknown. The mapping is a declarative `Remediation` table on the rule, and a
  test fails if a supported framework has no entry — otherwise the generic
  fallback quietly becomes the answer for a framework nobody thought about.
- **Reporters render only what fits.** The terminal shows the fix for the
  detected framework; the rest are behind `explain`.
- **References are curated, not dumped.** One to three authoritative links: the
  OWASP category, the CWE, and the rule's own page. A test enforces the range,
  because a reading list is not remediation.
- **Remediation lives with the rule**, not in a table inside the reporter, so a
  plugin author ships fixes alongside their rule.
- **Everything works offline.** The reader may be an agent with no browser, so
  the full remediation set ships in the binary and the link to `RULES.md` is an
  enhancement rather than a dependency.

The definition of done for a rule is therefore: at least one framework-specific
fix with a patch, a `why`, and one to three references. `crates/detectors/tests/fixtures.rs`
asserts all three, so a rule cannot ship without them.

## 6. `owlwarden explain <id>`

The long-form write-up for one rule: the rationale, every framework's fix, and
the references. This is what keeps the scan view terse — depth is one command
away rather than crammed into every finding.

```bash
owlwarden explain stack-trace-leak
owlwarden explain stack-trace-leak --json
```

## 7. Suppressions, baseline, and planned work

Baseline mode (`--baseline` / `--write-baseline`) and `--report-suppressions`
shipped in 0.0.2. See [ADR 0013](docs/adr/0013-suppressions-and-baseline.md)
and [docs/how-to/suppressions.md](docs/how-to/suppressions.md).

Still planned:

- **`report` command** — re-render a saved JSON result in another format.
