# owlwarden

A keen-eyed security auditor for web apps and APIs. Rust engine, npm install,
passive by default.

```bash
npx owlwarden scan
```

**Status: v0.0.** Nine rules across six of the OWASP Top 10, static analysis
only, with first-class support for **Next.js, Nuxt, NestJS, Express, and
Fastify**.

## What a finding looks like

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

 ↳  fix (Next.js)   Return a generic message; log the error server-side.
                    console.error(err)
                    return NextResponse.json(
                      { error: 'Internal Server Error' },
                      { status: 500 },
                    )
 ↳  why             Stack traces expose absolute file paths, dependency
                    versions, and internal call structure — enough to
                    fingerprint the stack and locate other weaknesses.
 ⓘ  ref             OWASP A05:2021 · CWE-209 · RULES.md#stack-trace-leak
```

Every finding carries the fix inline, for the framework you actually use. There
is no "see the docs for details": the reader might be an AI agent with no
browser, and even a human should not have to open a tab to act on a scanner.

## Install

```bash
npm i -D owlwarden
```

Node 20 or newer. The engine ships as a prebuilt native addon for macOS, Linux
(glibc and musl), and Windows — no compiler step, and no `postinstall` that
downloads anything.

```json
{
  "scripts": {
    "security-check": "owlwarden scan"
  }
}
```

## Usage

```bash
owlwarden scan                          # zero config
owlwarden scan --preset owasp-top10     # a named rule bundle
owlwarden scan --ci                     # JSON on stdout, exit codes for CI
owlwarden coverage                      # what the rules reach, and what they do not
owlwarden explain sql-injection         # the full write-up, offline
owlwarden rules                         # the catalogue
```

Exit codes are a contract: `0` clean, `1` findings at or above `--fail-on`, `2`
the scan could not run. A failed scan is not a clean scan.

## Two things worth knowing before you trust it

**Precision is tested, not claimed.** Every vulnerable test project has a
corrected twin, and any finding in the corrected set fails our build. A scanner
that flags correct code gets switched off, and everything it would have caught
goes with it.

**It tells you what it misses.** `owlwarden coverage` reports which OWASP
categories the rules reach and which they do not, computed from the rules that
actually shipped in the binary you installed. "No findings" and "did not look"
are different answers, and conflating them is worse than not scanning.

## Safety

Passive by default. v0.0 reads your source and sends no requests, so it cannot
change the state of anything. There is no telemetry of any kind — not off by
default, absent. Nothing about your code leaves the machine.

## Documentation

Full docs, the rule catalogue, and the design record live in the repository:
[github.com/suthat/owlwarden](https://github.com/suthat/owlwarden).

- [Rule catalogue](https://github.com/suthat/owlwarden/blob/main/RULES.md)
- [Using it in CI](https://github.com/suthat/owlwarden/blob/main/docs/how-to/ci.md)
- [Reading the coverage report](https://github.com/suthat/owlwarden/blob/main/docs/explanation/coverage.md)
- [Confidence and false positives](https://github.com/suthat/owlwarden/blob/main/docs/explanation/false-positives.md)

Found a false positive? That is a bug, and a higher-priority one than a missing
rule. Please [open an issue](https://github.com/suthat/owlwarden/issues).

## Licence

MIT OR Apache-2.0.
