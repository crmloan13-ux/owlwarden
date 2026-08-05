# 0009. Hand-written argument parsing

**Status:** Accepted
**Date:** 2026-01-24

## Context

Both CLIs need to parse arguments. The default answer is `clap` in Rust and
`commander` or `yargs` in TypeScript, and both are good libraries.

A security tool's dependency tree is part of its argument, though. We tell users
that supply chain risk is real and that install scripts are arbitrary code
execution; installing forty transitive packages to parse eleven flags sits
badly with that. Every dependency is also something a user has to trust
transitively, and a scanner asks for more trust than most tools.

The counter-argument is real: hand-written parsers get subtly wrong things like
`--flag=value`, `--`, and clustered short flags, and getting them wrong in a
tool that decides what gets scanned is not harmless.

## Decision

- **TypeScript CLI:** Node's built-in `node:util` `parseArgs` in strict mode. It
  is part of the runtime, so it is not a dependency at all, and it handles the
  syntax edge cases correctly.
- **Rust CLI:** about a hundred lines in `crates/cli-native/src/cli.rs`, with
  tests for every branch including the error paths.

In both, an unknown flag is an error. A mistyped `--presset` must not fall back
to the default preset — silently scanning with fewer rules than the user asked
for is exactly the failure a security tool cannot have.

## Consequences

- The Rust parser does not support `--flag=value` or clustered short flags. If
  that becomes a real complaint, adding `clap` is a small PR and this ADR gets
  superseded — the surface is contained in one file.
- Help text is written by hand and can drift from the flags. The test that
  checks every preset appears in the help catches the worst case.
- The two CLIs' flag surfaces are maintained separately. Both are covered by
  tests, and the shared behaviour that actually matters — exit codes, rendering,
  presets — lives in the engine, not in either parser.
