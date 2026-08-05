# 0007. Reporters are Rust, not TypeScript

**Status:** Accepted
**Date:** 2026-01-22

## Context

The obvious split is: Rust computes findings, TypeScript prints them. Terminal
rendering is presentation, TypeScript has good libraries for it, and the CLI is
already TypeScript.

Except there are two CLIs. The npm package and the standalone binary both have
to print a report, and if rendering lives in TypeScript the binary needs its own
implementation. Two implementations of a code-frame layout will not agree for
long — one will fix an off-by-one in the underline column and the other will
not, and the snapshot tests will only cover one of them.

## Decision

Rendering is Rust, in `crates/reporters`, behind the `Reporter` trait. The npm
CLI calls `render(reportJson, optionsJson)` over the napi bridge and writes the
string it gets back.

TypeScript still decides *whether* to colour — that needs `process.stdout.isTTY`
and `NO_COLOR`, which are the caller's business — and passes the answer in. The
banner works the same way: the art is in Rust, the decision to show it is in the
CLI, because only the CLI knows about its own streams.

## Consequences

- One code-frame implementation, one set of snapshot tests, and they cover both
  distribution channels.
- The napi surface grows a `render` and a `banner` function. Small price.
- A user cannot write a custom reporter in TypeScript today. The `Reporter`
  trait is the extension point and it is Rust-side; a TypeScript reporter API
  would be a v0.1 decision, and `--format json` covers the case in the meantime.
- ANSI handling goes through `anstream`, which converts escapes into console
  calls on Windows rather than printing them at the user.
