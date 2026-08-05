# 0002. Rust core, distributed as an npm native addon

**Status:** Accepted
**Date:** 2026-01-16

## Context

The people who need this tool are JavaScript developers, and they install
things with `npm`. Anything that asks them for a Go toolchain, a Docker daemon,
or a `cargo install` first will be tried by a tenth as many of them.

But the engine has to be fast enough to run on every save — the budget for
scanning one file is under 300 ms, because that is what fits in an editor and in
an agent's edit loop. It also has to enforce hard memory and time bounds against
hostile input, and it has to be able to sandbox untrusted plugins later.

A pure-TypeScript implementation gives up the performance and most of the
sandboxing. A pure-Rust CLI gives up the distribution.

## Decision

Rust engine, TypeScript orchestration, joined by napi-rs v3.

- `crates/*` hold the engine: scheduling, parsing, rules, rendering.
- `packages/*` hold the CLI, the config loader, and the published types.
- The engine is compiled per platform and published as optional npm
  dependencies (`@dointhai/owlwarden-core-native-darwin-arm64` and friends). The loader
  picks the right one. There is no compilation and no download at install time.
- A standalone `owlwarden` binary (`crates/cli-native`) exists for people who do
  not want Node at all. It is the same engine, not a second implementation.

## Consequences

- Release engineering is a matrix build across seven targets, and Windows is a
  day-one target rather than a later port.
- Contributors need both toolchains. `pnpm build` runs them in order.
- Two CLIs parse flags. They share the engine but not the argument parser; the
  duplication is small, it is tested on both sides, and the alternative — having
  the npm CLI shell out to a binary — costs a process spawn per scan and makes
  the error surface worse.
- Anything that must be identical between the two lives in Rust: rendering,
  rule metadata, presets, exit-code logic.
