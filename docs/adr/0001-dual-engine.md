# 0001. Static and dynamic engines over one finding model

**Status:** Accepted
**Date:** 2026-01-15

## Context

Two kinds of web security tool exist and neither is satisfying on its own.

A static analyser reads source. It knows exactly which line is wrong, and it can
be run on every save, but it cannot tell you whether the vulnerable path is
reachable in production — a header set by an ingress controller is invisible to
it, and so is a route that is never deployed.

A dynamic scanner probes a running app. It knows what the server actually does,
and it produces evidence you can hand to someone who does not believe you. It
also has no idea which file to open.

Picking one means either high-precision findings you cannot confirm, or
confirmed findings you cannot locate.

## Decision

Build both, over one `Finding` model, and correlate them.

- The **static engine** reads source through a `SourceProvider` port and parses
  with oxc. It is passive by definition.
- The **dynamic engine** sends bounded HTTP requests through a `Transport` port,
  under a scope allowlist that denies everything by default.
- **Correlation** matches a static finding to a dynamic observation of the same
  route. A finding that both engines agree on is reported as `Confirmed`.

Build the static engine first. It carries no scanning risk, it is the half that
works in an editor and in an agent's edit loop, and correlation needs it anyway.

## Consequences

- `Confidence` has to exist in the model from the start, and `Confirmed` has to
  mean something a static rule cannot reach on its own. See ADR 0006.
- `Location` has to describe both a source position and an HTTP endpoint. It is
  an untagged enum so the common static case stays `{ path, line, col }`.
- The core cannot depend on either engine — both are adapters behind ports. That
  constraint is what makes the static-only v0.0 possible without designing
  ourselves into a corner.
- More surface than a single-engine tool. Correlation for the first rule
  (`security-headers-missing`) shipped in 0.1.0; see ADR 0014. Active checks
  and broader dynamic coverage remain later.
