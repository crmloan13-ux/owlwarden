# 0019. First-party active detector: csrf-cross-origin-post

**Status:** Accepted
**Date:** 2026-08-11

## Context

v0.3 wired `--allow-active`, rate limiting, and the request audit log, but no
first-party detector issued POST/PUT/PATCH/DELETE. An unused gate decays: teams
never exercise it, and the next person to add an active probe invents policy
under pressure.

Active probes can mutate staging data. The first rule must be one request, a
documented canary body, and an honest signal — not an exploit chain.

## Decision

**Ship one rule: `csrf-cross-origin-post`.** With `--target` and
`--allow-active`, send a single `POST` to the exact target URL with:

- `Origin: https://owlwarden-untrusted.invalid`
- `Content-Type: application/x-www-form-urlencoded`
- body `owlwarden_probe=1` (fixed canary; never attacker-controlled)

**Finding when the response status is 2xx.** Accepting a cross-origin
state-changing request without rejecting it is the classic CSRF shape on cookie
session apps. Confidence is `Likely` (max), never `Confirmed` — a 2xx JSON API
that is token-authenticated can still return 200 for an empty body, and we do
not claim to know the auth model.

**No crawl, no second hop, no body from the repository.** Scope and pacing stay
inside `Transport`. MCP still cannot set `--allow-active`.

**Not correlated with a static rule in this release.** Static CSRF detection is
a separate, harder problem; pairing them later needs its own honest signal.

## Consequences

- Operators must only point `--allow-active` at staging they control; the canary
  POST may still create a resource if the route is a create endpoint.
- A06/A01 coverage for CSRF stays partial and is declared as such.
- Further active rules each need their own ADR; this one does not open the door
  to exploit payloads.
