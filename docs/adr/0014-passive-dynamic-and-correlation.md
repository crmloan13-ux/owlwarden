# 0014. Passive dynamic engine and correlation

**Status:** Accepted
**Date:** 2026-08-06

## Context

ADR 0001 decided on a dual-engine model. The static half shipped in v0.0.
`Confirmed` confidence is defined as both engines agreeing (ADR 0006), and that
value has been unreachable because nothing probes a live target.

Opening the network is the highest-risk change the tool will make before
plugins. A scanner that follows a redirect off-scope becomes an SSRF gadget; a
scanner that takes its target from a scanned repository's config file becomes a
CI-time attack on anything the runner can reach. The design has to make those
failures impossible by construction, not by detector courtesy.

## Decision

**Passive only in this release.** The transport may issue `GET`, `HEAD`, and
`OPTIONS`. State-changing methods remain behind `--allow-active`, and no
detector that needs `active` ships yet. v0.3 owns active checks.

**Target and scope are operator intent, never project config.** `--target` and
`--scope` come from the command line. A file inside the scanned tree cannot
point the scanner at a host — that is how a hostile pull request would turn CI
into an SSRF client. Config keys for target/scope are deliberately absent.

**Scope is an allowlist of origins, deny-by-default.** An entry is
`scheme://host[:port][/path-prefix]`. Matching requires equal scheme, equal
host (DNS names compared case-insensitively; IP literals must match exactly),
equal port (defaulted from the scheme when omitted), and a path that equals or
is under the optional prefix. When `--scope` is omitted, the allowlist is
exactly the origin of `--target`. Localhost is not special-cased.

**Scope is enforced inside `Transport::send`, including every redirect hop.**
Automatic client redirects are disabled; the adapter follows manually and
re-checks scope each time. An off-scope `Location` is
`TransportError::OutOfScope`, not a followed request.

**Limits are enforced while streaming.** Body bytes are counted as they arrive.
`Content-Length` is never trusted as a substitute. Automatic response
decompression is off so a hostile `Content-Encoding` cannot expand past
`max_decompress_ratio` before we notice. Headers-only probes set
`max_body_bytes = 0` and do not pull a body chunk at all. Redirect `Location`
values are re-parsed through the same target validator (credentials, scheme,
control characters, length). Oversized response header values are dropped, not
truncated — a half CSP is worse than a missing one.

**HTTP client: `reqwest` with `rustls-tls`, no default features.** The
architecture named this adapter in advance. The alternative — a hand-rolled
HTTP/1.1 client — would concentrate TLS and protocol bugs in our tree rather
than in a crate that is reviewed in public. The dependency is justified by the
surface it replaces, and is confined to `crates/transport`.

**Correlation is a post-pass, not a concurrent detector.** Detectors run in
parallel and cannot see each other's findings. After the scheduler returns, a
pure function matches pairs that agree and upgrades the static finding to
`Confirmed`. The dynamic-only duplicate is dropped so the report does not show
the same problem twice at two confidences.

**First correlated rule: `security-headers-missing`.** Static analysis cannot
see headers set by a CDN or ingress, which is why that rule already reports
`Possible` when it finds no config. A passive probe of `--target` that observes
the same headers missing is exactly the corroboration ADR 0006 described. Other
rules stay static-only until each has an honest runtime signal of its own —
adding probes that cannot corroborate would only raise confidence theatre.

**Confidence filtering happens after correlation.** A `Possible` static finding
must still be present so a matching dynamic observation can raise it. Filtering
on `--min-confidence` before that pass would make `Confirmed` unreachable for
the cases that need it most.

## Consequences

- `watch` refuses `--target`. Re-probing on every save is hostile to the
  developer's own server (REVIEW.md L1) and stays out of scope.
- `--ci` with `--target` is allowed: the operator named the host on the command
  line. There is still no path from repository content to the request URL.
- `Location::Endpoint` findings appear only when dynamic ran without a matching
  static finding; correlated results keep the source location and carry the
  probed URL in `context.evidence`.
- A04 remains out of reach. Passive probes do not find design flaws.
- Active checks, authenticated scans, and crawling beyond the target URL are
  not part of this decision.
