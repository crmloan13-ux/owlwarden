# 0015. Plugin host on wasmtime, source-only in v0.2

**Status:** Accepted
**Date:** 2026-08-08

## Context

`ARCHITECTURE.md` §6 has described a plugin system since v0.0: a WASM tier
for scanning logic, sandboxed and capability-gated, distinct from the
TypeScript "recipe" tier that already runs trusted, in-process. Nothing
implemented it — `crates/plugin-host` did not exist, and the architecture
doc said so plainly rather than shipping a placeholder that would only be
noise.

Owlwarden runs against source nobody on the team vetted, on developer
machines and CI runners. A third-party detector is the same problem one
level up: code from a wider set of authors than the engine's own, running
against the same untrusted trees, and now also capable of being hostile to
the *host* rather than merely wrong about the target. `AGENTS.md`'s two
rules for this whole project — a false positive costs more than a missed
finding, and the tool must not become the vulnerability it hunts — both
apply directly to a plugin author who is not us.

## Decision

**wasmtime, and it is the only crate allowed to depend on it.**
`core` and every rule crate keep `#![forbid(unsafe_code)]` unconditionally;
`plugin-host` is the one exception in the workspace, and in practice adds no
`unsafe` of its own — the sandbox comes entirely from wasmtime's, audited in
one place instead of scattered wherever a rule crate might have reached for
FFI. Alternatives considered:

- **Wasmer** — comparable feature set, smaller community and slower CVE
  response history for a dependency that is now load-bearing for isolation
  itself.
- **A subprocess with seccomp/gVisor** — real isolation, but platform-specific
  (no story on Windows, which is a day-one target per `ARCHITECTURE.md` §2)
  and reintroduces IPC framing as a second boundary to get right.
- **Writing our own interpreter** — the option that best matches "minimal
  dependencies" (ADR 0009) on paper, and the one most likely to have a
  sandbox-escape bug nobody outside this repository has ever tried to find.

wasmtime is a Bytecode Alliance project with fuzzing infrastructure, a
security disclosure process, and exactly the primitives this host needs
built in: fuel-based deterministic compute limits, `StoreLimits` for memory,
and epoch interruption for wall-clock. Rebuilding any one of those correctly
is a bigger risk than depending on a runtime whose whole job is running
untrusted code.

**Floored at 36.0.13, not "26 or 28."** The original plan named 26.x or 28.x
on MSRV grounds alone. Checking the RustSec advisory database (`cargo deny
check`) at implementation time turned up eight open advisories against every
wasmtime release below 36.0.13, several of them sandbox escapes on specific
compiler backends — exactly the failure this crate exists to prevent, not
merely one it should avoid causing elsewhere. Shipping a known-vulnerable
version of the *isolation layer itself* would contradict the reason
`plugin-host` exists. 36.0.13 is the lowest patch that closes all of them
while keeping the crate's MSRV (1.86) under the workspace's own (1.88;
`rust-version.workspace = true`); `cargo deny check` re-verifies this
against the live advisory database on every CI run, so a new disclosure
against 36.x fails the build rather than shipping silently.

**Default features are off; only `cranelift`, `runtime`, and `std` are
enabled.** wasmtime's defaults pull in the component model, WASI-adjacent
tooling, async support, and a profiler — none of which this host uses, since
v0.2 is synchronous, core-wasm-only, and reads no ambient signal an async
runtime or a profiler would need. The profiler in particular depends on
`fxprof-processed-profile`, which pulls the unmaintained `fxhash` crate
(RUSTSEC-2025-0057); trimming to the three features this crate actually
calls removes that dependency rather than allowlisting it. A smaller feature
set is also a smaller attack surface in the literal sense `AGENTS.md`
means by "a security tool's install footprint is part of its argument."

`anyhow` is a direct dependency (not merely transitive) because wasmtime
signals a host-function trap by returning `Err(anyhow::Error)`; there is no
way to use the API without it. `wat` is dev-only: the sandbox-escape suite
assembles adversarial modules from text at test time, so no binary `.wasm`
fixture has to be checked in and hand-decoded by a reviewer to know what it
does.

**v0.2 ships source-only.** A plugin declares capabilities the same way a
first-party detector declares them (`Capabilities` in `core::detector`), but
only `source` has a host function behind it in this release — one wired
import, `owlwarden::emit_finding(ptr, len) -> i32`, and one thing the host
writes into guest memory before calling `detect`: a capped JSON snapshot of
project source. Everything else a WASI-shaped host might offer — clocks,
files, sockets — is simply absent. Not sandboxed-and-denied; not present.
There is no WASI import in this host at all, ambient or otherwise.

**A manifest declaring `network` or `active` is refused at load time**
(`ManifestCapabilities::ensure_supported`), not silently downgraded to
source-only. Downgrading would let a plugin's own manifest lie about what it
does — a plugin author who wrote `"network": true` believing their code runs
requests would ship broken and never know why, and a reviewer reading the
manifest would trust a claim the host quietly ignored.

**Resource caps live beside every other limit, in `core::limits::plugin`,**
not in `plugin-host` itself — `ARCHITECTURE.md` §9's existing invariant, that
a reviewer auditing the resource posture never has to leave one file. The
numbers: 64 MiB memory (`StoreLimits`, enforced by wasmtime, not requested of
the guest), 10,000,000 fuel, a 5-second wall-clock backstop via epoch
interruption (belt-and-suspenders on top of fuel, for a plugin that is
technically making progress but too slowly to be useful), 256 findings and
10,000 host calls per invocation, and an 8 MiB compiled-module ceiling.

**`DetectorMeta`'s text fields became `Cow<'static, str>`.** A first-party
rule still writes `"foo".into()` and borrows a literal for free; a
`WasmDetector` building its metadata from a parsed JSON manifest has no
`'static` string to borrow and needs `Cow::Owned`. One type serves both
without a parallel "owned meta" struct that could drift from the one
`RULES.md` and `explain` already read.

**The wall-clock deadline is ticked by a watchdog thread, not an async
store.** wasmtime's own timeout support requires an async `Store`, which
would mean every detector in the workspace paying for an async runtime
boundary so that one, source-only, single-call-per-invocation plugin type
can time out. A thread that sleeps for `MAX_INVOCATION_TIME` and calls
`Engine::increment_epoch` on wake is the smaller footprint for the same
guarantee, and fuel is the primary defence in practice — the watchdog only
matters for a plugin that is host-call-bound rather than compute-bound.

## Consequences

- A plugin that asks for `network` or `active` cannot be loaded at all in
  v0.2, even if the operator would have accepted the risk. Wiring either is
  future work with its own capability plumbing, not a flag on this one.
- `--plugin` is refused under `--ci` unless `--allow-plugins` is also passed
  — the same trust posture `--allow-baseline` and `--allow-suppressions`
  already established for other tree-controlled opt-ins.
- The guest ABI (`memory`, `alloc(len) -> ptr`, `detect(ptr, len) -> i32`,
  and the one import `emit_finding`) is intentionally the smallest surface
  that lets a plugin analyze a snapshot and report findings. It has no
  story yet for a plugin that wants to stream results or ask for more
  source mid-invocation; that is a v0.3+ question if it turns out to matter.
- Every claim `emit_finding` receives is re-validated against the plugin's
  own declared rule set, its own `max_confidence` ceiling, and
  `RelPath`'s project-root check — the same boundary discipline as any other
  untrusted input, just applied to a caller that is, by construction, always
  untrusted.
