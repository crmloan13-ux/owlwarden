//! Every hard cap in one place.
//!
//! `ARCHITECTURE.md` §9: defaults are overridable in config, but nothing is
//! ever *unbounded*. Any path that turns attacker-controlled size into an
//! allocation clamps first. Keeping the numbers here rather than scattered
//! through the code means a reviewer can audit the whole resource posture by
//! reading one file.

use std::time::Duration;

/// Caps on a single HTTP exchange (dynamic engine).
pub mod http {
    use super::Duration;

    /// Wall-clock ceiling for one request/response.
    pub const TIMEOUT: Duration = Duration::from_secs(15);
    /// Largest response body we will buffer: 8 MiB.
    pub const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;
    /// Redirect hops followed before giving up.
    pub const MAX_REDIRECTS: u8 = 5;
    /// Refuse a compressed body that expands more than this (zip bomb guard).
    pub const MAX_DECOMPRESS_RATIO: u32 = 20;
    /// Largest request body we will send.
    pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
    /// Longest absolute URL we will accept as a target, scope entry, or redirect.
    /// A hostile `Location` must not force multi-megabyte string copies.
    pub const MAX_URL_BYTES: usize = 8 * 1024;
    /// Longest single response header value we retain. Oversized values are
    /// dropped (treated as absent) rather than truncated — a truncated CSP is
    /// worse than a missing one for our detectors.
    pub const MAX_HEADER_VALUE_BYTES: usize = 8 * 1024;
    /// Response headers retained per exchange.
    pub const MAX_RESPONSE_HEADERS: usize = 64;
    /// Request headers a detector may attach to one exchange.
    pub const MAX_REQUEST_HEADERS: usize = 32;
}

/// Caps on a whole scan run.
pub mod scan {
    use super::Duration;

    /// Detectors running at once. Also caps in-flight HTTP.
    pub const MAX_CONCURRENCY: usize = 16;
    /// Detectors a single run will execute. Guards against a config or plugin
    /// set that has grown pathological.
    pub const MAX_DETECTORS: usize = 512;
    /// Findings retained in a report. Beyond this the report is marked
    /// truncated rather than growing without limit — a hostile or simply
    /// enormous target must not exhaust memory.
    pub const MAX_FINDINGS: usize = 10_000;
    /// Wall-clock ceiling for one detector.
    pub const DETECTOR_TIME_SLICE: Duration = Duration::from_secs(60);
    /// Wall-clock ceiling for the whole scan.
    pub const TOTAL_TIME: Duration = Duration::from_secs(600);
    /// HTTP requests one scan may issue in total.
    pub const MAX_REQUESTS: u32 = 10_000;
}

/// Caps on reading project source (static engine).
pub mod source {
    /// Files a single scan will read. A repository with more is either not what
    /// we were pointed at, or is trying to make us walk forever.
    pub const MAX_FILES: usize = 20_000;
    /// Largest single file we will parse: 2 MiB. Bigger files in a TS project
    /// are generated bundles or vendored blobs; parsing them costs seconds and
    /// finds nothing useful.
    pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
    /// Total bytes read in one scan: 512 MiB.
    pub const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
    /// Directory depth walked before we stop descending. Guards against
    /// pathological or symlink-looped trees.
    pub const MAX_DEPTH: usize = 32;
    /// Findings a single file may produce, across all rules. A file that fires
    /// dozens of times is either generated or has tripped a broken rule;
    /// truncating keeps the report readable and the run bounded.
    pub const MAX_FINDINGS_PER_FILE: usize = 64;
    /// Inline suppression directives retained for one scan, across the whole
    /// tree. Matching and the report use the same capped set — otherwise a
    /// hostile repository could inflate memory, or suppress findings that never
    /// appear in `--report-suppressions`.
    pub const MAX_SUPPRESSIONS: usize = 10_000;
    /// Bracket / angle-bracket nesting a source file may contain before we
    /// refuse to hand it to oxc. The parser is recursive with no depth limit of
    /// its own; past a few thousand levels it aborts the process. See
    /// [ADR 0008](../../../docs/adr/0008-bound-parser-recursion.md).
    pub const MAX_NESTING_DEPTH: u32 = 256;
}

/// Caps applied to WASM plugins (`plugin-host`, v0.2).
///
/// `plugin-host` is the only crate allowed to import `wasmtime`
/// (`ARCHITECTURE.md` §3), but the numbers themselves live here so a reviewer
/// auditing the resource posture never has to leave this file.
pub mod plugin {
    use super::Duration;

    /// Linear memory ceiling per plugin instance. Enforced by a
    /// `wasmtime::StoreLimits`, not merely requested of the guest.
    pub const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
    /// Wall-clock ceiling per plugin invocation. Belt-and-suspenders on top of
    /// fuel: fuel bounds compute, this bounds a plugin that is technically
    /// making progress but too slowly to be useful (e.g. host-call-bound).
    pub const MAX_INVOCATION_TIME: Duration = Duration::from_secs(5);
    /// Fuel granted per invocation. Wasmtime decrements fuel on every bounded
    /// unit of work and traps at zero, so a plugin that loops forever is
    /// stopped deterministically rather than merely killed on a timer.
    pub const MAX_FUEL: u64 = 10_000_000;
    /// Largest compiled module we will load: 8 MiB. A legitimate detector
    /// compiles to kilobytes; a module past this is either not what it claims
    /// to be or is trying to make the host spend a long time compiling it.
    pub const MAX_PLUGIN_BYTES: usize = 8 * 1024 * 1024;
    /// Plugins a single scan will load. Guards against a config listing
    /// hundreds of plugin directories turning `scan` into a compile farm.
    pub const MAX_PLUGINS_PER_SCAN: usize = 32;
    /// Findings accepted from one plugin invocation. A plugin that emits more
    /// than this either found a generated file or is flooding the host on
    /// purpose; either way the excess is dropped, not queued.
    pub const MAX_FINDINGS_PER_INVOCATION: usize = 256;
    /// Calls into `emit_finding` a single invocation may make, accepted or
    /// not. Rejected findings still cost a call, so this is the backstop that
    /// keeps a flood from costing the host more than a bounded number of
    /// validations even before [`MAX_FINDINGS_PER_INVOCATION`] applies.
    pub const MAX_HOST_CALLS: u32 = 10_000;
    /// Largest `owlwarden.plugin.json` we will parse: 64 KiB. The manifest is
    /// untrusted input read before any sandboxing exists, so its size is
    /// clamped before the bytes are even handed to `serde_json`.
    pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
    /// Rules a single plugin may declare. Bounds the loop that turns manifest
    /// entries into `DetectorMeta` and the map `emit_finding` validates
    /// against.
    pub const MAX_RULES_PER_PLUGIN: usize = 64;
    /// Files included in the source snapshot handed to one plugin invocation.
    /// Independent of [`crate::limits::source::MAX_FILES`]: that cap is for
    /// the whole scan, this one is for what a single sandboxed guest has to
    /// hold in its 64 MiB of linear memory at once.
    pub const MAX_SNAPSHOT_FILES: usize = 2_000;
    /// Total bytes of source content placed in one snapshot. Comfortably
    /// under [`MAX_MEMORY_BYTES`] so the guest's own analysis has room to work
    /// in without immediately hitting the memory limiter.
    pub const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
    /// Largest `emit_finding` payload the host will read out of guest memory.
    /// The guest supplies `len` itself, so this is what stops a hostile
    /// length from turning one host call into a multi-gigabyte allocation.
    pub const MAX_FINDING_JSON_BYTES: usize = 64 * 1024;
}
