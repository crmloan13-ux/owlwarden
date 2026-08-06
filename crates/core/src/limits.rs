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
pub mod plugin {
    use super::Duration;

    /// Linear memory ceiling per plugin instance.
    pub const MAX_MEMORY_BYTES: usize = 64 * 1024 * 1024;
    /// Wall-clock ceiling per plugin invocation.
    pub const MAX_INVOCATION_TIME: Duration = Duration::from_secs(5);
}
