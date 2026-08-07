//! Every way loading or running a plugin can fail.
//!
//! One enum, `thiserror`-derived, no `unwrap`/`expect`/`panic!` anywhere in
//! this crate's library paths — a hostile plugin is exactly the kind of input
//! a security tool has to fail on cleanly rather than crash on.

use std::time::Duration;

use owlwarden_core::finding::RuleIdError;

/// A plugin could not be loaded, or a loaded plugin could not finish running.
///
/// Loading and running are different failure modes but share one type: both
/// are "this plugin did not work", and a caller building a report entry does
/// not need to know which stage failed, only why.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// The manifest or module file could not be read.
    #[error("could not read {path}: {source}")]
    Io {
        /// Path being read.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The manifest file exceeded [`owlwarden_core::limits::plugin::MAX_MANIFEST_BYTES`].
    #[error("manifest {path} is {size} bytes, over the {max}-byte limit")]
    ManifestTooLarge {
        /// Manifest path.
        path: String,
        /// Actual size.
        size: u64,
        /// Configured cap.
        max: u64,
    },

    /// The manifest was not valid JSON, or did not match the documented shape.
    #[error("manifest {path} is invalid: {message}")]
    ManifestInvalid {
        /// Manifest path.
        path: String,
        /// Parser or validation message.
        message: String,
    },

    /// `schemaVersion` was not one this host understands.
    #[error("manifest {path} declares schemaVersion {found}, this host supports {expected}")]
    UnsupportedSchemaVersion {
        /// Manifest path.
        path: String,
        /// What the manifest declared.
        found: u64,
        /// What we support.
        expected: u32,
    },

    /// The plugin id failed the same charset/length check as a rule id.
    #[error("plugin id {id:?} is invalid: {reason}")]
    InvalidPluginId {
        /// The offending id.
        id: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A field exceeded its length cap. Manifests are untrusted input; a
    /// string of unbounded length must never reach an allocation.
    #[error("manifest field {field} is {len} bytes, over the {max}-byte limit")]
    FieldTooLong {
        /// Field name, e.g. `"rules[0].description"`.
        field: String,
        /// Actual length.
        len: usize,
        /// Configured cap.
        max: usize,
    },

    /// The plugin declared no rules at all, so it cannot contribute findings.
    #[error("plugin {id} declares no rules")]
    NoRules {
        /// Plugin id.
        id: String,
    },

    /// The plugin declared more rules than
    /// [`owlwarden_core::limits::plugin::MAX_RULES_PER_PLUGIN`].
    #[error("plugin {id} declares {found} rules, over the {max} allowed")]
    TooManyRules {
        /// Plugin id.
        id: String,
        /// Rules declared.
        found: usize,
        /// Configured cap.
        max: usize,
    },

    /// A rule id in the manifest failed [`owlwarden_core::finding::RuleId::parse`].
    #[error("plugin rule id {id:?} is invalid: {source}")]
    InvalidRuleId {
        /// The offending id.
        id: String,
        /// Why it was rejected.
        #[source]
        source: RuleIdError,
    },

    /// A plugin rule id must be namespaced under the plugin id so it cannot
    /// collide with a first-party catalogue id (and so suppressions / baselines
    /// cannot be confused across trust boundaries).
    #[error(
        "plugin rule id {id:?} must start with \"{plugin_id}-\"; \
         namespacing keeps plugin findings distinct from the built-in catalogue"
    )]
    RuleIdNotNamespaced {
        /// Plugin id.
        plugin_id: String,
        /// The offending rule id.
        id: String,
    },

    /// Source-only plugins cannot declare `confirmed` — that confidence is
    /// reserved for live correlation ([ADR 0014](../../docs/adr/0014-passive-dynamic-and-correlation.md)).
    #[error(
        "plugin rule {id:?} declares maxConfidence \"confirmed\", which source-only \
         plugins cannot reach; use \"likely\" or \"possible\""
    )]
    ConfidenceTooHigh {
        /// The offending rule id.
        id: String,
    },

    /// The manifest declared `network` or `active`, which this host does not
    /// wire. Refusing to load is the honest response — silently downgrading
    /// the plugin to source-only would contradict what its own manifest says
    /// it needs.
    #[error(
        "plugin {id} declares the {capability} capability, which plugin-host does not grant \
         in v0.2 (source-only detectors); remove it from the manifest to load this plugin"
    )]
    UnsupportedCapability {
        /// Plugin id.
        id: String,
        /// The capability that was refused.
        capability: &'static str,
    },

    /// More plugin directories were requested than
    /// [`owlwarden_core::limits::plugin::MAX_PLUGINS_PER_SCAN`] allows.
    #[error("{found} plugins were requested, over the {max} allowed per scan")]
    TooManyPlugins {
        /// Plugins requested.
        found: usize,
        /// Configured cap.
        max: usize,
    },

    /// The compiled module exceeded
    /// [`owlwarden_core::limits::plugin::MAX_PLUGIN_BYTES`].
    #[error("plugin module {path} is {size} bytes, over the {max}-byte limit")]
    ModuleTooLarge {
        /// Module path.
        path: String,
        /// Actual size.
        size: u64,
        /// Configured cap.
        max: u64,
    },

    /// wasmtime could not compile the module — not valid WASM, or used a
    /// feature we do not enable.
    #[error("plugin module {path} could not be compiled: {message}")]
    Compile {
        /// Module path.
        path: String,
        /// wasmtime's message.
        message: String,
    },

    /// The module compiled but does not satisfy the guest ABI: it is missing
    /// `memory`, `alloc`, or `detect`, or one of them has the wrong type.
    #[error("plugin {id} does not implement the required guest ABI: {reason}")]
    AbiMismatch {
        /// Plugin id.
        id: String,
        /// Which export was missing or wrong.
        reason: String,
    },

    /// Instantiation or a call into the guest failed at runtime: a trap (out
    /// of fuel, memory limit, guest `unreachable`, ...), a timeout, or a host
    /// function returning an error.
    #[error("plugin {id} failed while running: {message}")]
    Runtime {
        /// Plugin id.
        id: String,
        /// Human-readable cause.
        message: String,
    },

    /// The invocation ran past [`owlwarden_core::limits::plugin::MAX_INVOCATION_TIME`].
    #[error("plugin {id} exceeded its {}ms time budget", limit.as_millis())]
    TimedOut {
        /// Plugin id.
        id: String,
        /// The budget that elapsed.
        limit: Duration,
    },
}
