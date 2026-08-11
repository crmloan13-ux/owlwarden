//! Sandboxed WASM plugin host for owlwarden (`ARCHITECTURE.md` §6, v0.2).
//!
//! A plugin is a `.wasm` module plus an `owlwarden.plugin.json` manifest
//! declaring who it is, what rules it contributes, and what it needs. This
//! crate turns that pair into a [`WasmDetector`] the scheduler can run like
//! any other [`Detector`], and is the *only* crate in the workspace allowed
//! to depend on `wasmtime` — see [`docs/adr/0015-plugin-host-wasmtime.md`]
//! for why that boundary is drawn at a whole crate rather than a feature
//! flag, and why `wasmtime` was chosen over the alternatives.
//!
//! # What v0.2 ships
//!
//! Source-only. A plugin can read a capped snapshot of project source and
//! call back into the host exactly once, through `emit_finding`. It cannot
//! reach the network, the filesystem, the clock, or any WASI import — there
//! is no WASI in this host at all, ambient or otherwise. A manifest that
//! declares `network` or `active` is refused at load time
//! ([`capability::ManifestCapabilities::ensure_supported`]) rather than
//! silently downgraded, because a downgrade would let the plugin's own
//! manifest lie about what it does.
//!
//! # The sandbox
//!
//! Every invocation gets a fresh [`wasmtime::Store`] bounded on three axes
//! before the guest runs a single instruction:
//! - **Fuel** (`limits::plugin::MAX_FUEL`) — deterministic compute limit.
//! - **Memory** (`limits::plugin::MAX_MEMORY_BYTES`) — a `StoreLimits`
//!   enforced by wasmtime itself, not requested of the guest.
//! - **Wall clock** (`limits::plugin::MAX_INVOCATION_TIME`) — epoch
//!   interruption ticked by a watchdog thread, belt-and-suspenders on top of
//!   fuel for a plugin that is technically progressing but too slowly.
//!
//! and everything the guest sends back through `emit_finding` is validated
//! against the plugin's *own* manifest before it becomes a [`Finding`] — see
//! [`host::HostState`] for what "validated" means there.
//!
//! # Loading a plugin
//!
//! ```no_run
//! use std::path::PathBuf;
//! use owlwarden_plugin_host::load_plugins;
//!
//! # fn main() -> Result<(), owlwarden_plugin_host::PluginError> {
//! let detectors = load_plugins(&[PathBuf::from("plugins/my-plugin")])?;
//! // `detectors` is `Vec<Arc<dyn Detector>>` — hand it to the scheduler
//! // alongside the first-party detectors.
//! # Ok(())
//! # }
//! ```
//!
//! `plugins/my-plugin/` must contain `owlwarden.plugin.json` and
//! `plugin.wasm` (or pass a bare `.wasm` path with a sidecar
//! `<name>.plugin.json` beside it — see [`loader::load_one`]).
//!
//! [`Finding`]: owlwarden_core::finding::Finding
//! [`Detector`]: owlwarden_core::detector::Detector

pub mod capability;
pub mod detector;
pub mod error;
pub mod host;
pub mod integrity;
pub mod loader;
pub mod manifest;

pub use capability::ManifestCapabilities;
pub use detector::WasmDetector;
pub use error::PluginError;
pub use integrity::{
    ArtifactInspection, DigestStatus, LoadOptions, SignatureStatus, inspect_artifact, module_path,
};
pub use loader::{
    MANIFEST_FILENAME, MODULE_FILENAME, load_one, load_one_with, load_plugins, load_plugins_with,
};
pub use manifest::{PluginArtifact, PluginManifest, PluginRule, SCHEMA_VERSION};
