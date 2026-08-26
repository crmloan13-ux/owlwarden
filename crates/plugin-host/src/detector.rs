//! `WasmDetector` — one loaded plugin, wired as a core [`Detector`].
//!
//! The module is compiled once, at load time, and reused for every scan; each
//! [`Detector::run`] creates a fresh [`Store`] so one invocation's state (its
//! findings, its host-call count, its memory) never leaks into the next.
//!
//! # The guest ABI
//!
//! A plugin exports:
//! - `memory` — standard linear memory.
//! - `alloc(len: i32) -> i32` — reserve `len` bytes, return a pointer. Called
//!   once per invocation so the host has somewhere to write the snapshot.
//! - `detect(ptr: i32, len: i32) -> i32` — analyze the snapshot at
//!   `ptr`/`len` (a UTF-8 JSON document, `{"files":[{"path","content"}]}`)
//!   and call `emit_finding` for each hit. The return value is not
//!   otherwise interpreted.
//!
//! and imports exactly one function, under module name `"owlwarden"`:
//! - `emit_finding(ptr: i32, len: i32) -> i32` — submit one finding as JSON
//!   (see [`crate::host`]). Returns `1` if accepted, `0` otherwise.
//!
//! Nothing else is wired. No WASI, no clock, no filesystem, no network.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use async_trait::async_trait;
use owlwarden_core::context::ScanContext;
use owlwarden_core::detector::{Capabilities, Detector, DetectorError, DetectorKind, DetectorMeta};
use owlwarden_core::finding::{Confidence, Finding, RuleId, Severity};
use owlwarden_core::limits::plugin as limits;
use owlwarden_core::source::FileSelector;
use owlwarden_core::surface::Surface;
use serde::Serialize;
use wasmtime::{Config, Engine, Instance, Linker, Module, Store, StoreLimitsBuilder};

use crate::error::PluginError;
use crate::host::{HostState, add_emit_finding};
use crate::manifest::PluginManifest;

/// The source snapshot handed to a plugin before `detect` runs.
///
/// Serialized once per invocation and written into the guest's own linear
/// memory — the plugin never gets a handle to [`ScanContext::source`]
/// itself, only these bytes.
#[derive(Debug, Serialize)]
struct Snapshot<'a> {
    files: Vec<SnapshotFile<'a>>,
}

#[derive(Debug, Serialize)]
struct SnapshotFile<'a> {
    path: &'a str,
    content: &'a str,
}

/// One loaded, compiled plugin.
pub struct WasmDetector {
    engine: Engine,
    module: Module,
    plugin_id: String,
    rules: Arc<HashMap<String, DetectorMeta>>,
    capabilities: Capabilities,
    meta: DetectorMeta,
}

impl WasmDetector {
    /// Compiles `wasm_bytes` under a fuel- and epoch-instrumented [`Engine`]
    /// and checks it exports the guest ABI by name.
    ///
    /// # Errors
    /// [`PluginError::ModuleTooLarge`] over [`limits::MAX_PLUGIN_BYTES`];
    /// [`PluginError::Compile`] if wasmtime rejects the bytes;
    /// [`PluginError::AbiMismatch`] if `memory`, `alloc`, or `detect` is
    /// missing. A type mismatch on those exports is caught later, on first
    /// use, because wasmtime only reports types once function types are
    /// resolved against a concrete `Store`.
    pub fn load(manifest: &PluginManifest, wasm_bytes: &[u8]) -> Result<Self, PluginError> {
        let size = u64::try_from(wasm_bytes.len()).unwrap_or(u64::MAX);
        if wasm_bytes.len() > limits::MAX_PLUGIN_BYTES {
            return Err(PluginError::ModuleTooLarge {
                path: manifest.id.clone(),
                size,
                max: limits::MAX_PLUGIN_BYTES as u64,
            });
        }

        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|error| PluginError::Compile {
            path: manifest.id.clone(),
            message: error.to_string(),
        })?;
        let module = Module::new(&engine, wasm_bytes).map_err(|error| PluginError::Compile {
            path: manifest.id.clone(),
            message: error.to_string(),
        })?;

        ensure_abi_exports(&module, &manifest.id)?;

        Ok(Self {
            engine,
            module,
            plugin_id: manifest.id.clone(),
            rules: Arc::new(manifest.rule_map()),
            capabilities: manifest.capabilities.to_core(),
            meta: plugin_meta(manifest),
        })
    }

    /// The plugin's own id, as declared in its manifest.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Builds the JSON snapshot for one invocation, capped by
    /// [`limits::MAX_SNAPSHOT_FILES`] and [`limits::MAX_SNAPSHOT_BYTES`].
    ///
    /// Files are read best-effort: one unreadable file (permissions, a broken
    /// symlink the provider already refused) is skipped rather than failing
    /// the whole invocation — the same posture `StaticEngine` takes.
    fn build_snapshot(ctx: &ScanContext<'_>) -> Result<Vec<u8>, DetectorError> {
        let source = ctx.source();
        let files = source.files(&FileSelector::all())?;

        let mut budget = limits::MAX_SNAPSHOT_BYTES;
        let mut snapshot_files = Vec::new();
        let mut contents: Vec<(String, std::sync::Arc<str>)> = Vec::new();

        for file in files.into_iter().take(limits::MAX_SNAPSHOT_FILES) {
            let Ok(content) = source.read(&file) else {
                continue;
            };
            let cost = content.len();
            if cost > budget {
                break;
            }
            budget -= cost;
            contents.push((file.path.as_str().to_owned(), content));
        }

        for (path, content) in &contents {
            snapshot_files.push(SnapshotFile {
                path: path.as_str(),
                content: content.as_ref(),
            });
        }

        serde_json::to_vec(&Snapshot {
            files: snapshot_files,
        })
        .map_err(|error| DetectorError::Other(format!("could not build plugin snapshot: {error}")))
    }

    /// Instantiates the module in a fresh, capped `Store` and runs `detect`
    /// once.
    fn run_sandboxed(&self, snapshot: &[u8]) -> Result<Vec<Finding>, PluginError> {
        let mut linker = Linker::new(&self.engine);
        add_emit_finding(&mut linker, &self.plugin_id)?;

        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits::MAX_MEMORY_BYTES)
            .table_elements(limits::MAX_TABLE_ELEMENTS)
            .tables(limits::MAX_TABLES)
            .memories(limits::MAX_MEMORIES)
            .instances(1)
            .build();
        let state = HostState::new(Arc::clone(&self.rules), store_limits);
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(limits::MAX_FUEL)
            .map_err(|error| self.runtime_error(&error))?;
        // Trap (rather than yield) once the deadline below is reached; there
        // is no async executor here to yield to.
        store.epoch_deadline_trap();
        store.set_epoch_deadline(1);

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|error| self.runtime_error(&error))?;

        // A watchdog thread is the simplest correct way to turn a wall-clock
        // budget into an epoch tick: wasmtime's own timer support requires an
        // async store, and this crate deliberately stays synchronous (see
        // module docs on why `Detector::run` does not need to be async here).
        let engine_for_watchdog = self.engine.clone();
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let watchdog = thread::spawn(move || {
            if cancel_rx.recv_timeout(limits::MAX_INVOCATION_TIME).is_err() {
                engine_for_watchdog.increment_epoch();
            }
        });

        let outcome = self.call_detect(&instance, &mut store, snapshot);

        drop(cancel_tx);
        let _ = watchdog.join();

        outcome?;
        Ok(store.into_data().into_findings())
    }

    fn call_detect(
        &self,
        instance: &Instance,
        store: &mut Store<HostState>,
        snapshot: &[u8],
    ) -> Result<(), PluginError> {
        let len = i32::try_from(snapshot.len()).map_err(|_| PluginError::AbiMismatch {
            id: self.plugin_id.clone(),
            reason: "snapshot exceeds the addressable range of a 32-bit guest".to_owned(),
        })?;

        let alloc = instance
            .get_typed_func::<i32, i32>(&mut *store, "alloc")
            .map_err(|error| self.abi_error(&error))?;
        let ptr = alloc
            .call(&mut *store, len)
            .map_err(|error| self.runtime_error(&error))?;

        let memory =
            instance
                .get_memory(&mut *store, "memory")
                .ok_or_else(|| PluginError::AbiMismatch {
                    id: self.plugin_id.clone(),
                    reason: "no exported memory".to_owned(),
                })?;
        let offset = usize::try_from(ptr).map_err(|_| PluginError::Runtime {
            id: self.plugin_id.clone(),
            message: format!("alloc returned an out-of-range pointer {ptr}"),
        })?;
        memory
            .write(&mut *store, offset, snapshot)
            .map_err(|error| PluginError::Runtime {
                id: self.plugin_id.clone(),
                message: format!("writing the snapshot into guest memory failed: {error}"),
            })?;

        let detect = instance
            .get_typed_func::<(i32, i32), i32>(&mut *store, "detect")
            .map_err(|error| self.abi_error(&error))?;
        detect
            .call(&mut *store, (ptr, len))
            .map_err(|error| self.runtime_error(&error))?;
        Ok(())
    }

    fn abi_error(&self, error: &wasmtime::Error) -> PluginError {
        PluginError::AbiMismatch {
            id: self.plugin_id.clone(),
            reason: error.to_string(),
        }
    }

    /// Turns a wasmtime failure into a typed [`PluginError`], naming a
    /// timeout distinctly from any other trap so callers (and tests) can
    /// tell "the plugin ran too long" apart from "the plugin crashed".
    fn runtime_error(&self, error: &wasmtime::Error) -> PluginError {
        if matches!(
            error.downcast_ref::<wasmtime::Trap>(),
            Some(wasmtime::Trap::Interrupt)
        ) {
            return PluginError::TimedOut {
                id: self.plugin_id.clone(),
                limit: limits::MAX_INVOCATION_TIME,
            };
        }
        PluginError::Runtime {
            id: self.plugin_id.clone(),
            message: error.to_string(),
        }
    }
}

fn ensure_abi_exports(module: &Module, plugin_id: &str) -> Result<(), PluginError> {
    let names: Vec<&str> = module.exports().map(|export| export.name()).collect();
    for required in ["memory", "alloc", "detect"] {
        if !names.contains(&required) {
            return Err(PluginError::AbiMismatch {
                id: plugin_id.to_owned(),
                reason: format!("missing required export {required:?}"),
            });
        }
    }
    Ok(())
}

/// Synthesizes the meta this `Detector` reports for itself.
///
/// Mirrors `StaticEngine`'s own `meta()`: it identifies the engine, not any
/// one vulnerability class — the plugin's actual rule ids travel on the
/// findings it produces, via [`crate::host::HostState`].
fn plugin_meta(manifest: &PluginManifest) -> DetectorMeta {
    let severity = manifest
        .rules
        .iter()
        .map(|rule| rule.meta.severity)
        .max()
        .unwrap_or(Severity::Info);
    let max_confidence = manifest
        .rules
        .iter()
        .map(|rule| rule.meta.max_confidence)
        .max()
        .unwrap_or(Confidence::Possible);

    // The manifest id already passed the same charset/length check as a rule
    // id (`manifest::validate_id`), so this only falls back to the generic
    // "plugin" id in practice if that check's rules ever drift from
    // `RuleId::parse`'s — never in normal operation.
    let id = RuleId::parse(&manifest.id).unwrap_or_else(|_| RuleId::new_static("plugin"));

    DetectorMeta {
        id,
        title: format!("Plugin: {}", manifest.id).into(),
        severity,
        max_confidence,
        owasp: None,
        asi: None,
        cwe: None,
        surface: Surface::WebApp,
        category: "plugin".into(),
        description: format!(
            "External detector loaded from a WASM plugin ({} rule(s)).",
            manifest.rules.len()
        )
        .into(),
    }
}

#[async_trait]
impl Detector for WasmDetector {
    fn meta(&self) -> DetectorMeta {
        self.meta.clone()
    }

    fn kind(&self) -> DetectorKind {
        // v0.2 ships source-only plugins; `capabilities()` is what the
        // scheduler actually gates on, this is a display-only classification.
        DetectorKind::Static
    }

    fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    async fn run(&self, ctx: &ScanContext<'_>) -> Result<Vec<Finding>, DetectorError> {
        let snapshot = Self::build_snapshot(ctx)?;
        self.run_sandboxed(&snapshot)
            .map_err(|error| DetectorError::Other(error.to_string()))
    }
}
