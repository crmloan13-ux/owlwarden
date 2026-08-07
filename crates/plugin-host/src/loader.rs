//! Turns a list of plugin paths into loaded [`Detector`]s.
//!
//! Every path is untrusted the same way a config file is: a manifest here is
//! read before any sandbox exists, so its size is capped
//! ([`limits::MAX_MANIFEST_BYTES`]) before a single byte reaches `serde_json`,
//! and the module bytes are capped ([`limits::MAX_PLUGIN_BYTES`]) before
//! wasmtime spends any time compiling them.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use owlwarden_core::detector::Detector;
use owlwarden_core::limits::plugin as limits;

use crate::detector::WasmDetector;
use crate::error::PluginError;
use crate::manifest::PluginManifest;

/// Manifest filename expected inside a plugin directory.
pub const MANIFEST_FILENAME: &str = "owlwarden.plugin.json";
/// Module filename expected inside a plugin directory.
pub const MODULE_FILENAME: &str = "plugin.wasm";

/// Loads every plugin named in `paths` as a boxed [`Detector`].
///
/// # Errors
/// [`PluginError::TooManyPlugins`] if `paths.len()` exceeds
/// [`limits::MAX_PLUGINS_PER_SCAN`]. Otherwise, the first plugin that fails
/// to load stops the call: a scan that silently drops some of the plugins it
/// was explicitly asked to load is a worse failure mode than one that names
/// which one broke and refuses to start.
pub fn load_plugins(paths: &[PathBuf]) -> Result<Vec<Arc<dyn Detector>>, PluginError> {
    if paths.len() > limits::MAX_PLUGINS_PER_SCAN {
        return Err(PluginError::TooManyPlugins {
            found: paths.len(),
            max: limits::MAX_PLUGINS_PER_SCAN,
        });
    }

    paths
        .iter()
        .map(|path| load_one(path).map(|detector| Arc::new(detector) as Arc<dyn Detector>))
        .collect()
}

/// Loads a single plugin from a directory (`owlwarden.plugin.json` +
/// `plugin.wasm`) or a bare `.wasm` file with a sidecar manifest.
///
/// # Errors
/// See [`PluginManifest::parse`] and [`WasmDetector::load`] for the specific
/// [`PluginError`] variants this can return.
pub fn load_one(path: &Path) -> Result<WasmDetector, PluginError> {
    let (manifest_path, module_path) = resolve_paths(path);

    let manifest_bytes = read_bounded(&manifest_path, limits::MAX_MANIFEST_BYTES)?;
    let manifest_json =
        String::from_utf8(manifest_bytes).map_err(|_error| PluginError::ManifestInvalid {
            path: manifest_path.display().to_string(),
            message: "manifest is not valid UTF-8".to_owned(),
        })?;
    let manifest = PluginManifest::parse(&manifest_json, &manifest_path.display().to_string())?;

    let wasm_bytes = read_bounded(&module_path, limits::MAX_PLUGIN_BYTES as u64)?;

    WasmDetector::load(&manifest, &wasm_bytes)
}

/// Resolves `path` to a `(manifest, module)` pair without touching the
/// filesystem beyond `is_dir` — the actual reads happen in [`read_bounded`],
/// which is where a missing file becomes a typed error.
fn resolve_paths(path: &Path) -> (PathBuf, PathBuf) {
    if path.is_dir() {
        return (path.join(MANIFEST_FILENAME), path.join(MODULE_FILENAME));
    }
    let mut sidecar = path.to_path_buf();
    sidecar.set_extension("plugin.json");
    let manifest = if sidecar.is_file() {
        sidecar
    } else {
        path.with_file_name(MANIFEST_FILENAME)
    };
    (manifest, path.to_path_buf())
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, PluginError> {
    let to_io_error = |source: std::io::Error| PluginError::Io {
        path: path.display().to_string(),
        source,
    };
    let metadata = fs::metadata(path).map_err(to_io_error)?;
    if metadata.len() > max {
        return Err(PluginError::ManifestTooLarge {
            path: path.display().to_string(),
            size: metadata.len(),
            max,
        });
    }
    fs::read(path).map_err(to_io_error)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::fs;

    use tempfile::tempdir;

    use super::*;

    const MANIFEST: &str = r#"{
        "schemaVersion": 1,
        "id": "demo-plugin",
        "version": "0.1.0",
        "rules": [
            {
                "id": "demo-rule",
                "title": "Demo",
                "severity": "medium",
                "maxConfidence": "likely",
                "category": "demo",
                "description": "A demonstration rule."
            }
        ]
    }"#;

    fn trivial_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"(module
                (import "owlwarden" "emit_finding" (func (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "alloc") (param i32) (result i32) i32.const 0)
                (func (export "detect") (param i32 i32) (result i32) i32.const 0))"#,
        )
        .unwrap()
    }

    #[test]
    fn a_plugin_directory_with_both_files_loads() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(MANIFEST_FILENAME), MANIFEST).unwrap();
        fs::write(dir.path().join(MODULE_FILENAME), trivial_wasm()).unwrap();

        let detector = load_one(dir.path()).unwrap();
        assert_eq!(detector.plugin_id(), "demo-plugin");
    }

    #[test]
    fn a_missing_manifest_is_a_typed_io_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(MODULE_FILENAME), trivial_wasm()).unwrap();

        assert!(matches!(load_one(dir.path()), Err(PluginError::Io { .. })));
    }

    #[test]
    fn more_plugins_than_the_cap_is_refused_before_touching_disk() {
        let paths: Vec<PathBuf> = (0..=limits::MAX_PLUGINS_PER_SCAN)
            .map(|i| PathBuf::from(format!("/nonexistent-{i}")))
            .collect();
        assert!(matches!(
            load_plugins(&paths),
            Err(PluginError::TooManyPlugins { .. })
        ));
    }

    #[test]
    fn a_bare_wasm_file_with_a_sidecar_manifest_loads() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("plugin.plugin.json"), MANIFEST).unwrap();
        let wasm_path = dir.path().join("plugin.wasm");
        fs::write(&wasm_path, trivial_wasm()).unwrap();

        let detector = load_one(&wasm_path).unwrap();
        assert_eq!(detector.plugin_id(), "demo-plugin");
    }
}
