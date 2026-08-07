//! Turns a list of plugin paths into loaded [`Detector`]s.
//!
//! Every path is untrusted the same way a config file is: a manifest here is
//! read before any sandbox exists, so its size is capped
//! ([`limits::MAX_MANIFEST_BYTES`]) before a single byte reaches `serde_json`,
//! and the module bytes are capped ([`limits::MAX_PLUGIN_BYTES`]) before
//! wasmtime spends any time compiling them.
//!
//! Reads use `O_NOFOLLOW` + `Read::take` — never trust `metadata().len()` then
//! `fs::read`, which races a growing file and follows a final-component
//! symlink (same contract as `owlwarden_static::safe_io::read_bounded`).

use std::fs::{File, OpenOptions};
use std::io::Read;
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

    let manifest_bytes = read_bounded(&manifest_path, limits::MAX_MANIFEST_BYTES)
        .map_err(|error| map_read_error(&manifest_path, limits::MAX_MANIFEST_BYTES, error, true))?;
    let manifest_json =
        String::from_utf8(manifest_bytes).map_err(|_error| PluginError::ManifestInvalid {
            path: manifest_path.display().to_string(),
            message: "manifest is not valid UTF-8".to_owned(),
        })?;
    let manifest = PluginManifest::parse(&manifest_json, &manifest_path.display().to_string())?;

    let wasm_bytes =
        read_bounded(&module_path, limits::MAX_PLUGIN_BYTES as u64).map_err(|error| {
            map_read_error(&module_path, limits::MAX_PLUGIN_BYTES as u64, error, false)
        })?;

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

fn map_read_error(path: &Path, max: u64, error: std::io::Error, is_manifest: bool) -> PluginError {
    if error.kind() == std::io::ErrorKind::InvalidData {
        if is_manifest {
            return PluginError::ManifestTooLarge {
                path: path.display().to_string(),
                size: max.saturating_add(1),
                max,
            };
        }
        return PluginError::ModuleTooLarge {
            path: path.display().to_string(),
            size: max.saturating_add(1),
            max,
        };
    }
    PluginError::Io {
        path: path.display().to_string(),
        source: error,
    }
}

/// Opens `path` without following a final-component symlink, then reads at
/// most `max_bytes`. Same contract as `owlwarden_static::safe_io::read_bounded`
/// — duplicated here so `plugin-host` does not pull the whole static engine.
fn read_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut file = open_nofollow(path)?;
    let mut buf = Vec::new();
    let limit = max_bytes.saturating_add(1);
    Read::take(Read::by_ref(&mut file), limit).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} bytes"),
        ));
    }
    Ok(buf)
}

fn open_nofollow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW: i32 = 0x20000;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW: i32 = 0x100;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )))]
        const O_NOFOLLOW: i32 = 0;

        OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to read through a symlink",
            ));
        }
        File::open(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::fs;
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;

    const MANIFEST: &str = r#"{
        "schemaVersion": 1,
        "id": "demo-plugin",
        "version": "0.1.0",
        "rules": [
            {
                "id": "demo-plugin-rule",
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

    #[test]
    fn an_oversized_manifest_is_refused_without_reading_the_rest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        let mut file = fs::File::create(&path).unwrap();
        // Write past the cap; Read::take must stop and report InvalidData.
        let chunk = vec![b'x'; 4096];
        let mut written = 0u64;
        while written <= limits::MAX_MANIFEST_BYTES {
            file.write_all(&chunk).unwrap();
            written += chunk.len() as u64;
        }
        drop(file);
        fs::write(dir.path().join(MODULE_FILENAME), trivial_wasm()).unwrap();

        assert!(matches!(
            load_one(dir.path()),
            Err(PluginError::ManifestTooLarge { .. })
        ));
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_manifest_is_refused() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.json");
        fs::write(&real, MANIFEST).unwrap();
        let link = dir.path().join(MANIFEST_FILENAME);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        fs::write(dir.path().join(MODULE_FILENAME), trivial_wasm()).unwrap();

        assert!(matches!(load_one(dir.path()), Err(PluginError::Io { .. })));
    }
}
