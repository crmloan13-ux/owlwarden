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

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use owlwarden_core::detector::Detector;
use owlwarden_core::limits::plugin as limits;

use crate::detector::WasmDetector;
use crate::error::PluginError;
use crate::integrity::{self, LoadOptions};
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
    load_plugins_with(paths, &LoadOptions::default())
}

/// Like [`load_plugins`] with explicit load policy (ADR 0021).
pub fn load_plugins_with(
    paths: &[PathBuf],
    options: &LoadOptions,
) -> Result<Vec<Arc<dyn Detector>>, PluginError> {
    if paths.len() > limits::MAX_PLUGINS_PER_SCAN {
        return Err(PluginError::TooManyPlugins {
            found: paths.len(),
            max: limits::MAX_PLUGINS_PER_SCAN,
        });
    }

    paths
        .iter()
        .map(|path| {
            load_one_with(path, options).map(|detector| Arc::new(detector) as Arc<dyn Detector>)
        })
        .collect()
}

/// Loads a single plugin from a directory (`owlwarden.plugin.json` +
/// `plugin.wasm`) or a bare `.wasm` file with a sidecar manifest.
///
/// # Errors
/// See [`PluginManifest::parse`] and [`WasmDetector::load`] for the specific
/// [`PluginError`] variants this can return.
pub fn load_one(path: &Path) -> Result<WasmDetector, PluginError> {
    load_one_with(path, &LoadOptions::default())
}

/// Like [`load_one`] with explicit load policy (ADR 0021).
pub fn load_one_with(path: &Path, options: &LoadOptions) -> Result<WasmDetector, PluginError> {
    let (plugin_dir, manifest_path) = resolve_manifest(path);

    let manifest_bytes = read_bounded(&manifest_path, limits::MAX_MANIFEST_BYTES)
        .map_err(|error| map_read_error(&manifest_path, limits::MAX_MANIFEST_BYTES, error, true))?;
    let manifest_json =
        String::from_utf8(manifest_bytes).map_err(|_error| PluginError::ManifestInvalid {
            path: manifest_path.display().to_string(),
            message: "manifest is not valid UTF-8".to_owned(),
        })?;
    let manifest = PluginManifest::parse(&manifest_json, &manifest_path.display().to_string())?;

    let module_path = integrity::module_path(&plugin_dir, &manifest);
    let wasm_bytes =
        read_bounded(&module_path, limits::MAX_PLUGIN_BYTES as u64).map_err(|error| {
            map_read_error(&module_path, limits::MAX_PLUGIN_BYTES as u64, error, false)
        })?;

    integrity::enforce_artifact_policy(&plugin_dir, &manifest, &wasm_bytes, &module_path, options)?;

    WasmDetector::load(&manifest, &wasm_bytes)
}

/// Resolves `path` to `(plugin_dir, manifest_path)` without reading bytes.
fn resolve_manifest(path: &Path) -> (PathBuf, PathBuf) {
    if path.is_dir() {
        return (path.to_path_buf(), path.join(MANIFEST_FILENAME));
    }
    let plugin_dir = path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut sidecar = path.to_path_buf();
    sidecar.set_extension("plugin.json");
    let manifest = if sidecar.is_file() {
        sidecar
    } else {
        plugin_dir.join(MANIFEST_FILENAME)
    };
    (plugin_dir, manifest)
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

        fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        // Windows has no portable O_NOFOLLOW; refuse a final-component symlink
        // via symlink_metadata, then open. TOCTOU remains — same residual as
        // other Windows sandbox boundaries in this crate.
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

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;
    use crate::integrity::sha256_hex;

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

    fn manifest_with_digest(wasm: &[u8]) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "id": "demo-plugin",
                "version": "0.1.0",
                "artifact": {{ "path": "plugin.wasm", "sha256": "{}" }},
                "rules": [{{
                    "id": "demo-plugin-rule",
                    "title": "Demo",
                    "severity": "medium",
                    "maxConfidence": "likely",
                    "category": "demo",
                    "description": "A demonstration rule."
                }}]
            }}"#,
            sha256_hex(wasm)
        )
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
    fn matching_declared_digest_loads() {
        let wasm = trivial_wasm();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            manifest_with_digest(&wasm),
        )
        .unwrap();
        fs::write(dir.path().join(MODULE_FILENAME), &wasm).unwrap();

        load_one(dir.path()).unwrap();
    }

    #[test]
    fn digest_mismatch_refuses_load() {
        let wasm = trivial_wasm();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            manifest_with_digest(&wasm),
        )
        .unwrap();
        fs::write(dir.path().join(MODULE_FILENAME), b"tampered").unwrap();

        assert!(matches!(
            load_one(dir.path()),
            Err(PluginError::ArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn signed_plugin_loads_with_trust_root_and_require_signed() {
        let wasm = trivial_wasm();
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            manifest_with_digest(&wasm),
        )
        .unwrap();
        let module = dir.path().join(MODULE_FILENAME);
        fs::write(&module, &wasm).unwrap();

        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let digest = Sha256::digest(&wasm);
        let sig = signing.sign(digest.as_slice());
        fs::write(
            format!("{}.sig", module.display()),
            base64_encode(sig.to_bytes().as_slice()),
        )
        .unwrap();

        fs::create_dir_all(dir.path().join(".owlwarden")).unwrap();
        let hex_key = hex_encode(signing.verifying_key().as_bytes());
        fs::write(
            dir.path().join(".owlwarden/plugin-trust.json"),
            format!(r#"{{"keys":["{hex_key}"]}}"#),
        )
        .unwrap();

        load_one_with(
            dir.path(),
            &LoadOptions {
                require_signed_plugins: true,
            },
        )
        .unwrap();
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

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut index = 0;
        while index < bytes.len() {
            let b0 = bytes[index];
            let b1 = bytes.get(index + 1).copied().unwrap_or(0);
            let b2 = bytes.get(index + 2).copied().unwrap_or(0);
            out.push(TABLE[(b0 >> 2) as usize] as char);
            out.push(TABLE[(((b0 & 0x3) << 4) | (b1 >> 4)) as usize] as char);
            if index + 1 < bytes.len() {
                out.push(TABLE[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if index + 2 < bytes.len() {
                out.push(TABLE[(b2 & 0x3f) as usize] as char);
            } else if index + 1 < bytes.len() {
                out.push('=');
            }
            index += 3;
        }
        out
    }
}
