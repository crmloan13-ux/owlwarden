//! Plugin artifact digest and detached ed25519 signature verification (ADR 0021).
//!
//! Integrity is checked before wasmtime compiles anything. Trust roots come from
//! the environment and optional project-local files — no remote registry.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::PluginError;
use crate::manifest::PluginManifest;

/// Maximum relative artifact path length in a manifest.
const MAX_ARTIFACT_PATH_BYTES: usize = 256;
/// Maximum ed25519 public keys loaded from any one trust source.
const MAX_TRUST_KEYS: usize = 32;
/// Largest `.sig` file we will read (base64 ed25519 is ~88 bytes).
const MAX_SIG_FILE_BYTES: usize = 256;
/// Trust file relative to a plugin or project root.
const TRUST_REL_PATH: &str = ".owlwarden/plugin-trust.json";
/// Colon-separated hex ed25519 public keys (`32` bytes → `64` hex chars each).
const ENV_TRUST: &str = "OWLWARDEN_PLUGIN_TRUST";

/// Options controlling plugin load policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// When true, refuse plugins whose detached signature did not verify against
    /// a configured trust root.
    pub require_signed_plugins: bool,
}

/// Result of comparing manifest `artifact.sha256` to file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestStatus {
    /// Manifest declares no `artifact.sha256`.
    Absent,
    /// Declared digest matches the module bytes.
    Ok,
    /// Declared digest does not match.
    Mismatch,
}

/// Result of verifying `<artifact>.sig` against trust roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// No signature file beside the artifact.
    Absent,
    /// Signature verified against a trust root.
    Verified,
    /// Signature present but not trusted (missing roots, bad encoding, or no match).
    Untrusted,
}

/// Non-loading inspection of digest + signature status (ADR 0021 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactInspection {
    /// Manifest digest check outcome.
    pub digest: DigestStatus,
    /// Detached signature check outcome.
    pub signature: SignatureStatus,
}

/// Resolves the WASM module path for a plugin directory and manifest.
///
/// Uses `manifest.artifact.path` when present, otherwise `plugin.wasm`.
#[must_use]
pub fn module_path(plugin_dir: &Path, manifest: &PluginManifest) -> PathBuf {
    manifest.artifact.as_ref().map_or_else(
        || plugin_dir.join(super::loader::MODULE_FILENAME),
        |artifact| plugin_dir.join(&artifact.path),
    )
}

/// Inspects digest and signature without loading WASM.
#[must_use]
pub fn inspect_artifact(
    plugin_dir: &Path,
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    module_path: &Path,
) -> ArtifactInspection {
    let digest = digest_status(manifest, wasm_bytes);
    let signature = signature_status(plugin_dir, wasm_bytes, module_path);
    ArtifactInspection { digest, signature }
}

/// Verifies digest (when declared) and enforces signature policy.
///
/// # Errors
/// [`PluginError`] on digest mismatch, or when [`LoadOptions::require_signed_plugins`]
/// is set and the signature did not verify.
pub fn enforce_artifact_policy(
    plugin_dir: &Path,
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    module_path: &Path,
    options: &LoadOptions,
) -> Result<(), PluginError> {
    let inspection = inspect_artifact(plugin_dir, manifest, wasm_bytes, module_path);
    if inspection.digest == DigestStatus::Mismatch {
        let expected = manifest
            .artifact
            .as_ref()
            .map(|artifact| artifact.sha256.as_str())
            .unwrap_or("");
        return Err(PluginError::ArtifactDigestMismatch {
            path: module_path.display().to_string(),
            expected: expected.to_owned(),
            actual: sha256_hex(wasm_bytes),
        });
    }
    if options.require_signed_plugins && inspection.signature != SignatureStatus::Verified {
        return Err(PluginError::SignatureRequired {
            id: manifest.id.clone(),
            path: module_path.display().to_string(),
        });
    }
    Ok(())
}

fn digest_status(manifest: &PluginManifest, wasm_bytes: &[u8]) -> DigestStatus {
    let Some(artifact) = &manifest.artifact else {
        return DigestStatus::Absent;
    };
    if sha256_hex(wasm_bytes).eq_ignore_ascii_case(&artifact.sha256) {
        DigestStatus::Ok
    } else {
        DigestStatus::Mismatch
    }
}

fn signature_status(plugin_dir: &Path, wasm_bytes: &[u8], module_path: &Path) -> SignatureStatus {
    let sig_path = signature_path(module_path);
    let Some(sig_text) = read_sig_file_optional(&sig_path) else {
        return SignatureStatus::Absent;
    };
    let Ok(signature) = parse_signature(&sig_text) else {
        return SignatureStatus::Untrusted;
    };
    let digest = Sha256::digest(wasm_bytes);
    let keys = match load_trust_roots(plugin_dir) {
        Ok(keys) => keys,
        Err(_) => return SignatureStatus::Untrusted,
    };
    if keys.is_empty() {
        return SignatureStatus::Untrusted;
    }
    if keys
        .iter()
        .any(|key| key.verify(digest.as_slice(), &signature).is_ok())
    {
        SignatureStatus::Verified
    } else {
        SignatureStatus::Untrusted
    }
}

fn signature_path(module_path: &Path) -> PathBuf {
    let mut sig_name = module_path.file_name().map_or_else(
        || std::ffi::OsString::from("plugin.wasm"),
        std::ffi::OsString::from,
    );
    sig_name.push(".sig");
    match module_path.parent() {
        Some(parent) => parent.join(sig_name),
        None => PathBuf::from(sig_name),
    }
}

fn read_sig_file_optional(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > MAX_SIG_FILE_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn parse_signature(text: &str) -> Result<Signature, ()> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SIG_FILE_BYTES {
        return Err(());
    }
    let bytes = decode_base64(trimmed)?;
    Signature::from_slice(&bytes).map_err(|_| ())
}

/// Validates and normalises `artifact` from a manifest.
pub(crate) fn parse_artifact(
    path: String,
    sha256: String,
) -> Result<crate::manifest::PluginArtifact, PluginError> {
    if path.is_empty() {
        return Err(PluginError::InvalidArtifact {
            message: "artifact.path is empty".to_owned(),
        });
    }
    if path.len() > MAX_ARTIFACT_PATH_BYTES {
        return Err(PluginError::InvalidArtifact {
            message: format!("artifact.path exceeds {MAX_ARTIFACT_PATH_BYTES} bytes"),
        });
    }
    if path.contains('\\') || path.starts_with('/') || path.contains("..") {
        return Err(PluginError::InvalidArtifact {
            message: "artifact.path must be a relative path without '..'".to_owned(),
        });
    }
    let normalized = parse_sha256_hex(&sha256).ok_or_else(|| PluginError::InvalidArtifact {
        message: "artifact.sha256 must be 64 hex characters".to_owned(),
    })?;
    Ok(crate::manifest::PluginArtifact {
        path,
        sha256: normalized,
    })
}

fn parse_sha256_hex(raw: &str) -> Option<String> {
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
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

fn load_trust_roots(plugin_dir: &Path) -> Result<Vec<VerifyingKey>, PluginError> {
    let mut keys = Vec::new();
    keys.extend(parse_env_trust()?);
    for trust_path in trust_file_paths(plugin_dir) {
        keys.extend(read_trust_file(&trust_path)?);
        if keys.len() > MAX_TRUST_KEYS {
            return Err(PluginError::TooManyTrustKeys {
                max: MAX_TRUST_KEYS,
            });
        }
    }
    keys.truncate(MAX_TRUST_KEYS);
    Ok(keys)
}

fn trust_file_paths(plugin_dir: &Path) -> [PathBuf; 2] {
    [
        plugin_dir.join(TRUST_REL_PATH),
        plugin_dir
            .parent()
            .unwrap_or(plugin_dir)
            .join(TRUST_REL_PATH),
    ]
}

fn parse_env_trust() -> Result<Vec<VerifyingKey>, PluginError> {
    let Some(raw) = std::env::var(ENV_TRUST).ok() else {
        return Ok(Vec::new());
    };
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut keys = Vec::new();
    for (index, entry) in raw.split(':').take(MAX_TRUST_KEYS).enumerate() {
        if entry.is_empty() {
            continue;
        }
        let key = parse_trust_hex(entry).map_err(|message| PluginError::InvalidTrustRoot {
            detail: format!("{ENV_TRUST} entry {index}: {message}"),
        })?;
        keys.push(key);
    }
    Ok(keys)
}

fn read_trust_file(path: &Path) -> Result<Vec<VerifyingKey>, PluginError> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path).map_err(|source| PluginError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if bytes.len() > owlwarden_core::limits::plugin::MAX_MANIFEST_BYTES as usize {
        return Err(PluginError::TrustFileInvalid {
            path: path.display().to_string(),
            message: "trust file is too large".to_owned(),
        });
    }
    let file: TrustFile =
        serde_json::from_slice(&bytes).map_err(|error| PluginError::TrustFileInvalid {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    if file.keys.len() > MAX_TRUST_KEYS {
        return Err(PluginError::TooManyTrustKeys {
            max: MAX_TRUST_KEYS,
        });
    }
    file.keys
        .into_iter()
        .take(MAX_TRUST_KEYS)
        .enumerate()
        .map(|(index, hex)| {
            parse_trust_hex(&hex).map_err(|message| PluginError::InvalidTrustRoot {
                detail: format!("{} keys[{index}]: {message}", path.display()),
            })
        })
        .collect()
}

#[derive(Debug, serde::Deserialize)]
struct TrustFile {
    keys: Vec<String>,
}

fn parse_trust_hex(hex: &str) -> Result<VerifyingKey, &'static str> {
    let bytes = parse_fixed_hex(hex, 32)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid ed25519 public key")
}

fn parse_fixed_hex(hex: &str, len: usize) -> Result<[u8; 32], &'static str> {
    if hex.len() != len * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected hex public key");
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex.as_bytes().chunks(2).take(len).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex"),
    }
}

fn decode_base64(input: &str) -> Result<Vec<u8>, ()> {
    let filtered: String = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(char::from)
        .collect();
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for ch in filtered.bytes() {
        let Some(value) = base64_value(ch) else {
            if ch == b'=' {
                break;
            }
            return Err(());
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if out.is_empty() || out.len() > 128 {
        return Err(());
    }
    Ok(out)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => None,
        b'\n' | b'\r' | b'\t' | b' ' => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::fs;

    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::*;
    use crate::manifest::PluginManifest;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn manifest_with_digest(wasm: &[u8]) -> PluginManifest {
        let json = format!(
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
                    "description": "demo"
                }}]
            }}"#,
            sha256_hex(wasm)
        );
        PluginManifest::parse(&json, "owlwarden.plugin.json").unwrap()
    }

    #[test]
    fn matching_digest_passes_policy() {
        let wasm = b"wasm-bytes";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        enforce_artifact_policy(
            dir.path(),
            &manifest,
            wasm,
            &dir.path().join("plugin.wasm"),
            &LoadOptions::default(),
        )
        .unwrap();
    }

    #[test]
    fn digest_mismatch_is_refused() {
        let manifest = manifest_with_digest(b"expected");
        let dir = tempdir().unwrap();
        let error = enforce_artifact_policy(
            dir.path(),
            &manifest,
            b"actual",
            &dir.path().join("plugin.wasm"),
            &LoadOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(error, PluginError::ArtifactDigestMismatch { .. }));
    }

    #[test]
    fn signed_plugin_verifies_with_trust_root() {
        let wasm = b"signed-wasm";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        let digest = Sha256::digest(wasm);
        let sig = signing.sign(digest.as_slice());
        let encoded = base64_encode(sig.to_bytes().as_slice());
        fs::write(signature_path(&module), encoded).unwrap();

        let hex_key = hex_encode(signing.verifying_key().as_bytes());
        fs::create_dir_all(dir.path().join(".owlwarden")).unwrap();
        fs::write(
            dir.path().join(TRUST_REL_PATH),
            format!(r#"{{"keys":["{hex_key}"]}}"#),
        )
        .unwrap();

        let inspection = inspect_artifact(dir.path(), &manifest, wasm, &module);
        assert_eq!(inspection.digest, DigestStatus::Ok);
        assert_eq!(inspection.signature, SignatureStatus::Verified);

        enforce_artifact_policy(
            dir.path(),
            &manifest,
            wasm,
            &module,
            &LoadOptions {
                require_signed_plugins: true,
            },
        )
        .unwrap();
    }

    #[test]
    fn require_signed_without_signature_is_refused() {
        let wasm = b"unsigned-wasm";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let error = enforce_artifact_policy(
            dir.path(),
            &manifest,
            wasm,
            &module,
            &LoadOptions {
                require_signed_plugins: true,
            },
        )
        .unwrap_err();
        assert!(matches!(error, PluginError::SignatureRequired { .. }));
    }

    #[test]
    fn require_signed_rejects_wrong_key() {
        let wasm = b"signed-wasm-wrong-key";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        let digest = Sha256::digest(wasm);
        let sig = signing.sign(digest.as_slice());
        fs::write(
            signature_path(&module),
            base64_encode(sig.to_bytes().as_slice()),
        )
        .unwrap();

        // Trust a different key — signature must not verify.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let hex_key = hex_encode(other.verifying_key().as_bytes());
        fs::create_dir_all(dir.path().join(".owlwarden")).unwrap();
        fs::write(
            dir.path().join(TRUST_REL_PATH),
            format!(r#"{{"keys":["{hex_key}"]}}"#),
        )
        .unwrap();

        let inspection = inspect_artifact(dir.path(), &manifest, wasm, &module);
        assert_eq!(inspection.signature, SignatureStatus::Untrusted);

        let error = enforce_artifact_policy(
            dir.path(),
            &manifest,
            wasm,
            &module,
            &LoadOptions {
                require_signed_plugins: true,
            },
        )
        .unwrap_err();
        assert!(matches!(error, PluginError::SignatureRequired { .. }));
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
