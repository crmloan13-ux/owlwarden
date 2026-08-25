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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadOptions {
    /// When true, refuse plugins whose detached signature did not verify against
    /// a configured trust root.
    pub require_signed_plugins: bool,
    /// The operator's project root, the only directory a trust file is read
    /// from besides [`ENV_TRUST`].
    ///
    /// # Why this is not the plugin's own directory
    ///
    /// It used to be — `plugin_dir/.owlwarden/plugin-trust.json` and the same
    /// path one level up. Both are inside the artifact being verified, so a
    /// plugin could sign itself with a key it generated, ship the public half
    /// beside the signature, and come back `Verified`. That is not a weakened
    /// check; it is the complete absence of one, and it made
    /// `--require-signed-plugins` a flag that refused nothing.
    ///
    /// A signature answers "which author is this?", and the list of acceptable
    /// authors has to come from the person asking. `None` means the environment
    /// variable is the only source.
    pub trust_root_dir: Option<PathBuf>,
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
    trust_root_dir: Option<&Path>,
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    module_path: &Path,
) -> ArtifactInspection {
    let digest = digest_status(manifest, wasm_bytes);
    let signature = signature_status(trust_root_dir, wasm_bytes, module_path);
    ArtifactInspection { digest, signature }
}

/// Verifies digest (when declared) and enforces signature policy.
///
/// # Errors
/// [`PluginError`] on digest mismatch, or when [`LoadOptions::require_signed_plugins`]
/// is set and the signature did not verify.
pub fn enforce_artifact_policy(
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    module_path: &Path,
    options: &LoadOptions,
) -> Result<(), PluginError> {
    let inspection = inspect_artifact(
        options.trust_root_dir.as_deref(),
        manifest,
        wasm_bytes,
        module_path,
    );
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

fn signature_status(
    trust_root_dir: Option<&Path>,
    wasm_bytes: &[u8],
    module_path: &Path,
) -> SignatureStatus {
    let sig_path = signature_path(module_path);
    let Some(sig_text) = read_sig_file_optional(&sig_path) else {
        return SignatureStatus::Absent;
    };
    let Ok(signature) = parse_signature(&sig_text) else {
        return SignatureStatus::Untrusted;
    };
    let digest = Sha256::digest(wasm_bytes);
    let keys = match load_trust_roots(trust_root_dir) {
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

fn load_trust_roots(trust_root_dir: Option<&Path>) -> Result<Vec<VerifyingKey>, PluginError> {
    let mut keys = Vec::new();
    keys.extend(parse_env_trust()?);
    if let Some(dir) = trust_root_dir {
        keys.extend(read_trust_file(&dir.join(TRUST_REL_PATH))?);
    }
    if keys.len() > MAX_TRUST_KEYS {
        return Err(PluginError::TooManyTrustKeys {
            max: MAX_TRUST_KEYS,
        });
    }
    Ok(keys)
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
            &manifest,
            b"actual",
            &dir.path().join("plugin.wasm"),
            &LoadOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(error, PluginError::ArtifactDigestMismatch { .. }));
    }

    /// Writes a trust file naming `key` under `dir`.
    fn trust(dir: &Path, key: &VerifyingKey) {
        fs::create_dir_all(dir.join(".owlwarden")).unwrap();
        fs::write(
            dir.join(TRUST_REL_PATH),
            format!(r#"{{"keys":["{}"]}}"#, hex_encode(key.as_bytes())),
        )
        .unwrap();
    }

    /// Signs `wasm` with `signing` and writes the detached signature.
    fn sign(module: &Path, wasm: &[u8], signing: &SigningKey) {
        let sig = signing.sign(Sha256::digest(wasm).as_slice());
        fs::write(
            signature_path(module),
            base64_encode(sig.to_bytes().as_slice()),
        )
        .unwrap();
    }

    #[test]
    fn signed_plugin_verifies_with_trust_root() {
        let _guard = env_guard();
        let wasm = b"signed-wasm";
        let manifest = manifest_with_digest(wasm);
        // Two directories, deliberately: the plugin is the thing being checked,
        // the project is where the operator's answer about authors lives. When
        // these were one directory, the bug below was invisible.
        let plugin = tempdir().unwrap();
        let project = tempdir().unwrap();
        let module = plugin.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        sign(&module, wasm, &signing);
        trust(project.path(), &signing.verifying_key());

        let options = LoadOptions {
            require_signed_plugins: true,
            trust_root_dir: Some(project.path().to_path_buf()),
        };

        let inspection =
            inspect_artifact(options.trust_root_dir.as_deref(), &manifest, wasm, &module);
        assert_eq!(inspection.digest, DigestStatus::Ok);
        assert_eq!(inspection.signature, SignatureStatus::Verified);

        enforce_artifact_policy(&manifest, wasm, &module, &options).unwrap();
    }

    #[test]
    fn a_trust_file_inside_the_plugin_does_not_vouch_for_the_plugin() {
        let _guard = env_guard();
        // The bug this replaced: trust roots were read from the plugin's own
        // directory and from its parent. Both are inside the artifact under
        // verification, so a plugin could generate a key, sign itself, ship the
        // public half beside the signature, and come back `Verified` —
        // `--require-signed-plugins` refused nothing at all.
        let wasm = b"self-signed-wasm";
        let manifest = manifest_with_digest(wasm);
        let plugin = tempdir().unwrap();
        let module = plugin.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        sign(&module, wasm, &signing);
        // The plugin supplies the key that vouches for it, in both places the
        // old implementation looked.
        trust(plugin.path(), &signing.verifying_key());
        trust(plugin.path().parent().unwrap(), &signing.verifying_key());

        let options = LoadOptions {
            require_signed_plugins: true,
            trust_root_dir: None,
        };
        assert_eq!(
            inspect_artifact(None, &manifest, wasm, &module).signature,
            SignatureStatus::Untrusted,
        );
        assert!(matches!(
            enforce_artifact_policy(&manifest, wasm, &module, &options).unwrap_err(),
            PluginError::SignatureRequired { .. }
        ));

        // ...and naming a project root does not resurrect it either.
        let project = tempdir().unwrap();
        let scoped = LoadOptions {
            require_signed_plugins: true,
            trust_root_dir: Some(project.path().to_path_buf()),
        };
        assert!(matches!(
            enforce_artifact_policy(&manifest, wasm, &module, &scoped).unwrap_err(),
            PluginError::SignatureRequired { .. }
        ));
    }

    #[test]
    fn a_trust_file_beside_the_plugin_directory_does_not_vouch_for_it() {
        let _guard = env_guard();
        // The second path the old implementation searched: one level up from
        // the plugin. `--plugin ./vendor/thing` put `./vendor` in scope, which
        // is still inside whatever tree shipped the plugin.
        let wasm = b"sibling-trust-wasm";
        let manifest = manifest_with_digest(wasm);
        let outer = tempdir().unwrap();
        let plugin = outer.path().join("vendor").join("thing");
        fs::create_dir_all(&plugin).unwrap();
        let module = plugin.join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        sign(&module, wasm, &signing);
        trust(&outer.path().join("vendor"), &signing.verifying_key());

        assert_eq!(
            inspect_artifact(None, &manifest, wasm, &module).signature,
            SignatureStatus::Untrusted,
        );
    }

    #[test]
    fn the_environment_alone_is_enough_to_verify() {
        let _guard = env_guard();
        // The operator's shell is a trust source with no directory involved,
        // and it has to keep working when `trust_root_dir` is `None`.
        let wasm = b"env-trusted-wasm";
        let manifest = manifest_with_digest(wasm);
        let plugin = tempdir().unwrap();
        let module = plugin.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        sign(&module, wasm, &signing);

        // SAFETY: `env_guard()` above is held for the rest of this test, and
        // every other test that reads `ENV_TRUST` takes the same guard.
        unsafe {
            std::env::set_var(ENV_TRUST, hex_encode(signing.verifying_key().as_bytes()));
        }
        let status = inspect_artifact(None, &manifest, wasm, &module).signature;
        unsafe {
            std::env::remove_var(ENV_TRUST);
        }
        assert_eq!(status, SignatureStatus::Verified);
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serialises every test whose answer depends on `OWLWARDEN_PLUGIN_TRUST`.
    ///
    /// The environment is process-wide and `cargo test` runs these on threads,
    /// so a test that sets the variable changes the answer for every other test
    /// running at that moment. That is not hypothetical: it made two unrelated
    /// signature tests fail in a workspace run and pass in isolation, which is
    /// the worst way for a suite to be wrong.
    ///
    /// Acquiring the guard also clears the variable, so a test asserting on "no
    /// trust roots configured" is asserting on that and not on whatever the
    /// developer happens to have exported.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        let guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: the guard is held for the duration of the calling test, and
        // every other test that reads this variable takes the same guard.
        unsafe {
            std::env::remove_var(ENV_TRUST);
        }
        guard
    }

    #[test]
    fn require_signed_without_signature_is_refused() {
        let _guard = env_guard();
        let wasm = b"unsigned-wasm";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let error = enforce_artifact_policy(
            &manifest,
            wasm,
            &module,
            &LoadOptions {
                require_signed_plugins: true,
                trust_root_dir: Some(dir.path().to_path_buf()),
            },
        )
        .unwrap_err();
        assert!(matches!(error, PluginError::SignatureRequired { .. }));
    }

    #[test]
    fn require_signed_rejects_wrong_key() {
        let _guard = env_guard();
        let wasm = b"signed-wasm-wrong-key";
        let manifest = manifest_with_digest(wasm);
        let dir = tempdir().unwrap();
        let module = dir.path().join("plugin.wasm");
        fs::write(&module, wasm).unwrap();

        let signing = test_signing_key();
        sign(&module, wasm, &signing);

        // Trust a different key — signature must not verify.
        let project = tempdir().unwrap();
        trust(
            project.path(),
            &SigningKey::from_bytes(&[9u8; 32]).verifying_key(),
        );

        let options = LoadOptions {
            require_signed_plugins: true,
            trust_root_dir: Some(project.path().to_path_buf()),
        };
        let inspection =
            inspect_artifact(options.trust_root_dir.as_deref(), &manifest, wasm, &module);
        assert_eq!(inspection.signature, SignatureStatus::Untrusted);

        let error = enforce_artifact_policy(&manifest, wasm, &module, &options).unwrap_err();
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
