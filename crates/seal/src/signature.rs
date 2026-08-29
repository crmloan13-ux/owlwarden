//! Detached ed25519 verification for `.owlwarden/surface.lock`.
//!
//! Reuses [ADR 0021](../../../docs/adr/0021-plugin-artifact-signing.md)
//! unchanged: a `.sig` beside the file, base64 over an ed25519 signature of the
//! file's sha256, verified against trust roots that come from **outside the
//! repository**.
//!
//! # Why verify-only
//!
//! Nothing here signs. The signing key lives in a developer's keychain or a CI
//! secret, and that is the property that makes the whole scheme worth having: a
//! process that can write files in the working tree cannot produce a valid
//! signature, so CI's verification is meaningful even when the developer's
//! machine is compromised. A tool that could sign would be a tool with a key to
//! steal.
//!
//! # Why the trust root cannot come from the repository
//!
//! The same reason ADR 0021 moved the plugin trust file out of the plugin
//! directory. If the roots lived in the tree, whatever wrote the drift could
//! also write a key it generated, sign the drifted seal, and come back
//! `Verified` — which is not a weakened check but the complete absence of one.
//!
//! So roots come from `OWLWARDEN_SEAL_TRUST` (colon-separated hex public keys)
//! and from a file the operator names explicitly. Never from the scan root.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Largest `.sig` file read. Base64 ed25519 is about 88 bytes.
const MAX_SIG_BYTES: usize = 256;

/// Most keys accepted from any one source.
const MAX_TRUST_KEYS: usize = 32;

/// Colon-separated hex ed25519 public keys.
pub const ENV_TRUST: &str = "OWLWARDEN_SEAL_TRUST";

/// The outcome of checking a seal's detached signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// No `.sig` beside the lockfile.
    Absent,
    /// Verified against a configured trust root.
    Verified,
    /// A signature is present and did not verify — bad encoding, no roots
    /// configured, or no root matched.
    ///
    /// One value rather than three, deliberately. Every one of them means the
    /// same thing to a caller enforcing `--require-signed-seal`: this seal was
    /// not vouched for by anyone you trust. Splitting them would invite a
    /// caller to treat "no roots configured" as benign, which is exactly the
    /// case an attacker arranges.
    Untrusted,
}

impl SignatureStatus {
    /// One clause for a report.
    #[must_use]
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::Absent => "no signature beside the seal",
            Self::Verified => "signed, and the signature verifies against a configured trust root",
            Self::Untrusted => "a signature is present and did not verify against any trust root",
        }
    }
}

/// Verifies a detached signature over `bytes`.
///
/// `trust_file` is an operator-supplied path, never one inside the scanned
/// tree. Both sources may be empty, in which case any present signature is
/// [`SignatureStatus::Untrusted`] — a signature nobody vouches for is not
/// evidence.
#[must_use]
pub fn verify_detached(
    bytes: &[u8],
    signature_text: Option<&str>,
    trust_file: Option<&Path>,
) -> SignatureStatus {
    verify_detached_with(
        bytes,
        signature_text,
        trust_file,
        std::env::var(ENV_TRUST).ok().as_deref(),
    )
}

/// [`verify_detached`] with the environment's trust roots passed in.
///
/// The environment read is lifted out so the decision is a pure function of its
/// inputs. That matters more here than convenience: this is the check CI relies
/// on, and a test for "a signature with no configured root is untrusted" that
/// had to mutate process environment would be a test that passes or fails
/// depending on what else is running.
#[must_use]
pub fn verify_detached_with(
    bytes: &[u8],
    signature_text: Option<&str>,
    trust_file: Option<&Path>,
    env_trust: Option<&str>,
) -> SignatureStatus {
    let Some(text) = signature_text else {
        return SignatureStatus::Absent;
    };
    let Some(signature) = parse_signature(text) else {
        return SignatureStatus::Untrusted;
    };
    let keys = trust_roots(env_trust, trust_file);
    if keys.is_empty() {
        return SignatureStatus::Untrusted;
    }
    let digest = Sha256::digest(bytes);
    if keys
        .iter()
        .any(|key| key.verify(digest.as_slice(), &signature).is_ok())
    {
        SignatureStatus::Verified
    } else {
        SignatureStatus::Untrusted
    }
}

/// Reads a `.sig` file, if it exists and is small enough to be one.
#[must_use]
pub fn read_signature(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > MAX_SIG_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Every trust root available, from the environment and an explicit file.
fn trust_roots(env_trust: Option<&str>, trust_file: Option<&Path>) -> Vec<VerifyingKey> {
    let mut keys: Vec<VerifyingKey> = Vec::new();
    if let Some(raw) = env_trust {
        for entry in raw.split(':').take(MAX_TRUST_KEYS) {
            if entry.is_empty() {
                continue;
            }
            if let Some(key) = parse_key(entry) {
                keys.push(key);
            }
        }
    }
    if let Some(path) = trust_file {
        keys.extend(read_trust_file(path));
    }
    keys.truncate(MAX_TRUST_KEYS);
    keys
}

#[derive(serde::Deserialize)]
struct TrustFile {
    #[serde(default)]
    keys: Vec<String>,
}

fn read_trust_file(path: &Path) -> Vec<VerifyingKey> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    if bytes.len() > 64 * 1024 {
        return Vec::new();
    }
    let Ok(file) = serde_json::from_slice::<TrustFile>(&bytes) else {
        return Vec::new();
    };
    file.keys
        .iter()
        .take(MAX_TRUST_KEYS)
        .filter_map(|entry| parse_key(entry))
        .collect()
}

fn parse_key(hex: &str) -> Option<VerifyingKey> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let start = index.checked_mul(2)?;
        let pair = trimmed.get(start..start.checked_add(2)?)?;
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    VerifyingKey::from_bytes(&bytes).ok()
}

fn parse_signature(text: &str) -> Option<Signature> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_SIG_BYTES {
        return None;
    }
    let bytes = decode_base64(trimmed)?;
    Signature::from_slice(&bytes).ok()
}

/// Strict base64, no padding tolerance beyond the canonical form.
///
/// Hand-written rather than a dependency, matching
/// [ADR 0009](../../../docs/adr/0009-minimal-dependencies.md): the input is 88
/// bytes and the alternative is a crate in the trust path of a security check.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        if byte == b'=' || byte == b'\n' || byte == b'\r' {
            continue;
        }
        let value = TABLE.iter().position(|candidate| *candidate == byte)?;
        accumulator = (accumulator << 6) | u32::try_from(value).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let shifted = (accumulator >> bits) & 0xff;
            out.push(u8::try_from(shifted).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(bytes: &[u8]) -> (String, String) {
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let digest = Sha256::digest(bytes);
        let signature = key.sign(digest.as_slice());
        (
            base64(&signature.to_bytes()),
            crate::model::hex(key.verifying_key().as_bytes()),
        )
    }

    fn base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut buffer = [0u8; 3];
            for (slot, byte) in buffer.iter_mut().zip(chunk) {
                *slot = *byte;
            }
            let value =
                (u32::from(buffer[0]) << 16) | (u32::from(buffer[1]) << 8) | u32::from(buffer[2]);
            for index in 0..4 {
                if index * 6 > chunk.len() * 8 {
                    out.push('=');
                } else {
                    let slot = usize::try_from((value >> (18 - index * 6)) & 0x3f).unwrap_or(0);
                    out.push(char::from(TABLE.get(slot).copied().unwrap_or(b'A')));
                }
            }
        }
        out
    }

    #[test]
    fn a_signature_verifies_against_a_root_from_outside_the_repository() {
        let bytes = b"{\"schemaVersion\":1}";
        let (signature, key) = signed(bytes);
        let trust = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(trust.path(), format!("{{\"keys\":[\"{key}\"]}}")).unwrap();

        assert_eq!(
            verify_detached(bytes, Some(&signature), Some(trust.path())),
            SignatureStatus::Verified
        );
    }

    #[test]
    fn a_resealed_surface_fails_against_the_old_signature() {
        // The property CI depends on: whatever wrote the drift could rewrite
        // the lockfile, and cannot produce a signature for the new bytes.
        let (signature, key) = signed(b"{\"schemaVersion\":1}");
        let trust = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(trust.path(), format!("{{\"keys\":[\"{key}\"]}}")).unwrap();

        assert_eq!(
            verify_detached(
                b"{\"schemaVersion\":1,\"drift\":true}",
                Some(&signature),
                Some(trust.path())
            ),
            SignatureStatus::Untrusted
        );
    }

    #[test]
    fn a_signature_with_no_configured_root_is_untrusted_not_verified() {
        // The case an attacker arranges: sign with a key you generated, ship
        // the public half, and hope the verifier accepts any root it finds.
        let (signature, _) = signed(b"payload");
        assert_eq!(
            verify_detached_with(b"payload", Some(&signature), None, None),
            SignatureStatus::Untrusted
        );
    }

    #[test]
    fn no_signature_is_absent_rather_than_untrusted() {
        assert_eq!(
            verify_detached_with(b"payload", None, None, None),
            SignatureStatus::Absent
        );
    }

    #[test]
    fn hostile_signature_text_is_refused_without_panicking() {
        for text in ["", "!!!!", &"A".repeat(4096), "====", "\u{0}\u{0}"] {
            assert_eq!(
                verify_detached_with(b"payload", Some(text), None, None),
                SignatureStatus::Untrusted
            );
        }
    }

    #[test]
    fn a_malformed_trust_file_yields_no_keys_rather_than_an_error() {
        let trust = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(trust.path(), "{ not json").unwrap();
        assert!(read_trust_file(trust.path()).is_empty());
    }
}
