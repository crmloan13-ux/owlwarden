//! Where a trust root may come from.
//!
//! ADR 0021 says trust roots come from `OWLWARDEN_PLUGIN_TRUST` and from
//! `.owlwarden/plugin-trust.json` *in the project*. The distinction is the
//! whole mechanism: `--require-signed-plugins` means "an author I chose signed
//! this", and an author who supplies the list of acceptable authors has been
//! asked to grade their own work.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use owlwarden_plugin_host::{
    LoadOptions, MANIFEST_FILENAME, PluginManifest, SignatureStatus, inspect_artifact,
    load_one_with, module_path,
};
use sha2::{Digest, Sha256};

const WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A plugin directory with an artifact, a valid signature, and a trust file
/// placed wherever the caller asks.
fn plant(root: &Path, trust_at: Option<&Path>) -> std::path::PathBuf {
    let dir = root.join("plugin");
    fs::create_dir_all(&dir).unwrap();

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let digest = Sha256::digest(WASM);
    let signature = key.sign(digest.as_slice());

    fs::write(dir.join("plugin.wasm"), WASM).unwrap();
    fs::write(
        dir.join("plugin.wasm.sig"),
        base64_encode(&signature.to_bytes()),
    )
    .unwrap();
    fs::write(
        dir.join(MANIFEST_FILENAME),
        format!(
            r#"{{"schemaVersion":1,"id":"self-signed","version":"1.0.0",
                 "artifact":{{"path":"plugin.wasm","sha256":"{}"}},
                 "rules":[{{"id":"self-signed-x","title":"x","severity":"low",
                            "maxConfidence":"possible","category":"other",
                            "description":"self-signed"}}]}}"#,
            hex(&Sha256::digest(WASM))
        ),
    )
    .unwrap();

    if let Some(at) = trust_at {
        fs::create_dir_all(at.join(".owlwarden")).unwrap();
        fs::write(
            at.join(".owlwarden/plugin-trust.json"),
            format!(r#"{{"keys":["{}"]}}"#, hex(key.verifying_key().as_bytes())),
        )
        .unwrap();
    }

    dir
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn a_plugin_may_not_supply_the_key_that_vouches_for_it() {
    let tmp = tempfile::tempdir().unwrap();
    // The trust file goes inside the plugin's own directory — everything a
    // self-certifying plugin would ship, and nothing the operator wrote.
    let dir = plant(tmp.path(), None);
    let dir = plant(tmp.path(), Some(&dir));

    assert_ne!(
        signature_of(&dir, None),
        SignatureStatus::Verified,
        "a plugin that ships its own trust root signed off on itself"
    );

    let refused = load_one_with(
        &dir,
        &LoadOptions {
            require_signed_plugins: true,
            trust_root_dir: None,
        },
    );
    assert!(
        refused.is_err(),
        "--require-signed-plugins accepted a self-certified plugin"
    );
}

#[test]
fn the_directory_holding_the_plugin_may_not_supply_it_either() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = plant(tmp.path(), Some(tmp.path()));

    assert_ne!(signature_of(&dir, None), SignatureStatus::Verified);
}

/// Signature status of a plugin directory, without instantiating anything.
fn signature_of(dir: &Path, trust_root: Option<&Path>) -> SignatureStatus {
    let path = dir.join(MANIFEST_FILENAME);
    let manifest = PluginManifest::parse(
        &fs::read_to_string(&path).unwrap(),
        &path.display().to_string(),
    )
    .unwrap();
    let module = module_path(dir, &manifest);
    let bytes = fs::read(&module).unwrap();
    inspect_artifact(trust_root, &manifest, &bytes, &module).signature
}

/// The shared vector both implementations must accept.
///
/// The Rust host and `packages/cli/src/plugin-integrity.ts` verify the same
/// signatures against the same trust roots, in two languages, and 1.1 shipped
/// after finding an independent bug in each: the host trusted keys the plugin
/// supplied, and the mirror could not import a public key at all, so it
/// answered `untrusted` for every signature ever made. Both failed quietly.
///
/// A vector neither side generates is the cheapest thing that would have caught
/// the second one: if either implementation stops accepting these exact bytes,
/// or starts accepting them when it should not, a test fails on that side.
#[test]
fn the_shared_signature_vector_verifies() {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        public_key_hex: String,
        wasm_hex: String,
        digest_hex: String,
        signature_base64: String,
    }

    let raw = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugin-signature-vector.json"),
    )
    .unwrap();
    let vector: Vector = serde_json::from_str(&raw).unwrap();

    let wasm = decode_hex(&vector.wasm_hex);
    assert_eq!(
        hex(Sha256::digest(&wasm).as_slice()),
        vector.digest_hex,
        "the vector's digest does not match its own bytes"
    );

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("plugin");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("plugin.wasm"), &wasm).unwrap();
    fs::write(dir.join("plugin.wasm.sig"), &vector.signature_base64).unwrap();
    fs::write(
        dir.join(MANIFEST_FILENAME),
        format!(
            r#"{{"schemaVersion":1,"id":"vector","version":"1.0.0",
                 "artifact":{{"path":"plugin.wasm","sha256":"{}"}},
                 "rules":[{{"id":"vector-x","title":"x","severity":"low",
                            "maxConfidence":"possible","category":"other",
                            "description":"vector"}}]}}"#,
            vector.digest_hex
        ),
    )
    .unwrap();

    let project = tmp.path().join("project");
    fs::create_dir_all(project.join(".owlwarden")).unwrap();
    fs::write(
        project.join(".owlwarden/plugin-trust.json"),
        format!(r#"{{"keys":["{}"]}}"#, vector.public_key_hex),
    )
    .unwrap();

    assert_eq!(
        signature_of(&dir, Some(&project)),
        SignatureStatus::Verified,
        "the Rust host rejected the shared vector"
    );
    // ...and the same bytes under a trust root that does not name the key.
    assert_eq!(
        signature_of(&dir, Some(tmp.path())),
        SignatureStatus::Untrusted
    );
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
