# 0021. Plugin artifact integrity and local trust roots

**Status:** Accepted
**Date:** 2026-08-11

## Context

ADR 0018 made `plugin inspect` a local capability preview, not a marketplace.
ROADMAP still puts a curated remote registry beyond 1.0. What we can ship now
is integrity + optional signatures so a tree cannot quietly swap `plugin.wasm`.

## Decision

**Integrity first, signatures second, no remote store.**

1. Manifest may declare `artifact: { "path": "plugin.wasm", "sha256": "<hex>" }`.
   When present, the host refuses to load if the file's SHA-256 mismatches.
2. Optional detached signature: `<artifact>.sig` containing base64 ed25519
   signature over the raw SHA-256 digest bytes (32 bytes), verified against
   trust roots from `OWLWARDEN_PLUGIN_TRUST` (colon-separated hex public keys)
   and/or `.owlwarden/plugin-trust.json` in the project (`{ "keys": ["…"] }`).
3. `owlwarden plugin inspect` reports `digest: ok|mismatch|absent` and
   `signature: verified|untrusted|absent` without instantiating WASM.
4. `--require-signed-plugins` (and under `--ci` the same flag) refuses plugins
   that are not signature-verified. Off by default so local scaffolds still
   work.

**Still source-only.** Network/active caps remain refused (ADR 0015). A signed
malicious source-only plugin can still emit findings — trust roots choose
authors, they do not expand the sandbox.

**No hosted registry in this ADR.** Publishing, discovery, and revocation lists
stay later work.

## As shipped

§2 says trust roots come from `.owlwarden/plugin-trust.json` "in the project".
The 1.0 implementation read it from the *plugin's* directory and from that
directory's parent instead — both inside the artifact being verified. A plugin
could generate a key, sign itself, ship the public half beside the signature,
and be reported `verified`; `--require-signed-plugins` refused nothing.

Fixed in 1.1. `LoadOptions::trust_root_dir` is supplied by the caller and set to
the scan root, and the plugin directory is no longer consulted. `inspect_artifact`
takes the trust directory rather than deriving it, so there is no path by which
the artifact can name its own roots.

**Residual, accepted:** the scan root's trust file is honoured, so a repository
whose `.owlwarden/plugin-trust.json` was written by a contributor is trusted for
plugins the operator explicitly passed with `--plugin` in that tree. That is the
same trust the operator already extended by naming the plugin: `vet` refuses
plugins outright, and `--ci` requires `--allow-plugins`.

## Consequences

- New optional manifest fields; old manifests keep loading (unsigned).
- Adds `sha2` + `ed25519-dalek` to `plugin-host` (justified: verify-only,
  no new network).
- Remote "app store" claims remain forbidden in docs and marketing.
