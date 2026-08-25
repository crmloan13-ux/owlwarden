# Load and verify WASM plugins

Optional. Built-in rules cover most Node web apps; plugins add org-specific
checks without forking the engine. They are **source-only WASM** — no network,
no filesystem, no active probes — and there is **no hosted plugin store**.

## Scaffold

```bash
owlwarden plugin scaffold company-rules
# → company-rules/owlwarden.plugin.json + stub source
```

Build the `.wasm` artifact per the stub's instructions, then load it:

```bash
owlwarden scan --plugin ./company-rules
```

Under `--ci`, plugins require `--allow-plugins`. Do not enable that on pull
requests from outside the team unless you reviewed the plugin tree.

## Inspect before load

`plugin inspect` reads the manifest and reports capabilities, digest, and
signature status **without** instantiating WASM:

```bash
owlwarden plugin inspect ./company-rules
```

Use it in review workflows the same way you would read a dependency's
`package.json` — a local preview, not a marketplace verdict.

## Artifact integrity

Manifests may pin the WASM bytes:

```json
{
  "artifact": {
    "path": "plugin.wasm",
    "sha256": "<hex>"
  }
}
```

When `sha256` is present, the host refuses to load if the file does not match.
`plugin inspect` reports `digest: ok | mismatch | absent`.

## Optional signatures

A detached `<artifact>.sig` holds a base64 ed25519 signature over the raw
32-byte SHA-256 digest. Trust roots come from:

- `OWLWARDEN_PLUGIN_TRUST` — colon-separated hex public keys, or
- `.owlwarden/plugin-trust.json` — `{ "keys": ["…"] }` **in the scan root**

Those two, and nothing else. In particular a trust file *inside the plugin*, or
beside its directory, is not read: a plugin that supplies the key vouching for
it has been asked to grade its own work, and `--require-signed-plugins` would
refuse nothing. A signature answers "which author is this?", so the list of
acceptable authors has to come from the person asking.

`plugin inspect` reports `signature: verified | untrusted | absent`. It reads
no trust file at all — a plugin inspected outside a project reports `untrusted`
unless the environment names a key, which is the honest answer.

Require verified signatures in CI:

```bash
owlwarden scan --ci --allow-plugins --require-signed-plugins --plugin ./company-rules
```

Off by default so local scaffolds still work. Signatures choose which authors
you trust; they do not widen the sandbox.

## Authoring

Plugins implement the same `FileRule` / `ProjectRule` interfaces as built-ins.
Start from the scaffold, read the sandbox limits in
[SECURITY.md](../../SECURITY.md), and see
[extend.md](extend.md#plugins) for the full walkthrough.

[ADR 0021](../adr/0021-plugin-artifact-signing.md) ·
[ADR 0015](../adr/0015-plugin-host-wasmtime.md)
