# Plugin API v1

Frozen at owlwarden 1.0. Breaking changes after this require an
[RFC](../rfc/README.md) and a deprecation cycle. Additive fields may appear in
a minor release; a plugin that validates with `schemaVersion: 1` on 1.0 must
still load.

Authoring walkthrough: [how-to/plugins.md](../how-to/plugins.md). Sandbox:
[ADR 0015](../adr/0015-plugin-host-wasmtime.md). Integrity:
[ADR 0021](../adr/0021-plugin-artifact-signing.md). Freeze decision:
[ADR 0024](../adr/0024-plugin-api-v1.md).

## Manifest (`owlwarden.plugin.json`)

Validated by `@dointhai/owlwarden-sdk` (`pluginManifestSchema`) and again by
the Rust host. The two must agree.

| Field | Rule |
|---|---|
| `schemaVersion` | Integer `1`. Other values refuse to load. |
| `id` | `[a-z][a-z0-9-]*`, max 64 |
| `version` | String, max 64 |
| `capabilities` | `source: true`. `network` and `active` must be false — declaring them is an error, not a silent downgrade |
| `rules` | 1–64 entries. Each `id` must start with `{plugin-id}-` |
| `artifact` | Optional `{ path, sha256 }`. Relative path, 64 hex chars |

Rule `maxConfidence` may be `likely` or `possible`, never `confirmed`.

## Host contract

- One fresh wasmtime store per invocation. Fuel, 64 MiB memory, wall-clock
  deadline.
- The only host function is `emit_finding`. Every claim is re-validated
  against the plugin's own manifest before it becomes a finding.
- No filesystem, no network, no clocks, no environment.
- `--ci` refuses `--plugin` unless `--allow-plugins`.
- Trust roots come from `OWLWARDEN_PLUGIN_TRUST` or
  `.owlwarden/plugin-trust.json` **in the scan root**, never from the plugin's
  own directory.
- `--require-signed-plugins` requires a verified ed25519 `.sig` over the
  artifact digest.

## Deprecation

- **Additive** (new optional manifest field, new read-only host query): minor
  version. Old plugins keep loading.
- **Behavioural** (stricter validation of a field that used to be accepted):
  minor, with a changelog note and at least one release that warns.
- **Breaking** (remove a field, change `schemaVersion`, grant a new
  capability class): RFC, then a new `schemaVersion`. `1` is not reused.

Rule ids contributed by plugins follow the same permanence rule as first-party
ids once they have been published by their author.
