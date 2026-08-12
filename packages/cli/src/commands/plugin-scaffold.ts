/**
 * `owlwarden plugin scaffold <name>` — a starter guest + manifest.
 *
 * Does not compile WASM (that needs a wasm toolchain). It writes the
 * directory layout and a WAT stub authors can assemble, plus a valid
 * `owlwarden.plugin.json`.
 *
 * Writes refuse symlinked destinations, matching `--out` / `init`.
 */

import { lstat } from "node:fs/promises";
import { join, resolve } from "node:path";

import { pluginManifestSchema } from "@dointhai/owlwarden-sdk";

import { EXIT } from "../exit.js";
import { mkdirNoFollow, refuseSymlinkAncestors, writeReplacing } from "../safe-write.js";

/** Runs the scaffold command. */
export async function runPluginScaffold(
  name: string,
  cwd: string,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(name)) {
    stderr.write(
      "error: plugin name must be lowercase letters, digits, hyphens (max 32)\n",
    );
    return EXIT.ERROR;
  }

  const root = resolve(cwd, name);
  try {
    const existing = await lstat(root);
    if (existing.isSymbolicLink()) {
      stderr.write(`error: refusing to scaffold into symlink ${root}\n`);
      return EXIT.ERROR;
    }
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? (error as { code?: string }).code
        : undefined;
    if (code !== "ENOENT") {
      stderr.write(
        `error: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return EXIT.ERROR;
    }
  }

  const manifest = pluginManifestSchema.parse({
    schemaVersion: 1,
    id: name,
    version: "0.1.0",
    capabilities: { source: true, network: false, active: false },
    rules: [
      {
        id: `${name}-example`,
        title: "Example plugin finding",
        severity: "low",
        maxConfidence: "possible",
        category: "example",
        description:
          "Replace this rule with a real check. The host is source-only (API v1).",
      },
    ],
  });

  try {
    await refuseSymlinkAncestors(cwd);
    await mkdirNoFollow(root);
    await writeReplacing(
      join(root, "owlwarden.plugin.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    await writeReplacing(join(root, "plugin.wat"), WAT_STUB);
    await writeReplacing(join(root, "README.md"), readme(name));
  } catch (error) {
    stderr.write(
      `error: could not scaffold ${root}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT.ERROR;
  }

  stderr.write(`scaffolded ${root}\n`);
  stderr.write("assemble plugin.wat → plugin.wasm, then:\n");
  stderr.write(`  owlwarden scan --plugin ${name}\n`);
  return EXIT.CLEAN;
}

function readme(name: string): string {
  return `# ${name}

WASM detector scaffold for owlwarden.

1. Edit \`owlwarden.plugin.json\` (rule ids must start with \`${name}-\`).
2. Implement \`plugin.wat\` (or a Rust \`cdylib\` targeting \`wasm32-unknown-unknown\`).
3. Assemble to \`plugin.wasm\` next to the manifest.
4. Optional: pin integrity in \`owlwarden.plugin.json\`:

   \`\`\`json
   "artifact": { "path": "plugin.wasm", "sha256": "<hex from sha256sum plugin.wasm>" }
   \`\`\`

5. Optional: sign the digest and add trust roots (ADR 0021):

   - Write base64 ed25519 signature of the raw SHA-256 digest to \`plugin.wasm.sig\`
   - Trust keys via \`OWLWARDEN_PLUGIN_TRUST\` or \`.owlwarden/plugin-trust.json\`

6. Scan with \`owlwarden scan --plugin ./${name}\`.

Guest ABI (v0.2):

- Import \`owlwarden.emit_finding(ptr, len) -> i32\`
- Export \`detect(ptr, len) -> i32\` — \`ptr\`/\`len\` point at a JSON source snapshot
- No WASI. Source-only. See docs/adr/0015-plugin-host-wasmtime.md.
`;
}

/** Minimal guest that emits nothing. Authors replace the body. */
const WAT_STUB = `(module
  (import "owlwarden" "emit_finding" (func $emit_finding (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  ;; detect(ptr, len) -> 0 on success. The host wrote a JSON snapshot at ptr.
  (func (export "detect") (param $ptr i32) (param $len i32) (result i32)
    i32.const 0
  )
)
`;
