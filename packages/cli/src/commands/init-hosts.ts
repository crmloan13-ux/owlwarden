import { join } from "node:path";

import { readFileBounded, writeReplacing } from "../safe-write.js";

/**
 * `owlwarden init --claude-code | --cursor | --generic` — wiring the gate into
 * a host.
 *
 * # The hook this deliberately does not write
 *
 * None of these targets writes a `SessionStart` hook, and the omission is the
 * point.
 *
 * `agent-hook-autoexec` reports repository configuration that runs a command
 * when the workspace is opened, at high severity, because anyone who clones the
 * repository and opens it runs that command. A tool that ships that rule and
 * then writes exactly that entry into your `.claude/settings.json` would be
 * indefensible — and `owlwarden scan` would report its own output.
 *
 * So the wiring is bound to events the developer causes: an edit, a command
 * they asked for, the end of a turn. The session digest is a real feature and
 * belongs in *user* settings, which a cloned repository cannot write, and the
 * printed instructions say so rather than quietly doing it.
 *
 * # Why the invocation is a path and not `npx`
 *
 * `agent-mcp-unpinned-remote` reports a server launched with `npx -y <pkg>`:
 * the code that gets a tool call today is not necessarily the code that got one
 * yesterday. The same reasoning applies to a hook. `node_modules/.bin/owlwarden`
 * is what the lockfile already pinned, is reviewable in a diff, and is what
 * these files therefore use.
 *
 * The result is configuration that owlwarden itself scans clean, which is the
 * only version of this feature worth shipping.
 */

/** Cap on any config file this merges into. */
const MAX_CONFIG_BYTES = 256_000;

/** The binary, as the generated configuration invokes it. */
const BIN = "node_modules/.bin/owlwarden";

/** One file to write, and what it is for. */
export interface HostFile {
  /** Project-relative path. */
  path: string;
  /** The whole file, after merging with anything already there. */
  contents: string;
  /** One line for the summary the command prints. */
  purpose: string;
}

/** Which host to wire up. */
export type HostTarget = "claude-code" | "cursor" | "generic";

/** Builds the files for one host, merging with what is already on disk. */
export async function hostFiles(target: HostTarget, root: string): Promise<HostFile[]> {
  switch (target) {
    case "claude-code":
      return [
        {
          path: ".claude/settings.json",
          contents: await mergeJson(root, ".claude/settings.json", claudeSettings),
          purpose: "hooks: after every edit, before a shell command, at the turn boundary",
        },
        {
          path: ".mcp.json",
          contents: await mergeJson(root, ".mcp.json", mcpEntry),
          purpose: "MCP server: read-only, static-only, for the exploratory case",
        },
      ];
    case "cursor":
      return [
        {
          path: ".cursor/hooks.json",
          contents: await mergeJson(root, ".cursor/hooks.json", cursorHooks),
          purpose: "hooks: after every edit, before a shell command, at the turn boundary",
        },
        {
          path: ".cursor/mcp.json",
          contents: await mergeJson(root, ".cursor/mcp.json", mcpEntry),
          purpose: "MCP server: read-only, static-only",
        },
        {
          path: ".cursor/rules/owlwarden.mdc",
          contents: CURSOR_RULES,
          purpose: "rules file: what the gate blocks on, so the model knows before it writes",
        },
      ];
    case "generic":
      return [
        {
          path: ".owlwarden/gate.sh",
          contents: GENERIC_WRAPPER,
          purpose: "a shell wrapper any host can call; owlwarden's own event and exit codes",
        },
      ];
  }
}

/** What to print after writing, per host. */
export function hostNextSteps(target: HostTarget): string {
  const shared =
    "\nNo SessionStart hook was written. Repository config that runs on open is what\n" +
    "`agent-hook-autoexec` reports, and shipping the rule while writing the entry would\n" +
    "be indefensible. If you want the session digest, add it to your *user* settings —\n" +
    "a cloned repository cannot write those.\n";

  switch (target) {
    case "claude-code":
      return (
        "Next:\n" +
        "  1. pnpm add -D owlwarden      (the hooks call node_modules/.bin/owlwarden)\n" +
        "  2. restart Claude Code so it reloads .claude/settings.json\n" +
        "  3. owlwarden vet .            (check what is already in the tree)\n" +
        shared
      );
    case "cursor":
      return (
        "Next:\n" +
        "  1. pnpm add -D owlwarden      (the hooks call node_modules/.bin/owlwarden)\n" +
        "  2. restart Cursor so it reloads .cursor/hooks.json\n" +
        "  3. owlwarden vet .\n" +
        shared
      );
    case "generic":
      return (
        "Next:\n" +
        "  1. chmod +x .owlwarden/gate.sh\n" +
        "  2. call it from your host's post-edit and turn-end events, passing the\n" +
        "     event JSON on stdin. Exit codes: 0 allow, 1 deny, 2 ask.\n" +
        "  3. owlwarden vet .\n" +
        shared
      );
  }
}

/** The Claude Code hook block, merged into any existing settings. */
function claudeSettings(existing: Record<string, unknown>): Record<string, unknown> {
  const hooks = asObject(existing["hooks"]);
  return {
    ...existing,
    hooks: {
      ...hooks,
      // After a write: scope is the file that was written.
      PostToolUse: [
        {
          matcher: "Edit|Write|MultiEdit|NotebookEdit",
          hooks: [{ type: "command", command: `${BIN} gate --host claude-code` }],
        },
      ],
      // Before a shell command: the only event that sits before execution, and
      // therefore the only one that fails closed.
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [{ type: "command", command: `${BIN} gate --host claude-code` }],
        },
      ],
      // The loop-closer, and the one that decides whether this stays
      // installed. `turn` rather than `gate --since HEAD`: both scan what
      // changed, but `gate` reports every finding standing on those files and
      // `turn` reports only the ones this turn introduced. An agent handed a
      // repository's inherited debt at the end of every turn starts triaging a
      // backlog nobody asked it to touch.
      Stop: [
        {
          hooks: [
            { type: "command", command: `${BIN} turn --hook claude-code --record` },
          ],
        },
      ],
    },
  };
}

/** The Cursor hook block. */
function cursorHooks(existing: Record<string, unknown>): Record<string, unknown> {
  const hooks = asObject(existing["hooks"]);
  return {
    ...existing,
    hooks: {
      ...hooks,
      afterFileEdit: [{ command: `${BIN} gate --host cursor` }],
      beforeShellExecution: [{ command: `${BIN} gate --host cursor` }],
      stop: [{ command: `${BIN} turn --hook cursor --record` }],
    },
  };
}

/**
 * The MCP entry, invoked by path.
 *
 * `npx -y owlwarden mcp` would work and is what most tools generate. It is also
 * exactly the shape `agent-mcp-unpinned-remote` reports, so this writes the
 * lockfile-pinned form instead.
 */
function mcpEntry(existing: Record<string, unknown>): Record<string, unknown> {
  const servers = asObject(existing["mcpServers"]);
  return {
    ...existing,
    mcpServers: {
      ...servers,
      owlwarden: { command: BIN, args: ["mcp"] },
    },
  };
}

const CURSOR_RULES = `---
description: What owlwarden blocks on in this repository
alwaysApply: true
---

# Security floor

A deterministic scanner runs on every edit and at the end of every turn. It
blocks on **high**-severity findings at **likely** confidence or better. Fixing
a finding is always cheaper than arguing with it: the gate runs outside the
model, so nothing in this file can change its verdict.

Before writing code, prefer the shapes it will not flag:

- Never return \`err.stack\`, \`err.message\`, or a raw error object to a client.
  Log server-side and return a generic message.
- Build SQL with parameters, never with template interpolation.
- Take redirect targets from an allowlist, never from the request.
- Use \`crypto.randomUUID()\` or \`crypto.randomBytes\` for anything an attacker
  should not guess. Never \`Math.random()\`.
- Read secrets from \`process.env\`. Never write one into a source file.
- Do not add hooks, tasks, or MCP servers to this repository's configuration.
  Repository config that executes is the surface \`owlwarden vet\` exists for.

Run \`owlwarden explain <rule-id>\` for the full write-up on any rule, offline.
`;

const GENERIC_WRAPPER = `#!/bin/sh
# owlwarden gate, for any host that can run a process.
#
# Reads the host's event on stdin, writes owlwarden's decision JSON on stdout,
# and exits 0 (allow), 1 (deny), or 2 (ask / could not run) — the same exit
# codes every other owlwarden command uses.
#
# Wire it to whichever events your host has. The two that matter:
#
#   post-edit     scope is the file that was written
#   turn-boundary scope is everything changed since the turn began
#
# The event name is read from the JSON on stdin, so most hosts can pass their
# own payload straight through:
#
#   { "event": "file-edited", "paths": ["app/api/users/route.ts"] }
#   { "event": "turn-boundary" }
#
set -eu

ROOT="\${OWLWARDEN_PROJECT_ROOT:-.}"
BIN="\${OWLWARDEN_BIN:-node_modules/.bin/owlwarden}"

exec "$BIN" gate --host generic "$ROOT"
`;

/**
 * Reads a JSON file, applies `merge`, and returns the rendered result.
 *
 * A file that is absent or does not parse starts from an empty object: a host
 * config that will not parse is a finding, not a reason to be unable to add a
 * hook. A file we *refused* to read is different, and rethrows — see
 * {@link readExisting}.
 */
async function mergeJson(
  root: string,
  path: string,
  merge: (existing: Record<string, unknown>) => Record<string, unknown>,
): Promise<string> {
  const text = await readExisting(join(root, path));
  let existing: Record<string, unknown> = {};
  if (text !== undefined) {
    try {
      existing = asObject(JSON.parse(text));
    } catch {
      // Unparseable. Start clean rather than refusing to write a hook.
    }
  }
  return `${JSON.stringify(merge(existing), null, 2)}\n`;
}

/**
 * Reads a file that may not exist, or `undefined` if it does not.
 *
 * Every other failure rethrows, and the one that matters is the symlink. A
 * `.claude/settings.json` that is a symlink is refused by
 * {@link readFileBounded}; swallowing that would make `init` treat the file as
 * absent and replace it — quietly discarding a config, and doing so on exactly
 * the shape someone planted deliberately.
 */
async function readExisting(path: string): Promise<string | undefined> {
  try {
    return await readFileBounded(path, MAX_CONFIG_BYTES);
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? (error as { code?: string }).code
        : undefined;
    if (code === "ENOENT") return undefined;
    throw error;
  }
}

/**
 * Narrows a parsed JSON value to a plain object.
 *
 * `JSON.parse` gives `__proto__` as an own property rather than setting the
 * prototype, and every use below spreads into a fresh object literal, so
 * nothing here can pollute `Object.prototype`. Stated because it is the first
 * question to ask of any code that merges parsed JSON into an object, and the
 * answer should not have to be re-derived.
 */
function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/** Writes one host file, or reports what it would have replaced. */
export async function writeHostFile(
  absolutePath: string,
  file: HostFile,
  force: boolean,
  stderr: NodeJS.WritableStream,
): Promise<number> {
  const existing = await readExisting(absolutePath);

  if (existing !== undefined && existing === file.contents) {
    stderr.write(`unchanged ${file.path}\n`);
    return 0;
  }

  if (existing !== undefined && !force) {
    // A diff rather than a silent overwrite: this is somebody's editor
    // configuration, and the merge above may not be what they wanted.
    stderr.write(`skipped ${file.path} (exists; pass --force to replace)\n`);
    for (const line of diffLines(existing, file.contents).slice(0, 40)) {
      stderr.write(`  ${line}\n`);
    }
    return 0;
  }

  await writeReplacing(absolutePath, file.contents);
  stderr.write(`wrote ${file.path} — ${file.purpose}\n`);
  return 1;
}

/**
 * A line-level diff, enough to see what `--force` would change.
 *
 * Deliberately not a real diff algorithm: the question is "is this what you
 * meant?", and a list of removed and added lines answers it in twenty lines of
 * code rather than two hundred.
 */
function diffLines(before: string, after: string): string[] {
  const previous = new Set(before.split("\n"));
  const next = new Set(after.split("\n"));
  const out: string[] = [];
  for (const line of before.split("\n")) {
    if (!next.has(line) && line.trim().length > 0) out.push(`- ${line.trim()}`);
  }
  for (const line of after.split("\n")) {
    if (!previous.has(line) && line.trim().length > 0) out.push(`+ ${line.trim()}`);
  }
  return out;
}
