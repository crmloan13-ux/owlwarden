# Engine error codes

When a scan cannot run, the engine returns an envelope rather than throwing:

```json
{
  "ok": false,
  "error": {
    "code": "E_UNKNOWN_PRESET",
    "message": "unknown preset \"quik\"; available presets are quick, owasp-top10, deep",
    "help": "https://github.com/suthat/owlwarden/blob/main/docs/reference/errors.md#e_unknown_preset"
  }
}
```

The `code` is stable and safe to branch on. The `message` is written for a
human and may be reworded between releases, so do not match on it.

**A failed scan is not a clean scan.** The CLI exits `2`, distinct from `0`
(nothing found) and `1` (findings at or above `--fail-on`). If your pipeline
treats any non-`1` exit as success, a broken scan will look like a passing one —
which is the failure mode this whole page exists to prevent.

## E_UNKNOWN_PRESET

The `--preset` name is not one the engine has.

Unknown presets are an error rather than a fallback to the default, on purpose.
A typo in `--preset owsap-top10` that quietly ran the default would mean
scanning with a different rule set than the one written in your CI config, and
nothing would say so. The message lists the presets the installed engine
actually has; `owlwarden rules` shows what each one selects.

## E_PROJECT_UNREADABLE

The path given does not exist, is not a directory, or cannot be read.

Usually a wrong working directory in CI, or a path relative to the repository
root when the step runs somewhere else. It is also what you get if the directory
exists but the process lacks permission to read it — worth checking when a scan
works locally and fails in a container running as a non-root user.

## E_SCAN_FAILED

A rule or the scheduler failed while running.

This is a bug in owlwarden, not something wrong with your code. Individual file
parse failures do not reach here — they are collected into `report.errors` and
the scan continues, because one unparseable file should not lose you the
findings from the other four hundred. Reaching `E_SCAN_FAILED` means the run
itself could not complete.

Please [open an issue](https://github.com/suthat/owlwarden/issues) with the
message and, if you can share it, the shape of the file involved.

## E_BASELINE_INVALID

The `--baseline` file could not be parsed, names an unsupported schema, or
exceeds the entry limit. Fix the file or regenerate it with
`--write-baseline`.

## E_BASELINE_WRITE

owlwarden could not write the path given to `--write-baseline` (missing
directory, permissions, or a full disk).

## E_TARGET_INVALID

`--target` or `--scope` could not be used: the URL is not absolute http(s),
contains credentials, is outside the allowlist, or `--scope` was passed without
`--target`.

Target and scope are operator intent. They come from the command line only —
never from a file inside the scanned tree — so a hostile pull request cannot
point the scanner at an internal host.

## E_PLUGIN_INVALID

A path passed via `--plugin` could not be loaded: the manifest is missing or
invalid, the module could not be compiled, the plugin declares a capability
this host does not grant (`network` or `active`), or more plugins were listed
than the per-scan limit.

Plugins are sandboxed with wasmtime — a plugin that misbehaves at *runtime*
(loops, floods findings, tries to escape its memory limit) is contained and
does not surface here; this code is only for a plugin that never got as far
as running. See `ARCHITECTURE.md` §6 and
[ADR 0015](../adr/0015-plugin-host-wasmtime.md).

## E_TURN_REQUEST

`owlwarden turn` handed the engine a request it could not read.

A programming error in the CLI rather than anything you did. It is a code and
not a thrown exception for the same reason every other failure here is: a hook
or a CI step that receives a stack trace has nothing to act on.

## E_TURN_REPORT

One of the two reports the turn verdict compares could not be read by the
engine.

Almost always version skew: the TypeScript CLI and the native addon came from
different releases, so one is producing a report shape the other does not know.
Reinstall `owlwarden` so both come from the same release.

This is refused rather than worked around. A turn verdict computed from a
report the engine only half-understood could report a finding as introduced
because a field it keys on went missing, which is the one mistake this command
must not make.

## E_ENCODE

The report could not be serialised to JSON.

Should be unreachable: the report model is owned by owlwarden and contains
nothing that can fail to encode. It exists so that the failure path itself
returns valid JSON — a caller that receives a truncated or malformed response
has no way to tell a broken scan from a clean one, and that is exactly the
confusion a security tool must not create.

If you see this, it is a bug worth reporting.
