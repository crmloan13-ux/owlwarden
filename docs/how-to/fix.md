# Apply Safe autofixes

Optional. Most remediations stay `Manual` on purpose — only drop-in highlight
replacements marked `Safe` are applied automatically.

```bash
owlwarden scan --fix              # Safe only; requires a clean git tree
owlwarden scan --fix --dry-run    # show what would change
owlwarden scan --fix --allow-dirty
```

## Gates

- Never on a `Possible` finding.
- Never a multi-line educational patch (`Manual`).
- `--fix-unsafe` is required for `Unsafe` remediations.
- Working tree must be clean unless `--allow-dirty`.
- Highlight text must still match what the scan saw — a file edited between
  scan and apply is refused rather than rewritten blindly.
- After a real write, owlwarden re-scans and reports what remains.
- Not available under `--ci` or over MCP (agents stay read-only).

## What ships as Safe today

| Rule | Replacement |
|---|---|
| `stack-trace-leak` | underlined `.stack` expression → `'Internal Server Error'` |
| `weak-crypto` (GuessableToken) | underlined `Math.random()` → Web Crypto expression |
| `weak-crypto` (HashedSecret) | underlined algorithm literal only (`'md5'` / `'sha1'` → `'sha256'`) |
| `insecure-cookie` | underlined options object with only security keys (or `{}`) → full `httpOnly`/`secure`/`sameSite` object |

`Possible` cookie writes with no options object stay Manual — never autofixed.
Framework-specific multi-line examples in `explain` remain `Manual`.

## See also

- [agent-integration.md](../explanation/agent-integration.md) — agent trust model
- [ADR 0006](../adr/0006-confidence-in-the-model.md) — why Possible is never auto-fixed
