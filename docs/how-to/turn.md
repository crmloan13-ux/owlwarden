# The turn verdict

*What did this turn just introduce?*

`owlwarden turn` scans the files that changed since a base commit, scans the
same files as they stand at that commit, and reports the difference. Findings
you introduced are shown in full. Findings that were already there are counted
on one line and never printed.

**Carried findings never fail a turn, at any threshold.** There is no flag that
changes it. See [ADR 0032](../adr/0032-turn-verdict.md) for why.

---

## The three states

```bash
owlwarden turn
```

```
◉ᴥ◉ turn · 7 files · since HEAD a1b2c3d · 0.31s
✔ clean — nothing introduced
  2 fixed · 5 carried (already at a1b2c3d, not this turn's)
    - stack-trace-leak app/api/users/route.ts:13
```

| state | meaning | can fail the turn |
|---|---|---|
| `introduced` | present now, absent at the base | **yes** |
| `carried` | present in both | no |
| `fixed` | present at the base, absent now | no |

When something *is* introduced:

```
◉ᴥ◉ turn · 1 file · since HEAD a8a6b93 · 0.16s
✘ blocked — 1 introduced at or above high
  1 carried (already at HEAD a8a6b93, not this turn's)

────────────────────────────────────────────────────────────────────────
HIGH  likely  internet  Stack trace leaked in error response    A05:2021
────────────────────────────────────────────────────────────────────────
 app/api/users/route.ts:7:39  (GET /api/users)

 ↳  new            introduced this turn; a8a6b93 does not have it
```

A turn that introduces something *below* the threshold is still reported, and
says which threshold:

```
✔ clean at high — 1 introduced below the bar, shown anyway
```

The verdict never prints *nothing introduced* over something the turn
introduced.

## In an agent's loop

```bash
owlwarden init --claude-code
```

writes a **Stop** hook that runs `turn --hook claude-code --record`. The
per-edit and pre-command hooks stay on `gate`: those must be cheap and have no
meaningful base to compare against.

Under `--hook`, stdout is the host's own JSON and nothing else — no code frames,
no banner. The reason the model receives names what is new *and* says the rest
were already there:

> 1 finding that was not present at a8a6b93. […] 17 other finding(s) on these
> files were already at a8a6b93. They are not this turn's and are not what is
> being asked of you.

That second sentence is doing real work. An agent handed a repository's
inherited debt at the end of every turn starts fixing files nobody asked it to
touch, in a session the developer is paying for.

To wire it into another host yourself:

```json
{ "hooks": { "Stop": [{ "hooks": [
  { "type": "command", "command": "node_modules/.bin/owlwarden turn --hook claude-code" }
] }] } }
```

## In CI, on a pull request

The base is a flag, so the "turn" can be a whole branch:

```yaml
- run: npx owlwarden turn --base origin/${{ github.base_ref }} --fail-on medium
```

This fails the job for what the branch introduced and stays silent about what
`main` already carried. Use `owlwarden scan` in a scheduled job for the whole
repository — that is a different question, asked at a different time, and
answering both in the pull request is how a pipeline gets a `continue-on-error`
added to it.

Needs the full history: set `fetch-depth: 0` on `actions/checkout`, or the base
ref will not resolve.

## Keeping a record

```bash
owlwarden turn --record
```

appends one JSON line to `.owlwarden/turns.jsonl`, keeping the last 200. Every
field except the timestamp and the stopwatch is derived from the two reports and
the base, so two runs over an unchanged tree produce identical records — which
is what makes one worth keeping. Commit the file if you want the audit trail in
review; gitignore it if you do not.

```bash
jq -r 'select(.verdict == "blocked") | "\(.recordedAt) \(.counts.introduced) \(.base.commit[0:7])"' \
  .owlwarden/turns.jsonl
```

## Reading a verdict honestly

**`clean` is a claim about a comparison.** It means *nothing was introduced
since that commit*, never *this repository is clean*. The base is printed on
every line of the output for exactly that reason, and `owlwarden scan` is the
command that answers the other question.

**The base is a commit, so the verdict is as trustworthy as the commit is.** An
agent that can commit can commit a finding and have the next turn report it as
carried. This is a detection and review control, not a containment one — the
same limit the [seal](seal.md) states about itself. If that matters for your
threat model, run `turn --base origin/main` in CI, where the base is one
somebody else set.

**It cannot see across the base.** A turn that introduces a finding and commits
it in the same breath reports nothing, because there is no longer a difference
to see.

## Cost

Two scans and a tree checkout: 0.16–0.63s end to end on the repositories tested,
against a repository of about a thousand tracked files. The base tree is laid
out with `read-tree` into a private `GIT_INDEX_FILE` and `checkout-index` into a
temporary directory, so **your index and working tree are never touched** —
`git status` is byte-identical across a run, staged changes included.

Over 400 changed files, `turn` refuses. That is a merge or a reformat, not a
turn, and the verdict a developer wanted is not in there.

## See also

- [ADR 0032](../adr/0032-turn-verdict.md) — the design, and what it refuses to do
- [CLI reference](../reference/cli.md#turn) — every flag and default
- [Agents and hooks](../tutorials/agents.md) — the whole loop
- [`seal`](seal.md) — the same question, asked of the agent's execution surface
