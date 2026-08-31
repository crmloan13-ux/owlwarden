# 0032 — The turn verdict: what did *this* turn change

**Status:** Accepted
**Date:** 2026-09-01
**Related:** [0013](0013-suppressions-and-baseline.md) (the fingerprint this reuses), [0026](0026-deterministic-agent-gate.md) (the gate this replaces at the turn boundary), [0027](0027-workspace-seal.md) (the surface it reports), [0029](0029-exposure-model.md) (the third axis it inherits)

---

## Context

1.1 answered *what is here*. 1.2 answered *what changed on the agent surface*, *which findings are reachable*, and *how often are we wrong*. Each of those made a flat list of findings more useful. None of them changed who the list belongs to.

Run any of the three on a six-month-old repository and the output is a set of findings that are all, in the same undifferentiated way, somebody's problem some day. Twenty-three of them. Ten high. Three internet-reachable. That is a *much* better list than 1.0 produced, and it is still a list a person closes.

Meanwhile the thing that actually happens, dozens of times an hour, is narrower and more urgent than anything on that list: a developer or an agent changed seven files in the last thirty seconds. There is one question worth asking at that moment, and no version of this tool could answer it.

Three facts from the outside world sharpen the point.

**The bottleneck moved.** As of mid-2026 the median professional developer spends more time reviewing generated code than writing new code. The scarce resource is not detection; it is attention at review time.

**The category filled in.** Scanning `.claude/settings.json` was a gap in August 2026 and is a commodity by the end of it — Snyk's Agent Scan, AgentShield, Golf, half a dozen SaaS scanners, and a marketplace full of "security-scan" skills. Lockfiles for the agent surface are converging the same way. A release that adds a twenty-sixth rule or a seventeenth framework is competing on the axis where every other tool is also competing, from further behind.

**Alert fatigue is what kills these tools.** Not missed findings — noise. That is the consistent finding across every survey of why static analysis gets switched off, and the industry's answer to it in 2026 is to put a language model on top of the results and have it guess which ones matter.

owlwarden cannot take that answer. A non-deterministic filter over a deterministic engine gives up the only property the whole project is built on. But there is a deterministic answer to the same question, and it has been available since the baseline fingerprint shipped in 0.0.2: **a finding you just introduced is categorically different from a finding you inherited.** One is a regression with an author who is still at the keyboard. The other is debt, and debt is scheduled, not gated.

Nothing in the tool made that distinction. `scan --since HEAD` narrows the *files* and then reports every finding standing on them, inherited or not. `gate --since HEAD` does the same at the turn boundary, which means an agent finishing a turn on a legacy file is handed a backlog it did not write and did not ask about — and starts working on it.

---

## Decision

### 1. `owlwarden turn` — one command, three states

Scan the working tree at the paths that changed since a base commit. Scan the same paths as they stand at that commit. Diff the two.

| state | meaning | can fail the turn |
|---|---|---|
| `introduced` | in the working tree, not at the base | **yes** |
| `carried` | in both | no |
| `fixed` | at the base, gone now | no |

**Carried findings never fail a turn, at any threshold.** There is no flag that changes this, and `TurnDiff::blocking` filters `introduced` before the gate is consulted, so there is no code path that could grow one. A gate that blocks on debt the turn did not create is a gate that gets removed on the second day, and everything it would have caught goes with it.

Everything introduced is *reported*, whether or not it blocks. A turn that adds a medium under a `high` gate is `clean at high — 1 introduced below the bar, shown anyway`. The verdict never says "nothing introduced" over something the turn introduced; that is the one sentence this command cannot afford, and `TurnReport` carries `blocking` separately from `counts.introduced` so the two can never be conflated.

### 2. Identity is the baseline fingerprint, not the location

`rule@path:line` is the obvious key and it is wrong. A fix on line 8 shifts a finding on line 40 down by two, and a line-keyed diff reports that as one fixed and one introduced — manufacturing exactly the noise this command exists to remove. (`verify` has had this bug since 0.3 and this ADR is where it gets noticed; it is not fixed here, because `verify` compares two states of the *same* file seconds apart and the case is rare. It is now a known issue rather than an unknown one.)

`baseline::fingerprint_at` already drops the line, collapses whitespace, and carries an occurrence index so two identical `err.stack` findings in one file stay two findings. `--baseline` uses it. `seal --accept` uses it. `turn` uses it. **One notion of "the same finding" in the whole tool**, tested in one place, and `fingerprints()` is public so no caller can assign occurrence indices its own way.

### 3. The gate is the scan's gate, applied to a smaller set

`report::fails_gate` is extracted from `Report::should_fail_with` and called from both. `turn` is not a second, laxer standard; it is the same standard asked of a newer, smaller set of findings. `Possible` confidence never blocks a turn, exactly as it never fails a build.

The *default* differs: `--fail-on high --min-confidence likely`, against `scan`'s `info` / `possible`. A turn verdict runs after every turn, and a control that stops an agent over a medium it introduced in passing is a control somebody disables. The threshold is printed on the verdict line, so raising it is one flag and reading it is no work at all.

### 4. Two scans, not diff-hunk attribution

Attributing findings to added lines is cheaper and answers a narrower question. It cannot see the turn that deleted a middleware and made forty routes internet-reachable — the case [ADR 0029](0029-exposure-model.md) exists for — and it cannot count what the turn *fixed*, which is the only line in this tool that reports something going right.

A scan is deterministic and a commit is immutable, so the second scan answers a question with one correct answer. That is worth doing twice over a handful of files.

### 5. The base tree is laid out through a private index

`read-tree` into a temporary `GIT_INDEX_FILE`, then `checkout-index` into a temporary work tree. Measured at 0.15s over 1,057 files, against 0.57s for `git archive | tar` and minutes for `cp -r` on any repository with a build directory.

Two properties matter more than the speed:

- **`git worktree add` is not used**, because it writes into `.git/`. A command that runs unattended after every turn, in a tree the developer is actively working in, should not modify repository metadata to answer a question.
- **The private index is not an optimisation.** Without `GIT_INDEX_FILE`, checking out a tree rewrites the real index. A security tool that unstages someone's work mid-session has done more damage than the finding it was looking for. A test asserts `git status --porcelain` is byte-identical across a `turn`.

### 6. Under `--hook`, the answer goes through the gate's adapters

A Stop hook is a Stop hook. Claude Code reads `decision: "block"` with a `reason`; Cursor reads its own shape; `generic` emits owlwarden's. Those three translations exist in `crates/gate/src/adapters`, are tested against each host's schema, and get updated when a host changes. `turn --hook <host>` calls them rather than writing a fourth encoder, which would give the project two places to be wrong about the same JSON and only one of them would get fixed.

The reason text shares its body with `gate`'s denial — same sanitisation of paths and titles, same cap, same fix lines — and adds the sentence only this command can say:

> 1 finding that was not present at a8a6b93. […] 17 other finding(s) on these files were already at a8a6b93. They are not this turn's and are not what is being asked of you.

An agent told *there are eighteen findings* starts triaging a backlog. An agent told *you introduced one* fixes one thing and stops.

`init --claude-code` and `init --cursor` therefore wire the Stop hook to `turn --hook <host> --record` instead of `gate --host <host> --since HEAD`. The per-edit and pre-command hooks are unchanged: `gate` still owns those, they must be cheap, and neither has a meaningful base to compare against.

### 7. `--record` is a bounded JSONL file, not a directory

`.owlwarden/turns.jsonl`, last 200 records, next to the seal. One file per turn would grow a file a minute, which is a directory somebody gitignores — and a gitignored audit trail is no audit trail.

Every field except `recordedAt` and `durationMs` is derived from the two reports and the base, so two runs over an unchanged tree produce identical records. That is asserted on both sides of the language boundary. It is what makes a record something a reviewer can re-derive rather than merely trust, and it is a claim no scanner with a model in the loop can make.

### 8. `turn` renders as `pretty` or `json`, and nothing else

Not SARIF. A SARIF upload describing seven files would overwrite the repository's real code-scanning results with a seven-file slice, and the failure would look like the repository getting cleaner.

---

## Consequences

**What gets better.** The output of a turn is one to three findings with an author, instead of twenty-three with none. The `fixed` count gives the tool something to say when things go right. The base commit is printed on every line, so a screenshot of a clean verdict carries its own caveat and `clean` can never be read as *this repository is clean*.

**What this costs.** Two scans instead of one, plus a tree checkout: measured at 0.16–0.63s end to end on the repositories tested. That is acceptable at a turn boundary and would not be acceptable after every edit, which is why `gate` still owns that event.

**What this does not do.**

- It is **not a taint engine** and not a new analysis. Every finding it reports came out of the same rules `scan` runs.
- **The base is exactly as trustworthy as the commit is.** An agent that can commit can commit a finding and have the next turn report it as carried. This is the same class of limit [ADR 0027](0027-workspace-seal.md) states about the seal — a detection and review control, not a containment one — and it is why the base is named in the output rather than assumed.
- **It cannot see across the base.** A turn that reverts a fix made two commits ago and re-introduces an old finding reports it as introduced, correctly; a turn that introduces a finding *and* commits it in the same breath reports nothing, because there is no longer a difference to see. `--base origin/main` is the answer for the review-time question, and CI is where that belongs.

**Rejected: putting a model on the noise problem.** It is the industry's 2026 answer and it works. It also makes the output non-reproducible, which would cost this project the one property that distinguishes it from every tool in the comparison table. The turn diff gets a large part of the same benefit deterministically.

**Rejected: making `gate` turn-aware instead of adding a command.** It would have meant passing a fingerprint set into the gate's Rust decision path, a base scan inside a hook that must stay cheap, and a `gate` that behaves differently depending on a flag. `turn` is a different question asked at a different moment; the adapters are shared, and nothing else needed to be.

**Rejected: `turn` as a mode of `scan`.** `scan --turn` would inherit `scan`'s formats, thresholds, and defaults, every one of which is wrong here.

---

## Exit criteria

1. A finding present at the base and still present never blocks a turn, at any threshold, including the strictest. ✅ `carried_findings_never_fail_a_turn`
2. A reformat that moves a finding down a file is `carried`, not `fixed` + `introduced`. ✅ `reformatting_that_moves_a_line_is_not_a_regression`
3. Two identical findings in one file stay two findings across the diff. ✅ `two_identical_findings_in_one_file_stay_two`
4. A `possible`-confidence introduced finding is reported and does not block. ✅ `the_turn_gate_is_the_scan_gate_applied_to_a_smaller_set`
5. A turn that introduces something below the gate says so, and never prints "nothing introduced". ✅ `something_introduced_below_the_bar_is_clean_but_not_silent`
6. `git status --porcelain` is byte-identical before and after a turn, including staged entries. ✅ `does not touch the developer's index or working tree`
7. Two runs over an unchanged tree produce identical records but for the clock. ✅ `a_record_is_byte_identical_apart_from_its_timestamp`, `reaches the same verdict twice over an unchanged tree`
8. Under `--hook`, stdout parses as the host's JSON and carries nothing else. ✅ `under --hook nothing but the host's JSON reaches stdout`
9. Outside a git repository the command refuses rather than inventing a base. ✅ `refuses to run outside a git repository rather than inventing a base`
10. The turn record round-trips through the zod schema with no field lost. ✅ `fixtures/golden/turn.json`, both sides.
