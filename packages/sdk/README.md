# @dointhai/owlwarden-sdk

Types and zod schemas for [owlwarden](https://github.com/suthat/owlwarden)
output. Install this if you consume owlwarden's JSON — a dashboard, a bot, a CI
gate of your own — rather than just running the CLI.

```bash
npm i @dointhai/owlwarden-sdk
```

```ts
import { reportSchema, type Report } from "@dointhai/owlwarden-sdk";

const report: Report = reportSchema.parse(JSON.parse(stdout));

for (const finding of report.findings) {
  console.log(finding.id, finding.severity, finding.location.path);
}
```

The schemas are not a hand-written description of the engine's output. A test in
the repository serialises a report from the Rust engine and parses it with these
schemas, so the two cannot drift: if the engine changes a field and this package
does not, the build fails. See
[ADR 0010](https://github.com/suthat/owlwarden/blob/main/docs/adr/0010-cross-language-contract.md).

## What is worth reading before you branch on it

- **`suppressedCount`** exists so that `findings: []` is never mistaken for "no
  problems". Zero findings with a non-zero suppressed count means someone made a
  judgement call you may want to look at.
- **`confidence`** is `confirmed`, `likely`, or `possible`. Static analysis
  cannot produce `confirmed`; only correlation with a live probe can. Treat
  `possible` as "worth a human's attention", not "broken".
- **`truncated`** means limits were hit and the report is incomplete. A
  truncated report always fails the CI gate (`shouldFail` / `--ci` exit 1).
- **Rule ids are permanent.** Safe to hard-code, reference in config, and store.

## Licence

MIT OR Apache-2.0.
