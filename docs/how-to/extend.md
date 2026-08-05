# Extending owlwarden

Three things you might want to add, in increasing order of effort: a framework,
a rule, and a whole new dialect of the request. This page is the practical
version; the reasoning behind the shapes is in
[ADR 0011](../adr/0011-framework-profiles.md) and
[ADR 0012](../adr/0012-request-origin-not-taint.md).

The rule that governs all of it: **nothing framework-specific belongs in a
rule, and nothing rule-specific belongs in a profile.** When those mix, adding
the sixth framework means editing every rule, and that edit is the kind you can
forget without anything failing.

## Add a framework

Say you want Hono.

### 1. A profile

In `crates/static-engine/src/framework/profiles.rs`, add a `FrameworkProfile`:

```rust
FrameworkProfile {
    id: Framework::new_static("hono"),
    // How to detect it. Matched against package.json dependencies.
    packages: vec!["hono".into()],
    // Who wins when several match. Hono sits above the generic profile but
    // below a meta-framework built on top of it.
    specificity: 10,
    config_files: vec![],
    bootstrap_files: vec!["src/index.ts".into()],
    http: HttpVocabulary {
        // What a response object is called in this framework.
        response_objects: vec!["c".into(), "ctx".into()],
        // Methods that write a body. Not `status()` — that sets a code.
        body_methods: vec!["json".into(), "text".into(), "html".into()],
        response_constructors: vec!["Response".into()],
        cookie_setters: vec!["setCookie".into()],
        cors_enablers: vec!["cors".into()],
        // Bare functions that write a response, for frameworks that have them.
        response_helpers: vec![],
    },
    handlers: vec![HandlerStyle::RouterCall],
    route_for_path: None,
}
```

`specificity` is the part people get wrong. It is not a ranking of frameworks,
it is a statement about the dependency graph: a NestJS app really does depend on
Express, so Nest must outrank it or every Nest project reports Express advice.

### 2. Remediation on every rule

Add `Framework::new_static("hono")` to `SUPPORTED_FRAMEWORKS` in
`crates/detectors/src/lib.rs` and run:

```bash
cargo test -p owlwarden-detectors framework
```

The test names every rule with no Hono-specific advice. Work down the list,
adding a `.manual(...)` or `.fix(...)` entry to each rule's `remediation()`.
The generic fallback exists so a rule is never advice-less, but shipping a
framework where every rule falls back to it is not support — it is a claim of
support.

### 3. Fixtures

Two projects under `fixtures/`: one with the bugs, one with the same code
corrected. Add a row to `MATRIX` in `crates/detectors/tests/fixtures.rs`:

```rust
Expectation {
    framework: "hono",
    vulnerable: "vulnerable/hono-api",
    clean: "should-not-fire/hono-api-clean",
    fires: &[("stack-trace-leak", 1), ("sql-injection", 1)],
},
```

The clean fixture is the half that matters. Anyone can write a rule that fires;
the corpus that has to stay silent is what makes precision a tested property
rather than a claim. Put code in it that *resembles* each rule without being
it — MD5 as a cache key, `Math.random()` for a shard index, `app.get('trust
proxy')` reading a setting rather than registering a route.

### 4. Check

```bash
pnpm check
node scripts/generate-rules-md.mjs
```

`owlwarden coverage` should now show Hono with every rule carrying specific
remediation.

## Add a rule

Copy the shape of an existing one; `crates/detectors/src/ssrf.rs` is a good
model because it uses everything.

**Ask the profile, never the name.** If you find yourself writing
`if object_name == "res"`, stop — that is `owlwarden_static::http::is_response_sink`,
and hardcoding it means the rule works on Express and silently does nothing on
Fastify.

**Use `RequestOrigin` for "did this come from the caller".** Drive it from your
visitor's `visit_variable_declarator` and ask `origin.taints(expr)` at the sink.
Do not write another list of request identifiers.

**Two conditions, not one.** Every rule here requires a dangerous *sink* and a
dangerous *value*. `sql-injection` needs a database sink, a runtime-built
string, and SQL keywords; drop any one and it fires on
`` analytics.query(`event ${name}`) ``. A rule with one condition is a linter
rule, and people turn those off.

**Be honest in `confidence`.** `Likely` means the code says so. `Possible`
means it is worth a look and must never fail CI on its own. Autofix refuses to
touch a `Possible` finding, and that only works if the level means something.

**Write the `why` for someone who has not met this bug.** Not "avoid SQL
injection" — what an attacker gets, in one specific sentence. The rule's job is
to make someone care enough to fix it.

**Then wire it in:** register in `all_file_rules()` (or `all_project_rules()`),
add fixtures on both sides, run `pnpm check`, regenerate `RULES.md`.

Presets need no edit. They are predicates over rule metadata, so a new rule
mapped to an OWASP category joins `owasp-top10` automatically.

## Teach the engine a new request dialect

If your framework reads the request through functions the engine does not know
— an `useRequestBody()` helper, say — add it to `SOURCE_HELPERS` in
`crates/static-engine/src/taint.rs`. Every origin-sensitive rule improves at
once, which is the entire reason that list is in the engine and not in a rule.

## Plugins

The interfaces above are the same ones a plugin uses. A plugin registers
profiles through `Project::discover_with` and its rules implement the same
`FileRule` / `ProjectRule` traits, so a plugin rule lands in the coverage table
next to the built-ins and is held to the same remediation-coverage rule.

Two constraints that are not negotiable, from `ARCHITECTURE.md` §6 and §9:

- **Plugins are untrusted.** They run in WASM/WASI with no ambient
  capabilities. Filesystem and network are host functions granted per declared
  capability, not things a plugin simply has.
- **A plugin cannot widen the scan.** It cannot reach outside the project root
  and it cannot make the scan active. Those are the user's decisions, taken on
  the command line.

The WASM host is v0.2. Until then the extension points are in-process and the
API is the Rust one described above.
