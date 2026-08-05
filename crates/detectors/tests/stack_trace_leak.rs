//! Shape-by-shape behaviour of `stack-trace-leak`.
//!
//! The fixture tests prove the rule works on realistic projects. These prove it
//! works on the *specific expressions* people actually write — and, just as
//! importantly, that it stays quiet on the ones that merely look similar.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use owlwarden_core::finding::Framework;
use owlwarden_core::source::RelPath;
use owlwarden_detectors::StackTraceLeak;
use owlwarden_static::rule::{FileRule, FindingSink};
use owlwarden_static::unit::UnitMeta;

/// Wraps a snippet in a route handler so `return` is legal and the rule sees
/// the same shape it sees in a real file.
fn as_handler(body: &str) -> String {
    format!("export async function GET() {{\n{body}\n}}\n")
}

/// Runs the rule over a snippet and returns the number of findings.
fn count(framework: &Framework, path: &str, body: &str) -> usize {
    let relative = RelPath::new(Path::new(path)).unwrap();
    let meta = UnitMeta::for_framework(framework, &relative);
    let source = as_handler(body);
    owlwarden_static::with_parsed(&relative, &source, meta, |unit| {
        let mut sink = FindingSink::new();
        StackTraceLeak.check(unit, &mut sink);
        sink.len()
    })
    .unwrap_or_else(|error| panic!("snippet should parse: {error}"))
}

/// Asserts the rule fires exactly once in a Next.js project.
fn fires(source: &str) {
    fires_in(&Framework::NEXT, source);
}

/// Asserts the rule fires exactly once in the named framework.
fn fires_in(framework: &Framework, source: &str) {
    assert_eq!(
        count(framework, "app/api/x/route.ts", source),
        1,
        "expected a finding in {framework} for:\n{source}"
    );
}

/// Asserts the rule stays quiet.
fn silent(source: &str) {
    assert_eq!(
        count(&Framework::NEXT, "app/api/x/route.ts", source),
        0,
        "expected no finding for:\n{source}"
    );
}

#[test]
fn fires_on_the_common_response_shapes() {
    fires("try { f() } catch (err) { return NextResponse.json({ error: err.stack }) }");
    fires("try { f() } catch (err) { return Response.json({ stack: err.stack }) }");
    fires("try { f() } catch (err) { res.status(500).json({ trace: err.stack }) }");
    fires("try { f() } catch (err) { res.send(err.stack) }");
}

#[test]
fn every_supported_framework_has_its_own_spelling_covered() {
    // One rule, five frameworks, no framework named anywhere in the rule. Each
    // of these is the idiomatic way that stack ends a request, and the rule
    // recognises it because the profile describes it.
    let leak = "try { f() } catch (err) { %s }";
    for (framework, response) in [
        (
            Framework::NEXT,
            "return NextResponse.json({ e: err.stack })",
        ),
        (Framework::NUXT, "return send(event, err.stack)"),
        (
            Framework::NEST,
            "throw new InternalServerErrorException({ s: err.stack })",
        ),
        (Framework::EXPRESS, "res.status(500).json({ s: err.stack })"),
        (Framework::FASTIFY, "reply.code(500).send({ s: err.stack })"),
    ] {
        fires_in(&framework, &leak.replace("%s", response));
    }
}

#[test]
fn a_fastify_reply_is_not_a_sink_in_a_project_without_fastify() {
    // The precision the framework profiles buy. `reply` means nothing in a
    // Next.js codebase, and treating it as a response object there would fire
    // on any variable someone happened to call `reply`.
    assert_eq!(
        count(
            &Framework::NEXT,
            "app/api/x/route.ts",
            "try { f() } catch (err) { reply.send({ s: err.stack }) }"
        ),
        0
    );
    assert_eq!(
        count(
            &Framework::FASTIFY,
            "src/routes.ts",
            "try { f() } catch (err) { reply.send({ s: err.stack }) }"
        ),
        1
    );
}

#[test]
fn fires_when_the_stack_is_nested_inside_the_body() {
    fires(
        "try { f() } catch (err) {
           return new Response(JSON.stringify({ detail: { trace: err.stack } }))
         }",
    );
}

#[test]
fn fires_on_nest_http_exception_bodies() {
    fires(
        "try { f() } catch (err) {
           throw new InternalServerErrorException({ stack: err.stack })
         }",
    );
    fires("try { f() } catch (e) { throw new HttpException({ s: e.stack }, 500) }");
}

#[test]
fn stays_quiet_when_the_stack_only_reaches_a_log() {
    silent("try { f() } catch (err) { console.error(err.stack) }");
    silent("try { f() } catch (err) { logger.error('failed', err.stack) }");
    silent("try { f() } catch (err) { this.logger.error(err.stack) }");
    silent("try { f() } catch (err) { Sentry.captureException(err) }");
}

#[test]
fn stays_quiet_on_a_stack_that_is_not_an_error_stack() {
    // The single most likely false positive: a `.stack` that is a list of
    // technologies, a parser diagnostic, or a UI layout prop.
    silent("res.json({ stack: project.stack })");
    silent("return NextResponse.json({ stack: diagnostic.stack })");
    silent("res.json({ layout: theme.stack })");
}

#[test]
fn stays_quiet_when_the_stack_is_captured_but_not_returned() {
    silent(
        "try { f() } catch (err) {
           const trace = err.stack
           if (dev) console.debug(trace)
           return NextResponse.json({ error: 'Internal Server Error' })
         }",
    );
}

#[test]
fn a_bare_error_name_outside_a_catch_is_reported_but_not_claimed_as_certain() {
    // `error.stack` in a response is still a leak, but we inferred that
    // `error` holds an error from its name alone. Lower confidence, and so it
    // never fails CI by itself.
    let relative = RelPath::new(Path::new("app/api/x/route.ts")).unwrap();
    let source = as_handler("const error = new Error('x'); res.json({ s: error.stack })");
    let confidence = owlwarden_static::with_parsed(
        &relative,
        &source,
        UnitMeta::for_framework(&Framework::NEXT, &relative),
        |unit| {
            let mut sink = FindingSink::new();
            StackTraceLeak.check(unit, &mut sink);
            sink.drain().first().map(|finding| finding.confidence)
        },
    )
    .unwrap();

    assert_eq!(
        confidence,
        Some(owlwarden_core::finding::Confidence::Possible)
    );
}

#[test]
fn the_per_file_cap_bounds_a_pathological_file() {
    // A generated file could contain thousands of leaks. The report must stay
    // finite regardless of what the input does.
    let body = "try { f() } catch (err) { res.json({ s: err.stack }) }\n".repeat(500);
    let found = count(&Framework::NEXT, "app/api/x/route.ts", &body);
    assert!(found > 0, "the rule should still fire");
    assert!(
        found <= owlwarden_core::limits::source::MAX_FINDINGS_PER_FILE,
        "expected the per-file cap to apply, got {found}"
    );
}

#[test]
fn declaration_files_are_skipped_entirely() {
    let relative = RelPath::new(Path::new("types/api.d.ts")).unwrap();
    assert!(
        !StackTraceLeak.applies_to(&relative),
        "a .d.ts file has no executable code to leak anything"
    );
}
