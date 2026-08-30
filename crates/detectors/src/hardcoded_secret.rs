//! `hardcoded-secret` — a credential written into source.
//!
//! # Two ways to be sure, and they are not equally sure
//!
//! **By shape.** `sk_live_...`, `ghp_...`, `AKIA...`, a PEM private key block.
//! These prefixes are issued by one service and mean one thing. A match is
//! close to proof, and it does not care what the variable is called — so this
//! path catches the secret pasted into an array, a config object, or a fetch
//! header. `Likely`.
//!
//! **By name.** `const apiKey = "8f2c..."`. A string assigned to something
//! called a key, a secret, or a password. Strong signal, not proof: it could be
//! a key *identifier*, a fixture, or a value that is public by design.
//! `Possible`, which means it is shown and never fails CI on its own.
//!
//! # Precision is most of the work here
//!
//! This is the rule most likely to cry wolf, and a secret scanner that cries
//! wolf gets switched off with everything else in the tool. Four filters:
//!
//! - **Test and fixture files are skipped entirely.** A credential in a test is
//!   usually a made-up one, and flagging them buries the real finding.
//! - **Placeholders are recognised.** `your-api-key-here`, `changeme`, `xxx`,
//!   anything in angle brackets.
//! - **Short values are ignored.** Nothing under [`MIN_SECRET_LEN`] characters
//!   is a credential; `password = "1"` is a fixture or a flag.
//! - **Values with whitespace are ignored.** Issued credentials do not contain
//!   spaces, but sentences assigned to `errorMessage` do.
//!
//! Reading a secret from the environment is the correct pattern, and it does
//! not match here because `process.env.API_KEY` is not a string literal.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::runtime::Runtime;
use owlwarden_core::source::RelPath;
use owlwarden_core::surface::Surface;
use owlwarden_static::ast::property_name;
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{BindingPattern, Expression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder;

/// The rule id. Permanent public API.
pub const ID: &str = "hardcoded-secret";

/// Shortest string that could be an issued credential.
///
/// Every provider issues longer than this. Below it we are looking at a flag, a
/// fixture, or an identifier.
const MIN_SECRET_LEN: usize = 12;

/// Longest string we will consider. Beyond this it is a minified bundle, a
/// base64 image, or generated data.
const MAX_SECRET_LEN: usize = 512;

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 32;

/// Credential prefixes that identify their issuer.
///
/// Only prefixes a provider actually reserves. A generic "long hex string" test
/// would match commit hashes, content digests, and colour palettes.
const TOKEN_PREFIXES: &[(&str, &str)] = &[
    ("sk_live_", "Stripe live secret key"),
    ("rk_live_", "Stripe live restricted key"),
    ("sk_test_", "Stripe test secret key"),
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth token"),
    ("ghs_", "GitHub server token"),
    ("github_pat_", "GitHub fine-grained token"),
    ("glpat-", "GitLab personal access token"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("xapp-", "Slack app token"),
    ("npm_", "npm access token"),
    ("SG.", "SendGrid API key"),
    ("shpat_", "Shopify access token"),
];

// Deliberately absent: Google's `AIza` prefix. Every Firebase web app ships one
// in its client configuration, where it is public by design and restricted by
// referrer instead. Reporting them would put a High finding in front of a large
// share of users for something that is working as intended, and one such
// finding is enough for a team to stop reading the rest.

/// Words that make an identifier a credential holder.
const SECRET_WORDS: &[&str] = &[
    "apikey",
    "secret",
    "password",
    "passwd",
    "privatekey",
    "accesskey",
    "accesstoken",
    "authtoken",
    "refreshtoken",
    "bearertoken",
    "credential",
    "clientsecret",
    "signingkey",
    "encryptionkey",
    "sessionkey",
];

/// Words that mean an identifier holds a *reference* to a credential rather
/// than the credential.
///
/// `secretName`, `tokenUrl`, `apiKeyHeader`, `publicKey` — all legitimately
/// hold a literal string, and none of them is a leak.
const NOT_A_SECRET: &[&str] = &[
    "public",
    "name",
    "path",
    "url",
    "uri",
    "header",
    "prefix",
    "suffix",
    "type",
    "field",
    "label",
    "id",
    "regex",
    "pattern",
    "placeholder",
    "hint",
    "error",
    "message",
    "column",
    "table",
];

/// Substrings that mark a value as a placeholder rather than a credential.
const PLACEHOLDERS: &[&str] = &[
    "xxx",
    "your",
    "changeme",
    "change-me",
    "change_me",
    "example",
    "placeholder",
    "todo",
    "dummy",
    "fake",
    "sample",
    "redacted",
    "insert",
    "replace",
    "somekey",
    "mysecret",
    "n/a",
    "notreal",
];

/// Path fragments that mark a file as tests or fixtures.
const TEST_PATHS: &[&str] = &[
    "/test/",
    "/tests/",
    "/__tests__/",
    "/__mocks__/",
    "/mocks/",
    "/fixtures/",
    "/e2e/",
    ".test.",
    ".spec.",
    ".stories.",
];

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct HardcodedSecret;

impl HardcodedSecret {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Credential hardcoded in source".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A07:2021")),
            asi: None,
            cwe: Some(798),
            surface: Surface::WebApp,
            category: "secrets".into(),
            description: "A credential appears as a literal in source. Anything committed is in \
                          the repository's history, in every clone, and in every build artefact, \
                          so removing the line later does not revoke it. Read secrets from the \
                          environment or a secret manager, and rotate anything that has been \
                          committed."
                .into(),
        }
    }
}

impl RuleInfo for HardcodedSecret {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for HardcodedSecret {
    fn applies_to(&self, path: &RelPath) -> bool {
        let path = format!("/{}", path.as_str());
        if path.ends_with(".d.ts") {
            return false;
        }
        // A credential in a test is nearly always invented, and reporting them
        // buries the one real finding among twenty fake ones.
        !TEST_PATHS.iter().any(|fragment| path.contains(fragment))
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = SecretVisitor::default();
        visitor.visit_program(unit.program);

        for hit in &visitor.hits {
            if !sink.push(build_finding(unit, hit)) {
                break;
            }
        }
    }
}

/// Why we think a literal is a credential.
enum Reason {
    /// The value carries a provider's prefix.
    Shape(&'static str),
    /// The value is assigned to a credential-shaped name.
    Name(String),
}

/// One suspected credential.
struct Hit {
    span: Span,
    reason: Reason,
    /// The literal value — used only to redact the snippet before it leaves
    /// the process. Never placed in `evidence`.
    value: String,
}

#[derive(Default)]
struct SecretVisitor {
    hits: Vec<Hit>,
    /// Spans already reported, so a value matched by shape is not reported a
    /// second time by name.
    seen: Vec<Span>,
}

impl SecretVisitor {
    fn record(&mut self, span: Span, reason: Reason, value: &str) {
        if self.hits.len() >= MAX_PER_FILE || self.seen.contains(&span) {
            return;
        }
        self.seen.push(span);
        self.hits.push(Hit {
            span,
            reason,
            value: value.to_owned(),
        });
    }

    /// Considers a name/value pair found anywhere a binding can occur.
    fn consider(&mut self, name: &str, value: &Expression<'_>) {
        let Expression::StringLiteral(literal) = value else {
            return;
        };
        let text = literal.value.as_str();
        if !is_secret_name(name) || !could_be_a_credential(text) {
            return;
        }
        self.record(literal.span, Reason::Name(name.to_owned()), text);
    }
}

impl<'a> Visit<'a> for SecretVisitor {
    fn visit_string_literal(&mut self, literal: &oxc_ast::ast::StringLiteral<'a>) {
        // The shape path deliberately ignores the surrounding name: a live
        // Stripe key is a live Stripe key wherever it is written.
        let text = literal.value.as_str();
        if let Some(issuer) = issued_token(text) {
            self.record(literal.span, Reason::Shape(issuer), text);
        }
    }

    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(identifier) = &declarator.id
            && let Some(init) = &declarator.init
        {
            self.consider(identifier.name.as_str(), init);
        }
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
    }

    fn visit_object_property(&mut self, property: &oxc_ast::ast::ObjectProperty<'a>) {
        if let Some(name) = property_name(&property.key) {
            self.consider(name, &property.value);
        }
        oxc_ast_visit::walk::walk_object_property(self, property);
    }

    fn visit_property_definition(&mut self, property: &oxc_ast::ast::PropertyDefinition<'a>) {
        if let Some(name) = property_name(&property.key)
            && let Some(value) = &property.value
        {
            self.consider(name, value);
        }
        oxc_ast_visit::walk::walk_property_definition(self, property);
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        if let Some(target) = assignment.left.as_member_expression()
            && let Some(name) = owlwarden_static::ast::member_property(target)
        {
            self.consider(name, &assignment.right);
        }
        oxc_ast_visit::walk::walk_assignment_expression(self, assignment);
    }
}

/// The issuer of a token, recognised by its reserved prefix.
fn issued_token(value: &str) -> Option<&'static str> {
    if value.len() > MAX_SECRET_LEN {
        return None;
    }
    // Providers put their own prefixes in their documentation, and people paste
    // those examples into code as placeholders. `AKIAIOSFODNN7EXAMPLE` is in
    // AWS's own docs. The prefix is real; the credential is not.
    let lowered = value.to_ascii_lowercase();
    if PLACEHOLDERS
        .iter()
        .any(|placeholder| lowered.contains(placeholder))
    {
        return None;
    }
    // A PEM block is unmistakable and has no prefix in the table's sense.
    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY") {
        return Some("PEM private key");
    }
    if is_aws_access_key(value) {
        return Some("AWS access key id");
    }
    TOKEN_PREFIXES
        .iter()
        .find(|(prefix, _)| value.starts_with(prefix) && value.len() > prefix.len() + 8)
        .map(|(_, issuer)| *issuer)
}

/// AWS access key ids are `AKIA` or `ASIA` followed by 16 uppercase
/// alphanumerics, and nothing else looks like that.
fn is_aws_access_key(value: &str) -> bool {
    if value.len() != 20 {
        return false;
    }
    let Some(rest) = value
        .strip_prefix("AKIA")
        .or_else(|| value.strip_prefix("ASIA"))
    else {
        return false;
    };
    rest.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// Whether an identifier names something that holds a credential.
fn is_secret_name(name: &str) -> bool {
    let normalised: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();

    if NOT_A_SECRET
        .iter()
        .any(|marker| normalised.contains(marker))
    {
        return false;
    }
    SECRET_WORDS.iter().any(|word| normalised.contains(word))
        // `token` and `key` on their own are too common to match anywhere, but
        // as the whole identifier they are unambiguous.
        || matches!(normalised.as_str(), "token" | "secret" | "password" | "apikey" | "key")
}

/// Whether a literal could plausibly be an issued credential.
fn could_be_a_credential(value: &str) -> bool {
    let length = value.chars().count();
    if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&length) {
        return false;
    }
    // Issued credentials have no spaces. Sentences do.
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    // `${...}` is interpolation the parser left in a literal-looking place, and
    // a path or URL is configuration rather than a credential.
    if value.contains("${") || value.starts_with('/') || value.contains("://") {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    if PLACEHOLDERS
        .iter()
        .any(|placeholder| lowered.contains(placeholder))
    {
        return false;
    }
    // `<your-key>` and friends.
    if value.starts_with('<') || value.ends_with('>') {
        return false;
    }
    // A run of one character is a mask, not a secret.
    let first = value.chars().next();
    if first.is_some_and(|first| value.chars().all(|c| c == first)) {
        return false;
    }
    // Real credentials mix character classes. A single-class string of this
    // length is far more often an identifier, a slug, or a constant name.
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_alpha = value.chars().any(|c| c.is_ascii_alphabetic());
    has_digit && has_alpha
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = HardcodedSecret::meta();

    let (confidence, why, evidence) = match &hit.reason {
        Reason::Shape(issuer) => (
            Confidence::Likely,
            format!(
                "This literal carries the prefix of a {issuer}, so it is a real credential rather \
                 than a placeholder. It is in the repository's history and in every clone; \
                 deleting the line does not revoke it."
            ),
            format!("looks like a {issuer}"),
        ),
        Reason::Name(name) => (
            Confidence::Possible,
            format!(
                "A literal is assigned to `{name}`. If it is a real credential it is now in the \
                 repository's history and in every build artefact, and deleting the line will \
                 not revoke it."
            ),
            format!("literal assigned to `{name}`"),
        ),
    };

    // Redact on the full line *before* the frame truncates it — otherwise a
    // long secret survives as the first 400 characters of the JSON snippet.
    let secret = hit.value.clone();
    let masked = mask_secret(&secret);
    let snippet = unit.code_frame_mapped(hit.span, "credential written into source", |line| {
        if secret.is_empty() {
            line.to_owned()
        } else {
            line.replace(&secret, &masked)
        }
    });

    finding_builder(&meta)
        .confidence(confidence)
        .why(why)
        .location(unit.location(hit.span))
        // Evidence never carries the value; the snippet is redacted too so CI
        // JSON and pretty output cannot re-leak the credential.
        .snippet(snippet)
        .context(unit.context(None, Some(evidence)))
        .fixes(remediation().select_for_runtime(unit.framework(), unit.runtime().runtime))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

fn mask_secret(secret: &str) -> String {
    let prefix: String = secret.chars().take(4).collect();
    if secret.chars().count() <= 4 {
        return "***".to_owned();
    }
    format!("{prefix}***")
}

/// Every framework's fix.
///
/// All of them say the same thing in the framework's own idiom, plus the part
/// people skip: rotate. A committed credential is compromised whether or not
/// anyone has used it, and moving it to `.env` without rotating fixes nothing.
fn remediation() -> Remediation {
    let table = Remediation::new(
        "Move the value into an environment variable or a secret manager, and rotate it — once \
         committed it is in the history and in every clone, so removing the line does not revoke \
         it.",
    )
    .manual(
        Framework::NEXT,
        "Read it from the environment on the server. A NEXT_PUBLIC_ prefix ships the value to \
         the browser, so never use one for a secret.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::NUXT,
        "Put it in runtimeConfig; keys outside `public` stay server-side.",
        "// nuxt.config.ts\nruntimeConfig: {\n  apiKey: process.env.API_KEY,\n}\n\n\
         // in a server route\nconst { apiKey } = useRuntimeConfig()",
    )
    .manual(
        Framework::NEST,
        "Read it through ConfigService and validate at startup.",
        "constructor(private readonly config: ConfigService) {}\n\n\
         const apiKey = this.config.getOrThrow<string>('API_KEY')",
    )
    .manual(
        Framework::EXPRESS,
        "Read it from the environment and fail fast if it is missing.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::FASTIFY,
        "Declare it in the @fastify/env schema so a missing value fails at boot.",
        "await app.register(env, {\n  \
         schema: {\n    \
         type: 'object',\n    \
         required: ['API_KEY'],\n    \
         properties: { API_KEY: { type: 'string' } },\n  \
         },\n\
         })",
    )
    .manual(
        Framework::HONO,
        "Read it from the environment (or c.env on Workers) and fail fast if it is missing.",
        "const apiKey = process.env.API_KEY ?? c.env?.API_KEY\n\
         if (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::KOA,
        "Read it from the environment and fail fast if it is missing.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::HAPI,
        "Read it from the environment at server creation and fail fast if it is missing.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::SAILS,
        "Put it in config/local.js (or the environment) rather than the source.",
        "// config/local.js\n\
         module.exports = {\n  \
         custom: {\n    \
         apiKey: process.env.API_KEY,\n  \
         },\n\
         }",
    )
    .manual(
        Framework::ASTRO,
        "Read it with import.meta.env on the server; never use a PUBLIC_ prefix for a secret.",
        "const apiKey = import.meta.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::REMIX,
        "Read it from the environment on the server, in a loader or action.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::GATSBY,
        "Read it from the environment; only a GATSBY_ prefix ships a value to the browser, so \
         never use one for a secret.",
        "const apiKey = process.env.API_KEY\nif (!apiKey) throw new Error('API_KEY is not set')",
    );
    // `process.env` does not exist on a fetch-API runtime. Workers hands the
    // handler an `env` binding and Deno uses `Deno.env.get`, so the base fix —
    // "read it from process.env" — is advice that throws.;
    fixes_added_in_1_2(table)
}

/// The four frameworks added in 1.2, and the runtime deltas.
///
/// A continuation rather than more of the same function. Sixteen profiles plus
/// the deltas is past what fits on a screen, and a table nobody scrolls to the
/// end of is a table with a hole in it.
fn fixes_added_in_1_2(table: Remediation) -> Remediation {
    table    .delta_each(
        &[
            Framework::NEXT,
            Framework::NUXT,
            Framework::HONO,
            Framework::ASTRO,
            Framework::REMIX,
            Framework::SVELTEKIT,
            Framework::TANSTACK_START,
            Framework::SOLIDSTART,
            Framework::ELYSIA,
        ],
        Runtime::WebWorker,
        "There is no process.env on this runtime. Read the value from the binding the host \
         passes the handler, and declare it as a secret rather than a plaintext var.",
        "// wrangler.toml / .dev.vars declare it; the handler receives it.\n\
         export default {\n  \
         async fetch(request: Request, env: { API_KEY: string }) {\n    \
         const key = env.API_KEY\n    \
         if (!key) throw new Error('API_KEY is not bound')\n    \
         return handle(request, key)\n  \
         },\n\
         }",
    )
    .delta(
        Framework::HONO,
        Runtime::Deno,
        "There is no process.env on Deno. Use Deno.env.get, and run with an explicit --allow-env \
         list so the process cannot read variables it was never meant to see.",
        "const key = Deno.env.get('API_KEY')\nif (!key) throw new Error('API_KEY is not set')",
    )
    .manual(
        Framework::SVELTEKIT,
        "Read it from `$env/dynamic/private`, which SvelteKit refuses to import into client code — that refusal is the point.",
        "import { env } from '$env/dynamic/private'\n\nconst stripeKey = env.STRIPE_KEY\nif (!stripeKey) throw new Error('STRIPE_KEY is not set')",
    )
    .manual(
        Framework::TANSTACK_START,
        "Read it from the environment inside the server function, and rotate the committed value.",
        "const stripeKey = process.env.STRIPE_KEY\nif (!stripeKey) throw new Error('STRIPE_KEY is not set')",
    )
    .manual(
        Framework::SOLIDSTART,
        "Read it from the environment in server-only code. A `VITE_`-prefixed variable is bundled into the client; this one must not be.",
        "const stripeKey = process.env.STRIPE_KEY\nif (!stripeKey) throw new Error('STRIPE_KEY is not set')",
    )
    .manual(
        Framework::ELYSIA,
        "Read it from the environment at startup so a missing value fails the boot rather than the first request.",
        "const stripeKey = process.env.STRIPE_KEY\nif (!stripeKey) throw new Error('STRIPE_KEY is not set')",
    )
}

/// Every framework's fix, for `owlwarden explain`.
#[must_use]
pub fn all_fixes() -> Vec<owlwarden_core::finding::Fix> {
    remediation().all()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn issued_tokens_are_recognised_by_their_prefix() {
        assert_eq!(
            issued_token("sk_live_51HxAbCdEfGhIjKlMnOp"),
            Some("Stripe live secret key")
        );
        assert_eq!(
            issued_token("ghp_16CharactersOfTokenHere00"),
            Some("GitHub personal access token")
        );
        assert_eq!(
            issued_token("AKIA4NPQR7TVWXYZ2CDE"),
            Some("AWS access key id")
        );
        assert_eq!(
            issued_token("-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
            Some("PEM private key")
        );
    }

    #[test]
    fn a_bare_prefix_is_not_a_token() {
        // Documentation and validation code contain the prefix on its own.
        assert_eq!(issued_token("sk_live_"), None);
        assert_eq!(issued_token("ghp_"), None);
        // A commit hash is not an AWS key.
        assert_eq!(issued_token("a94a8fe5ccb19ba61c4c"), None);
    }

    #[test]
    fn mask_secret_keeps_a_short_prefix() {
        assert_eq!(mask_secret("sk_live_abcdef"), "sk_l***");
        assert_eq!(mask_secret("ab"), "***");
    }

    #[test]
    fn the_documented_example_key_is_not_a_leak() {
        // `AKIAIOSFODNN7EXAMPLE` is the key in AWS's own documentation, and it
        // is pasted into tutorials, tests, and README files everywhere. The
        // prefix is real, the credential is not, and firing on it is how a
        // secret scanner earns a reputation for crying wolf.
        assert_eq!(issued_token("AKIAIOSFODNN7EXAMPLE"), None);
        assert_eq!(issued_token("sk_live_YOUR_KEY_HERE_000000"), None);
        assert_eq!(issued_token("ghp_exampleTokenValue000000"), None);
    }

    #[test]
    fn names_that_hold_a_reference_are_not_secrets() {
        assert!(is_secret_name("apiKey"));
        assert!(is_secret_name("STRIPE_SECRET_KEY"));
        assert!(is_secret_name("clientSecret"));
        assert!(is_secret_name("password"));

        // These all legitimately hold a literal.
        assert!(!is_secret_name("publicKey"));
        assert!(!is_secret_name("secretName"));
        assert!(!is_secret_name("tokenUrl"));
        assert!(!is_secret_name("apiKeyHeader"));
        assert!(!is_secret_name("passwordFieldLabel"));
        assert!(!is_secret_name("username"));
    }

    #[test]
    fn placeholders_and_prose_are_not_credentials() {
        assert!(could_be_a_credential("8f2c91ba77de4410b3"));

        assert!(!could_be_a_credential("your-api-key-here"));
        assert!(!could_be_a_credential("<INSERT KEY>"));
        assert!(!could_be_a_credential("changeme123456"));
        assert!(!could_be_a_credential("xxxxxxxxxxxxxxxx"));
        assert!(!could_be_a_credential("short1"));
        assert!(!could_be_a_credential("the password was wrong"));
        assert!(!could_be_a_credential("${process.env.KEY}"));
        assert!(!could_be_a_credential("https://api.example.com/v1"));
        // Single character class: an identifier or a slug, not a credential.
        assert!(!could_be_a_credential("averylongidentifier"));
    }
}
