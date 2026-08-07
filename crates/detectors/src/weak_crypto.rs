//! `weak-crypto` — broken primitives used where they have to hold.
//!
//! # The three things it finds
//!
//! **A broken hash on a password.** `crypto.createHash('md5')` or `'sha1'`
//! feeding something named like a credential. Both are fast by design, which is
//! precisely the wrong property: a modern GPU tries billions of candidates a
//! second, so a leaked table of MD5 password hashes is a leaked table of
//! passwords. Password hashing needs a *slow* algorithm — bcrypt, scrypt,
//! argon2 — and this rule exists because `createHash('md5')` is what an
//! autocomplete suggests.
//!
//! **`Math.random()` used for something security-relevant.** It is a PRNG
//! seeded from a value an attacker can often infer, and V8's implementation is
//! documented as unsuitable for cryptography. Session ids, password-reset
//! tokens, and API keys built from it are guessable. `crypto.randomUUID()` and
//! `crypto.randomBytes()` are one line away and correct.
//!
//! **A broken cipher.** DES, RC4, or any ECB mode. ECB leaks structure —
//! identical plaintext blocks produce identical ciphertext blocks, which is why
//! the famous encrypted-penguin image is still recognisably a penguin.
//!
//! # How it stays quiet
//!
//! A hash is only a finding when the *use* is security-relevant. MD5 as a cache
//! key, an `ETag`, or a content fingerprint is completely fine and extremely
//! common, so the rule requires evidence of a credential use — the variable or
//! property name — before reporting, and says so in the confidence. The same
//! goes for `Math.random()`: picking a random array element or a jitter delay
//! is not a finding, and if this rule fired on every `Math.random()` in a
//! codebase it would be turned off within a day.

use owlwarden_core::detector::DetectorMeta;
use owlwarden_core::finding::{
    Confidence, Finding, Framework, OwaspRef, Reference, RuleId, Severity,
};
use owlwarden_core::remediation::Remediation;
use owlwarden_core::source::RelPath;
use owlwarden_static::ast::{root_identifier, static_property, string_value};
use owlwarden_static::rule::{FileRule, FindingSink, RuleInfo};
use owlwarden_static::unit::FileUnit;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_span::Span;

use crate::build::finding_builder_with;

/// The rule id. Permanent public API.
pub const ID: &str = "weak-crypto";

/// Hash algorithms that must not protect a credential.
///
/// Fast by design. That is a virtue for a checksum and a defect for a password.
const BROKEN_HASHES: &[&str] = &["md5", "md4", "sha1", "sha-1", "ripemd160"];

/// Ciphers and modes that are broken outright.
const BROKEN_CIPHERS: &[&str] = &[
    "des",
    "des-ecb",
    "des-cbc",
    "rc4",
    "rc2",
    "bf",
    "blowfish",
    "aes-128-ecb",
    "aes-192-ecb",
    "aes-256-ecb",
];

/// Names that make a value security-relevant.
///
/// The whole precision of this rule rests on this list. Hashing a file for a
/// cache key is correct and common; hashing a password is not, and only the
/// name tells them apart.
const SECURITY_CONTEXT: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "session",
    "sessionid",
    "credential",
    "apikey",
    "api_key",
    "auth",
    "signature",
    "sign",
    "hmac",
    "nonce",
    "salt",
    "csrf",
    "otp",
    "reset",
    "verification",
    "privatekey",
    "accesskey",
];

/// Findings collected from one file before the visitor stops.
const MAX_PER_FILE: usize = 32;

/// The rule.
#[derive(Debug, Default, Clone, Copy)]
pub struct WeakCrypto;

impl WeakCrypto {
    /// Metadata, also used to generate `RULES.md`.
    #[must_use]
    pub fn meta() -> DetectorMeta {
        DetectorMeta {
            id: RuleId::new_static(ID),
            title: "Broken cryptographic primitive protecting a secret".into(),
            severity: Severity::High,
            max_confidence: Confidence::Likely,
            owasp: Some(OwaspRef::new_static("A02:2021")),
            cwe: Some(327),
            category: "crypto".into(),
            description: "A hash, cipher, or random source that cannot carry the weight it has \
                          been given: MD5 or SHA-1 over a password, a DES or ECB cipher, or \
                          Math.random() producing a token. Each has a drop-in replacement in the \
                          standard library, so the fix is small — the cost of not making it is \
                          that the protection is decorative."
                .into(),
        }
    }
}

impl RuleInfo for WeakCrypto {
    fn meta(&self) -> DetectorMeta {
        Self::meta()
    }

    fn remediation(&self) -> Remediation {
        remediation()
    }
}

impl FileRule for WeakCrypto {
    fn applies_to(&self, path: &RelPath) -> bool {
        !path.as_str().ends_with(".d.ts")
    }

    fn check(&self, unit: &FileUnit<'_>, sink: &mut FindingSink) {
        let mut visitor = CryptoVisitor {
            hits: Vec::new(),
            enclosing: Vec::new(),
        };
        visitor.visit_program(unit.program);

        for hit in &visitor.hits {
            if !sink.push(build_finding(unit, hit)) {
                break;
            }
        }
    }
}

/// What was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Weakness {
    /// A broken hash over something named like a credential.
    HashedSecret,
    /// A broken cipher or mode, in any context.
    BrokenCipher,
    /// `Math.random()` producing something named like a credential.
    GuessableToken,
}

/// One weak primitive.
struct Hit {
    span: Span,
    weakness: Weakness,
    /// The algorithm or call as written, for the evidence line.
    detail: String,
    /// The name that made it security-relevant, if there was one.
    context: Option<String>,
}

struct CryptoVisitor {
    hits: Vec<Hit>,
    /// Names of the bindings and properties we are currently inside.
    ///
    /// A stack rather than a single name because the call is usually nested:
    /// `const passwordHash = createHash('md5').update(pw).digest()` puts the
    /// telling name two levels above the call, and
    /// `{ token: Math.random().toString(36) }` puts it on the property.
    enclosing: Vec<String>,
}

/// Deepest nesting of names we keep. Bounded because the input is untrusted.
const MAX_ENCLOSING: usize = 32;

impl CryptoVisitor {
    /// The nearest enclosing name that marks this as security-relevant.
    fn security_context(&self) -> Option<String> {
        self.enclosing
            .iter()
            .rev()
            .find(|name| is_security_name(name))
            .cloned()
    }

    fn push_name(&mut self, name: &str) -> bool {
        if self.enclosing.len() >= MAX_ENCLOSING {
            return false;
        }
        self.enclosing.push(name.to_ascii_lowercase());
        true
    }
}

impl<'a> Visit<'a> for CryptoVisitor {
    fn visit_variable_declarator(&mut self, declarator: &oxc_ast::ast::VariableDeclarator<'a>) {
        let pushed = match &declarator.id {
            oxc_ast::ast::BindingPattern::BindingIdentifier(identifier) => {
                self.push_name(&identifier.name)
            }
            _ => false,
        };
        oxc_ast_visit::walk::walk_variable_declarator(self, declarator);
        if pushed {
            self.enclosing.pop();
        }
    }

    fn visit_object_property(&mut self, property: &oxc_ast::ast::ObjectProperty<'a>) {
        let pushed = property
            .key
            .static_name()
            .is_some_and(|name| self.push_name(&name));
        oxc_ast_visit::walk::walk_object_property(self, property);
        if pushed {
            self.enclosing.pop();
        }
    }

    fn visit_assignment_expression(&mut self, assignment: &oxc_ast::ast::AssignmentExpression<'a>) {
        let pushed = assignment
            .left
            .get_expression()
            .and_then(static_property)
            .is_some_and(|name| self.push_name(name));
        oxc_ast_visit::walk::walk_assignment_expression(self, assignment);
        if pushed {
            self.enclosing.pop();
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if self.hits.len() < MAX_PER_FILE {
            self.inspect(call);
        }
        oxc_ast_visit::walk::walk_call_expression(self, call);
    }
}

impl CryptoVisitor {
    fn inspect(&mut self, call: &CallExpression<'_>) {
        let Some(method) = callee_name(call) else {
            return;
        };

        match method {
            "createHash" | "createHmac" => {
                let Some(algorithm) = first_string(call) else {
                    return;
                };
                let lowered = algorithm.to_ascii_lowercase();
                if !BROKEN_HASHES.contains(&lowered.as_str()) {
                    return;
                }
                // A broken hash is only a finding when it is protecting
                // something. As a cache key or an ETag it is correct.
                let Some(context) = self.security_context() else {
                    return;
                };
                self.hits.push(Hit {
                    span: call.span,
                    weakness: Weakness::HashedSecret,
                    detail: lowered,
                    context: Some(context),
                });
            }
            "createCipheriv" | "createDecipheriv" | "createCipher" | "createDecipher" => {
                let Some(algorithm) = first_string(call) else {
                    return;
                };
                let lowered = algorithm.to_ascii_lowercase();
                if !BROKEN_CIPHERS.contains(&lowered.as_str()) {
                    return;
                }
                // No name check: there is no benign use of DES or ECB.
                self.hits.push(Hit {
                    span: call.span,
                    weakness: Weakness::BrokenCipher,
                    detail: lowered,
                    context: self.security_context(),
                });
            }
            "random" => {
                if root_identifier(&call.callee) != Some("Math") {
                    return;
                }
                let Some(context) = self.security_context() else {
                    return;
                };
                self.hits.push(Hit {
                    span: call.span,
                    weakness: Weakness::GuessableToken,
                    detail: "Math.random()".to_owned(),
                    context: Some(context),
                });
            }
            _ => {}
        }
    }
}

/// The name being called, whether through a namespace or imported bare.
///
/// Both spellings are idiomatic and the bare one is more common in TypeScript:
/// `import { createHash } from 'node:crypto'`. Recognising only
/// `crypto.createHash` would have missed most real code — which it did, until a
/// fixture caught it.
fn callee_name<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
    match &call.callee {
        Expression::Identifier(identifier) => Some(identifier.name.as_str()),
        callee => static_property(callee),
    }
}

/// The first argument, if it is a string literal.
fn first_string(call: &CallExpression<'_>) -> Option<String> {
    call.arguments
        .first()
        .and_then(Argument::as_expression)
        .and_then(string_value)
        .map(str::to_owned)
}

/// Whether a name marks its value as security-relevant.
fn is_security_name(name: &str) -> bool {
    let normalised: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    SECURITY_CONTEXT
        .iter()
        .any(|marker| normalised.contains(&marker.replace('_', "")))
}

/// Builds the finding.
fn build_finding(unit: &FileUnit<'_>, hit: &Hit) -> Finding {
    let meta = WeakCrypto::meta();

    let (severity, why, label) = match hit.weakness {
        Weakness::HashedSecret => (
            Severity::High,
            "This hash is fast, and speed is the attacker's advantage: a commodity GPU tries \
             billions of candidates a second, so a leaked table of these hashes is a leaked \
             table of the values behind them. Password hashing needs a deliberately slow \
             algorithm with a per-value salt.",
            "fast hash protecting a credential",
        ),
        Weakness::BrokenCipher => (
            Severity::High,
            "This cipher or mode is broken independently of the key. DES has a keyspace small \
             enough to search, RC4 has biased output, and ECB encrypts identical plaintext \
             blocks to identical ciphertext blocks — the structure of the data survives \
             encryption.",
            "broken cipher",
        ),
        Weakness::GuessableToken => (
            Severity::High,
            "Math.random() is a fast PRNG, not a cryptographic one; V8 documents it as \
             unsuitable for security. An attacker who sees a few outputs can predict the rest, \
             which for a session id or a reset token means minting valid ones.",
            "predictable random source used for a secret",
        ),
    };

    let evidence = hit.context.as_ref().map_or_else(
        || hit.detail.clone(),
        |context| format!("{} used for `{context}`", hit.detail),
    );

    finding_builder_with(&meta, severity)
        // The name is strong evidence and not proof — someone may have called a
        // cache key `tokenHash`. Saying `Likely` rather than `Confirmed` is the
        // difference between a rule people trust and one they argue with.
        .confidence(Confidence::Likely)
        .why(why)
        .location(unit.location(hit.span))
        .snippet(unit.code_frame(hit.span, label))
        .context(unit.context(None, Some(evidence)))
        .fixes(remediation().select(unit.framework()))
        .reference(Reference::rule_page(&meta.id))
        .build()
}

/// The replacement, which is the same on every runtime because it is in the
/// standard library.
const NODE_PATCH: &str = "import { randomBytes, randomUUID, scrypt } from 'node:crypto'\n\
     \n\
     // Tokens and session ids: unpredictable, not merely random-looking.\n\
     const sessionId = randomUUID()\n\
     const resetToken = randomBytes(32).toString('base64url')\n\
     \n\
     // Passwords: a slow hash with a per-password salt. bcrypt and argon2 are\n\
     // equally correct; scrypt needs no dependency.\n\
     const salt = randomBytes(16)\n\
     const hash = await new Promise<Buffer>((resolve, reject) =>\n  \
     scrypt(password, salt, 64, (error, key) => (error ? reject(error) : resolve(key))),\n\
     )";

/// Every framework's fix.
///
/// The advice barely varies, because the problem is the primitive rather than
/// the framework. It is still stated per framework: a Nuxt developer reading
/// "use node:crypto" wants to know it works inside Nitro, and the runtime note
/// is the part they cannot guess.
fn remediation() -> Remediation {
    Remediation::new(
        "Use a slow, salted hash for passwords and a cryptographic random source for tokens. \
         Both are in the Node standard library; neither needs a dependency.",
    )
    .generic_patch(NODE_PATCH)
    .manual(
        Framework::NEXT,
        "Use node:crypto in the route handler. Note that the edge runtime has no node:crypto — \
         use globalThis.crypto.randomUUID() and Web Crypto there, or pin the route to nodejs.",
        NODE_PATCH,
    )
    .manual(
        Framework::NUXT,
        "node:crypto works inside Nitro on the node preset. On a worker preset use the Web \
         Crypto API, which Nitro exposes globally as `crypto`.",
        NODE_PATCH,
    )
    .manual(
        Framework::NEST,
        "Put the hashing behind a provider so every caller gets the same algorithm, rather than \
         each service choosing one.",
        "@Injectable()\nexport class PasswordService {\n  \
         async hash(plain: string) {\n    \
         return await argon2.hash(plain)\n  \
         }\n  \
         async verify(hash: string, plain: string) {\n    \
         return await argon2.verify(hash, plain)\n  \
         }\n\
         }",
    )
    .manual(
        Framework::EXPRESS,
        "Replace the hash at the point of use; there is no middleware for this.",
        NODE_PATCH,
    )
    .manual(
        Framework::FASTIFY,
        "Replace the hash at the point of use. If you use @fastify/secure-session, let it \
         generate the session key rather than deriving one yourself.",
        NODE_PATCH,
    )
    .manual(
        Framework::HONO,
        "Use node:crypto when running on Node; on Workers/Deno use the Web Crypto API instead.",
        NODE_PATCH,
    )
    .manual(
        Framework::KOA,
        "Replace the primitive at the point of use; there is no middleware for this.",
        NODE_PATCH,
    )
    .manual(
        Framework::HAPI,
        "Replace the primitive at the point of use; there is no plugin for this.",
        NODE_PATCH,
    )
    .manual(
        Framework::SAILS,
        "Replace the primitive at the point of use in the model or service.",
        NODE_PATCH,
    )
    .manual(
        Framework::ASTRO,
        "Use node:crypto in server endpoints; on edge/Workers adapters use the Web Crypto API \
         instead.",
        NODE_PATCH,
    )
    .manual(
        Framework::REMIX,
        "Use node:crypto in loaders/actions on the Node runtime; on Workers/Deno use the Web \
         Crypto API instead.",
        NODE_PATCH,
    )
    .manual(
        Framework::GATSBY,
        "Replace the primitive at the point of use in the Function handler.",
        NODE_PATCH,
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
    fn security_names_are_matched_across_spellings() {
        assert!(is_security_name("password"));
        assert!(is_security_name("passwordHash"));
        assert!(is_security_name("API_KEY"));
        assert!(is_security_name("resetToken"));
        assert!(is_security_name("csrfSecret"));
    }

    #[test]
    fn ordinary_names_do_not_make_a_hash_a_finding() {
        // MD5 as a cache key or an ETag is correct and everywhere. If these
        // start matching, the rule becomes noise on every build pipeline.
        assert!(!is_security_name("cacheKey"));
        assert!(!is_security_name("etag"));
        assert!(!is_security_name("fileHash"));
        assert!(!is_security_name("checksum"));
        assert!(!is_security_name("colorIndex"));
    }

    #[test]
    fn ecb_is_broken_in_every_key_length() {
        // The key length is not the problem; the mode is. Listing only
        // aes-256-ecb would let the weaker variants through.
        for algorithm in ["aes-128-ecb", "aes-192-ecb", "aes-256-ecb"] {
            assert!(BROKEN_CIPHERS.contains(&algorithm), "{algorithm} missing");
        }
        assert!(!BROKEN_CIPHERS.contains(&"aes-256-gcm"), "GCM is correct");
    }

    #[test]
    fn sha256_is_not_on_the_broken_list() {
        assert!(!BROKEN_HASHES.contains(&"sha256"));
        assert!(!BROKEN_HASHES.contains(&"sha512"));
    }
}
