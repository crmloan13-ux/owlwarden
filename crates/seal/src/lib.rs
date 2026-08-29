//! `.owlwarden/surface.lock` — a lockfile for the agent execution surface.
//!
//! # What this is for
//!
//! The ten agent-surface rules and `owlwarden vet` are point-in-time. They
//! answer *is this configuration dangerous right now*. The attack they were
//! written for is not point-in-time: the August 2026 worm's second infection
//! route worked by *writing* into `.claude/settings.json` and
//! `.vscode/tasks.json`, using stolen credentials to commit them into branches
//! of repositories it never otherwise touched.
//!
//! A rule catches that only if the injected configuration happens to match a
//! shape somebody enumerated. A `SessionStart` hook running
//! `node ./scripts/warm-cache.mjs` is indistinguishable from a legitimate one by
//! inspection, and both the rules and a human reviewer will treat it as
//! ordinary.
//!
//! What is *not* ambiguous is that it was not there yesterday.
//!
//! `package-lock.json` does not judge whether a package is malicious. It records
//! what was resolved and makes a change loud, and it works because the diff is
//! reviewable even when the content is not. This is that, for the set of files
//! an agent loads and executes out of the working tree
//! ([ADR 0027](../../../docs/adr/0027-workspace-seal.md)).
//!
//! # What it is not
//!
//! **A detection and review control, not a containment control.** An unsigned
//! seal detects accident, drift, and opportunistic malware. It does not stop an
//! attacker with code execution who can run `owlwarden seal --yes` before you
//! next look. A signed seal with the key outside the repository raises the bar
//! substantially, because CI verifies a signature that a process writing files
//! in the working tree cannot forge. A targeted attacker who compromises the
//! signing key defeats it, as they defeat every signing scheme.
//!
//! Nothing in this crate signs. Verification is one direction on purpose: a
//! security tool that holds a private key is a security tool with a private key
//! to steal, and the key belongs in a developer's keychain or a CI secret where
//! this process cannot reach it.
//!
//! # Layout
//!
//! - [`model`] — the file format, and the digests it records.
//! - [`extract`] — reading the current surface out of an `AgentWorkspace`.
//! - [`diff`] — comparing two surfaces in the surface's own vocabulary.
//! - [`signature`] — detached ed25519 verification, reusing ADR 0021's roots.
//! - [`store`] — reading and writing the file, with the caps that make a
//!   hostile lockfile boring.

#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod diff;
pub mod extract;
pub mod model;
pub mod signature;
pub mod store;

pub use diff::{Change, ChangeKind, SurfaceDiff};
pub use extract::{ExtractError, extract};
pub use model::{
    AcceptedFinding, EngineStamp, SealedFile, SealedHook, SealedMcpServer, SealedPermissions,
    SurfaceLock, SurfaceRecord,
};
pub use signature::{SignatureStatus, verify_detached, verify_detached_with};
pub use store::{LOCK_PATH, SIGNATURE_PATH, SealError, load, write};
