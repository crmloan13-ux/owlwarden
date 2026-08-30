//! Reading and writing `.owlwarden/surface.lock`.
//!
//! The lockfile is committed, so it is also *input* — a hostile branch can put
//! anything in it. Every bound here exists for that reason: a lockfile that can
//! exhaust memory or recursion is a lockfile that turns `seal --verify` from a
//! check into a denial of service against the person running it.

use std::path::{Path, PathBuf};

use crate::model::{SCHEMA_VERSION, SurfaceLock};

/// Where the lockfile lives, relative to the project root.
pub const LOCK_PATH: &str = ".owlwarden/surface.lock";

/// Where its detached signature lives.
pub const SIGNATURE_PATH: &str = ".owlwarden/surface.lock.sig";

/// Largest lockfile read.
///
/// Generous for a real one — a surface of five hundred files lands well under
/// a megabyte — and small enough that a 2 GB file committed by a hostile branch
/// is refused rather than read.
pub const MAX_LOCK_BYTES: u64 = 4 * 1024 * 1024;

/// Reading or writing the lockfile failed.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// No lockfile at the expected path.
    #[error("no seal at {path}; run `owlwarden seal` to write one")]
    Missing {
        /// The path looked for.
        path: String,
    },
    /// The file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The path.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_LOCK_BYTES`].
    #[error("{path} is {size} bytes; the maximum is {max}")]
    TooLarge {
        /// The path.
        path: String,
        /// Its size.
        size: u64,
        /// The cap.
        max: u64,
    },
    /// The file is not a lockfile we understand.
    #[error("{path} is not a valid surface lock: {message}")]
    Malformed {
        /// The path.
        path: String,
        /// What went wrong, safe to display.
        message: String,
    },
    /// The file declares a schema version this build does not know.
    ///
    /// Refused rather than best-effort parsed. A seal is a comparison against a
    /// recorded surface, and comparing against a format we are guessing at
    /// would produce a diff nobody should act on.
    #[error(
        "{path} declares schemaVersion {found}; this build understands {SCHEMA_VERSION}. \
         Upgrade owlwarden, or re-seal with this version."
    )]
    UnknownVersion {
        /// The path.
        path: String,
        /// The version it declared.
        found: u32,
    },
    /// An `accepted` entry carried no reason.
    #[error("{path}: accepted entry for {rule} has no reason; every acceptance needs one")]
    AcceptanceWithoutReason {
        /// The path.
        path: String,
        /// The rule the entry names.
        rule: String,
    },
}

/// The absolute path of the lockfile under a project root.
#[must_use]
pub fn lock_path(root: &Path) -> PathBuf {
    root.join(LOCK_PATH)
}

/// The absolute path of the detached signature under a project root.
#[must_use]
pub fn signature_path(root: &Path) -> PathBuf {
    root.join(SIGNATURE_PATH)
}

/// Reads the lockfile, or reports why it could not be trusted.
///
/// # Errors
/// [`SealError`] when the file is absent, oversized, malformed, written under a
/// schema this build does not know, or carries an acceptance with no reason.
pub fn load(root: &Path) -> Result<(SurfaceLock, Vec<u8>), SealError> {
    let path = lock_path(root);
    let display = path.display().to_string();

    let metadata = std::fs::metadata(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            SealError::Missing {
                path: display.clone(),
            }
        } else {
            SealError::Io {
                path: display.clone(),
                source,
            }
        }
    })?;
    if metadata.len() > MAX_LOCK_BYTES {
        return Err(SealError::TooLarge {
            path: display,
            size: metadata.len(),
            max: MAX_LOCK_BYTES,
        });
    }

    let bytes = std::fs::read(&path).map_err(|source| SealError::Io {
        path: display.clone(),
        source,
    })?;
    // Size is re-checked after the read: the metadata call and the read are two
    // syscalls, and the file can grow between them.
    if bytes.len() as u64 > MAX_LOCK_BYTES {
        return Err(SealError::TooLarge {
            path: display,
            size: bytes.len() as u64,
            max: MAX_LOCK_BYTES,
        });
    }

    let lock: SurfaceLock =
        serde_json::from_slice(&bytes).map_err(|error| SealError::Malformed {
            path: display.clone(),
            message: error.to_string(),
        })?;
    if lock.schema_version != SCHEMA_VERSION {
        return Err(SealError::UnknownVersion {
            path: display,
            found: lock.schema_version,
        });
    }
    if let Some(entry) = lock
        .accepted
        .iter()
        .find(|entry| entry.reason.trim().is_empty())
    {
        return Err(SealError::AcceptanceWithoutReason {
            path: display,
            rule: entry.rule.clone(),
        });
    }
    Ok((lock, bytes))
}

/// Renders a lockfile exactly as it is written to disk.
///
/// Pretty-printed with a trailing newline, because the whole point is that a
/// human reads the diff. Deterministic: the same surface produces the same
/// bytes, so re-sealing an unchanged tree is a no-op in git.
///
/// # Errors
/// [`SealError::Malformed`] only if serialization fails, which it cannot for
/// this shape.
pub fn render(lock: &SurfaceLock) -> Result<String, SealError> {
    let mut text = serde_json::to_string_pretty(lock).map_err(|error| SealError::Malformed {
        path: LOCK_PATH.to_owned(),
        message: error.to_string(),
    })?;
    text.push('\n');
    Ok(text)
}

/// Writes the lockfile under a project root, creating `.owlwarden/`.
///
/// # Errors
/// [`SealError::Io`] if the directory or file cannot be written.
pub fn write(root: &Path, lock: &SurfaceLock) -> Result<PathBuf, SealError> {
    let path = lock_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| SealError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let text = render(lock)?;
    owlwarden_static::write_replacing(&path, text.as_bytes()).map_err(|source| SealError::Io {
        path: path.display().to_string(),
        source: std::io::Error::other(source.to_string()),
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::model::{AcceptedFinding, EngineStamp, SurfaceRecord};

    fn lock() -> SurfaceLock {
        SurfaceLock {
            schema_version: SCHEMA_VERSION,
            sealed_at: "2026-08-27T09:14:02Z".to_owned(),
            engine: EngineStamp {
                version: "1.2.0".to_owned(),
                catalogue_digest: "sha256:cafe".to_owned(),
            },
            surface: SurfaceRecord::default(),
            accepted: Vec::new(),
        }
    }

    #[test]
    fn a_seal_round_trips_byte_identically() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), &lock()).unwrap();
        let first = std::fs::read(lock_path(root.path())).unwrap();
        write(root.path(), &lock()).unwrap();
        let second = std::fs::read(lock_path(root.path())).unwrap();
        assert_eq!(
            first, second,
            "re-sealing an unchanged tree must be a no-op"
        );

        let (loaded, _) = load(root.path()).unwrap();
        assert_eq!(loaded, lock());
    }

    #[test]
    fn a_missing_seal_says_how_to_write_one() {
        let root = tempfile::tempdir().unwrap();
        let error = load(root.path()).unwrap_err();
        assert!(matches!(error, SealError::Missing { .. }));
        assert!(error.to_string().contains("owlwarden seal"));
    }

    #[test]
    fn a_future_schema_is_refused_rather_than_guessed_at() {
        let root = tempfile::tempdir().unwrap();
        let mut future = lock();
        future.schema_version = SCHEMA_VERSION + 1;
        write(root.path(), &future).unwrap();
        assert!(matches!(
            load(root.path()).unwrap_err(),
            SealError::UnknownVersion { .. }
        ));
    }

    #[test]
    fn an_acceptance_without_a_reason_fails_to_load() {
        // The same rule suppressions live under: an accepted finding nobody can
        // explain is a finding nobody decided.
        let root = tempfile::tempdir().unwrap();
        let mut unreasoned = lock();
        unreasoned.accepted.push(AcceptedFinding {
            fingerprint: "abc".to_owned(),
            rule: "agent-hook-autoexec".to_owned(),
            reason: "   ".to_owned(),
        });
        write(root.path(), &unreasoned).unwrap();
        assert!(matches!(
            load(root.path()).unwrap_err(),
            SealError::AcceptanceWithoutReason { .. }
        ));
    }

    #[test]
    fn an_oversized_seal_is_refused_before_it_is_parsed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".owlwarden")).unwrap();
        let padding = vec![b'x'; usize::try_from(MAX_LOCK_BYTES).unwrap() + 1];
        std::fs::write(lock_path(root.path()), padding).unwrap();
        assert!(matches!(
            load(root.path()).unwrap_err(),
            SealError::TooLarge { .. }
        ));
    }

    #[test]
    fn a_hostile_lockfile_is_a_parse_error_and_not_a_panic() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".owlwarden")).unwrap();
        for body in [
            String::new(),
            "null".to_owned(),
            "[]".to_owned(),
            "{\"schemaVersion\":\"one\"}".to_owned(),
            format!("{{\"schemaVersion\":1,\"surface\":{}}}", "[".repeat(2000)),
        ] {
            std::fs::write(lock_path(root.path()), &body).unwrap();
            assert!(load(root.path()).is_err(), "accepted {body:?}");
        }
    }
}
