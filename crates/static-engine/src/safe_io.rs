//! Filesystem helpers that refuse to follow symlinks when writing, and that
//! bound reads so a file that grows under our feet cannot exhaust memory.
//!
//! The source sandbox already refuses to *read* paths that escape the project
//! root. Write paths (`--out`, `--write-baseline`) are chosen by the caller and
//! are not confined to the project — but they must still not quietly follow a
//! symlink an attacker planted in the tree and overwrite `~/.ssh/…`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Removes a temp path if it is still present when dropped.
struct TempGuard(Option<PathBuf>);

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// Writes `contents` to `path` without following a symlink at the destination.
///
/// Strategy: write a sibling temp file, then `rename` over `path`. On Unix,
/// `rename` replaces a symlink inode itself rather than writing through it, so
/// a planted link to an outside file cannot be used as a write gadget.
///
/// # Errors
/// Underlying I/O errors, or when the destination path has no parent directory
/// we can place a temp file in.
pub fn write_replacing(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let temp = temp_sibling(parent, path);
    let mut guard = TempGuard(Some(temp.clone()));

    {
        let mut file = File::create(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    fs::rename(&temp, path)?;
    guard.0 = None;
    Ok(())
}

fn temp_sibling(parent: &Path, target: &Path) -> PathBuf {
    let stem = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("owlwarden-out");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Include pid so two processes writing the same path do not collide.
    let name = format!(".owlwarden-{stem}-{nanos}-{}.tmp", std::process::id());
    parent.join(name)
}

/// Opens `path` for reading without following a final-component symlink, then
/// reads at most `max_bytes` into a buffer.
///
/// On Unix this uses `O_NOFOLLOW`. On other platforms it rejects a symlink via
/// `symlink_metadata` first (still a short race, but far better than an
/// unbounded `fs::read` through a link).
///
/// # Errors
/// I/O errors, or when the file is larger than `max_bytes`.
pub fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let mut file = open_nofollow(path)?;
    let mut buf = Vec::new();
    let limit = max_bytes.saturating_add(1);
    Read::take(Read::by_ref(&mut file), limit).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} bytes"),
        ));
    }
    Ok(buf)
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW values: Linux/Android 0x20000, macOS/iOS/BSD 0x100.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        const O_NOFOLLOW: i32 = 0x20000;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW: i32 = 0x100;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        )))]
        const O_NOFOLLOW: i32 = 0;

        OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to read through a symlink",
            ));
        }
        File::open(path)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::io::Write;

    #[test]
    fn write_replaces_symlink_instead_of_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.txt");
        fs::write(&target, b"do-not-clobber").unwrap();

        let link = dir.path().join("report.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(not(unix))]
        {
            // Windows symlink creation often needs elevation; skip the race
            // shape and just check a normal write round-trip.
            write_replacing(&link, b"{\"ok\":true}").unwrap();
            assert_eq!(fs::read(&link).unwrap(), b"{\"ok\":true}");
            return;
        }

        write_replacing(&link, b"{\"ok\":true}").unwrap();
        // The symlink inode was replaced; the outside target is untouched.
        assert_eq!(fs::read(&link).unwrap(), b"{\"ok\":true}");
        assert_eq!(fs::read(&target).unwrap(), b"do-not-clobber");
        assert!(
            !fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn read_bounded_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.txt");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[b'a'; 32]).unwrap();
        let err = read_bounded(&path, 16).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    #[cfg(unix)]
    fn read_nofollow_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        fs::write(&target, b"hello").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = read_bounded(&link, 1024).unwrap_err();
        // ELOOP / EINVAL depending on platform; either way it must not return
        // the target's bytes.
        assert!(err.raw_os_error().is_some() || err.kind() == io::ErrorKind::InvalidInput);
    }
}
