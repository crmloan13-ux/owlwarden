//! Lockfile → [`PackageQuery`] extraction for OSV (ADR 0016).
//!
//! Parses npm / pnpm / yarn lockfiles with bounded scanners. No YAML library:
//! we only need package name + version, and a full parser is not worth the
//! install footprint for three formats (`ci_unpinned_action` takes the same
//! posture for workflows).

use owlwarden_core::advisory::PackageQuery;
use owlwarden_core::limits;
use owlwarden_core::source::{FileSelector, SourceFile, SourceProvider};

/// One resolved package located in a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfilePackage {
    /// Project-relative lockfile path.
    pub path: String,
    /// 1-based line of the package entry (best effort).
    pub line: u32,
    /// Query to send to the advisory client.
    pub query: PackageQuery,
}

/// Glob patterns for lockfiles we understand (root and nested).
const LOCKFILE_GLOBS: &[&str] = &[
    "package-lock.json",
    "**/package-lock.json",
    "pnpm-lock.yaml",
    "**/pnpm-lock.yaml",
    "yarn.lock",
    "**/yarn.lock",
];

/// Reads every supported lockfile under the project and extracts packages.
///
/// Caps at [`limits::advisory::MAX_PACKAGES`]. Malformed lockfiles are skipped
/// rather than failing the scan — a half-written lockfile mid-install must not
/// abort an otherwise useful audit.
pub fn collect_packages(source: &dyn SourceProvider) -> Vec<LockfilePackage> {
    let Ok(files) = source.files(&FileSelector::include(
        LOCKFILE_GLOBS
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect::<Vec<_>>(),
    )) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for file in files.iter().take(32) {
        if out.len() >= limits::advisory::MAX_PACKAGES {
            break;
        }
        let Ok(text) = source.read(file) else {
            continue;
        };
        let remaining = limits::advisory::MAX_PACKAGES.saturating_sub(out.len());
        let parsed = parse_lockfile(file, &text, remaining);
        out.extend(parsed);
    }
    out
}

fn parse_lockfile(file: &SourceFile, text: &str, max: usize) -> Vec<LockfilePackage> {
    let name = file.path.file_name();
    match name {
        "package-lock.json" => parse_package_lock(file.path.as_str(), text, max),
        "pnpm-lock.yaml" => parse_pnpm_lock(file.path.as_str(), text, max),
        "yarn.lock" => parse_yarn_lock(file.path.as_str(), text, max),
        _ => Vec::new(),
    }
}

fn parse_package_lock(path: &str, text: &str, max: usize) -> Vec<LockfilePackage> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(packages) = value.get("packages").and_then(|v| v.as_object()) else {
        return Vec::new();
    };

    // One linear scan for key → line. Looking up each key with a full-file
    // scan would be O(packages × lines) on multi-megabyte lockfiles.
    let line_index = package_lock_key_lines(text);

    let mut out = Vec::new();
    for (key, entry) in packages
        .iter()
        .take(limits::advisory::MAX_PACKAGES.saturating_mul(2))
    {
        if out.len() >= max {
            break;
        }
        if key.is_empty() {
            continue;
        }
        let Some(name) = npm_name_from_packages_key(key) else {
            continue;
        };
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_plausible_version(version) || !is_plausible_name(&name) {
            continue;
        }
        let line = line_index.get(key.as_str()).copied().unwrap_or(1);
        out.push(LockfilePackage {
            path: path.to_owned(),
            line,
            query: PackageQuery {
                ecosystem: "npm".to_owned(),
                name,
                version: version.to_owned(),
            },
        });
    }
    out
}

/// Maps `"node_modules/…"` package-lock keys to their 1-based source line.
fn package_lock_key_lines(text: &str) -> std::collections::HashMap<String, u32> {
    let mut map = std::collections::HashMap::new();
    for (index, line) in text.lines().enumerate().take(200_000) {
        let trimmed = line.trim();
        // `"node_modules/lodash": {` or `"node_modules/@scope/pkg": {`
        let Some(rest) = trimmed.strip_prefix('"') else {
            continue;
        };
        let Some((key, _)) = rest.split_once('"') else {
            continue;
        };
        if !key.contains("node_modules/") {
            continue;
        }
        let line_no = u32::try_from(index + 1).unwrap_or(1);
        map.entry(key.to_owned()).or_insert(line_no);
    }
    map
}

/// `node_modules/lodash` → `lodash`; `node_modules/@scope/pkg` → `@scope/pkg`.
fn npm_name_from_packages_key(key: &str) -> Option<String> {
    let trimmed = key.trim_start_matches("./");
    let after = trimmed.rsplit("node_modules/").next()?;
    if after.is_empty() || after.contains("node_modules/") {
        return None;
    }
    // Scoped packages are two segments: `@scope/name`.
    if after.starts_with('@') {
        let mut parts = after.split('/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if parts.next().is_some() || scope.len() < 2 || name.is_empty() {
            return None;
        }
        return Some(format!("{scope}/{name}"));
    }
    if after.contains('/') {
        return None;
    }
    Some(after.to_owned())
}

/// Line-scans the `packages:` map in pnpm-lock.yaml.
///
/// Keys look like `/lodash@4.17.19:` or `/@scope/pkg@1.2.3(peer@1):`.
fn parse_pnpm_lock(path: &str, text: &str, max: usize) -> Vec<LockfilePackage> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for (index, line) in text.lines().enumerate().take(200_000) {
        if out.len() >= max {
            break;
        }
        if !in_packages {
            if line == "packages:" || line.starts_with("packages:") {
                in_packages = true;
            }
            continue;
        }
        // A new top-level key ends the packages block.
        if !line.is_empty()
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && !line.starts_with('#')
        {
            break;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('/') && !trimmed.starts_with('\'') && !trimmed.starts_with('"') {
            continue;
        }
        let key = trimmed
            .trim_start_matches(['\'', '"'])
            .trim_end_matches(':')
            .trim_end_matches(['\'', '"']);
        let Some((name, version)) = parse_pnpm_key(key) else {
            continue;
        };
        if !is_plausible_version(&version) || !is_plausible_name(&name) {
            continue;
        }
        out.push(LockfilePackage {
            path: path.to_owned(),
            line: u32::try_from(index + 1).unwrap_or(1),
            query: PackageQuery {
                ecosystem: "npm".to_owned(),
                name,
                version,
            },
        });
    }
    out
}

fn parse_pnpm_key(key: &str) -> Option<(String, String)> {
    let key = key.strip_prefix('/')?;
    // Drop peer/dependency suffixes: `lodash@4.17.19(foo@1)` → before `(`.
    let key = key.split('(').next().unwrap_or(key);
    if let Some(rest) = key.strip_prefix('@') {
        // `@scope/name@version`
        let (scope_name, version) = rest.rsplit_once('@')?;
        if !scope_name.contains('/') {
            return None;
        }
        return Some((format!("@{scope_name}"), version.to_owned()));
    }
    let (name, version) = key.rsplit_once('@')?;
    if name.is_empty() || name.contains('@') {
        return None;
    }
    Some((name.to_owned(), version.to_owned()))
}

/// Classic yarn.lock: a descriptor block followed by `  version "x.y.z"`.
fn parse_yarn_lock(path: &str, text: &str, max: usize) -> Vec<LockfilePackage> {
    let mut out = Vec::new();
    let mut pending_name: Option<String> = None;
    for (index, line) in text.lines().enumerate().take(200_000) {
        if out.len() >= max {
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
            pending_name = yarn_name_from_descriptor(line.trim_end_matches(':'));
            continue;
        }
        let trimmed = line.trim();
        let Some(name) = pending_name.take() else {
            continue;
        };
        let Some(version) = trimmed
            .strip_prefix("version ")
            .map(str::trim)
            .map(|v| v.trim_matches('"'))
        else {
            pending_name = Some(name);
            continue;
        };
        if !is_plausible_version(version) || !is_plausible_name(&name) {
            continue;
        }
        out.push(LockfilePackage {
            path: path.to_owned(),
            line: u32::try_from(index + 1).unwrap_or(1),
            query: PackageQuery {
                ecosystem: "npm".to_owned(),
                name,
                version: version.to_owned(),
            },
        });
    }
    out
}

fn yarn_name_from_descriptor(descriptor: &str) -> Option<String> {
    // `lodash@^4.17.0:` or `"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":`
    let first = descriptor.split(',').next()?.trim().trim_matches('"');
    if let Some(rest) = first.strip_prefix('@') {
        let (scope_name, _) = rest.rsplit_once('@')?;
        return Some(format!("@{scope_name}"));
    }
    let (name, _) = first.rsplit_once('@')?;
    Some(name.to_owned())
}

fn is_plausible_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 214
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'/' | b'-' | b'_' | b'.'))
}

fn is_plausible_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && !version.contains("..")
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn package_lock_v3_packages_map() {
        let text = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.19" },
    "node_modules/@scope/pkg": { "version": "1.2.3" }
  }
}"#;
        let pkgs = parse_package_lock("package-lock.json", text, 100);
        assert_eq!(pkgs.len(), 2);
        assert!(
            pkgs.iter()
                .any(|p| p.query.name == "lodash" && p.query.version == "4.17.19")
        );
        assert!(
            pkgs.iter()
                .any(|p| p.query.name == "@scope/pkg" && p.query.version == "1.2.3")
        );
    }

    #[test]
    fn pnpm_packages_keys() {
        let text = "lockfileVersion: '9.0'\n\npackages:\n\n  /lodash@4.17.19:\n    resolution: {integrity: sha512-aaa}\n\n  /@scope/pkg@1.2.3:\n    resolution: {integrity: sha512-bbb}\n";
        let pkgs = parse_pnpm_lock("pnpm-lock.yaml", text, 100);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.first().unwrap().query.name, "lodash");
        assert_eq!(pkgs.first().unwrap().query.version, "4.17.19");
        assert_eq!(pkgs.get(1).unwrap().query.name, "@scope/pkg");
    }

    #[test]
    fn yarn_classic_blocks() {
        let text = r#"# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.19"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.19.tgz"

"@scope/pkg@^1.0.0":
  version "1.2.3"
"#;
        let pkgs = parse_yarn_lock("yarn.lock", text, 100);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs.first().unwrap().query.name, "lodash");
        assert_eq!(pkgs.first().unwrap().query.version, "4.17.19");
        assert_eq!(pkgs.get(1).unwrap().query.name, "@scope/pkg");
    }

    #[test]
    fn max_packages_is_honoured() {
        use std::fmt::Write as _;
        let mut text = String::from("{\n  \"packages\": {\n");
        for i in 0..50 {
            let _ = writeln!(
                text,
                "    \"node_modules/pkg-{i}\": {{ \"version\": \"1.0.{i}\" }},"
            );
        }
        text.push_str("    \"\": { \"name\": \"root\" }\n  }\n}");
        let pkgs = parse_package_lock("package-lock.json", &text, 3);
        assert_eq!(pkgs.len(), 3);
    }
}
