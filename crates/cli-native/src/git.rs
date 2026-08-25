//! Resolving `--since` / `--staged` / `--paths` into a list of files.
//!
//! # Why git lives here and not in the engine
//!
//! The engine executes nothing. That is not a slogan — it is what makes
//! `owlwarden vet` safe to point at a repository nobody has read, and it is why
//! configuration is parsed rather than loaded and `$schema` is never fetched.
//!
//! `--since origin/main` needs a diff, and a diff needs git. So the CLI runs
//! git, at the operator's explicit request, and hands the engine a plain list
//! of project-relative paths. The engine never learns that git exists, and the
//! same list can come from a host's event JSON, a `--paths` flag, or a shell
//! pipeline without any of them being special-cased downstream.
//!
//! `git` is invoked with `--` before any user-supplied value and with no shell,
//! so a ref name cannot become an argument to something else.

use std::path::Path;
use std::process::Command;

/// Most paths accepted from one diff.
///
/// A merge of a long-lived branch can touch thousands of files; past this the
/// scoped scan is not meaningfully cheaper than a full one, and pretending
/// otherwise would hide a full scan behind a narrow-looking summary line.
const MAX_SCOPED_PATHS: usize = 5_000;

/// A resolved diff scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffScope {
    /// Project-relative paths, `/`-separated, deduplicated and sorted.
    pub paths: Vec<String>,
    /// What to print in the summary line: `"since origin/main"`, `"staged"`,
    /// `"3 paths"`.
    pub label: String,
}

/// Resolves the scoping flags, or `None` when the scan is not narrowed.
///
/// # Errors
/// A message the user can act on when git is unavailable, the ref does not
/// exist, or the flags conflict. A `--since` that silently fell back to a full
/// scan would be worse than an error: the summary line would say `since
/// origin/main` over a result that was not scoped at all.
pub fn resolve_scope(
    root: &str,
    since: Option<&str>,
    staged: bool,
    paths: &[String],
) -> Result<Option<DiffScope>, String> {
    let requested = usize::from(since.is_some()) + usize::from(staged) + usize::from(!paths.is_empty());
    if requested == 0 {
        return Ok(None);
    }
    if requested > 1 {
        return Err(
            "--since, --staged, and --paths each narrow the scan a different way; pass one"
                .to_owned(),
        );
    }

    if !paths.is_empty() {
        let normalised = normalise(paths.iter().map(String::as_str));
        let count = normalised.len();
        return Ok(Some(DiffScope {
            paths: normalised,
            label: format!("{count} path{}", if count == 1 { "" } else { "s" }),
        }));
    }

    if staged {
        let output = run_git(root, &["diff", "--cached", "--name-only", "--diff-filter=ACMRT"])?;
        return Ok(Some(DiffScope {
            paths: normalise(output.lines()),
            label: "staged".to_owned(),
        }));
    }

    let reference = since.unwrap_or("HEAD");
    // `--diff-filter=ACMRT` drops deletions: a file that no longer exists
    // cannot be scanned, and including it would make the file count wrong.
    let output = run_git(
        root,
        &["diff", "--name-only", "--diff-filter=ACMRT", reference, "--"],
    )?;
    // Untracked files are part of "what changed" to every human who asks, and
    // are exactly what an agent just wrote.
    let untracked = run_git(root, &["ls-files", "--others", "--exclude-standard"])?;

    Ok(Some(DiffScope {
        paths: normalise(output.lines().chain(untracked.lines())),
        label: format!("since {reference}"),
    }))
}

/// Deduplicates, sorts, and caps a path list.
fn normalise<'a>(paths: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = paths
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(|path| path.replace('\\', "/"))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_SCOPED_PATHS);
    out
}

/// Runs git in the project root, capturing stdout.
fn run_git(root: &str, args: &[&str]) -> Result<String, String> {
    let root = Path::new(root);
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("could not run git: {error}. --since and --staged need git on PATH."))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn no_flags_means_no_scope() {
        assert_eq!(resolve_scope(".", None, false, &[]), Ok(None));
    }

    #[test]
    fn two_scoping_flags_are_an_error_rather_than_a_guess() {
        let error = resolve_scope(".", Some("HEAD"), true, &[]).unwrap_err();
        assert!(error.contains("pass one"));
    }

    #[test]
    fn explicit_paths_are_normalised_and_labelled() {
        let scope = resolve_scope(
            ".",
            None,
            false,
            &[
                "b.ts".to_owned(),
                "a.ts".to_owned(),
                "a.ts".to_owned(),
                "  ".to_owned(),
            ],
        )
        .unwrap()
        .expect("a scope");
        assert_eq!(scope.paths, ["a.ts", "b.ts"]);
        assert_eq!(scope.label, "2 paths");
    }

    #[test]
    fn windows_separators_are_normalised_so_a_baseline_still_matches() {
        let scope = resolve_scope(".", None, false, &["app\\api\\route.ts".to_owned()])
            .unwrap()
            .expect("a scope");
        assert_eq!(scope.paths, ["app/api/route.ts"]);
    }

    #[test]
    fn a_real_repository_resolves_its_own_diff() {
        // Exercised against a throwaway repository rather than a mock: the
        // thing worth testing is that our argument list is one git accepts.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.email", "t@example.com"],
            vec!["config", "user.name", "t"],
        ] {
            assert!(run_git(&root, &args).is_ok(), "setup: git {args:?}");
        }
        std::fs::write(dir.path().join("a.ts"), "export const a = 1\n").unwrap();
        run_git(&root, &["add", "a.ts"]).unwrap();

        let staged = resolve_scope(&root, None, true, &[]).unwrap().expect("a scope");
        assert_eq!(staged.paths, ["a.ts"]);
        assert_eq!(staged.label, "staged");

        run_git(&root, &["commit", "-qm", "one"]).unwrap();
        std::fs::write(dir.path().join("b.ts"), "export const b = 2\n").unwrap();

        let since = resolve_scope(&root, Some("HEAD"), false, &[])
            .unwrap()
            .expect("a scope");
        assert_eq!(
            since.paths,
            ["b.ts"],
            "an untracked file is part of what changed — it is what an agent just wrote"
        );
        assert_eq!(since.label, "since HEAD");
    }

    #[test]
    fn a_ref_that_does_not_exist_is_an_error_not_a_full_scan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_string_lossy().into_owned();
        run_git(&root, &["init", "-q"]).unwrap();
        let error = resolve_scope(&root, Some("no-such-ref"), false, &[]).unwrap_err();
        assert!(error.contains("git diff"), "got: {error}");
    }
}
