import { spawnSync } from "node:child_process";

/**
 * Turning `--since` / `--staged` / `--paths` into a list of files.
 *
 * # Why git runs here and not in the engine
 *
 * The engine executes nothing. That is not a slogan — it is what makes
 * `owlwarden vet` safe to point at a repository nobody has read, and it is why
 * agent configuration is parsed rather than loaded and `$schema` is never
 * fetched.
 *
 * A diff needs git. So the CLI runs git, at the operator's explicit request,
 * and hands the engine a plain list of project-relative paths. The engine never
 * learns that git exists, and the same list can arrive from a host's event JSON
 * or a `--paths` flag without anything downstream being special-cased.
 *
 * `spawnSync` with an argument array and `shell: false` (the default): a ref
 * name is an argument, never a fragment of a command line.
 */

/** Most paths taken from one diff. */
const MAX_SCOPED_PATHS = 5_000;

/** A resolved diff scope. */
export interface DiffScope {
  /** Project-relative paths, `/`-separated, deduplicated and sorted. */
  paths: string[];
  /** What the summary line says: `"since origin/main"`, `"staged"`, `"3 paths"`. */
  label: string;
}

/** git was unavailable, or refused. */
export class GitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitError";
  }
}

/**
 * Resolves the scoping flags, or `undefined` when the scan is not narrowed.
 *
 * @throws {GitError} when git is unavailable, the ref does not exist, or more
 * than one narrowing flag was given. A `--since` that silently fell back to a
 * full scan would be worse than an error: the summary line would say
 * `since origin/main` over a result that was not scoped at all.
 */
export function resolveScope(
  root: string,
  options: { since?: string; staged?: boolean; paths?: string[] },
): DiffScope | undefined {
  const explicit = options.paths ?? [];
  const requested =
    Number(options.since !== undefined) + Number(options.staged === true) + Number(explicit.length > 0);
  if (requested === 0) return undefined;
  if (requested > 1) {
    throw new GitError(
      "--since, --staged, and --paths each narrow the scan a different way; pass one",
    );
  }

  if (explicit.length > 0) {
    const paths = normalise(explicit);
    return { paths, label: `${paths.length} path${paths.length === 1 ? "" : "s"}` };
  }

  if (options.staged === true) {
    const staged = git(root, ["diff", "--cached", "--name-only", "--diff-filter=ACMRT"]);
    return { paths: normalise(staged.split("\n")), label: "staged" };
  }

  const reference = options.since ?? "HEAD";
  // `--diff-filter=ACMRT` drops deletions: a file that no longer exists cannot
  // be scanned, and counting it would make the file count wrong.
  const changed = git(root, ["diff", "--name-only", "--diff-filter=ACMRT", reference, "--"]);
  // Untracked files are what an agent just wrote, and are "what changed" to
  // every human who asks.
  const untracked = git(root, ["ls-files", "--others", "--exclude-standard"]);

  return {
    paths: normalise([...changed.split("\n"), ...untracked.split("\n")]),
    label: `since ${reference}`,
  };
}

/**
 * The paths an agent has written so far, for the suppression policy.
 *
 * Everything not committed: staged, unstaged, and untracked. A directive in one
 * of these is a directive that appeared while the agent was working, and the
 * gate reports it rather than honouring it.
 *
 * Returns an empty list rather than throwing when git is unavailable — the gate
 * still has a job to do outside a repository, and the honest degradation is to
 * honour every suppression rather than to refuse to run.
 */
export function sessionPaths(root: string): string[] {
  try {
    const status = git(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
    return normalise(
      status
        .split("\n")
        .map((line) => line.slice(3).trim())
        // A rename is `old -> new`; the new path is the one on disk.
        .map((entry) => entry.split(" -> ").pop() ?? entry),
    );
  } catch {
    return [];
  }
}

/** Whether `root` is inside a git work tree. */
export function isRepository(root: string): boolean {
  try {
    return git(root, ["rev-parse", "--is-inside-work-tree"]).trim() === "true";
  } catch {
    return false;
  }
}

function normalise(paths: string[]): string[] {
  const seen = new Set<string>();
  for (const raw of paths) {
    const path = raw.trim().replaceAll("\\", "/");
    if (path.length > 0) seen.add(path);
    if (seen.size >= MAX_SCOPED_PATHS) break;
  }
  return [...seen].sort();
}

function git(root: string, args: string[]): string {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    // A diff of a very large repository can be megabytes; the path list itself
    // is then capped by `normalise`.
    maxBuffer: 32 * 1024 * 1024,
  });

  if (result.error) {
    throw new GitError(
      `could not run git: ${result.error.message}. --since and --staged need git on PATH.`,
    );
  }
  if (result.status !== 0) {
    throw new GitError(`git ${args.join(" ")} failed: ${(result.stderr ?? "").trim()}`);
  }
  return result.stdout ?? "";
}
