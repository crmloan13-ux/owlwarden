/**
 * `--fix` applier: Safe (or Unsafe with `--fix-unsafe`) highlight replacements.
 *
 * Patches replace the highlighted span on one source line. Educational
 * multi-line Manual remediations are never applied. Never touches `Possible`
 * findings. Requires a clean git tree unless `--allow-dirty`.
 */

import { spawnSync } from "node:child_process";
import { relative, resolve, isAbsolute } from "node:path";

import type { Finding, Fix, Report } from "@dointhai/owlwarden-sdk";

import { readFileBounded, writeReplacing } from "./safe-write.js";

/** Largest source file `--fix` will rewrite. */
export const MAX_FIX_FILE_BYTES = 2 * 1024 * 1024;

/** One finding selected for application. */
export interface FixPlan {
  finding: Finding;
  fix: Fix;
  absolutePath: string;
  /** 0-based character offsets on the highlight line. */
  start: number;
  end: number;
}

export interface ApplyFixesOptions {
  projectRoot: string;
  report: Report;
  fixUnsafe: boolean;
  dryRun: boolean;
  allowDirty: boolean;
  stderr: NodeJS.WritableStream;
}

export interface ApplyFixesResult {
  attempted: number;
  applied: number;
  skipped: number;
  /** Absolute paths that were rewritten (empty on dry-run). */
  written: string[];
  errors: string[];
}

/** True when the working tree has no staged/unstaged changes. */
export function gitTreeIsClean(projectRoot: string): boolean {
  const result = spawnSync("git", ["status", "--porcelain"], {
    cwd: projectRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
  });
  if (result.error || result.status !== 0 || result.signal) {
    // Not a git repo, git missing, or hung: treat as dirty so `--fix` cannot
    // strand edits without a reversible checkpoint.
    return false;
  }
  return (result.stdout ?? "").trim().length === 0;
}

/**
 * Text that must sit under the highlight before `--fix` rewrites it.
 *
 * Prefer the characters from the code-frame line at the highlight columns so a
 * TOCTOU edit (or `--allow-dirty`) cannot replace an unrelated token that now
 * occupies the same columns.
 */
export function expectedHighlightText(finding: Finding): string | undefined {
  const highlight = finding.snippet?.highlight;
  if (highlight === undefined || finding.snippet === undefined) return undefined;
  const lineOffset = highlight.line - finding.snippet.startLine;
  if (lineOffset < 0 || lineOffset >= finding.snippet.lines.length) return undefined;
  const line = finding.snippet.lines[lineOffset] ?? "";
  const chars = [...line];
  const start = highlight.startCol - 1;
  const end = highlight.endCol - 1;
  if (start < 0 || end <= start || end > chars.length) return undefined;
  return chars.slice(start, end).join("");
}

/**
 * Picks the first applyable remediation on a finding, or `undefined`.
 *
 * Safe always qualifies. Unsafe needs `--fix-unsafe`. Manual never does.
 * `Possible` confidence never does. Need a source location, highlight, and
 * single-line patch (no newlines) — multi-line patches are documentation.
 */
export function selectFix(
  finding: Finding,
  fixUnsafe: boolean,
): { fix: Fix; start: number; end: number } | undefined {
  if (finding.confidence === "possible") return undefined;
  const location = finding.location;
  if (!("path" in location) || finding.snippet?.highlight === undefined) {
    return undefined;
  }
  const highlight = finding.snippet.highlight;
  if (highlight.startCol < 1 || highlight.endCol <= highlight.startCol) {
    return undefined;
  }
  // pretty.rs treats columns as 1-based half-open via endCol-1 exclusive.
  const start = highlight.startCol - 1;
  const end = highlight.endCol - 1;
  if (end <= start) return undefined;

  for (const fix of finding.remediation) {
    if (fix.patch === undefined || fix.patch.length === 0) continue;
    if (fix.patch.includes("\n") || fix.patch.includes("\r")) continue;
    if (fix.safety === "manual") continue;
    if (fix.safety === "unsafe" && !fixUnsafe) continue;
    if (fix.safety !== "safe" && fix.safety !== "unsafe") continue;
    return { fix, start, end };
  }
  return undefined;
}

/** Resolves a finding path under the project root or throws. */
export function resolveFindingPath(projectRoot: string, relPath: string): string {
  const base = resolve(projectRoot);
  const candidate = resolve(base, relPath);
  const rel = relative(base, candidate);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`fix path escapes project root: ${relPath}`);
  }
  return candidate;
}

/** Builds apply plans for every eligible finding (does not touch the disk). */
export function planFixes(
  projectRoot: string,
  report: Report,
  fixUnsafe: boolean,
): { plans: FixPlan[]; skipped: number; errors: string[] } {
  const plans: FixPlan[] = [];
  const errors: string[] = [];
  let skipped = 0;

  for (const finding of report.findings) {
    const selected = selectFix(finding, fixUnsafe);
    if (selected === undefined) {
      skipped += 1;
      continue;
    }
    if (!("path" in finding.location)) {
      skipped += 1;
      continue;
    }
    try {
      plans.push({
        finding,
        fix: selected.fix,
        absolutePath: resolveFindingPath(projectRoot, finding.location.path),
        start: selected.start,
        end: selected.end,
      });
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }

  return { plans, skipped, errors };
}

/**
 * Applies planned highlight replacements.
 *
 * Multiple plans on the same file are applied bottom-to-top so earlier column
 * offsets stay valid.
 */
export async function applyFixPlans(
  plans: FixPlan[],
  options: { dryRun: boolean; stderr: NodeJS.WritableStream },
): Promise<{ applied: number; written: string[]; errors: string[] }> {
  const byFile = new Map<string, FixPlan[]>();
  for (const plan of plans) {
    const list = byFile.get(plan.absolutePath) ?? [];
    list.push(plan);
    byFile.set(plan.absolutePath, list);
  }

  let applied = 0;
  const written: string[] = [];
  const errors: string[] = [];

  for (const [path, filePlans] of byFile) {
    filePlans.sort((a, b) => {
      const lineA = a.finding.snippet?.highlight?.line ?? 0;
      const lineB = b.finding.snippet?.highlight?.line ?? 0;
      if (lineA !== lineB) return lineB - lineA;
      return b.start - a.start;
    });

    let text: string;
    try {
      text = await readFileBounded(path, MAX_FIX_FILE_BYTES);
    } catch (error) {
      errors.push(
        `${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
      continue;
    }

    const newline = text.includes("\r\n") ? "\r\n" : "\n";
    const lines = text.split(/\r?\n/);
    let fileApplied = 0;

    for (const plan of filePlans) {
      const highlight = plan.finding.snippet?.highlight;
      if (highlight === undefined || plan.fix.patch === undefined) continue;
      const lineIndex = highlight.line - 1;
      if (lineIndex < 0 || lineIndex >= lines.length) {
        errors.push(`${path}:${highlight.line}: highlight line out of range`);
        continue;
      }
      const line = lines[lineIndex] ?? "";
      const chars = [...line];
      if (plan.end > chars.length || plan.start >= chars.length) {
        errors.push(
          `${path}:${highlight.line}: highlight columns out of range for current file contents`,
        );
        continue;
      }
      const expected = expectedHighlightText(plan.finding);
      const actual = chars.slice(plan.start, plan.end).join("");
      if (expected === undefined || actual !== expected) {
        errors.push(
          `${path}:${highlight.line}: highlight text changed since scan (refusing to apply)`,
        );
        continue;
      }
      const next = [
        ...chars.slice(0, plan.start),
        ...plan.fix.patch,
        ...chars.slice(plan.end),
      ].join("");
      lines[lineIndex] = next;
      fileApplied += 1;
      options.stderr.write(
        `${options.dryRun ? "would fix" : "fixed"} ${path}:${highlight.line} (${plan.finding.id})\n`,
      );
    }

    if (fileApplied === 0) continue;
    if (options.dryRun) {
      applied += fileApplied;
      continue;
    }
    try {
      await writeReplacing(path, lines.join(newline));
      written.push(path);
      applied += fileApplied;
    } catch (error) {
      errors.push(
        `${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  return { applied, written, errors };
}

/** Full `--fix` entry: dirty check, plan, apply. */
export async function applyFixes(options: ApplyFixesOptions): Promise<ApplyFixesResult> {
  if (!options.allowDirty && !gitTreeIsClean(options.projectRoot)) {
    return {
      attempted: 0,
      applied: 0,
      skipped: 0,
      written: [],
      errors: [
        "working tree is not clean; commit or stash changes, or pass --allow-dirty",
      ],
    };
  }

  const { plans, skipped, errors } = planFixes(
    options.projectRoot,
    options.report,
    options.fixUnsafe,
  );

  if (plans.length === 0) {
    return {
      attempted: 0,
      applied: 0,
      skipped,
      written: [],
      errors,
    };
  }

  const result = await applyFixPlans(plans, {
    dryRun: options.dryRun,
    stderr: options.stderr,
  });

  return {
    attempted: plans.length,
    applied: result.applied,
    skipped,
    written: result.written,
    errors: [...errors, ...result.errors],
  };
}
