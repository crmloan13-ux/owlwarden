/**
 * Exit codes. A documented contract (`docs/how-to/ci.md`) — CI scripts branch
 * on these, so they are as much public API as the JSON schema is.
 */
export const EXIT = {
  /** Nothing at or above the `--fail-on` threshold. */
  CLEAN: 0,
  /** Findings met the threshold. */
  FINDINGS: 1,
  /** The scan could not run: bad arguments, unreadable project, broken install. */
  ERROR: 2,
} as const;
