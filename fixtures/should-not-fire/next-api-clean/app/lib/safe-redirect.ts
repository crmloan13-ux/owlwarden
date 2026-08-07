/// Resolves a caller-supplied redirect target against our own origin.
///
/// Comparing origins rather than testing for a leading slash: the browser reads
/// `//evil.com` as a URL to another host, so a `startsWith('/')` check passes it.
export function safeRedirect(
  target: unknown,
  base: string,
  fallback = '/',
): string {
  if (typeof target !== 'string') return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}
