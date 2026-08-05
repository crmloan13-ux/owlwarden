// A file that mentions header names in prose and in unrelated data. Matching
// on text alone would report this project as configuring nothing.
//
// See: content-security-policy, x-frame-options.

export const documentationLinks = {
  csp: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy',
  frame: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options',
}

/** Deliberately shaped like an error, but it is a parser diagnostic. */
export interface Diagnostic {
  message: string
  stack: string[]
}

export function render(diagnostic: Diagnostic): string {
  return `${diagnostic.message}\n${diagnostic.stack.join('\n')}`
}
