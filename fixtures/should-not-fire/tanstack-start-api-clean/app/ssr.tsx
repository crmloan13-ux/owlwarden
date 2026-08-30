// The corrected version of `fixtures/vulnerable/tanstack-start-api`. Every
// rule that fires there must stay silent here.
const ALLOWED_ORIGINS = new Set(['https://app.example.com'])

export function withSecurityHeaders(request: Request, response: Response) {
  const headers = new Headers(response.headers)

  const origin = request.headers.get('origin') ?? ''
  if (ALLOWED_ORIGINS.has(origin)) {
    headers.set('access-control-allow-origin', origin)
    headers.append('Vary', 'Origin')
    headers.set('access-control-allow-credentials', 'true')
  }

  headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains')
  headers.set('content-security-policy', "default-src 'self'")
  headers.set('x-content-type-options', 'nosniff')
  headers.set('x-frame-options', 'DENY')
  headers.set('referrer-policy', 'strict-origin-when-cross-origin')
  return new Response(response.body, { status: response.status, headers })
}
