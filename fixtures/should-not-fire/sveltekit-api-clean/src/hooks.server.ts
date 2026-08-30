// The corrected version of `fixtures/vulnerable/sveltekit-api`. Every rule
// that fires there must stay silent here.
import type { Handle } from '@sveltejs/kit'

const ALLOWED_ORIGINS = new Set(['https://app.example.com'])

export const handle: Handle = async ({ event, resolve }) => {
  const response = await resolve(event)

  const origin = event.request.headers.get('origin') ?? ''
  if (ALLOWED_ORIGINS.has(origin)) {
    response.headers.set('access-control-allow-origin', origin)
    response.headers.append('Vary', 'Origin')
    response.headers.set('access-control-allow-credentials', 'true')
  }

  response.headers.set('strict-transport-security', 'max-age=63072000; includeSubDomains')
  response.headers.set('content-security-policy', "default-src 'self'")
  response.headers.set('x-content-type-options', 'nosniff')
  response.headers.set('x-frame-options', 'DENY')
  response.headers.set('referrer-policy', 'strict-origin-when-cross-origin')
  return response
}
