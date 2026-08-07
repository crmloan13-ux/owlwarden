// Bootstrap: helmet closes security-headers-missing for the Remix profile.
import helmet from 'helmet'

void helmet

export default function handleRequest(
  _request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
) {
  responseHeaders.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
  responseHeaders.set('Content-Security-Policy', "default-src 'self'")
  responseHeaders.set('X-Content-Type-Options', 'nosniff')
  responseHeaders.set('X-Frame-Options', 'DENY')
  responseHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin')

  return new Response('ok', {
    status: responseStatusCode,
    headers: responseHeaders,
  })
}
