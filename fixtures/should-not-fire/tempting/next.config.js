/** @type {import('next').NextConfig} */
const securityHeaders = [
  { key: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'content-security-policy', value: "default-src 'self'" },
  { key: 'x-content-type-options', value: 'nosniff' },
  { key: 'x-frame-options', value: 'SAMEORIGIN' },
  { key: 'referrer-policy', value: 'no-referrer' },
]

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}
