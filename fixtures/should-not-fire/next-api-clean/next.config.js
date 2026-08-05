/** @type {import('next').NextConfig} */
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'strict-transport-security', value: 'max-age=63072000; includeSubDomains' },
          { key: 'content-security-policy', value: "default-src 'self'" },
          { key: 'x-content-type-options', value: 'nosniff' },
          { key: 'x-frame-options', value: 'DENY' },
          { key: 'referrer-policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ]
  },
}
