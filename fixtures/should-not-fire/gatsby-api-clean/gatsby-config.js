const helmet = require('helmet')

// helmet in the config bootstrap closes security-headers-missing.
void helmet

module.exports = {
  siteMetadata: {
    title: 'fixture-gatsby-api-clean',
  },
  headers: [
    {
      source: '/*',
      headers: [
        { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
        { key: 'Content-Security-Policy', value: "default-src 'self'" },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      ],
    },
  ],
  plugins: [],
}
