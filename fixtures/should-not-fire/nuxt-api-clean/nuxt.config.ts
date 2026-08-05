export default defineNuxtConfig({
  runtimeConfig: {
    // Server-only: not under `public`, so it never reaches the browser.
    databaseUrl: process.env.DATABASE_URL,
  },
  routeRules: {
    '/**': {
      headers: {
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
      },
    },
  },
})
