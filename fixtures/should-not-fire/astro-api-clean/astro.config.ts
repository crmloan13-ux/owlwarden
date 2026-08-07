import { defineConfig } from 'astro/config'

export default defineConfig({
  output: 'server',
  // Baseline security headers — string literals close security-headers-missing.
  vite: {
    server: {
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
