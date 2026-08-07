// The corrected version of `fixtures/vulnerable/hapi-api`.
import axios from 'axios'
import Hapi from '@hapi/hapi'
import helmet from 'helmet'
import { Pool } from 'pg'

import { safeRedirect } from './safe-redirect'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

const server = Hapi.server({
  port: 3000,
  host: 'localhost',
})

// helmet identifier in the bootstrap closes security-headers-missing.
server.ext('onPreResponse', (request, h) => {
  void helmet
  const response = request.response
  if (!('isBoom' in response)) {
    response.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
    response.header('Content-Security-Policy', "default-src 'self'")
    response.header('X-Content-Type-Options', 'nosniff')
    response.header('X-Frame-Options', 'DENY')
    response.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  }
  return h.continue
})

server.route({
  method: 'POST',
  path: '/login',
  handler: async (request, h) => {
    const body = request.payload as {
      email?: string
      password?: string
      accessToken?: string
    }

    // Logging that a caller supplied a token, not the token itself.
    console.info({ hasAccessToken: Boolean(body.accessToken) })

    const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
      body.email,
    ])

    // Hapi's real attribute names. The detector accepts both these and the
    // Express spellings so a pasted remediation is not immediately re-flagged.
    h.state('session', String(rows.rows[0]?.id ?? 'anon'), {
      isHttpOnly: true,
      isSecure: process.env.NODE_ENV === 'production',
      isSameSite: 'Lax',
    })

    const response = h.response({ ok: true })
    response.header('Access-Control-Allow-Origin', 'https://app.example.com')
    response.header('Vary', 'Origin')
    return response
  },
})

server.route({
  method: 'GET',
  path: '/reports/{id}',
  handler: async (request, h) => {
    try {
      const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
        request.params.id,
      ])
      return h.response(report.rows)
    } catch (err) {
      console.error(err instanceof Error ? err.stack : err)
      return h.response({ error: 'Internal Server Error' }).code(500)
    }
  },
})

server.route({
  method: 'GET',
  path: '/go',
  handler: (request, h) => {
    const next = (request.query as { next?: string }).next
    return h.redirect(safeRedirect(next, 'https://app.example.com'))
  },
})

server.route({
  method: 'GET',
  path: '/go2',
  handler: (request, h) => {
    const next = (request.query as { next?: string }).next
    const response = h.response().code(302)
    response.header('Location', safeRedirect(next, 'https://app.example.com'))
    return response
  },
})

server.route({
  method: 'POST',
  path: '/import',
  handler: async (request, h) => {
    const body = request.payload as { sourceUrl?: string }
    const url = new URL(String(body.sourceUrl))
    if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
      return h.response({ error: 'source not allowed' }).code(400)
    }
    const upstream = await fetch(url, { redirect: 'error' })
    return h.response(await upstream.json())
  },
})

server.route({
  method: 'POST',
  path: '/import2',
  handler: async (request, h) => {
    const body = request.payload as { callerUrl?: string }
    const url = new URL(String(body.callerUrl))
    if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
      return h.response({ error: 'source not allowed' }).code(400)
    }
    const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
    return h.response(upstream.data)
  },
})

await server.start()
