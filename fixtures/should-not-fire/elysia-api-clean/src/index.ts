// The corrected version of `fixtures/vulnerable/elysia-api`. Every rule that
// fires there must stay silent here.
import axios from 'axios'
import { Elysia } from 'elysia'
import { cors } from '@elysiajs/cors'
import { Pool } from 'pg'

import { assertAllowedUrl } from './allowlist'
import { safeRedirect } from './safe-redirect'

const app = new Elysia()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

app.use(cors({ origin: ['https://app.example.com'], credentials: true }))

app.onAfterHandle(({ set }) => {
  set.headers['strict-transport-security'] = 'max-age=63072000; includeSubDomains'
  set.headers['content-security-policy'] = "default-src 'self'"
  set.headers['x-content-type-options'] = 'nosniff'
  set.headers['x-frame-options'] = 'DENY'
  set.headers['referrer-policy'] = 'strict-origin-when-cross-origin'
})

app.post('/login', async ({ body, cookie }) => {
  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  cookie.session.set({
    value: String(rows.rows[0]?.id ?? 'anon'),
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  return { ok: true }
})

app.get('/reports/:id', async ({ params }) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [params.id])
    return report.rows
  } catch (err) {
    console.error(err instanceof Error ? err.stack : err)
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'content-type': 'application/json' },
    })
  }
})

app.get('/go', ({ query, set }) => {
  set.status = 302
  set.headers.Location = safeRedirect(query.next, 'https://app.example.com')
  return null
})

app.post('/import', async ({ body }) => {
  const url = assertAllowedUrl(body.sourceUrl)
  const upstream = await fetch(url, { redirect: 'error' })

  const second = await axios.get(assertAllowedUrl(body.callerUrl).toString(), {
    maxRedirects: 0,
  })

  return { ok: true, second: second.data, upstream: await upstream.json() }
})

export default app
