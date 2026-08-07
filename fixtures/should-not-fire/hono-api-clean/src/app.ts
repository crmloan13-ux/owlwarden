// The corrected version of `fixtures/vulnerable/hono-api`. Every rule that
// fires there must stay silent here.
import axios from 'axios'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { setCookie } from 'hono/cookie'
import { secureHeaders } from 'hono/secure-headers'
import { Pool } from 'pg'

import { safeRedirect } from './safe-redirect'

const app = new Hono()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

app.use('*', secureHeaders())
app.use(
  '*',
  cors({
    origin: ['https://app.example.com'],
    credentials: true,
  }),
)

app.post('/login', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string; accessToken?: string }>()

  // Logging that a caller supplied a token, not the token itself.
  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  setCookie(c, 'session', String(rows.rows[0]?.id ?? 'anon'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax',
  })

  return c.json({ ok: true })
})

app.get('/reports/:id', async (c) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      c.req.param('id'),
    ])
    return c.json(report.rows)
  } catch (err) {
    // Logged server-side, generic body to the client.
    console.error(err instanceof Error ? err.stack : err)
    return c.json({ error: 'Internal Server Error' }, 500)
  }
})

app.get('/go', (c) => {
  const next = c.req.query('next')
  return c.redirect(safeRedirect(next, 'https://app.example.com'))
})

app.get('/go2', (c) => {
  const next = c.req.query('next')
  const headers = new Headers()
  headers.set('Location', safeRedirect(next, 'https://app.example.com'))
  return c.body(null, 302, headers)
})

app.post('/import', async (c) => {
  const body = await c.req.json<{ sourceUrl?: string }>()
  const url = new URL(String(body.sourceUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    return c.json({ error: 'source not allowed' }, 400)
  }
  const upstream = await fetch(url, { redirect: 'error' })
  return c.json(await upstream.json())
})

app.post('/import2', async (c) => {
  const body = await c.req.json<{ callerUrl?: string }>()
  const url = new URL(String(body.callerUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    return c.json({ error: 'source not allowed' }, 400)
  }
  const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
  return c.json(upstream.data)
})

export default app
