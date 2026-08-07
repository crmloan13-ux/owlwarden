// The corrected version of `fixtures/vulnerable/koa-api`.
import axios from 'axios'
import Koa from 'koa'
import Router from '@koa/router'
import cors from '@koa/cors'
import helmet from 'koa-helmet'
import { Pool } from 'pg'

import { safeRedirect } from './safe-redirect'

const app = new Koa()
const router = new Router()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

app.use(helmet())
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))

router.post('/login', async (ctx) => {
  const body = ctx.request.body as {
    email?: string
    password?: string
    accessToken?: string
  }

  // Logging that a caller supplied a token, not the token itself.
  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  ctx.cookies.set('session', String(rows.rows[0]?.id ?? 'anon'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  })

  ctx.body = { ok: true }
})

router.get('/reports/:id', async (ctx) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      ctx.params.id,
    ])
    ctx.body = report.rows
  } catch (err) {
    // Logged server-side; generic body to the client — the Koa assignment form.
    console.error(err instanceof Error ? err.stack : err)
    ctx.status = 500
    ctx.body = { error: 'Internal Server Error' }
  }
})

router.get('/go', async (ctx) => {
  ctx.redirect(safeRedirect(ctx.query.next, 'https://app.example.com'))
})

router.get('/go2', async (ctx) => {
  ctx.set('Location', safeRedirect(ctx.query.next, 'https://app.example.com'))
  ctx.status = 302
})

router.post('/import', async (ctx) => {
  const body = ctx.request.body as { sourceUrl?: string }
  const url = new URL(String(body.sourceUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    ctx.status = 400
    ctx.body = { error: 'source not allowed' }
    return
  }
  const upstream = await fetch(url, { redirect: 'error' })
  ctx.body = await upstream.json()
})

router.post('/import2', async (ctx) => {
  const body = ctx.request.body as { callerUrl?: string }
  const url = new URL(String(body.callerUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    ctx.status = 400
    ctx.body = { error: 'source not allowed' }
    return
  }
  const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
  ctx.body = upstream.data
})

app.use(router.routes()).use(router.allowedMethods())
app.listen(3000)
