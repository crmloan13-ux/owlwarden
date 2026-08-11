// Fixture: Koa. Middleware receives `ctx`; responses are often `ctx.body = …`
// and cookies are `ctx.cookies.set(...)`.
import https from 'node:https'
import axios from 'axios'
import Koa from 'koa'
import Router from '@koa/router'
import cors from '@koa/cors'
import { Pool } from 'pg'

const app = new Koa()
const router = new Router()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// cors-permissive: reflects any origin AND sends credentials.
app.use(cors({ origin: true, credentials: true }))

router.post('/login', async (ctx) => {
  const body = ctx.request.body as {
    email?: string
    password?: string
    accessToken?: string
  }

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: idiomatic three-part setter, no protective attributes.
  ctx.cookies.set('session', String(rows.rows[0]?.id ?? 'anon'))

  ctx.body = { ok: true }
})

router.get('/reports/:id', async (ctx) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      ctx.params.id,
    ])
    ctx.body = report.rows
  } catch (err) {
    // stack-trace-leak: the Koa spelling — assign the body, do not call a method.
    ctx.status = 500
    ctx.body = { error: (err as Error).stack }
  }
})

router.get('/go', async (ctx) => {
  // open-redirect: the caller chooses where the browser lands.
  // Pass the query read straight in — parking it behind `??` breaks the
  // one-hop origin tracker (same shape as express-api).
  ctx.redirect(ctx.query.next as string)
})

router.get('/go2', async (ctx) => {
  // open-redirect: a hand-rolled Location header instead of ctx.redirect().
  ctx.set('Location', ctx.query.next as string)
  ctx.status = 302
})

router.post('/import', async (ctx) => {
  const body = ctx.request.body as { sourceUrl?: string }
  // ssrf: the server fetches whatever host the caller names.
  const upstream = await fetch(body.sourceUrl as string)
  ctx.body = await upstream.json()
})

router.post('/import2', async (ctx) => {
  const body = ctx.request.body as { callerUrl?: string }
  // ssrf: axios reaches a second caller-controlled host.
  const upstream = await axios.get(body.callerUrl as string)
  ctx.body = upstream.data
})

router.get('/go3', async (ctx) => {
  // open-redirect: a third caller-chosen target.
  ctx.redirect(ctx.query.extraNext as string)
})

router.post('/import3', async (ctx) => {
  const body = ctx.request.body as { gotUrl?: string }
  // ssrf: got reaches a third caller-controlled host.
  const upstream = await got.get(body.gotUrl as string)
  ctx.body = upstream.body
})

router.post('/import4', async (ctx) => {
  const body = ctx.request.body as { nodeUrl?: string }
  // ssrf: node https.get to a fourth caller-controlled host.
  await new Promise<void>((resolve, reject) => {
    https.get(body.nodeUrl as string, (up) => {
      up.resume()
      up.on('end', () => resolve())
    }).on('error', reject)
  })
  ctx.body = { ok: true }
})

app.use(router.routes()).use(router.allowedMethods())
app.listen(3000)
