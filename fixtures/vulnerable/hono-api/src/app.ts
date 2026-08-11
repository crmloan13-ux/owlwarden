// Fixture: a Hono service with the mistakes owlwarden should find.
// Context is `c`; responses are `c.json` / `c.text`, cookies via setCookie.
import https from 'node:https'
import axios from 'axios'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { setCookie } from 'hono/cookie'
import { Pool } from 'pg'

const app = new Hono()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// cors-permissive: wildcard origin AND credentials.
app.use(
  '*',
  cors({
    origin: '*',
    credentials: true,
  }),
)

app.post('/login', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string; accessToken?: string }>()

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: setCookie with no protective attributes.
  setCookie(c, 'session', String(rows.rows[0]?.id ?? 'anon'))

  return c.json({ ok: true })
})

app.get('/reports/:id', async (c) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      c.req.param('id'),
    ])
    return c.json(report.rows)
  } catch (err) {
    // stack-trace-leak: the client learns the file layout and dependency versions.
    return c.json({ error: (err as Error).stack }, 500)
  }
})

app.get('/go', (c) => {
  // open-redirect: the caller chooses where the browser lands.
  const next = c.req.query('next') as string
  return c.redirect(next)
})

app.get('/go2', (c) => {
  // open-redirect: a hand-rolled Location header instead of c.redirect().
  const next = c.req.query('next') as string
  c.header('Location', next)
  return c.body(null, 302)
})

app.post('/import', async (c) => {
  const body = await c.req.json<{ sourceUrl?: string }>()
  // ssrf: the server fetches whatever host the caller names.
  const upstream = await fetch(body.sourceUrl as string)
  return c.json(await upstream.json())
})

app.post('/import2', async (c) => {
  const body = await c.req.json<{ callerUrl?: string }>()
  // ssrf: axios reaches a second caller-controlled host.
  const upstream = await axios.get(body.callerUrl as string)
  return c.json(upstream.data)
})


app.get('/go3', (c) => {
  // open-redirect: a third caller-chosen target.
  const extraNext = c.req.query('extraNext') as string
  return c.redirect(extraNext)
})

app.post('/import3', async (c) => {
  const body = await c.req.json<{ gotUrl?: string }>()
  // ssrf: got reaches a third caller-controlled host.
  const upstream = await got.get(body.gotUrl as string)
  return c.json(upstream.body)
})

app.post('/import4', async (c) => {
  const body = await c.req.json<{ nodeUrl?: string }>()
  // ssrf: node https.get to a fourth caller-controlled host.
  await new Promise<void>((resolve, reject) => {
    https.get(body.nodeUrl as string, (up) => {
      up.resume()
      up.on('end', () => resolve())
    }).on('error', reject)
  })
  return c.json({ ok: true })
})

export default app
