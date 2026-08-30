// Fixture: an Elysia service with the mistakes owlwarden should find.
// Routes chain off the app; `set` carries status and headers.
import https from 'node:https'
import axios from 'axios'
import { Elysia } from 'elysia'
import { Pool } from 'pg'

const app = new Elysia()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// cors-permissive: wildcard origin AND credentials.
app.use(cors({ origin: '*', credentials: true }))

app.post('/login', async ({ body, cookie }) => {
  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: value assigned with none of the protective attributes.
  cookie.session.set({ value: String(rows.rows[0]?.id ?? 'anon') })

  return { ok: true }
})

app.get('/reports/:id', async ({ params }) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [params.id])
    return report.rows
  } catch (err) {
    // stack-trace-leak: the client learns the file layout and dependency versions.
    return new Response(JSON.stringify({ error: (err as Error).stack }), {
      status: 500,
      headers: { 'content-type': 'application/json' },
    })
  }
})

app.get('/go', ({ query, set }) => {
  // open-redirect: the caller chooses where the browser lands.
  set.status = 302
  set.headers.Location = query.next as string
  return null
})

app.get('/go2', ({ query }) => {
  // open-redirect: a hand-rolled Location header on a Response.
  const headers = new Headers()
  headers.set('Location', query.next as string)
  return new Response(null, { status: 302, headers })
})

app.get('/go3', ({ query }) => {
  // open-redirect: a third caller-chosen target.
  return Response.redirect(query.extraNext as string, 303)
})

app.post('/import', async ({ body }) => {
  // ssrf: the server fetches whatever host the caller names.
  const upstream = await fetch(body.sourceUrl as string)

  // ssrf: axios reaches a second caller-controlled host.
  const second = await axios.get(body.callerUrl as string)

  // ssrf: got reaches a third caller-controlled host.
  const third = await got.get(body.gotUrl as string)

  // ssrf: node https.get to a fourth caller-controlled host.
  await new Promise<void>((resolve, reject) => {
    https.get(body.nodeUrl as string, (up) => {
      up.resume()
      up.on('end', () => resolve())
    }).on('error', reject)
  })

  return { ok: true, second: second.data, third: third.body, upstream: await upstream.json() }
})

export default app
