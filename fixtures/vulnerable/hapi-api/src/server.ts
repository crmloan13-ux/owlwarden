// Fixture: Hapi. Toolkit is `h`; handlers receive `request`.
import axios from 'axios'
import Hapi from '@hapi/hapi'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

const server = Hapi.server({
  port: 3000,
  host: 'localhost',
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

    // sensitive-data-logged: the password reaches the process log.
    console.info({ password: body.password })

    // sensitive-data-logged: an access token, logged the same way.
    console.info({ accessToken: body.accessToken })

    // sql-injection: the email comes straight from the payload into the query.
    const rows = await pool.query(
      `SELECT id, role FROM users WHERE email = '${body.email}'`,
    )

    // insecure-cookie: h.state without protective attributes.
    h.state('session', String(rows.rows[0]?.id ?? 'anon'))

    // cors-permissive: hand-rolled wildcard + credentials on the response.
    // (Route-level cors plugin shapes vary; header calls are detected reliably.)
    const response = h.response({ ok: true })
    response.header('Access-Control-Allow-Origin', '*')
    response.header('Access-Control-Allow-Credentials', 'true')
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
      // stack-trace-leak: h.response carries the stack to the client.
      return h.response({ error: (err as Error).stack }).code(500)
    }
  },
})

server.route({
  method: 'GET',
  path: '/go',
  handler: (request, h) => {
    // open-redirect: the caller chooses where the browser lands.
    const next = (request.query as { next?: string }).next as string
    return h.redirect(next)
  },
})

server.route({
  method: 'GET',
  path: '/go2',
  handler: (request, h) => {
    // open-redirect: a hand-rolled Location header instead of h.redirect().
    const next = (request.query as { next?: string }).next as string
    const response = h.response().code(302)
    response.header('Location', next)
    return response
  },
})

server.route({
  method: 'POST',
  path: '/import',
  handler: async (request, h) => {
    const body = request.payload as { sourceUrl?: string }
    // ssrf: the server fetches whatever host the caller names.
    const upstream = await fetch(body.sourceUrl as string)
    return h.response(await upstream.json())
  },
})

server.route({
  method: 'POST',
  path: '/import2',
  handler: async (request, h) => {
    const body = request.payload as { callerUrl?: string }
    // ssrf: axios reaches a second caller-controlled host.
    const upstream = await axios.get(body.callerUrl as string)
    return h.response(upstream.data)
  },
})

await server.start()
