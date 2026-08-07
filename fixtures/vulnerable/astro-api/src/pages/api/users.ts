// Fixture: Astro API route. Expected findings land on the shapes below.
import type { APIRoute } from 'astro'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export const POST: APIRoute = async ({ request, cookies }) => {
  const body = (await request.json()) as {
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

  // insecure-cookie: cookies.set without protective attributes.
  cookies.set('session', String(rows.rows[0]?.id ?? 'anon'))

  // cors-permissive: hand-rolled wildcard + credentials via Headers.set
  // (object-literal headers on Response are not the shape the rule reads).
  const response = new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
  response.headers.set('Access-Control-Allow-Origin', '*')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}

export const GET: APIRoute = async ({ params }) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      params.id,
    ])
    return new Response(JSON.stringify(report.rows), {
      headers: { 'Content-Type': 'application/json' },
    })
  } catch (err) {
    // stack-trace-leak: Response constructor carries the stack to the client.
    return new Response(JSON.stringify({ error: (err as Error).stack }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}
