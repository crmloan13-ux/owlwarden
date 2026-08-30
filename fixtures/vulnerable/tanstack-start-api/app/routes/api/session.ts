// Fixture: a TanStack Start service with the mistakes owlwarden should find.
// Server functions and API routes return a Response; there is no res object.
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function POST({ request }: { request: Request }) {
  const body = await request.json()

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  const headers = new Headers()
  // cors-permissive: wildcard origin AND credentials, hand-rolled.
  headers.set('access-control-allow-origin', '*')
  headers.set('access-control-allow-credentials', 'true')

  // insecure-cookie: no HttpOnly, no Secure, no SameSite.
  setCookie('session', String(rows.rows[0]?.id ?? 'anon'))

  return new Response(JSON.stringify({ ok: true }), { headers })
}

declare function setCookie(name: string, value: string, options?: unknown): void
