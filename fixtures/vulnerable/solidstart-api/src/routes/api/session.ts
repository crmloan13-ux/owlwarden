// Fixture: a SolidStart service with the mistakes owlwarden should find.
// API routes receive an APIEvent; `json` builds the response.
import { json } from '@solidjs/router'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function POST(event: { request: Request }) {
  const body = await event.request.json()

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: no httpOnly, no secure, no sameSite.
  setCookie(event, 'session', String(rows.rows[0]?.id ?? 'anon'))

  return json({ ok: true })
}

declare function setCookie(event: unknown, name: string, value: string, options?: unknown): void
