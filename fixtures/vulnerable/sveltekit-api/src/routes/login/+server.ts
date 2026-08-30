import { json } from '@sveltejs/kit'
import { Pool } from 'pg'
import { setSessionCookie } from '$lib/session'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function POST({ request, cookies }) {
  const body = await request.json()

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: no httpOnly, no secure, no sameSite.
  cookies.set('session', String(rows.rows[0]?.id ?? 'anon'))
  setSessionCookie(cookies)

  return json({ ok: true })
}
