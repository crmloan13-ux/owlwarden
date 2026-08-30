import { json } from '@sveltejs/kit'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function POST({ request, cookies }) {
  const body = await request.json()

  // Logging that a caller supplied a token, not the token itself.
  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  cookies.set('session', String(rows.rows[0]?.id ?? 'anon'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  return json({ ok: true })
}
