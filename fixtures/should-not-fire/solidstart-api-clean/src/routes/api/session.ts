import { json } from '@solidjs/router'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function POST(event: { request: Request }) {
  const body = await event.request.json()

  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  setCookie(event, 'session', String(rows.rows[0]?.id ?? 'anon'), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  return json({ ok: true })
}

declare function setCookie(event: unknown, name: string, value: string, options?: unknown): void
