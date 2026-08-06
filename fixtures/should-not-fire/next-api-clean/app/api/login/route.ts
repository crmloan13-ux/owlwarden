import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

declare const pool: {
  query: (sql: string, params: unknown[]) => Promise<{ rows: Array<{ id: string }> }>
}

export async function POST(request: Request) {
  const body = (await request.json()) as { email?: string }

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  cookies().set('session', rows.rows[0]?.id ?? 'anon', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  return NextResponse.json({ ok: true })
}
