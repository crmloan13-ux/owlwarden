// FIXTURE: deliberately vulnerable.
//   sql-injection — email interpolated into the query text.
//   insecure-cookie — cookies().set without protective attributes.
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'

declare const pool: {
  query: (sql: string) => Promise<{ rows: Array<{ id: string }> }>
}

export async function POST(request: Request) {
  const body = (await request.json()) as { email?: string; password?: string }

  // sql-injection
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  // insecure-cookie: Next's cookies().set with no attributes.
  cookies().set('session', rows.rows[0]?.id ?? 'anon')

  return NextResponse.json({ ok: true })
}
