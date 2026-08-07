import type { APIRoute } from 'astro'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export const POST: APIRoute = async ({ request, cookies }) => {
  const body = (await request.json()) as {
    email?: string
    password?: string
    accessToken?: string
  }

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

  const response = new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
  response.headers.set('Access-Control-Allow-Origin', 'https://app.example.com')
  response.headers.set('Vary', 'Origin')
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
    console.error(err instanceof Error ? err.stack : err)
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}
