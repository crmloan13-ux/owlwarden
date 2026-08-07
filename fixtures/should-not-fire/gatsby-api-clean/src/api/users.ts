import type { GatsbyFunctionRequest, GatsbyFunctionResponse } from 'gatsby'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export default async function handler(
  req: GatsbyFunctionRequest,
  res: GatsbyFunctionResponse,
) {
  if (req.method === 'POST') {
    const body = req.body as {
      email?: string
      password?: string
      accessToken?: string
    }

    // Logging that a caller supplied a token, not the token itself.
    console.info({ hasAccessToken: Boolean(body.accessToken) })

    const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
      body.email,
    ])

    res.cookie('session', rows.rows[0]?.id ?? 'anon', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    })

    res.header('Access-Control-Allow-Origin', 'https://app.example.com')
    res.header('Vary', 'Origin')

    return res.json({ ok: true })
  }

  try {
    const users = await pool.query('SELECT id, name FROM users LIMIT 50')
    return res.json({ users: users.rows })
  } catch (err) {
    console.error(err instanceof Error ? err.stack : err)
    return res.status(500).json({ error: 'Internal Server Error' })
  }
}
