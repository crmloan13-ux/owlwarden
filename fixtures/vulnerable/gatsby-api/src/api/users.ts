// Fixture: Gatsby Functions — Express-shaped (req, res).
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

    // sensitive-data-logged: the password reaches the process log.
    console.info({ password: body.password })

    // sensitive-data-logged: an access token, logged the same way.
    console.info({ accessToken: body.accessToken })

    // sql-injection: the email comes straight from the body into the query text.
    const rows = await pool.query(
      `SELECT id, role FROM users WHERE email = '${body.email}'`,
    )

    // insecure-cookie: res.cookie without protective attributes.
    res.cookie('session', rows.rows[0]?.id ?? 'anon')

    // cors-permissive: hand-rolled wildcard + credentials.
    res.header('Access-Control-Allow-Origin', '*')
    res.header('Access-Control-Allow-Credentials', 'true')

    return res.json({ ok: true })
  }

  try {
    const users = await pool.query('SELECT id, name FROM users LIMIT 50')
    return res.json({ users: users.rows })
  } catch (err) {
    // stack-trace-leak
    return res.status(500).json({ error: (err as Error).stack })
  }
}
