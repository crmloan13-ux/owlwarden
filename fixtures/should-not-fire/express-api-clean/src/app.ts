// The corrected version of `fixtures/vulnerable/express-api`. Every rule that
// fires there must stay silent here, and several lines are deliberately
// written to look like the bug without being it.
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import { Pool } from 'pg'

const app = express()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

app.use(helmet())
// An explicit allowlist, not a wildcard and not a reflection.
app.use(cors({ origin: ['https://app.example.com'], credentials: true }))

app.post('/login', async (req, res) => {
  // Logging that a caller supplied a token, not the token itself.
  console.info({ hasAccessToken: Boolean(req.body.accessToken) })

  // Bound, so the value is never parsed as SQL.
  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    req.body.email,
  ])

  res.cookie('session', rows.rows[0].id, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  })

  res.json({ ok: true })
})

app.get('/reports/:id', async (req, res) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      req.params.id,
    ])
    res.json(report.rows)
  } catch (err) {
    // Logged server-side, generic body to the client. This is the shape the
    // rule must not confuse with a leak.
    console.error(err.stack)
    res.status(500).json({ error: 'Internal Server Error' })
  }
})

app.listen(3000)
