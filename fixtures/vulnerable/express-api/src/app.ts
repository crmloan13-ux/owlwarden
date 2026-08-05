// Fixture: an Express service with the mistakes owlwarden should find.
// Every one of these is a shape that turns up in real code review.
import express from 'express'
import cors from 'cors'
import { Pool } from 'pg'

const app = express()
const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// cors-permissive: reflects any origin AND sends credentials, so any site a
// signed-in user visits can call this API as them.
app.use(cors({ origin: true, credentials: true }))

app.post('/login', async (req, res) => {
  // sql-injection: the email comes straight from the request body into the
  // query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${req.body.email}'`,
  )

  // insecure-cookie: no httpOnly, no secure, no sameSite.
  res.cookie('session', rows.rows[0].id)

  res.json({ ok: true })
})

app.get('/reports/:id', async (req, res) => {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
      req.params.id,
    ])
    res.json(report.rows)
  } catch (err) {
    // stack-trace-leak: the client learns the file layout and dependency
    // versions.
    res.status(500).json({ error: err.stack })
  }
})

app.listen(3000)
