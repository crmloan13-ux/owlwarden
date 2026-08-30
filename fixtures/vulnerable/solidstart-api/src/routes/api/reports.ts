import { json } from '@solidjs/router'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function GET(event: { request: Request }) {
  try {
    const id = new URL(event.request.url).searchParams.get('id')
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [id])
    return json(report.rows)
  } catch (err) {
    // stack-trace-leak: the client learns the file layout and dependency versions.
    return json({ error: (err as Error).stack }, { status: 500 })
  }
}
