import { json } from '@sveltejs/kit'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function GET({ params }) {
  try {
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [params.id])
    return json(report.rows)
  } catch (err) {
    // Logged server-side, generic body to the client.
    console.error(err instanceof Error ? err.stack : err)
    return json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
