import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function GET({ request }: { request: Request }) {
  try {
    const id = new URL(request.url).searchParams.get('id')
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [id])
    return Response.json(report.rows)
  } catch (err) {
    // stack-trace-leak: the client learns the file layout and dependency versions.
    return Response.json({ error: (err as Error).stack }, { status: 500 })
  }
}
