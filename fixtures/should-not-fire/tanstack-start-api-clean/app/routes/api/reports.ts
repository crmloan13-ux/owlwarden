import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

export async function GET({ request }: { request: Request }) {
  try {
    const id = new URL(request.url).searchParams.get('id')
    const report = await pool.query('SELECT * FROM reports WHERE id = $1', [id])
    return Response.json(report.rows)
  } catch (err) {
    console.error(err instanceof Error ? err.stack : err)
    return Response.json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
