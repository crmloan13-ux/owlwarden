// The file name states the route and the method: GET /api/users. A finding
// here should say so, which is what the Nitro routing in the Nuxt profile is
// for.
import { db } from '../utils/db'

export default defineEventHandler(async (event) => {
  const query = getQuery(event)

  try {
    // sql-injection: the sort column is interpolated into the statement.
    return await db.query(
      `SELECT id, name FROM users ORDER BY ${query.sort} LIMIT 50`,
    )
  } catch (err) {
    // stack-trace-leak: createError's message becomes the response body, so
    // the stack goes to the client.
    throw createError({
      statusCode: 500,
      statusMessage: (err as Error).stack,
    })
  }
})
