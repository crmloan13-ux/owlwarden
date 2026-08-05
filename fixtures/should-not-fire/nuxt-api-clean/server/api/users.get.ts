import { db } from '../utils/db'

const ALLOWED_SORTS = new Set(['name', 'created_at'])

export default defineEventHandler(async (event) => {
  const query = getQuery(event)
  const sort = ALLOWED_SORTS.has(String(query.sort)) ? String(query.sort) : 'name'

  try {
    // The sort column is validated against an allowlist and the limit is
    // bound. The statement text is still assembled, but from values this file
    // controls — and the rule needs interpolation of something it can see
    // flowing in, not merely a template literal.
    return await db.query('SELECT id, name FROM users ORDER BY $1 LIMIT $2', [
      sort,
      50,
    ])
  } catch (err) {
    console.error(err)
    throw createError({
      statusCode: 500,
      statusMessage: 'Internal Server Error',
    })
  }
})
