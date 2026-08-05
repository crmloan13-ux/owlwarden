import { randomUUID } from 'node:crypto'
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import helmet from '@fastify/helmet'
import mysql from 'mysql2/promise'

const app = Fastify({ logger: true })
await app.register(helmet)
await app.register(cookie)

const db = await mysql.createConnection(process.env.DATABASE_URL ?? '')

app.get('/search', async (request, reply) => {
  const term = (request.query as { q: string }).q

  const [rows] = await db.execute(
    'SELECT id, title FROM articles WHERE title LIKE ?',
    [`%${term}%`],
  )

  reply.setCookie('last_search', term, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
  })

  return reply.send(rows)
})

app.get('/articles/:id', async (request, reply) => {
  try {
    const [rows] = await db.execute('SELECT * FROM articles WHERE id = ?', [
      (request.params as { id: string }).id,
    ])
    return reply.send(rows)
  } catch (err) {
    // `code()` sets the status; only `send()` writes a body. The rule must not
    // count the chain twice, and must not treat the log call as a sink.
    request.log.error(err)
    return reply.code(500).send({ error: 'Internal Server Error' })
  }
})

app.post('/session', async (_request, reply) => {
  const sessionToken = randomUUID()
  reply.setCookie('sid', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
  })
  return reply.send({ ok: true })
})

// Jitter is not a security decision, and a rule that fired here would be
// firing on most of every codebase.
function backoffMs(attempt: number) {
  return 2 ** attempt * 100 + Math.random() * 50
}

await app.listen({ port: 3000, backlog: backoffMs(0) })
