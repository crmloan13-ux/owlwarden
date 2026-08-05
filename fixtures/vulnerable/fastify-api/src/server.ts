// Fixture: Fastify, whose reply object and route registration look nothing
// like Express's. The same rules have to find the same bugs here.
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import mysql from 'mysql2/promise'

const app = Fastify({ logger: true })
await app.register(cookie)

const db = await mysql.createConnection(process.env.DATABASE_URL ?? '')

app.get('/search', async (request, reply) => {
  const term = (request.query as { q: string }).q

  // sql-injection: concatenated rather than bound.
  const [rows] = await db.execute(
    'SELECT id, title FROM articles WHERE title LIKE "%' + term + '%"',
  )

  // insecure-cookie: options object present but missing secure and sameSite,
  // which is the "team owns cookie config and has a gap" case.
  reply.setCookie('last_search', term, { httpOnly: true })

  return reply.send(rows)
})

app.get('/articles/:id', async (request, reply) => {
  try {
    const [rows] = await db.execute('SELECT * FROM articles WHERE id = ?', [
      (request.params as { id: string }).id,
    ])
    return reply.send(rows)
  } catch (err) {
    // stack-trace-leak, in Fastify's chained spelling.
    return reply.code(500).send({ error: (err as Error).stack })
  }
})

app.post('/session', async (request, reply) => {
  // weak-crypto: a session id from a PRNG an attacker can predict after seeing
  // a handful of outputs.
  const sessionToken = Math.random().toString(36).slice(2)
  reply.setCookie('sid', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
  })
  return reply.send({ ok: true })
})

await app.listen({ port: 3000 })
