// Fixture: Fastify, whose reply object and route registration look nothing
// like Express's. The same rules have to find the same bugs here.
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import mysql from 'mysql2/promise'

import { mintSessionToken } from './crypto'

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

  // cors-permissive: hand-rolled wildcard + credentials.
  reply.header('Access-Control-Allow-Origin', '*')
  reply.header('Access-Control-Allow-Credentials', 'true')

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
  // sensitive-data-logged: Fastify's request.log is a real log sink.
  request.log.info({ password: (request.body as { password?: string }).password })

  const sessionToken = mintSessionToken()
  reply.setCookie('sid', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
  })
  return reply.send({ ok: true })
})

app.get('/go', async (request, reply) => {
  // open-redirect
  const next = (request.query as { next?: string }).next as string
  return reply.redirect(next)
})

app.post('/import', async (request, reply) => {
  // ssrf
  const sourceUrl = (request.body as { sourceUrl?: string }).sourceUrl as string
  const upstream = await fetch(sourceUrl)
  return reply.send(await upstream.json())
})

await app.listen({ port: 3000 })
