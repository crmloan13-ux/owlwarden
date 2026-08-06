import { randomUUID } from 'node:crypto'
import Fastify from 'fastify'
import cookie from '@fastify/cookie'
import helmet from '@fastify/helmet'
import mysql from 'mysql2/promise'

const app = Fastify({ logger: true })
await app.register(helmet)
await app.register(cookie)

const db = await mysql.createConnection(process.env.DATABASE_URL ?? '')
const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

function safeRedirect(target: unknown, base: string, fallback = '/'): string {
  if (typeof target !== 'string') return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}

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

  // Explicit origin, not a wildcard.
  reply.header('Access-Control-Allow-Origin', 'https://app.example.com')
  reply.header('Vary', 'Origin')

  return reply.send(rows)
})

app.get('/articles/:id', async (request, reply) => {
  try {
    const [rows] = await db.execute('SELECT * FROM articles WHERE id = ?', [
      (request.params as { id: string }).id,
    ])
    return reply.send(rows)
  } catch (err) {
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

app.get('/go', async (request, reply) => {
  const next = (request.query as { next?: string }).next
  return reply.redirect(safeRedirect(next, 'https://app.example.com'))
})

app.post('/import', async (request, reply) => {
  const url = new URL(String((request.body as { sourceUrl?: string }).sourceUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    return reply.code(400).send({ error: 'source not allowed' })
  }
  const upstream = await fetch(url, { redirect: 'error' })
  return reply.send(await upstream.json())
})

function backoffMs(attempt: number) {
  return 2 ** attempt * 100 + Math.random() * 50
}

await app.listen({ port: 3000, backlog: backoffMs(0) })
