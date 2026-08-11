// Fixture: Fastify, whose reply object and route registration look nothing
// like Express's. The same rules have to find the same bugs here.
import https from 'node:https'
import axios from 'axios'
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

  // sensitive-data-logged: an access token, logged the same way.
  request.log.info({
    accessToken: (request.body as { accessToken?: string }).accessToken,
  })

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

app.get('/go2', async (request, reply) => {
  // open-redirect: a hand-rolled Location header instead of reply.redirect().
  const next = (request.query as { next?: string }).next as string
  reply.header('Location', next)
  return reply.code(302).send()
})

app.post('/import', async (request, reply) => {
  // ssrf
  const sourceUrl = (request.body as { sourceUrl?: string }).sourceUrl as string
  const upstream = await fetch(sourceUrl)
  return reply.send(await upstream.json())
})

app.post('/import2', async (request, reply) => {
  // ssrf: axios reaches a second caller-controlled host.
  const callerUrl = (request.body as { callerUrl?: string }).callerUrl as string
  const upstream = await axios.get(callerUrl)
  return reply.send(upstream.data)
})

app.get('/go3', async (request, reply) => {
  // open-redirect: status-first form — still caller-controlled.
  const extraNext = (request.query as { extraNext?: string }).extraNext as string
  return reply.redirect(302, extraNext)
})

app.post('/import3', async (request, reply) => {
  // ssrf: got reaches a third caller-controlled host.
  const gotUrl = (request.body as { gotUrl?: string }).gotUrl as string
  const upstream = await got.get(gotUrl)
  return reply.send(upstream.body)
})

app.post('/import4', async (request, reply) => {
  // ssrf: node https.get to a fourth caller-controlled host.
  const nodeUrl = (request.body as { nodeUrl?: string }).nodeUrl as string
  await new Promise<void>((resolve, reject) => {
    https.get(nodeUrl, (up) => {
      up.resume()
      up.on('end', () => resolve())
    }).on('error', reject)
  })
  return reply.send({ ok: true })
})

await app.listen({ port: 3000 })
