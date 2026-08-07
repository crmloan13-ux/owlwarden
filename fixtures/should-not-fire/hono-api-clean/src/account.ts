import { createHash, randomBytes, randomUUID, scrypt } from 'node:crypto'
import { Hono } from 'hono'

import { safeRedirect } from './safe-redirect'

export const account = new Hono()

account.post('/register', async (c) => {
  const body = await c.req.json<{ email?: string; password?: string }>()

  const salt = randomBytes(16)
  const passwordHash = await new Promise<Buffer>((resolve, reject) =>
    scrypt(body.password ?? '', salt, 64, (error, key) =>
      error ? reject(error) : resolve(key),
    ),
  )
  const sessionToken = randomUUID()

  await saveUser(body.email ?? '', passwordHash.toString('hex'), sessionToken)
  return c.json({ ok: true })
})

account.get('/login', (c) => {
  return c.redirect(safeRedirect(c.req.query('next'), 'https://app.example.com'))
})

// MD5 as a cache key is correct and extremely common.
export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

// Math.random() picking a rotation index is not a security decision.
export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}

declare function saveUser(
  email: string,
  hash: string,
  token: string,
): Promise<void>
