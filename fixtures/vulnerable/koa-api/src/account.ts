import { createHash, createCipheriv } from 'node:crypto'
import Router from '@koa/router'

export const router = new Router()

router.post('/register', async (ctx) => {
  const body = ctx.request.body as { email?: string; password?: string }

  // weak-crypto: MD5 over a password.
  const passwordHash = createHash('md5').update(body.password ?? '').digest('hex')

  // weak-crypto: a session id anyone can predict from a few samples.
  const sessionToken = Math.random().toString(36).slice(2)

  await saveUser(body.email ?? '', passwordHash, sessionToken)
  ctx.body = { ok: true }
})

// weak-crypto: ECB leaks structure.
export function sealCard(pan: string, key: Buffer) {
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}

declare function saveUser(
  email: string,
  hash: string,
  token: string,
): Promise<void>
