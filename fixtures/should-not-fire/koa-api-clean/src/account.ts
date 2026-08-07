import { createHash, randomBytes, randomUUID, scrypt } from 'node:crypto'
import Router from '@koa/router'

export const router = new Router()

router.post('/register', async (ctx) => {
  const body = ctx.request.body as { email?: string; password?: string }

  const salt = randomBytes(16)
  const passwordHash = await new Promise<Buffer>((resolve, reject) =>
    scrypt(body.password ?? '', salt, 64, (error, key) =>
      error ? reject(error) : resolve(key),
    ),
  )
  const sessionToken = randomUUID()

  await saveUser(body.email ?? '', passwordHash.toString('hex'), sessionToken)
  ctx.body = { ok: true }
})

export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}

declare function saveUser(
  email: string,
  hash: string,
  token: string,
): Promise<void>
