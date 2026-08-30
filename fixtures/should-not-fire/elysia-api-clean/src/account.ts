import { createHash, randomBytes, randomUUID, scrypt } from 'node:crypto'

export async function register(email: string, password: string) {
  const salt = randomBytes(16)
  const passwordHash = await new Promise<Buffer>((resolve, reject) =>
    scrypt(password, salt, 64, (error, key) => (error ? reject(error) : resolve(key))),
  )
  const sessionToken = randomUUID()
  await saveUser(email, passwordHash.toString('hex'), sessionToken)
}

// MD5 as a cache key is correct and extremely common.
export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

// Math.random() picking a rotation index is not a security decision.
export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}

declare function saveUser(email: string, hash: string, token: string): Promise<void>
