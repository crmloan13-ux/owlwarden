import { createHash, randomUUID } from 'node:crypto'

export function mintSessionToken(): string {
  return randomUUID()
}

// MD5 as a cache key is correct. The rule must stay quiet here.
export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

// Math.random picking a shard is not a security decision.
export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}
