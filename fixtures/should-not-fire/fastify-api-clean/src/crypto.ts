import { createHash, randomUUID } from 'node:crypto'

export function mintSessionToken(): string {
  return randomUUID()
}

export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}
