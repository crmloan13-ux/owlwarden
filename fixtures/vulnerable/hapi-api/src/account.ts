import { createHash, createCipheriv } from 'node:crypto'

// weak-crypto: MD5 over a password.
export function hashPassword(password: string): string {
  const passwordHash = createHash('md5').update(password).digest('hex')
  return passwordHash
}

// weak-crypto: a session id anyone can predict from a few samples.
export function mintSessionToken(): string {
  const sessionToken = Math.random().toString(36).slice(2)
  return sessionToken
}

// weak-crypto: ECB leaks structure.
export function sealCard(pan: string, key: Buffer) {
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}
