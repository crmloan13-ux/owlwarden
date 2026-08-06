// FIXTURE: deliberately vulnerable. Three weak-crypto shapes — same set every
// framework must demonstrate so the matrix is not "one shape on next, three on
// express".
import { createCipheriv, createHash } from 'node:crypto'

export function hashPassword(password: string): string {
  // weak-crypto: MD5 over a password.
  const passwordHash = createHash('md5').update(password).digest('hex')
  return passwordHash
}

export function mintSessionToken(): string {
  // weak-crypto: predictable session token.
  const sessionToken = Math.random().toString(36).slice(2)
  return sessionToken
}

export function sealCard(pan: string, key: Buffer): Buffer {
  // weak-crypto: ECB leaks structure.
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}
