// FIXTURE: three weak-crypto shapes (parity with every other framework).
import { createCipheriv, createHash } from 'node:crypto'

export function hashPassword(password: string): string {
  const passwordHash = createHash('md5').update(password).digest('hex')
  return passwordHash
}

export function mintSessionToken(): string {
  const sessionToken = Math.random().toString(36).slice(2)
  return sessionToken
}

export function sealCard(pan: string, key: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}
