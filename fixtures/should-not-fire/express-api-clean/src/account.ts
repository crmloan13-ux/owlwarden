import { createHash, randomBytes, randomUUID, scrypt } from 'node:crypto'
import express from 'express'
import { safeRedirect } from './safe-redirect'

export const router = express.Router()

const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

router.post('/register', async (req, res) => {
  // A slow hash with a per-password salt, and a token from a cryptographic
  // source.
  const salt = randomBytes(16)
  const passwordHash = await new Promise<Buffer>((resolve, reject) =>
    scrypt(req.body.password, salt, 64, (error, key) =>
      error ? reject(error) : resolve(key),
    ),
  )
  const sessionToken = randomUUID()

  await saveUser(req.body.email, passwordHash.toString('hex'), sessionToken)
  res.json({ ok: true })
})

router.get('/login', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`
  res.redirect(safeRedirect(req.query.next, base))
})

router.post('/import', async (req, res) => {
  const url = new URL(String(req.body.sourceUrl))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    res.status(400).json({ error: 'source not allowed' })
    return
  }
  const upstream = await fetch(url, { redirect: 'error' })
  res.json(await upstream.json())
})

// MD5 as a cache key is correct and extremely common. The rule must stay quiet
// here or it is unusable on real codebases.
export function cacheKey(body: string) {
  return createHash('md5').update(body).digest('hex')
}

// Math.random() picking a rotation index is not a security decision.
export function pickShard(count: number) {
  return Math.floor(Math.random() * count)
}

// A redirect to a destination this file controls.
export function goHome(res: express.Response) {
  res.redirect('/dashboard')
}

declare function saveUser(
  email: string,
  hash: string,
  token: string,
): Promise<void>
