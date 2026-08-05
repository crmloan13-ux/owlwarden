import { createHash, createCipheriv } from 'node:crypto'
import express from 'express'

export const router = express.Router()

router.post('/register', async (req, res) => {
  // weak-crypto: MD5 over a password. Fast by design, which is the attacker's
  // advantage — a GPU tries billions of candidates a second.
  const passwordHash = createHash('md5').update(req.body.password).digest('hex')

  // weak-crypto: a session id anyone can predict from a few samples.
  const sessionToken = Math.random().toString(36).slice(2)

  await saveUser(req.body.email, passwordHash, sessionToken)
  res.json({ ok: true })
})

router.get('/login', (req, res) => {
  // open-redirect: the caller chooses where the browser lands, on a URL that
  // genuinely starts with this site's domain.
  res.redirect(req.query.next as string)
})

router.post('/import', async (req, res) => {
  // ssrf: the server fetches whatever host the caller names, including ones
  // only the server can reach.
  const upstream = await fetch(req.body.sourceUrl)
  res.json(await upstream.json())
})

// weak-crypto: ECB leaks structure — identical plaintext blocks produce
// identical ciphertext blocks.
export function sealCard(pan: string, key: Buffer) {
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}

declare function saveUser(
  email: string,
  hash: string,
  token: string,
): Promise<void>
