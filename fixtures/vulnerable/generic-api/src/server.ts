// FIXTURE: deliberately vulnerable, no framework dependency.
// Exercises generic-profile vocabulary (res.json / res.cookie / fetch).
import { createServer } from 'node:http'

const SECRET_KEY = 'sk_live_51Nx-AbCdEfGhIjKlMnOpQrStUvWx'

export function mount(handler: (req: Req, res: Res) => void) {
  return createServer((req, res) => handler(req as Req, res as Res))
}

export async function login(req: Req, res: Res) {
  console.info({ password: req.body?.password })
  res.cookie('session', 'anon')
  res.json({ ok: true, hint: SECRET_KEY.slice(0, 8) })
}

export async function proxy(req: Req, res: Res) {
  const upstream = await fetch(req.body?.sourceUrl as string)
  res.json(await upstream.json())
}

export function boom(_req: Req, res: Res) {
  try {
    throw new Error('load failed')
  } catch (err) {
    res.json({ error: (err as Error).stack })
  }
}

interface Req {
  body?: { password?: string; sourceUrl?: string }
}

interface Res {
  cookie: (name: string, value: string) => void
  json: (body: unknown) => void
}
