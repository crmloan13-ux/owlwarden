// Correct generic HTTP handlers. No framework package on purpose.
import { createServer } from 'node:http'

const ALLOWED = new Set(['files.partner.com'])

export function mount(handler: (req: Req, res: Res) => void) {
  return createServer((req, res) => handler(req as Req, res as Res))
}

export async function login(req: Req, res: Res) {
  console.info({ passwordLength: String(req.body?.password ?? '').length })
  res.cookie('session', 'anon', { httpOnly: true, secure: true, sameSite: 'lax' })
  res.json({ ok: true })
}

export async function proxy(req: Req, res: Res) {
  const url = new URL(String(req.body?.sourceUrl))
  if (url.protocol !== 'https:' || !ALLOWED.has(url.hostname)) {
    res.json({ error: 'source not allowed' })
    return
  }
  const upstream = await fetch(url, { redirect: 'error' })
  res.json(await upstream.json())
}

export function boom(_req: Req, res: Res) {
  try {
    throw new Error('load failed')
  } catch {
    res.json({ error: 'Bad Request' })
  }
}

// Tempting: technology `.stack`, not an error stack.
export function describe(project: { stack: string[] }, res: Res) {
  res.json({ stack: project.stack })
}

interface Req {
  body?: { password?: string; sourceUrl?: string }
}

interface Res {
  cookie: (name: string, value: string, opts?: Record<string, unknown>) => void
  json: (body: unknown) => void
}
