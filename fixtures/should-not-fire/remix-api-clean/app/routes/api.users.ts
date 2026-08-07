import axios from 'axios'
import { createCookie, json, redirect } from '@remix-run/node'
import type { ActionFunctionArgs, LoaderFunctionArgs } from '@remix-run/node'
import { Pool } from 'pg'

import { safeRedirect } from '../lib/safe-redirect'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const ALLOWED_HOSTS = new Set(['api.partner.com'])

const sessionCookie = createCookie('session', {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  path: '/',
})

export async function action({ request }: ActionFunctionArgs) {
  const body = (await request.json()) as {
    email?: string
    password?: string
    accessToken?: string
  }

  // Logging that a caller supplied a token, not the token itself.
  console.info({ hasAccessToken: Boolean(body.accessToken) })

  const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
    body.email,
  ])

  // Attributes were declared on createCookie; serialize just emits the value.
  const cookie = await sessionCookie.serialize(String(rows.rows[0]?.id ?? 'anon'))

  const response = json(
    { ok: true },
    { headers: { 'Set-Cookie': cookie } },
  )
  response.headers.set('Access-Control-Allow-Origin', 'https://app.example.com')
  response.headers.set('Vary', 'Origin')
  return response
}

export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')
  const callerUrl = url.searchParams.get('callerUrl')
  const manualNext = url.searchParams.get('manualNext')

  if (target) {
    const parsed = new URL(target)
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
      return json({ error: 'host not allowed' }, { status: 400 })
    }
    const upstream = await fetch(parsed, { redirect: 'error' })
    return json(await upstream.json())
  }

  if (callerUrl) {
    const parsed = new URL(callerUrl)
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
      return json({ error: 'host not allowed' }, { status: 400 })
    }
    const upstream = await axios.get(parsed.toString(), { maxRedirects: 0 })
    return json(upstream.data)
  }

  if (next) {
    return redirect(safeRedirect(next, url.origin))
  }

  if (manualNext) {
    const response = new Response(null, { status: 302 })
    response.headers.set('Location', safeRedirect(manualNext, url.origin))
    return response
  }

  try {
    const users = await pool.query('SELECT id, name FROM users LIMIT 50')
    return json({ users: users.rows })
  } catch (err) {
    console.error(err instanceof Error ? err.stack : err)
    return json({ error: 'Internal Server Error' }, { status: 500 })
  }
}
