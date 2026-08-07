import axios from 'axios'
import type { APIRoute } from 'astro'

import { safeRedirect } from '../../lib/safe-redirect'

const ALLOWED_HOSTS = new Set(['api.partner.com'])

export const GET: APIRoute = async ({ request, redirect }) => {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')
  const callerUrl = url.searchParams.get('callerUrl')
  const manualNext = url.searchParams.get('manualNext')

  if (target) {
    const parsed = new URL(target)
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
      return new Response(JSON.stringify({ error: 'host not allowed' }), {
        status: 400,
      })
    }
    const upstream = await fetch(parsed, { redirect: 'error' })
    return new Response(JSON.stringify(await upstream.json()), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  if (callerUrl) {
    const parsed = new URL(callerUrl)
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
      return new Response(JSON.stringify({ error: 'host not allowed' }), {
        status: 400,
      })
    }
    const upstream = await axios.get(parsed.toString(), { maxRedirects: 0 })
    return new Response(JSON.stringify(upstream.data), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  if (next) {
    return redirect(safeRedirect(next, url.origin))
  }

  if (manualNext) {
    const response = new Response(null, { status: 302 })
    response.headers.set('Location', safeRedirect(manualNext, url.origin))
    return response
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
}
