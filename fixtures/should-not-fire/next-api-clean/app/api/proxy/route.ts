import { redirect } from 'next/navigation'
import { NextResponse } from 'next/server'

const ALLOWED_HOSTS = new Set(['api.partner.com'])

function assertAllowedUrl(raw: string | null): URL {
  const url = new URL(String(raw))
  if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error('host not allowed')
  }
  return url
}

function safeRedirect(target: string | null, base: string, fallback = '/'): string {
  if (!target) return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}

export async function GET(request: Request) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')

  if (target) {
    const upstream = await fetch(assertAllowedUrl(target), { redirect: 'error' })
    return NextResponse.json(await upstream.json())
  }

  if (next) {
    redirect(safeRedirect(next, url.origin))
  }

  return NextResponse.json({ ok: true })
}
