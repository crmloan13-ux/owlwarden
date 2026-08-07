import axios from 'axios'

const ALLOWED_HOSTS = new Set(['api.partner.com'])

function assertAllowedUrl(raw: unknown): URL {
  const url = new URL(String(raw))
  if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) {
    throw createError({ statusCode: 400, statusMessage: 'host not allowed' })
  }
  return url
}

function safeRedirect(target: unknown, base: string, fallback = '/'): string {
  if (typeof target !== 'string') return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}

export default defineEventHandler(async (event) => {
  const query = getQuery(event)

  const target = assertAllowedUrl(query.target)
  const upstream = await $fetch(target.toString(), { redirect: 'error' })

  if (query.callerUrl) {
    const callerTarget = assertAllowedUrl(query.callerUrl)
    const axiosUpstream = await axios.get(callerTarget.toString(), {
      maxRedirects: 0,
    })
    return axiosUpstream.data
  }

  if (query.next) {
    const origin = getRequestURL(event).origin
    await sendRedirect(event, safeRedirect(query.next, origin), 302)
  }

  if (query.manualNext) {
    const origin = getRequestURL(event).origin
    event.node.res.statusCode = 302
    event.node.res.setHeader('Location', safeRedirect(query.manualNext, origin))
    return
  }

  return upstream
})
