import axios from 'axios'
import type { APIRoute } from 'astro'

export const GET: APIRoute = async ({ request, redirect }) => {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')
  const callerUrl = url.searchParams.get('callerUrl')
  const manualNext = url.searchParams.get('manualNext')

  // ssrf: the server fetches whatever host the caller names.
  if (target) {
    const upstream = await fetch(target)
    return new Response(JSON.stringify(await upstream.json()), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // ssrf: axios reaches a second caller-controlled host.
  if (callerUrl) {
    const upstream = await axios.get(callerUrl)
    return new Response(JSON.stringify(upstream.data), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // open-redirect: Astro's redirect() to a caller-chosen target.
  if (next) {
    return redirect(next)
  }

  // open-redirect: a hand-rolled Location header instead of redirect().
  if (manualNext) {
    const response = new Response(null, { status: 302 })
    response.headers.set('Location', manualNext)
    return response
  }

  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' },
  })
}
