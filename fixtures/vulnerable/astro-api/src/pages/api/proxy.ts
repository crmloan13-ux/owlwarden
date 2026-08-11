import https from 'node:https'
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

  const gotUrl = url.searchParams.get('gotUrl')
  const nodeUrl = url.searchParams.get('nodeUrl')
  const extraNext = url.searchParams.get('extraNext')

  // ssrf: got reaches a third caller-controlled host.
  if (gotUrl) {
    const upstream = await got.get(gotUrl)
    return new Response(JSON.stringify(upstream.body), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // ssrf: node https.get to a fourth caller-controlled host.
  if (nodeUrl) {
    await new Promise<void>((resolve, reject) => {
      https.get(nodeUrl, (res) => {
        res.resume()
        res.on('end', () => resolve())
      }).on('error', reject)
    })
    return new Response(JSON.stringify({ ok: true }), {
      headers: { 'Content-Type': 'application/json' },
    })
  }

  // open-redirect: Astro's redirect() to a caller-chosen target.
  if (next) {
    return redirect(next)
  }

  // open-redirect: a third caller-chosen target.
  if (extraNext) {
    return redirect(extraNext)
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
