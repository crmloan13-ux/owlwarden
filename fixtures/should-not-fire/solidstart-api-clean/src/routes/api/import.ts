import axios from 'axios'
import { json } from '@solidjs/router'
import { assertAllowedUrl } from '../../lib/allowlist'

export async function POST(event: { request: Request }) {
  const body = await event.request.json()

  const url = assertAllowedUrl(body.sourceUrl)
  const upstream = await fetch(url, { redirect: 'error' })

  const second = await axios.get(assertAllowedUrl(body.callerUrl).toString(), {
    maxRedirects: 0,
  })

  return json({ ok: true, second: second.data, upstream: await upstream.json() })
}
