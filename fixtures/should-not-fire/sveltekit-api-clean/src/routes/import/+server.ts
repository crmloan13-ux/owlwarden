import axios from 'axios'
import { json } from '@sveltejs/kit'
import { assertAllowedUrl } from '$lib/allowlist'

export async function POST({ request }) {
  const body = await request.json()

  const url = assertAllowedUrl(body.sourceUrl)
  const upstream = await fetch(url, { redirect: 'error' })

  const second = await axios.get(assertAllowedUrl(body.callerUrl).toString(), {
    maxRedirects: 0,
  })

  return json({ ok: true, second: second.data, upstream: await upstream.json() })
}
