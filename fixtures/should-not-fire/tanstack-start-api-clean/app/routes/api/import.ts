import axios from 'axios'
import { assertAllowedUrl } from '../../lib/allowlist'

export async function POST({ request }: { request: Request }) {
  const body = await request.json()

  const url = assertAllowedUrl(body.sourceUrl)
  const upstream = await fetch(url, { redirect: 'error' })

  const second = await axios.get(assertAllowedUrl(body.callerUrl).toString(), {
    maxRedirects: 0,
  })

  return Response.json({ ok: true, second: second.data, upstream: await upstream.json() })
}
