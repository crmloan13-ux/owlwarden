import https from 'node:https'
import axios from 'axios'
import { json } from '@solidjs/router'

export async function POST(event: { request: Request }) {
  const body = await event.request.json()

  // ssrf: the server fetches whatever host the caller names.
  const upstream = await fetch(body.sourceUrl as string)

  // ssrf: axios reaches a second caller-controlled host.
  const second = await axios.get(body.callerUrl as string)

  // ssrf: got reaches a third caller-controlled host.
  const third = await got.get(body.gotUrl as string)

  // ssrf: node https.get to a fourth caller-controlled host.
  await new Promise<void>((resolve, reject) => {
    https.get(body.nodeUrl as string, (up) => {
      up.resume()
      up.on('end', () => resolve())
    }).on('error', reject)
  })

  return json({
    ok: true,
    second: second.data,
    third: third.body,
    upstream: await upstream.json(),
  })
}
