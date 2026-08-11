import https from 'node:https'
import axios from 'axios'

export default defineEventHandler(async (event) => {
  const query = getQuery(event)

  // ssrf: Nitro's $fetch will happily call an internal host or the cloud
  // metadata endpoint on the caller's behalf.
  const upstream = await $fetch(query.target as string)

  // ssrf: axios reaches a second caller-controlled host.
  if (query.callerUrl) {
    const axiosUpstream = await axios.get(query.callerUrl as string)
    return axiosUpstream.data
  }

  // ssrf: got reaches a third caller-controlled host.
  if (query.gotUrl) {
    const gotUpstream = await got.get(query.gotUrl as string)
    return gotUpstream.body
  }

  // ssrf: node https.get to a fourth caller-controlled host.
  if (query.nodeUrl) {
    await new Promise<void>((resolve, reject) => {
      https.get(query.nodeUrl as string, (res) => {
        res.resume()
        res.on('end', () => resolve())
      }).on('error', reject)
    })
    return { ok: true }
  }

  // open-redirect: the caller decides where the browser goes next, from a link
  // that genuinely starts with this site's domain.
  if (query.next) {
    await sendRedirect(event, query.next as string, 302)
  }

  // open-redirect: a hand-rolled Location header instead of sendRedirect().
  if (query.manualNext) {
    event.node.res.statusCode = 302
    event.node.res.setHeader('Location', query.manualNext as string)
    return
  }

  // open-redirect: a third caller-chosen target.
  if (query.extraNext) {
    await sendRedirect(event, query.extraNext as string, 302)
  }

  return upstream
})
