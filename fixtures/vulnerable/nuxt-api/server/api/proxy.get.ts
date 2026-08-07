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

  return upstream
})
