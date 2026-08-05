export default defineEventHandler(async (event) => {
  const query = getQuery(event)

  // ssrf: Nitro's $fetch will happily call an internal host or the cloud
  // metadata endpoint on the caller's behalf.
  const upstream = await $fetch(query.target as string)

  // open-redirect: the caller decides where the browser goes next, from a link
  // that genuinely starts with this site's domain.
  if (query.next) {
    await sendRedirect(event, query.next as string, 302)
  }

  return upstream
})
