import axios from 'axios'
import type { GatsbyFunctionRequest, GatsbyFunctionResponse } from 'gatsby'

export default async function handler(
  req: GatsbyFunctionRequest,
  res: GatsbyFunctionResponse,
) {
  const target = req.query.target as string | undefined
  const next = req.query.next as string | undefined
  const callerUrl = req.query.callerUrl as string | undefined
  const manualNext = req.query.manualNext as string | undefined

  // ssrf
  if (target) {
    const upstream = await fetch(target)
    return res.json(await upstream.json())
  }

  // ssrf: axios reaches a second caller-controlled host.
  if (callerUrl) {
    const upstream = await axios.get(callerUrl)
    return res.json(upstream.data)
  }

  // open-redirect
  if (next) {
    return res.redirect(next)
  }

  // open-redirect: a hand-rolled Location header instead of res.redirect().
  // open-redirect via Location header.
  if (manualNext) {
    res.header('Location', manualNext)
    return res.status(302).end()
  }

  return res.json({ ok: true })
}
