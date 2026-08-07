import axios from 'axios'
import type { GatsbyFunctionRequest, GatsbyFunctionResponse } from 'gatsby'

import { safeRedirect } from '../lib/safe-redirect'

const ALLOWED_HOSTS = new Set(['api.partner.com'])

export default async function handler(
  req: GatsbyFunctionRequest,
  res: GatsbyFunctionResponse,
) {
  const target = req.query.target as string | undefined
  const next = req.query.next as string | undefined
  const callerUrl = req.query.callerUrl as string | undefined
  const manualNext = req.query.manualNext as string | undefined

  if (target) {
    const url = new URL(target)
    if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) {
      return res.status(400).json({ error: 'host not allowed' })
    }
    const upstream = await fetch(url, { redirect: 'error' })
    return res.json(await upstream.json())
  }

  if (callerUrl) {
    const url = new URL(callerUrl)
    if (url.protocol !== 'https:' || !ALLOWED_HOSTS.has(url.hostname)) {
      return res.status(400).json({ error: 'host not allowed' })
    }
    const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
    return res.json(upstream.data)
  }

  if (next) {
    return res.redirect(safeRedirect(next, 'https://app.example.com'))
  }

  if (manualNext) {
    res.header('Location', safeRedirect(manualNext, 'https://app.example.com'))
    return res.status(302).end()
  }

  return res.json({ ok: true })
}
