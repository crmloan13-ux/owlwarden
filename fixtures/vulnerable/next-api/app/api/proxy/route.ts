// FIXTURE: deliberately vulnerable.
//   ssrf — fetch of a caller-chosen URL, and axios to a second one.
//   open-redirect — redirect() to a caller-chosen target, and a hand-rolled
//   Location header to a second one.
import axios from 'axios'
import { redirect } from 'next/navigation'
import { NextResponse } from 'next/server'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')
  const callerUrl = url.searchParams.get('callerUrl')
  const manualNext = url.searchParams.get('manualNext')

  // ssrf
  if (target) {
    const upstream = await fetch(target)
    return NextResponse.json(await upstream.json())
  }

  // ssrf: axios reaches a second caller-controlled host.
  if (callerUrl) {
    const upstream = await axios.get(callerUrl)
    return NextResponse.json(upstream.data)
  }

  // open-redirect
  if (next) {
    redirect(next)
  }

  // open-redirect: a hand-rolled Location header instead of redirect().
  if (manualNext) {
    const headers = new Headers()
    headers.set('Location', manualNext)
    return new NextResponse(null, { status: 302, headers })
  }

  return NextResponse.json({ ok: true })
}
