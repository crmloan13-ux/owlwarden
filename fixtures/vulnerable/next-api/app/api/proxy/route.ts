// FIXTURE: deliberately vulnerable.
//   ssrf — fetch of a caller-chosen URL.
//   open-redirect — redirect() to a caller-chosen target.
import { redirect } from 'next/navigation'
import { NextResponse } from 'next/server'

export async function GET(request: Request) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')

  // ssrf
  if (target) {
    const upstream = await fetch(target)
    return NextResponse.json(await upstream.json())
  }

  // open-redirect
  if (next) {
    redirect(next)
  }

  return NextResponse.json({ ok: true })
}
