import { redirect } from '@solidjs/router'

export function GET(event: { request: Request }) {
  const url = new URL(event.request.url)

  // open-redirect: the caller chooses where the browser lands.
  const next = url.searchParams.get('next') as string
  return redirect(next)
}

export function POST(event: { request: Request }) {
  const url = new URL(event.request.url)

  // open-redirect: a hand-rolled Location header.
  const next = url.searchParams.get('next') as string
  const headers = new Headers()
  headers.set('Location', next)
  return new Response(null, { status: 302, headers })
}

export function PUT(event: { request: Request }) {
  const url = new URL(event.request.url)

  // open-redirect: a third caller-chosen target, status-first form.
  const extraNext = url.searchParams.get('extraNext') as string
  return redirect(extraNext, 303)
}
