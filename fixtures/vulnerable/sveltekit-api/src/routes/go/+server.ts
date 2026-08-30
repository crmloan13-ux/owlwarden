import { redirect } from '@sveltejs/kit'

export function GET({ url }) {
  // open-redirect: the caller chooses where the browser lands.
  const next = url.searchParams.get('next') as string
  redirect(302, next)
}

export function POST({ url }) {
  // open-redirect: a hand-rolled Location header instead of redirect().
  const next = url.searchParams.get('next') as string
  const headers = new Headers()
  headers.set('Location', next)
  return new Response(null, { status: 302, headers })
}

export function PUT({ url }) {
  // open-redirect: a third caller-chosen target, status-first form.
  const extraNext = url.searchParams.get('extraNext') as string
  redirect(303, extraNext)
}
