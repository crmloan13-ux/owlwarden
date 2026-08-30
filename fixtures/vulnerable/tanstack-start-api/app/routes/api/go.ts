export function GET({ request }: { request: Request }) {
  const url = new URL(request.url)

  // open-redirect: the caller chooses where the browser lands.
  const next = url.searchParams.get('next') as string
  return Response.redirect(next, 302)
}

export function POST({ request }: { request: Request }) {
  const url = new URL(request.url)

  // open-redirect: a hand-rolled Location header.
  const next = url.searchParams.get('next') as string
  const headers = new Headers()
  headers.set('Location', next)
  return new Response(null, { status: 302, headers })
}

export function PUT({ request }: { request: Request }) {
  const url = new URL(request.url)

  // open-redirect: a third caller-chosen target.
  const extraNext = url.searchParams.get('extraNext') as string
  return Response.redirect(extraNext, 303)
}
