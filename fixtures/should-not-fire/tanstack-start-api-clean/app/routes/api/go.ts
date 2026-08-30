import { safeRedirect } from '../../lib/safe-redirect'

export function GET({ request }: { request: Request }) {
  const next = new URL(request.url).searchParams.get('next')
  return Response.redirect(safeRedirect(next, 'https://app.example.com'), 302)
}
