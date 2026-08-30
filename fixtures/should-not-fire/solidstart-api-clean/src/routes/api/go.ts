import { redirect } from '@solidjs/router'
import { safeRedirect } from '../../lib/safe-redirect'

export function GET(event: { request: Request }) {
  const next = new URL(event.request.url).searchParams.get('next')
  return redirect(safeRedirect(next, 'https://app.example.com'))
}
