import { redirect } from '@sveltejs/kit'
import { safeRedirect } from '$lib/safe-redirect'

export function GET({ url }) {
  redirect(302, safeRedirect(url.searchParams.get('next'), 'https://app.example.com'))
}

export function POST({ url }) {
  const headers = new Headers()
  headers.set('Location', safeRedirect(url.searchParams.get('next'), 'https://app.example.com'))
  return new Response(null, { status: 302, headers })
}
