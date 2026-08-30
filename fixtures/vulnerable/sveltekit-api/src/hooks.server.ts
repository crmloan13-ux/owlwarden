// Fixture: a SvelteKit service with the mistakes owlwarden should find.
// Endpoints are `+server.ts`; the handler receives a RequestEvent.
import type { Handle } from '@sveltejs/kit'

export const handle: Handle = async ({ event, resolve }) => {
  const response = await resolve(event)
  // cors-permissive: wildcard origin AND credentials, hand-rolled.
  response.headers.set('access-control-allow-origin', '*')
  response.headers.set('access-control-allow-credentials', 'true')
  return response
}
