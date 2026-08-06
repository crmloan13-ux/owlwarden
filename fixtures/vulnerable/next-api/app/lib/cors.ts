// FIXTURE: cors-permissive — wildcard origin plus credentials headers.
// Kept out of middleware.ts so the headers rule still points at the missing
// next.config, not at this CORS helper.
import { NextResponse } from 'next/server'

export function applyOpenCors(response: NextResponse): NextResponse {
  response.headers.set('Access-Control-Allow-Origin', '*')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}
