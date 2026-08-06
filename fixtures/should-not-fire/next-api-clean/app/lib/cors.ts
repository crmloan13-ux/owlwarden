import { NextResponse } from 'next/server'

const ALLOWED = new Set(['https://app.example.com'])

export function applyCors(response: NextResponse, origin: string | null): NextResponse {
  if (origin && ALLOWED.has(origin)) {
    response.headers.set('Access-Control-Allow-Origin', origin)
    response.headers.set('Vary', 'Origin')
    response.headers.set('Access-Control-Allow-Credentials', 'true')
  }
  return response
}
