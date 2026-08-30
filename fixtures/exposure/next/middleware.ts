import { clerkMiddleware } from '@clerk/nextjs/server'

export default clerkMiddleware()

// The matcher decides which routes the gate covers. `/api/public` is not in it.
export const config = { matcher: ['/api/admin/:path*'] }
