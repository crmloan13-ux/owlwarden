export function requireSession(context: any, next: any) {
  if (!context.locals.user) return new Response(null, { status: 401 })
  return next()
}
