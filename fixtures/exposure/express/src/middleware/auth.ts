// The gate. Resolvable, and named so the classifier can say why.
export function requireAuth(req: any, res: any, next: any) {
  if (!req.user) return res.status(401).end()
  next()
}
