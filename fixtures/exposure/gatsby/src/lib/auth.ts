export async function requireUser(req: any) {
  if (!req.headers.authorization) throw new Error('unauthenticated')
  return req.headers.authorization
}
