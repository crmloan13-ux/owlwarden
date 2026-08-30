export async function requireUserId(request: Request) {
  const id = await readSession(request)
  if (!id) throw new Response(null, { status: 401 })
  return id
}
declare function readSession(request: Request): Promise<string | null>
