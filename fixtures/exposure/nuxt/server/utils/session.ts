export async function requireUserSession(event: unknown) {
  if (!event) throw createError({ statusCode: 401 })
}
declare function createError(options: { statusCode: number }): Error
