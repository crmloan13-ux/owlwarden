export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  const token = await signIn(body.email, body.password)

  setCookie(event, 'session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  })

  return { ok: true }
})
