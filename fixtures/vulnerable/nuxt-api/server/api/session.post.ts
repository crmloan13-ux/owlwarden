export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  // sensitive-data-logged: password from the body written to the process log.
  console.info({ password: body.password })
  const token = await signIn(body.email, body.password)

  // insecure-cookie: h3's setCookie is a bare helper, not a method on a
  // response object, and it is called here with no attributes at all.
  setCookie(event, 'session', token)

  return { ok: true }
})
