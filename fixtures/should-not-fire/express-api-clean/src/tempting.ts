// Code that resembles every rule in the catalogue and is correct. If owlwarden
// fires on anything here, the rule that did it is too eager.

// Reads a secret the right way. Not a literal, so nothing to report.
export const apiKey = process.env.API_KEY ?? ''

// A key *name*, not a key. `secretName` is on the not-a-secret list.
export const secretName = 'billing/stripe/live-key-2024'

// Documentation of the prefix, not a credential carrying it.
export const STRIPE_KEY_PREFIX = 'sk_live_'

// A placeholder in a template someone copies from.
export const examplePassword = 'your-password-here'

// A public key is public.
export const publicKey = 'AIzaSyDEMOKEYNOTREALFORTESTS0000'

// `.stack` that is not an error's.
export function describe(project: { stack: string[] }) {
  return { stack: project.stack }
}

// A query object whose method name matches but whose object is not a database.
export const analytics = {
  query(event: string) {
    return `tracked ${event}`
  },
}

// A constant SQL statement. No interpolation, nothing injectable.
export const LATEST_USERS = 'SELECT id, name FROM users ORDER BY created_at DESC'

// Prisma's tagged template binds its values; it only looks like the unsafe
// call.
export async function findUser(prisma: never, id: string) {
  return (prisma as never as { $queryRaw: (s: TemplateStringsArray, ...v: unknown[]) => unknown })
    .$queryRaw`SELECT * FROM users WHERE id = ${id}`
}

// `app.get` reading a setting, not registering a route.
export function trustProxy(app: { get: (key: string) => unknown }) {
  return app.get('trust proxy')
}


// --- v0.4 dialect tempting depth (must stay silent) ---

// Non-error `.stack` property in a response-shaped object (technology list).
export function projectStack(res: { json: (body: unknown) => unknown }, project: { stack: string[] }) {
  return res.json({ stack: project.stack })
}

// Logger that looks like a sink but is not a response.
const audit = {
  error(message: string, detail?: unknown) {
    console.error(message, detail)
  },
}

export function reportFailure(err: unknown) {
  audit.error('handler failed', err instanceof Error ? err.stack : err)
  // Stack captured locally and *not* returned to the client.
  const trace = err instanceof Error ? err.stack : undefined
  if (trace) {
    console.debug(trace)
  }
  return { error: 'Bad Request' }
}

// Product copy / length metadata — not a secret.
export function auditLogin(passwordLength: number) {
  console.info('password reset email queued')
  console.info({ passwordLength })
}

// Header names in documentation comments are not missing-header findings.
// Content-Security-Policy, Strict-Transport-Security, X-Frame-Options
export const HEADER_DOCS = 'See security headers in the runbook.'
