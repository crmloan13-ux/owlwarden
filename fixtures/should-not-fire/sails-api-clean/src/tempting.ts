// Code that resembles every rule in the catalogue and is correct.

export const apiKey = process.env.API_KEY ?? ''
export const secretName = 'billing/stripe/live-key-2024'
export const STRIPE_KEY_PREFIX = 'sk_live_'
export const examplePassword = 'your-password-here'
export const publicKey = 'AIzaSyDEMOKEYNOTREALFORTESTS0000'

export function describe(project: { stack: string[] }) {
  return { stack: project.stack }
}

export const analytics = {
  query(event: string) {
    return `tracked ${event}`
  },
}

export const LATEST_USERS = 'SELECT id, name FROM users ORDER BY created_at DESC'

export async function findUser(prisma: never, id: string) {
  return (prisma as never as { $queryRaw: (s: TemplateStringsArray, ...v: unknown[]) => unknown })
    .$queryRaw`SELECT * FROM users WHERE id = ${id}`
}

export function auditLogin(passwordLength: number) {
  console.info({ passwordLength })
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
