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
