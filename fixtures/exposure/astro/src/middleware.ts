import { requireSession } from './lib/auth'

export const onRequest = requireSession
