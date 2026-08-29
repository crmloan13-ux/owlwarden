import { requireUserSession } from '../utils/session'

export default defineEventHandler(async (event) => {
  await requireUserSession(event)
})
