import { requireUser } from '../../lib/auth'

export default async function handler(req: any, res: any) {
  await requireUser(req)
  res.json(await load(req.query.id))
}
declare function load(id: unknown): Promise<unknown>
