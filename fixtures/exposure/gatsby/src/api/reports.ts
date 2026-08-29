export default async function handler(req: any, res: any) {
  res.json(await load(req.query.id))
}
declare function load(id: unknown): Promise<unknown>
