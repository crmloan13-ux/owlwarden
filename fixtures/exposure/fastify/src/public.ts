export function routes(app: any) {
  app.get('/public/reports', async (req: any, reply: any) => {
    reply.send(await load(req.params.id))
  })
}
declare function load(id: unknown): Promise<unknown>
