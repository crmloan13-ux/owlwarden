import fastifyJwt from '@fastify/jwt'
export function routes(app: any) {
  // The gate is a route option, which is Fastify's own spelling.
  app.get('/admin/reports', { onRequest: [fastifyJwt.verify] }, async (req: any, reply: any) => {
    reply.send(await load(req.params.id))
  })
}
declare function load(id: unknown): Promise<unknown>
