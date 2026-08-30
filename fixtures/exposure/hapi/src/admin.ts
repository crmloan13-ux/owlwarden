export function register(server: any) {
  server.route({
    method: 'GET',
    path: '/admin/reports',
    options: { auth: 'jwt' },
    handler: async (request: any) => load(request.params.id),
  })
}
declare function load(id: unknown): Promise<unknown>
