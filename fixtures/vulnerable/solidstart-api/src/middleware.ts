export default createMiddleware({
  onBeforeResponse: [
    (event: { response: { headers: Headers } }) => {
      // cors-permissive: wildcard origin AND credentials, hand-rolled.
      event.response.headers.set('access-control-allow-origin', '*')
      event.response.headers.set('access-control-allow-credentials', 'true')
    },
  ],
})

declare function createMiddleware(options: unknown): unknown
