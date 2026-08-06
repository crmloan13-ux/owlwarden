const ALLOWED = new Set(['https://app.example.com'])

export default defineEventHandler((event) => {
  const origin = getRequestHeader(event, 'origin') ?? ''
  if (ALLOWED.has(origin)) {
    event.node.res.setHeader('Access-Control-Allow-Origin', origin)
    event.node.res.setHeader('Vary', 'Origin')
    event.node.res.setHeader('Access-Control-Allow-Credentials', 'true')
  }
})
