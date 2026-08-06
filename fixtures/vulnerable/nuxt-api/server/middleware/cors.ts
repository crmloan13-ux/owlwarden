// FIXTURE: cors-permissive — hand-rolled wildcard + credentials.
// handleCors(event, opts) puts the event first, so the rule cannot read the
// options object the way it does for cors()/enableCors(); setHeader is the
// shape that is actually detected here.
export default defineEventHandler((event) => {
  event.node.res.setHeader('Access-Control-Allow-Origin', '*')
  event.node.res.setHeader('Access-Control-Allow-Credentials', 'true')
})
