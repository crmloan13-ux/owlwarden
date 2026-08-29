import Router from '@koa/router'
const router = new Router()
router.get('/public/reports', async (ctx) => {
  ctx.body = await load(ctx.query.id)
})
export default router
declare function load(id: unknown): Promise<unknown>
