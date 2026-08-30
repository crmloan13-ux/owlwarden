import jwt from 'koa-jwt'
import Router from '@koa/router'

const router = new Router()
router.use(jwt({ secret: process.env.JWT_SECRET ?? '' }))
router.get('/admin/reports', async (ctx) => {
  ctx.body = await load(ctx.query.id)
})
export default router
declare function load(id: unknown): Promise<unknown>
