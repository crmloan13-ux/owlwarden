import { Hono } from 'hono'
const app = new Hono()
app.get('/admin/reports', async (c) => c.json(await load(c.req.url)))
export default app
declare function load(url: string): Promise<unknown>
