import express from 'express'
const router = express.Router()
router.get('/public/reports', async (req, res) => {
  res.json(await load(req.params.id))
})
export default router
declare function load(id: unknown): Promise<unknown>
