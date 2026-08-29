import express from 'express'
import { requireAuth } from './middleware/auth'

export const app = express()
app.use('/admin', requireAuth)
