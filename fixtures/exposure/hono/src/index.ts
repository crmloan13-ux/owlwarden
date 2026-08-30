import { Hono } from 'hono'
import { jwt } from 'hono/jwt'

export const app = new Hono()
app.use('/admin/*', jwt({ secret: process.env.JWT_SECRET ?? '' }))
