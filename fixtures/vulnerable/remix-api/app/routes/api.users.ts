// Fixture: Remix loader/action. json() and redirect() come from @remix-run/node.
import https from 'node:https'
import axios from 'axios'
import { createCookie, json, redirect } from '@remix-run/node'
import type { ActionFunctionArgs, LoaderFunctionArgs } from '@remix-run/node'
import { Pool } from 'pg'

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

// insecure-cookie: createCookie without protective attributes. Options belong
// here in Remix — serialize() only writes the already-configured cookie.
const sessionCookie = createCookie('session')

export async function action({ request }: ActionFunctionArgs) {
  const body = (await request.json()) as {
    email?: string
    password?: string
    accessToken?: string
  }

  // sensitive-data-logged: the password reaches the process log.
  console.info({ password: body.password })

  // sensitive-data-logged: an access token, logged the same way.
  console.info({ accessToken: body.accessToken })

  // sql-injection: the email comes straight from the body into the query text.
  const rows = await pool.query(
    `SELECT id, role FROM users WHERE email = '${body.email}'`,
  )

  const cookie = await sessionCookie.serialize(String(rows.rows[0]?.id ?? 'anon'))

  const response = json({ ok: true }, {
    headers: { 'Set-Cookie': cookie },
  })

  // cors-permissive: hand-rolled wildcard + credentials.
  response.headers.set('Access-Control-Allow-Origin', '*')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}

export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url)
  const target = url.searchParams.get('target')
  const next = url.searchParams.get('next')
  const callerUrl = url.searchParams.get('callerUrl')
  const manualNext = url.searchParams.get('manualNext')

  // ssrf
  if (target) {
    const upstream = await fetch(target)
    return json(await upstream.json())
  }

  // ssrf: axios reaches a second caller-controlled host.
  if (callerUrl) {
    const upstream = await axios.get(callerUrl)
    return json(upstream.data)
  }

  const gotUrl = url.searchParams.get('gotUrl')
  const nodeUrl = url.searchParams.get('nodeUrl')
  const extraNext = url.searchParams.get('extraNext')

  // ssrf: got reaches a third caller-controlled host.
  if (gotUrl) {
    const upstream = await got.get(gotUrl)
    return json(upstream.body)
  }

  // ssrf: node https.get to a fourth caller-controlled host.
  if (nodeUrl) {
    await new Promise<void>((resolve, reject) => {
      https.get(nodeUrl, (res) => {
        res.resume()
        res.on('end', () => resolve())
      }).on('error', reject)
    })
    return json({ ok: true })
  }

  // open-redirect
  if (next) {
    return redirect(next)
  }

  // open-redirect: a third caller-chosen target.
  if (extraNext) {
    return redirect(extraNext)
  }

  // open-redirect: a hand-rolled Location header instead of redirect().
  if (manualNext) {
    const response = new Response(null, { status: 302 })
    response.headers.set('Location', manualNext)
    return response
  }

  try {
    const users = await pool.query('SELECT id, name FROM users LIMIT 50')
    return json({ users: users.rows })
  } catch (err) {
    // stack-trace-leak: json() helper carries the stack to the client.
    return json({ error: (err as Error).stack }, { status: 500 })
  }
}
