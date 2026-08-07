// The corrected version of the vulnerable Sails AuthController.
const axios = require('axios')
const { Pool } = require('pg')

const pool = new Pool({ connectionString: process.env.DATABASE_URL })
const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

function safeRedirect(target, base, fallback = '/') {
  if (typeof target !== 'string') return fallback
  try {
    const resolved = new URL(target, base)
    return resolved.origin === new URL(base).origin
      ? resolved.pathname + resolved.search
      : fallback
  } catch {
    return fallback
  }
}

module.exports = {
  async login(req, res) {
    // Logging that a caller supplied a token, not the token itself.
    console.info({ hasAccessToken: Boolean(req.body.accessToken) })

    const rows = await pool.query('SELECT id, role FROM users WHERE email = $1', [
      req.body.email,
    ])

    res.cookie('session', rows.rows[0].id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    })

    res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com')
    res.setHeader('Vary', 'Origin')

    return res.json({ ok: true })
  },

  async reports(req, res) {
    try {
      const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
        req.params.id,
      ])
      return res.json(report.rows)
    } catch (err) {
      console.error(err.stack)
      return res.status(500).json({ error: 'Internal Server Error' })
    }
  },

  go(req, res) {
    return res.redirect(safeRedirect(req.query.next, 'https://app.example.com'))
  },

  goHeader(req, res) {
    res.setHeader('Location', safeRedirect(req.query.next, 'https://app.example.com'))
    return res.status(302).end()
  },

  async importRemote(req, res) {
    const url = new URL(String(req.body.sourceUrl))
    if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
      return res.status(400).json({ error: 'source not allowed' })
    }
    const upstream = await fetch(url, { redirect: 'error' })
    return res.json(await upstream.json())
  },

  async importRemoteViaAxios(req, res) {
    const url = new URL(String(req.body.callerUrl))
    if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
      return res.status(400).json({ error: 'source not allowed' })
    }
    const upstream = await axios.get(url.toString(), { maxRedirects: 0 })
    return res.json(upstream.data)
  },
}
