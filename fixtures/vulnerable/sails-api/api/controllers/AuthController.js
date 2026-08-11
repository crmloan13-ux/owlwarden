// Fixture: Sails controllers use Express-shaped res.json / res.cookie / res.redirect.
const https = require('node:https')
const axios = require('axios')
const { Pool } = require('pg')

const pool = new Pool({ connectionString: process.env.DATABASE_URL })

module.exports = {
  async login(req, res) {
    // sensitive-data-logged: the password reaches the process log.
    console.info({ password: req.body.password })

    // sensitive-data-logged: an access token, logged the same way.
    console.info({ accessToken: req.body.accessToken })

    // sql-injection: the email comes straight from the body into the query text.
    const rows = await pool.query(
      `SELECT id, role FROM users WHERE email = '${req.body.email}'`,
    )

    // insecure-cookie: no httpOnly, no secure, no sameSite.
    res.cookie('session', rows.rows[0].id)

    // cors-permissive: hand-rolled wildcard + credentials (detected reliably).
    res.setHeader('Access-Control-Allow-Origin', '*')
    res.setHeader('Access-Control-Allow-Credentials', 'true')

    return res.json({ ok: true })
  },

  async reports(req, res) {
    try {
      const report = await pool.query('SELECT * FROM reports WHERE id = $1', [
        req.params.id,
      ])
      return res.json(report.rows)
    } catch (err) {
      // stack-trace-leak: the client learns the file layout.
      return res.status(500).json({ error: err.stack })
    }
  },

  go(req, res) {
    // open-redirect: the caller chooses where the browser lands.
    return res.redirect(req.query.next)
  },

  goHeader(req, res) {
    // open-redirect: a hand-rolled Location header instead of res.redirect().
    res.setHeader('Location', req.query.next)
    return res.status(302).end()
  },

  async importRemote(req, res) {
    // ssrf: the server fetches whatever host the caller names.
    const upstream = await fetch(req.body.sourceUrl)
    return res.json(await upstream.json())
  },

  async importRemoteViaAxios(req, res) {
    // ssrf: axios reaches a second caller-controlled host.
    const upstream = await axios.get(req.body.callerUrl)
    return res.json(upstream.data)
  },

  goStatus(req, res) {
    // open-redirect: status-first form — still caller-controlled.
    return res.redirect(302, req.query.extraNext)
  },

  async importViaGot(req, res) {
    // ssrf: got reaches a third caller-controlled host.
    const upstream = await got.get(req.body.gotUrl)
    return res.json(upstream.body)
  },

  async importViaHttps(req, res) {
    // ssrf: node https.get to a fourth caller-controlled host.
    await new Promise((resolve, reject) => {
      https.get(req.body.nodeUrl, (up) => {
        up.resume()
        up.on('end', () => resolve())
      }).on('error', reject)
    })
    return res.json({ ok: true })
  },
}
