# owlwarden

Scan a Node web app for common security mistakes. Rust engine, npm install,
stays on your machine.

```bash
npx owlwarden scan
```

**v0.1.0** (plus unreleased framework work). Twelve rules, nine of the OWASP
Top 10 categories, fixes written for Next.js, Nuxt, NestJS, Express, Fastify,
Hono, Koa, Hapi, Sails.js, Astro, Remix, and Gatsby.

No telemetry. Optional `--target` for a live header check. Agents can use
`--format json` today; MCP is on the roadmap.

## Install

```bash
npm i -D owlwarden
```

Node 20+. Prebuilt addon for macOS, Linux, Windows.

```json
{
  "scripts": {
    "security-check": "owlwarden scan"
  }
}
```

## Commands

```bash
owlwarden scan
owlwarden scan --ci
owlwarden scan --target http://127.0.0.1:3000/
owlwarden watch
owlwarden coverage
owlwarden explain stack-trace-leak
```

Full docs: [repository README](../../README.md).
