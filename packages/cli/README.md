# owlwarden

Scan a Node web app for common security mistakes. Rust engine, npm install,
stays on your machine. Built so coding agents and humans get the same answer.

```bash
npx owlwarden scan
npx owlwarden mcp    # stdio MCP for Cursor, Claude, and other MCP hosts
```

**v0.2.0.** Twelve rules, nine of the OWASP Top 10 categories, first-class
fixes for Next.js, Nuxt, NestJS, Express, Fastify, Hono, Koa, Hapi, Sails.js,
Astro, Remix, and Gatsby. Sandboxed WASM plugins are source-only; MCP is
static and read-only. Autofix is later — see the root README and ROADMAP.

No telemetry. Optional `--target` for a live header check.

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
owlwarden mcp
owlwarden init --agent-rules
owlwarden watch
owlwarden coverage
owlwarden explain <rule-id>
```

Full docs: [github.com/suthat/owlwarden](https://github.com/suthat/owlwarden).
