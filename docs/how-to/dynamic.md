# Probe a running app

Optional. Most scans stay static. Use this when you have a local or staging
server and want runtime confirmation — especially for
`security-headers-missing`, where a CDN can hide the truth from source analysis.

```bash
# Start your app, then:
npx owlwarden scan --target http://127.0.0.1:3000/
```

Prefer an IP literal for local probes. Hostnames you do not control leave room
for DNS rebinding — see [SECURITY.md](../../SECURITY.md).

## What happens

1. Static analysis runs as usual.
2. owlwarden sends a passive `HEAD` (falling back to `GET`) to `--target`.
3. Correlation compares the two. For `security-headers-missing` only:
   - both see the same headers missing → confidence becomes `confirmed`
   - the live response already has the headers → the static gap is cleared
   - only the live side fires → a `likely` finding at the endpoint (no source
     location to attach)
   - disagreement that is not a clear/confirm case → both findings stay

Other rules stay static-only until each has its own honest runtime signal.

## Scope

Deny-by-default. With no `--scope`, the allowlist is exactly the origin of
`--target`. Redirects off that allowlist are refused, not followed.

```bash
npx owlwarden scan \
  --target http://127.0.0.1:3000/api/health \
  --scope http://127.0.0.1:3000/api
```

`--target` and `--scope` come from the command line only. A file in the scanned
tree cannot point the scanner at a host — that is how a hostile PR would turn
CI into an SSRF client.

## CI

Point at a staging URL you control, still from the workflow command line:

```bash
npx owlwarden scan --ci --fail-on medium --min-confidence likely \
  --target "$STAGING_URL"
```

Do not put the URL in project config. Under `--ci`, mute switches from the tree
still stay off unless you explicitly allow them — see [ci.md](ci.md).

## `--allow-active`

State-changing methods (POST/PUT/PATCH/DELETE) stay refused unless you pass
both `--target` and `--allow-active`. Rate limit (`ACTIVE_MIN_INTERVAL`) and a
request audit log (method/URL/status on stderr) always apply.

First-party rule: **`csrf-cross-origin-post`** ([ADR 0019](../adr/0019-first-party-active-detector.md)).
It sends one canary `POST` to the exact `--target` URL with
`Origin: https://owlwarden-untrusted.invalid` and body `owlwarden_probe=1`.
A 2xx response becomes a `Likely` finding. Point this only at staging you
control — the canary may still create a resource if the route is a create
endpoint.

MCP never sets `--allow-active`.

## What this is not

- Not a crawler. One URL, on purpose.
- Not an exploit toolkit. Active methods are gated; the canary body is fixed.
- Not for `watch`. Re-probing on every save is refused.
- Not “this framework’s real server.” The correlation tests use a dumb HTTP
  probe next to each framework’s static fixture; production still needs your
  app (or staging) listening at `--target`.

See [ADR 0014](../adr/0014-passive-dynamic-and-correlation.md) and
[SECURITY.md](../../SECURITY.md).
