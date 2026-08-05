// server/routes/** is mounted at the root, not under /api. This one is clean;
// it exists so the routing test has a non-/api route to check.
export default defineEventHandler(() => ({ status: 'ok' }))
