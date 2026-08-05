// No routeRules and no security module, so nothing sets response headers.
// This is the "no configuration anywhere" case the headers rule reports at
// lower confidence, because a CDN in front of the app might be doing it.
export default defineNuxtConfig({
  devtools: { enabled: true },
})
