const ALLOWED_IMPORT_HOSTS = new Set(['files.partner.com'])

export function assertAllowedUrl(input: unknown): URL {
  const url = new URL(String(input))
  if (url.protocol !== 'https:' || !ALLOWED_IMPORT_HOSTS.has(url.hostname)) {
    throw new Error('source not allowed')
  }
  return url
}
