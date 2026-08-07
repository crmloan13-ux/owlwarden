const { createHash, createCipheriv } = require('node:crypto')

// weak-crypto: MD5 over a password.
function hashPassword(password) {
  const passwordHash = createHash('md5').update(password).digest('hex')
  return passwordHash
}

// weak-crypto: a session id anyone can predict from a few samples.
function mintSessionToken() {
  const sessionToken = Math.random().toString(36).slice(2)
  return sessionToken
}

// weak-crypto: ECB leaks structure.
function sealCard(pan, key) {
  const cipher = createCipheriv('aes-256-ecb', key, null)
  return Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()])
}

module.exports = {
  hashPassword,
  mintSessionToken,
  sealCard,
}
