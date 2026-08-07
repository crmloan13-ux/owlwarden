const { createHash, randomUUID } = require('node:crypto')

function mintSessionToken() {
  return randomUUID()
}

function cacheKey(body) {
  return createHash('md5').update(body).digest('hex')
}

function pickShard(count) {
  return Math.floor(Math.random() * count)
}

module.exports = { mintSessionToken, cacheKey, pickShard }
