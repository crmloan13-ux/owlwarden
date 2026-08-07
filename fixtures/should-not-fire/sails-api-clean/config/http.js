// helmet in the middleware order closes security-headers-missing.
const helmet = require('helmet')

module.exports.http = {
  middleware: {
    helmet: helmet(),
    order: [
      'helmet',
      'cookieParser',
      'session',
      'bodyParser',
      'compress',
      'router',
    ],
  },
}
