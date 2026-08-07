// Bootstrap middleware stack. No helmet — security-headers-missing points here.
module.exports.http = {
  middleware: {
    order: ['cookieParser', 'session', 'bodyParser', 'compress', 'router'],
  },
}
