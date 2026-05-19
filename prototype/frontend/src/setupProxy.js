const { createProxyMiddleware } = require('http-proxy-middleware')

module.exports = function (app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'http://127.0.0.1:5000',
      changeOrigin: true,
      timeout: 600000,       // 10 minutes socket timeout
      proxyTimeout: 600000,  // 10 minutes proxy timeout
    })
  )
}
