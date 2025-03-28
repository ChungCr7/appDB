const adminRouter = require('./admin')
const productsRouter = require('./products')
const siteRouter = require('./site')
const policyRouter = require('./policy')
const authRouter = require('./auth')
const product_listRouter = require('./product_list')

function route(app) {
    app.use('/admin', adminRouter)
    app.use('/san-pham', productsRouter)
    app.use('/danh-muc-san-pham', product_listRouter)
    app.use('/chinh-sach', policyRouter)
    app.use('/', authRouter)
    app.use('/', siteRouter)
}

module.exports = route;