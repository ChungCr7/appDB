const Product = require('../models/Product');
const Rating = require('../models/Rating');

const { mongooseToObjiect } = require('../../util/mongoose')
class ProductController {
    // [GET] /san-pham/:slug
    show(req, res, next) {
        Product.findOne({ slug: req.params.slug })
            .populate('danh_gia.ratingId')
            .then((product) => {
                if (product.danh_gia.length) {
                    const product_danhgia = product.danh_gia.map(i => {
                        return i.ratingId.rating
                    })
                    let total = 0
                    product_danhgia.forEach(p => {
                        total += p
                    })
                    const totalRating = Math.round(total / (product_danhgia.length) * 10) / 10
                    res.render('products/show', {
                        product: mongooseToObjiect(product),
                        totalRating: totalRating
                    });
                } else {
                    res.render('products/show', {
                        product: mongooseToObjiect(product),
                    });
                }
            })
            .catch(next);
    }
}

module.exports = new ProductController;
