const mongoose = require('mongoose')

const Schema = mongoose.Schema
ratingSchema = mongoose.Schema(
    {
        rating: { type: Number },
        user: {
            email: { type: String },
            firstname: { type: String },
            lastname: { type: String },
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
        },
        productId: { type: Number, ref: 'Product', required: true },
        comment: { type: String },
        imgRating: { type: String },
        feedback: { type: String },
        createdAt: { type: Date, default: Date.now },
    }
)

module.exports = mongoose.model('Rating', ratingSchema);