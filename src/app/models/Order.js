const mongoose = require('mongoose')

const Schema = mongoose.Schema

const orderSchema = new Schema(
  {
    products: [
      {
        product: { type: Object, required: true },
        quantity: { type: Number, required: true }
      }
    ],
    user: {
      email: { type: String, required: true },
      firstname: { type: String, required: true },
      lastname: { type: String, required: true },
      userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    },
    tong_tien: { type: Number },
    status: { type: String, required: true },
    name: { type: String },
    phone: { type: String },
    address: { type: String },
    createdAt: { type: Date, default: Date.now },
  }
)

// Custom query helpers
orderSchema.query.sortable = function (req) {
  if (req.query.hasOwnProperty('_sort')) {
    const isValidtype = ['asc', 'desc'].includes(req.query.type)
    return this.sort({
      [req.query.column]: isValidtype ? req.query.type : 'desc'
    })
  }
  return this
}

module.exports = mongoose.model('Order', orderSchema);