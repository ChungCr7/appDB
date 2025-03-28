const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userSchema = new Schema(
  {
    id: { type: String }, // ID riêng từ API nếu cần dùng
    full_name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    phone_number: { type: String },
    address: { type: String },
    country: { type: String },
    resetToken: String,
    resetTokenExpiration: Date,
    role: { type: Number, default: 0 },

    cart: {
      items: [
        {
          productId: { type: Schema.Types.ObjectId, ref: 'Product', required: true },
          quantity: { type: Number, default: 1 }
        }
      ]
    },
  },
  { timestamps: true }
);

// Thêm sản phẩm vào giỏ hàng
userSchema.methods.addToCart = function (product, quantity) {
  const cartProductIndex = this.cart.items.findIndex(cp => {
    return cp.productId.toString() === product._id.toString();
  });

  let newQuantity = Number(quantity);
  const updatedCartItems = [...this.cart.items];

  if (cartProductIndex >= 0) {
    newQuantity = this.cart.items[cartProductIndex].quantity + newQuantity;
    updatedCartItems[cartProductIndex].quantity = newQuantity;
  } else {
    updatedCartItems.push({
      productId: product._id,
      quantity: newQuantity
    });
  }

  this.cart = { items: updatedCartItems };
  return this.save();
};

// Xoá sản phẩm khỏi giỏ hàng
userSchema.methods.removeFromCart = function (productId) {
  const updatedCartItems = this.cart.items.filter(item => {
    return item.productId.toString() !== productId.toString();
  });

  this.cart.items = updatedCartItems;
  return this.save();
};

// Xoá toàn bộ giỏ hàng
userSchema.methods.clearCart = function () {
  this.cart = { items: [] };
  return this.save();
};

module.exports = mongoose.model('User', userSchema);
