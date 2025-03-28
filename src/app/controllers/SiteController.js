const Product = require("../models/Product");
const Order = require("../models/Order");
const Story = require("../models/Story");
const Rating = require("../models/Rating");
const User = require("../models/User");
const path = require("path");

const { mutipleMongooseToObject } = require("../../util/mongoose");
const { mongooseToObjiect } = require("../../util/mongoose");

class SiteController {
  apiSearch(req, res, next) {
    const keyword = req.query.keyword;
    if (!keyword) {
      return res
        .status(400)
        .json({ message: "Vui lòng nhập từ khóa tìm kiếm" });
    }

    Product.find({
      name: { $regex: keyword, $options: "i" },
    })
      .then((productsSearch) => {
        res.json({
          success: true,
          data: productsSearch,
        });
      })
      .catch(next);
  }

  search(req, res, next) {
    const keyword = req.query.keyword;
    Product.find({
      name: { $regex: keyword, $options: "i" },
    })
      .then((productsSearch) => {
        res.render("search", {
          productsSearch: mutipleMongooseToObject(productsSearch),
        });
      })
      .catch(next);
  }

  //[GET] /huong-dan-mua-hang
  shoppingGuide(req, res, next) {
    res.render("mua-hang");
  }
  //[GET] /gioi-thieu
  show(req, res, next) {
    res.render("gioi-thieu");
  }

  //[GET] /tin-tuc
  showNews(req, res, next) {
    Story.find({}).then((stories) => {
      res.render("news", {
        stories: mutipleMongooseToObject(stories),
      });
    });
  }

  //[GET] /tin-tuc/:slug
  showNewsDetail(req, res, next) {
    Story.findOne({ slug: req.params.slug })
      .then((story) => {
        console.log(story);
        res.render("news/show", {
          story: mongooseToObjiect(story),
        });
      })
      .catch(next);
  }

  //[GET] /gio-hang
  getCart(req, res, next) {
    req.user.populate("cart.items.productId").then((user) => {
      console.log(user);

      // Lọc bỏ sản phẩm bị null
      user.cart.items = user.cart.items.filter((p) => p.productId);

      // Tính tổng giá trị giỏ hàng
      let total = user.cart.items.reduce(
        (sum, p) => sum + p.quantity * p.productId.price,
        0
      );

      res.render("cart", {
        products: mutipleMongooseToObject(user.cart.items),
        total: total,
      });
    });
  }

  //[POST] /gio-hang
  addCart(req, res, next) {
    const prodId = req.body.productId;
    const quantity = req.body.quantity;
    Product.findById(prodId)
      .then((product) => {
        return req.user.addToCart(product, quantity);
      })
      .then((result) => {
        req.session.user = req.user;
        return req.session.save(() => {
          res.redirect("/gio-hang");
        });
      });
  }

  //[POST] /cart-delete-item
  postCartDeleteProduct = (req, res, next) => {
    const prodId = req.body.productId;
    req.user.removeFromCart(prodId).then(() => {
      req.session.user = req.user;
      return req.session.save(() => {
        res.redirect("/gio-hang");
      });
    });
  };

  //[POST] /create-order
  postOrder = (req, res, next) => {
    req.user
      .populate("cart.items.productId")
      .then((user) => {
        const products = user.cart.items.map((i) => {
          return { quantity: i.quantity, product: { ...i.productId._doc } };
        });
        console.log(products);
        let total = 0;
        products.forEach((p) => {
          total += p.quantity * p.product.price;
        });
        const order = new Order({
          user: {
            email: req.user.email,
            firstname: req.user.firstname,
            lastname: req.user.lastname,
            userId: req.user,
          },
          status: "Chờ xác nhận",
          name: req.body.name,
          phone: req.body.phone,
          address: req.body.address,
          products: products,
          tong_tien: total,
        });
        return order.save();
      })
      .then((result) => {
        return req.user.clearCart();
      })
      .then(() => {
        req.session.user = req.user;
        return req.session.save(() => {
          res.redirect("/don-hang");
        });
      });
  };

  chatRealTime = (req, res, next) => {
    res.render("chat");
  };

  //[GET] /don-hang
  getPurchase(req, res, next) {
    Order.find({ "user.userId": req.user._id }).then((orders) => {
      res.render("purchase", {
        orders: mutipleMongooseToObject(orders),
      });
    });
  }

  //[GET] /danh-gia/:slug
  getEvaluate(req, res, next) {
    Product.findOne({ slug: req.params.slug })
      .then((product) => {
        res.render("evaluate", {
          product: mongooseToObjiect(product),
        });
      })
      .catch(next);
  }

  //[POST] /danh-gia
  postEvaluate(req, res, next) {
    req.body.imgRating = req.files
      .map((file) => path.join("uploads", file.filename).replace(/\\/g, "/"))
      .join(",");

    console.log(req.body);
    const rating = new Rating({
      rating: req.body.rating,
      comment: req.body.comment,
      productId: req.body.productId,
      user: {
        email: req.user.email,
        firstname: req.user.firstname,
        lastname: req.user.lastname,
        userId: req.user,
      },
      imgRating: req.body.imgRating,
    });

    rating
      .save()
      .then(() => {
        console.log([rating._id]);
        Product.updateOne(
          { _id: req.body.productId },
          { $push: { danh_gia: [{ ratingId: rating._id }] } }
        ).then(() => res.redirect("/don-hang"));
      })
      .catch(next);
  }

  //[GET] /tai-khoan
  showProfile(req, res, next) {
    User.findOne({ email: req.user.email }).then((user) => {
      res.render("profile", {
        user: mongooseToObjiect(user),
      });
    });
  }

  // [POST] /tai-khoan// [POST] /tai-khoan
  postProfile(req, res, next) {
    User.updateOne(
      { email: req.user.email },
      {
        full_name: req.body.full_name,
        phone_number: req.body.phone_number,
        address: req.body.address,
      }
    )
      .then(() => res.redirect("/tai-khoan"))
      .catch(next);
  }

  

  //[GET] /
  index(req, res, next) {
    res.render("home");
  }
}

module.exports = new SiteController();
