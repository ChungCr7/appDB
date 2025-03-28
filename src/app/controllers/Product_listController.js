const Product = require("../models/Product");
const { mutipleMongooseToObject } = require("../../util/mongoose");

class Product_listController {
  show_raucu(req, res, next) {
    Product.find({ product_type: "rau củ" })
      .then((products) => {
        res.render("product_list/rau-cu", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_sinhto(req, res, next) {
    Product.find({ product_type: "sinh tố" })
      .then((products) => {
        res.render("product_list/sinh-to", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_thucphamtuoisong(req, res, next) {
    Product.find({ product_type: "thực phẩm tươi sống" })
      .then((products) => {
        res.render("product_list/thuc-pham-tuoi-song", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_hoaqua(req, res, next) {
    Product.find({ product_type: "hoa quả" })
      .then((products) => {
        res.render("product_list/hoa-qua", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_cacloaihat(req, res, next) {
    Product.find({ product_type: "các loại hạt" })
      .then((products) => {
        res.render("product_list/cac-loai-hat", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_giavi(req, res, next) {
    Product.find({ product_type: "gia vị" })
      .then((products) => {
        res.render("product_list/gia-vi", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_ngucoc(req, res, next) {
    Product.find({ product_type: "ngũ cốc" })
      .then((products) => {
        res.render("product_list/ngu-coc", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  show_sieuthucpham(req, res, next) {
    Product.find({ product_type: "siêu thực phẩm" })
      .then((products) => {
        res.render("product_list/sieu-thuc-pham", {
          products: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for rau cu
  api_show_raucu(req, res, next) {
    Product.find({ product_type: "rau củ" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for sinh to
  api_show_sinhto(req, res, next) {
    Product.find({ product_type: "sinh tố" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for thuc pham tuoi song
  api_show_thucphamtuoisong(req, res, next) {
    Product.find({ product_type: "thực phẩm tươi sống" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for hoa qua
  api_show_hoaqua(req, res, next) {
    Product.find({ product_type: "hoa quả" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for cac loai hat
  api_show_cacloaihat(req, res, next) {
    Product.find({ product_type: "các loại hạt" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for gia vi
  api_show_giavi(req, res, next) {
    Product.find({ product_type: "gia vị" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for ngu coc
  api_show_ngucoc(req, res, next) {
    Product.find({ product_type: "ngũ cốc" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }

  // API for sieu thuc pham
  api_show_sieuthucpham(req, res, next) {
    Product.find({ product_type: "siêu thực phẩm" })
      .then((products) => {
        res.json({
          success: true,
          data: mutipleMongooseToObject(products),
        });
      })
      .catch(next);
  }
}

module.exports = new Product_listController();
