const express = require("express");
const router = express.Router();
var multer = require("multer");
const siteController = require("../app/controllers/SiteController");
const isAuth = require("../app/middlewares/is-auth");

var storage = multer.diskStorage({
  destination: function (req, files, cb) {
    cb(null, "src/public/uploads");
  },
  filename: function (req, files, cb) {
    cb(null, Date.now() + files.originalname);
  },
});

var upload = multer({ storage: storage });

router.get("/tim-kiem", siteController.search);

router.get("/huong-dan-mua-hang", siteController.shoppingGuide);

router.get("/gio-hang", isAuth, siteController.getCart);
router.post("/gio-hang", isAuth, siteController.addCart);
router.post("/cart-delete-item", isAuth, siteController.postCartDeleteProduct);

router.get("/gioi-thieu", siteController.show);

router.get("/tin-tuc", siteController.showNews);
router.get("/tin-tuc/:slug", siteController.showNewsDetail);

router.post("/create-order", isAuth, siteController.postOrder);

router.get("/don-hang", isAuth, siteController.getPurchase);
router.get("/danh-gia/:slug", isAuth, siteController.getEvaluate);
router.post(
  "/danh-gia",
  isAuth,
  upload.array("imgRating", 1),
  siteController.postEvaluate
);

router.get("/tai-khoan", isAuth, siteController.showProfile);
router.post("/tai-khoan", isAuth, siteController.postProfile);

router.get("/", siteController.index);
router.get("/api/search", siteController.apiSearch);
module.exports = router;
