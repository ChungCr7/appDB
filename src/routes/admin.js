const express = require("express");
const router = express.Router();
var multer = require("multer");

const adminController = require("../app/controllers/AdminController");
const isAuth = require("../app/middlewares/is-auth");
const isAuthAdmin = require("../app/middlewares/is-auth-admin");

var storage = multer.diskStorage({
  destination: function (req, files, cb) {
    cb(null, "src/public/uploads");
  },
  filename: function (req, files, cb) {
    cb(null, Date.now() + files.originalname);
  },
});

var upload = multer({ storage: storage });

router.get("/create", isAuth, isAuthAdmin, adminController.create);
router.post(
  "/store",
  isAuth,
  isAuthAdmin,
  upload.array("img", 4),
  adminController.store
);
router.get("/:id/edit", isAuth, isAuthAdmin, adminController.edit);
router.post(
  "/handle-form-actions",
  isAuth,
  isAuthAdmin,
  adminController.handleFormActions
);
router.put("/:id", isAuth, isAuthAdmin, adminController.update);
router.patch("/:id/restore", isAuth, isAuthAdmin, adminController.restore);
router.delete("/:id", isAuth, isAuthAdmin, adminController.destroy);
router.delete("/:id/force", isAuth, isAuthAdmin, adminController.forceDestroy);
router.get(
  "/stored/products",
  isAuth,
  isAuthAdmin,
  adminController.storedProducts
);
router.get(
  "/trash/products",
  isAuth,
  isAuthAdmin,
  adminController.trashProducts
);
router.put("/order/:id", isAuth, isAuthAdmin, adminController.updateStatusCart);
router.get("/order", isAuth, isAuthAdmin, adminController.getOrders);
router.get("/news/create", isAuth, isAuthAdmin, adminController.createNews);
router.get("/news", isAuth, isAuthAdmin, adminController.getNews);
router.post(
  "/news",
  isAuth,
  isAuthAdmin,
  upload.array("imgStory", 1),
  adminController.postNews
);
router.get("/news/:id/edit", isAuth, isAuthAdmin, adminController.editNews);
router.put("/news/:id", isAuth, isAuthAdmin, adminController.updateNews);
router.delete("/news/:id", isAuth, isAuthAdmin, adminController.destroyNews);
router.get("/trash/news", isAuth, isAuthAdmin, adminController.trashNews);
router.patch(
  "/news/:id/restore",
  isAuth,
  isAuthAdmin,
  adminController.restoreNews
);
router.delete(
  "/news/:id/force",
  isAuth,
  isAuthAdmin,
  adminController.forceDestroyNews
);
router.post("/feedback/:id", isAuth, isAuthAdmin, adminController.postFeedback);

module.exports = router;
