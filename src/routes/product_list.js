const express = require("express");
const router = express.Router();

const product_listController = require("../app/controllers/Product_listController");

router.get("/rau-cu", product_listController.show_raucu);
router.get("/sinh-to", product_listController.show_sinhto);
router.get(
  "/thuc-pham-tuoi-song",
  product_listController.show_thucphamtuoisong
);
router.get("/hoa-qua", product_listController.show_hoaqua);
router.get("/cac-loai-hat", product_listController.show_cacloaihat);
router.get("/gia-vi", product_listController.show_giavi);
router.get("/ngu-coc", product_listController.show_ngucoc);
router.get("/sieu-thuc-pham", product_listController.show_sieuthucpham);
//API
router.get("/api/rau-cu", product_listController.api_show_raucu);
router.get("/api/sinh-to", product_listController.api_show_sinhto);
router.get(
  "/api/thuc-pham-tuoi-song",
  product_listController.api_show_thucphamtuoisong
);
router.get("/api/hoa-qua", product_listController.api_show_hoaqua);
router.get("/api/cac-loai-hat", product_listController.api_show_cacloaihat);
router.get("/api/gia-vi", product_listController.api_show_giavi);
router.get("/api/ngu-coc", product_listController.api_show_ngucoc);
router.get("/api/sieu-thuc-pham", product_listController.api_show_sieuthucpham);

module.exports = router;
