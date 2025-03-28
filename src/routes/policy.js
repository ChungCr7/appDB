const express = require("express");
const router = express.Router();

const policyController = require("../app/controllers/PolicyController");

router.get("/doi-tra", policyController.show1);
router.get("/bao-mat", policyController.show2);
router.get("/van-chuyen", policyController.show3);
router.get("/phuong-thuc-thanh-toan", policyController.show4);

module.exports = router;
