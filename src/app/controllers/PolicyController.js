class PolicyController {
    //[GET] /chinh-sach/doi-tra
    show1(req, res) {
        res.render('policy/doi-tra')
    }

    //[GET] /chinh-sach/bao-mat
    show2(req, res) {
        res.render('policy/bao-mat')
    }

    //[GET] /chinh-sach/van-chuyen
    show3(req, res) {
        res.render('policy/van-chuyen')
    }
    
    //[GET] /chinh-sach/phuong-thuc-thanh-toan
    show4(req, res) {
        res.render('policy/phuong-thuc-thanh-toan')
    }
}
module.exports = new PolicyController;
