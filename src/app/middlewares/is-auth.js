module.exports = (req, res, next) =>{
    if(!req.session.isLoggedIn){
        return res.redirect('/dang-nhap')
    }
    next()
}