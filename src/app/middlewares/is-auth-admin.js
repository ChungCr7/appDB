module.exports = (req, res, next) =>{
    if(req.session.user.role === 2){
        return res.redirect('/')
    }
    next()
}