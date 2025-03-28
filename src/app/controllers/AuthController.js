require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const { validationResult } = require('express-validator/check');
const axios = require('axios');

const User = require('../models/User');

const transporter = nodemailer.createTransport(sendgridTransport({
    auth: {
        api_key: process.env.SENDGRID_API_KEY
    }
}));

class AuthController {

    getLogin(req, res, next) {
        res.render('auth/login', {
            errorMessage: req.flash('error'),
            oldInput: {
                email: '',
                password: '',
                confirmPassword: ''
            },
            validationErrors: []
        });
    }

    postLogin(req, res, next) {
        const email = req.body.email;
        const password = req.body.password;
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(422).render('auth/login', {
                errorMessage: errors.array()[0].msg,
                oldInput: { email, password },
                validationErrors: errors.array()
            });
        }

        User.findOne({ email: email })
            .then(user => {
                if (!user) {
                    // Nếu không có trong MongoDB → check API render
                    return axios.get('https://gkiltdd.onrender.com/api/users/')
                        .then(response => {
                            const users = response.data;
                            const apiUser = users.find(u => u.email === email && u.password === password);

                            if (!apiUser) {
                                return res.status(422).render('auth/login', {
                                    errorMessage: 'Email hoặc mật khẩu không hợp lệ!',
                                    oldInput: { email, password },
                                    validationErrors: []
                                });
                            }

                            req.session.isLoggedIn = true;
                            req.session.user = apiUser;
                            req.session.role = apiUser.role || 2;

                            return req.session.save(() => {
                                res.redirect('/');
                            });
                        })
                        .catch(error => {
                            console.log(error);
                            res.redirect('/dang-nhap');
                        });
                }

                // Nếu có user trong MongoDB → dùng bcrypt để xác thực
                bcrypt.compare(password, user.password)
                    .then(doMatch => {
                        if (doMatch) {
                            req.session.isLoggedIn = true;
                            req.session.user = user;
                            req.session.role = user.role;

                            return req.session.save(() => {
                                res.redirect('/');
                            });
                        }

                        return res.status(422).render('auth/login', {
                            errorMessage: 'Email hoặc mật khẩu không hợp lệ!',
                            oldInput: { email, password },
                            validationErrors: []
                        });
                    })
                    .catch(() => {
                        res.redirect('/dang-nhap');
                    });
            })
            .catch(next);
    }

    postLogout(req, res, next) {
        req.session.destroy(() => {
            res.redirect('/');
        });
    }

    getSignup(req, res, next) {
        res.render('auth/signup', {
            errorMessage: req.flash('error'),
            oldInput: {
                full_name: '',
                email: '',
                password: '',
                confirmPassword: ''
            },
            validationErrors: []
        });
    }

    postSignup(req, res, next) {
        const full_name = req.body.full_name;
        const email = req.body.email;
        const password = req.body.password;
        const phone_number = req.body.phone_number || '';
        const address = req.body.address || '';
        const country = req.body.country || 'Vietnam';

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).render('auth/signup', {
                errorMessage: errors.array()[0].msg,
                oldInput: {
                    full_name,
                    email,
                    password,
                    confirmPassword: req.body.confirmPassword,
                    phone_number,
                    address,
                    country
                },
                validationErrors: errors.array()
            });
        }

        bcrypt.hash(password, 12)
            .then(hashedPassword => {
                const user = new User({
                    full_name,
                    email,
                    password: hashedPassword,
                    role: 2, // 👈 Thêm role mặc định
                    cart: { items: [] }
                });

                return user.save().then(() => {
                    // Gửi user lên API Render (có role luôn)
                    return axios.post('https://gkiltdd.onrender.com/api/users/create', {
                        id: Date.now().toString(),
                        full_name,
                        email,
                        password,
                        phone_number,
                        address,
                        country,
                        role: 2  // 👈 Gửi role lên API
                    });
                });
            })
            .then(() => {
                res.redirect('/dang-nhap');
                return transporter.sendMail({
                    to: email,
                    from: 'mvt16102001@gmail.com',
                    subject: 'Đăng ký thành công',
                    html: '<h1>Bạn đã đăng ký thành công!</h1>'
                });
            })
            .catch(error => {
                console.error('❌ Lỗi trong quá trình đăng ký:', error.message);

                if (error.response) {
                    console.error('🔍 Lỗi chi tiết từ API Render:', error.response.data);
                    console.error('📦 Status code:', error.response.status);
                } else if (error.request) {
                    console.error('⚠️ Không nhận được phản hồi từ API Render');
                    console.error(error.request);
                } else {
                    console.error('⚙️ Lỗi cấu hình:', error.message);
                }

                return res.status(500).render('auth/signup', {
                    errorMessage: 'Lỗi máy chủ. Vui lòng thử lại.',
                    oldInput: {
                        full_name,
                        email,
                        password,
                        confirmPassword: req.body.confirmPassword,
                        phone_number,
                        address,
                        country
                    },
                    validationErrors: []
                });
            });
    }

    getReset(req, res, next) {
        res.render('auth/reset', {
            errorMessage: req.flash('error')
        });
    }

    postReset(req, res, next) {
        crypto.randomBytes(32, (err, buffer) => {
            if (err) {
                console.log(err);
                return res.redirect('/dat-lai-mat-khau');
            }
            const token = buffer.toString('hex');
            User.findOne({ email: req.body.email })
                .then(user => {
                    if (!user) {
                        req.flash('error', 'Không tìm thấy tài khoản');
                        return res.redirect('/dat-lai-mat-khau');
                    }
                    user.resetToken = token;
                    user.resetTokenExpiration = Date.now() + 360000;
                    return user.save();
                })
                .then(result => {
                    res.redirect('/');
                    transporter.sendMail({
                        to: req.body.email,
                        from: 'mvt16102001@gmail.com',
                        subject: 'Đặt lại mật khẩu',
                        html: `
                            <p>Chúng tôi đã nhận được yêu cầu đặt lại mật khẩu của bạn</p>
                            <p>Click vào <a href="http://localhost:3000/dat-lai-mat-khau/${token}">Đây</a> để đặt mật khẩu mới</p>
                        `
                    });
                })
                .catch(err => {
                    console.log(err);
                });
        });
    }

    getNewPassword(req, res, next) {
        const token = req.params.token;
        User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
            .then(user => {
                res.render('auth/new-password', {
                    errorMessage: req.flash('error'),
                    userId: user._id.toString(),
                    passwordToken: token
                });
            })
            .catch(err => console.log(err));
    }

    postNewPassword(req, res, next) {
        const newPassword = req.body.password;
        const userId = req.body.userId;
        const passwordToken = req.body.passwordToken;
        let resetUser;

        User.findOne({
            resetToken: passwordToken,
            resetTokenExpiration: { $gt: Date.now() },
            _id: userId
        })
            .then(user => {
                resetUser = user;
                return bcrypt.hash(newPassword, 12);
            })
            .then(hashedPassword => {
                resetUser.password = hashedPassword;
                resetUser.resetToken = undefined;
                resetUser.resetTokenExpiration = undefined;
                return resetUser.save();
            })
            .then(result => {
                res.redirect('/dang-nhap');
            })
            .catch(next);
    }
};

module.exports = new AuthController();
