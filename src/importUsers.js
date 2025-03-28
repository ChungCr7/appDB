const axios = require('axios');
const mongoose = require('mongoose');
const { connect } = require('./database'); // Nếu bạn dùng file connect DB tên khác thì sửa lại
const User = require('./models/user');

async function importUsers() {
  try {
    await connect();

    const response = await axios.get('https://gkiltdd.onrender.com/api/users/');
    const users = response.data;

    for (const u of users) {
      if (!u.email) continue;

      const existingUser = await User.findOne({ email: u.email });
      if (existingUser) {
        console.log(`⏩ User đã tồn tại: ${u.email}`);
        continue;
      }

      const newUser = new User({
        id: u.id || '',
        full_name: u.full_name || `${u.firstname || ''} ${u.lastname || ''}`,
        email: u.email,
        password: u.password,
        phone_number: u.phone_number || '',
        address: u.address || '',
        country: u.country || '',
        role: u.role || 0,
        cart: u.cart || { items: [] }
      });

      await newUser.save();
      console.log(`✅ Đã thêm user: ${newUser.email}`);
    }

    console.log('🎉 Import users thành công!');
    process.exit();
  } catch (err) {
    console.error('❌ Lỗi khi import:', err.message);
    process.exit(1);
  }
}

importUsers();
