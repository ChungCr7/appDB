const mongoose = require("mongoose");

async function connect() {
  try {
    await mongoose.connect(
      "mongodb+srv://baochungas3s:RhyPvXQXQpFoSKPJ@cluster0.aqlfw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log("Kết nối mongodb thành công");
  } catch (error) {
    console.log("Kết nối mongodb ko thành công");
  }
}

module.exports = { connect };
