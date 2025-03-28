module.exports = {
    mutipleMongooseToObject: function (mongooses) {
        return mongooses.map(mongoose => mongoose.toObject());
    },
    mongooseToObjiect: function (mongoose){
        return mongoose ? mongoose.toObject() : mongoose;
    }
}