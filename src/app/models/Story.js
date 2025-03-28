const mongoose = require('mongoose')
const mongooseDelete = require('mongoose-delete')

const Schema = mongoose.Schema

const storySchema = new Schema({
    title: { type: String },
    content: { type: String },
    imgStory: { type: String },
    createdAt: { type: Date, default: Date.now },
    slug: { type: String, slug: 'title', unique: true },
    user: {
        email: { type: String },
        firstname: { type: String },
        lastname: { type: String },
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
    },
    deleteAt: {},
})

storySchema.plugin(mongooseDelete, {
    deletedAt: true,
    overrideMethods: 'all',
});

// Custom query helpers
storySchema.query.sortable = function (req) {
    if (req.query.hasOwnProperty('_sort')) {
        const isValidtype = ['asc', 'desc'].includes(req.query.type)
        return this.sort({
            [req.query.column]: isValidtype ? req.query.type : 'desc'
        })
    }
    return this
}

module.exports = mongoose.model('Story', storySchema);