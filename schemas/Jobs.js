const mongoose = require('mongoose');


const multiLang = new mongoose.Schema({
    en: {
        type: String,
    },
    ar: {
        type: String,
    }
});

const bidderSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },
    message: {
        type: multiLang,
        required: true
    }

}, { timestamps: true });


const jobSchema = new mongoose.Schema({
    title: {
        type: multiLang,
        required: true
    },
    description: {
        type: multiLang,
        required: true
    },
    budget: {
        type: String,
        required: true
    },
    posterId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user',
        required: true
    },
    hiring: {
        type: multiLang,
        required: true
    },
    country: {
        type: String,
        required: true
    },
    bids: [bidderSchema]
},
    { timestamps: true }
);

module.exports = mongoose.model('job', jobSchema);
