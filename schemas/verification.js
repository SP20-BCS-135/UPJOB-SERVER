const mongoose = require('mongoose');

const verifySchema = new mongoose.Schema({
    email: {
        type: String,
        required: true
    },
    pin: {
        type: String,
        required: true
    }

}, { timestamps: true });


module.exports = mongoose.model('verify', verifySchema);
