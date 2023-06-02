const mongoose = require("mongoose");


const UserSchema = mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  city: {
    type: String,
    required: true,
  },
  country: {
    type: String,
    required: true,
  },
  type: {
    type: String,
    required: true,
  },
  profession: {
    type: String,
  },
  experience: {
    type: String,
  },
  contact: {
    type: String,
    required: true,
  },
  imageUrl: {
    type: String,
  },
  imageCollectionUrl: {
    type: [String],
  }
  ,
  createdAt: {
    type: Date,
    default: Date.now,
  },
}, { timestamps: true });

UserSchema.index({ email: 1, type: 1 }, { unique: true, partialFilterExpression: { email: { $exists: true }, type: { $exists: true } } });


module.exports = mongoose.model("user", UserSchema);
