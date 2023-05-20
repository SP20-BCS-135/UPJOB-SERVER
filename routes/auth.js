require("dotenv").config();
const express = require("express");
const User = require("../schemas/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const authenticateRequest = require("../middlewares/authRequest");
const router = express.Router();


//Registering a user POST /api/auth/register :No login required
router.post(
  "/register",
  [
    body("email").isEmail(),
    body("password", "must be min 5 chars").isLength({ min: 5 }),
    body("name").exists(),
    body("city").exists(),
    body("type").exists(),
  ],
  async (req, res) => {
    const { name, email, password, city, type, contact, profession, imageUrl, experience } = req.body;

    //express-validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    // Checking for a duplicate email
    User.findOne({ email, type }, (error, docs) => {
      if (error) res.status(500).send({ success: false, error });
      if (docs)
        res.status(500).json({ success: false, error: "Email already exists" });
      //creating a user after validation and encrypting password
      else
        bcrypt.genSalt(10, function (err, salt) {
          bcrypt.hash(password, salt, function (err, hashedPass) {
            User.create({
              name,
              email,
              contact,
              profession,
              experience,
              imageUrl,
              city,
              type,
              password: hashedPass,
            }).then((user) => {
              //data that will be encapsulated in the jwt token
              let data = { user: { id: user._id } };
              //Auth jwt token to send user to make every req with this token
              let authToken = jwt.sign(data, process.env.SECRET_KEY);
              res
                .status(200)
                .send({
                  success: true,
                  authToken,
                  user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    contact: user.contact,
                    city: user.city,
                    imageUrl: user.imageUrl,
                    type: user.type,
                    profession: user.profession,
                    experience: user.experience,
                  },
                });
            });
          });
        });
    });
  }
);

//Logging the user POST /api/auth/login :No login required
router.post(
  "/login",
  [
    body("email").isEmail().exists(),
    body("password", "must be min 5 chars").isLength({ min: 5 }),
    body("type"),
  ],
  (req, res) => {
    const { email, password, type } = req.body;
    //express-validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }
    //checking if the user exists or not based on email
    User.findOne({ email, type }, (error, user) => {
      if (error) res.status(500).send({ success: false, error });
      if (user) {
        bcrypt.compare(password, user.password, function (err, matched) {
          if (matched) {
            //data that will be encapsulated in the jwt token
            let data = { user: { id: user._id } };
            //Auth jwt token to send user to make every req with this token
            let authToken = jwt.sign(data, process.env.SECRET_KEY);
            res.status(200).send({
              success: true,
              authToken,
              user: { id: user._id, name: user.name, city: user.city, type: user.type, profession: user.profession, experience: user.experience, imageUrl: user.imageUrl },
            });
          } else res.status(400).send({ success: false, message: "Invalid Credentials" });
        });
      } else res.status(400).send({ success: false, message: "User not found" });
    });
  }
);

//Getting the user Info GET /api/auth/getuser : login (Tokened) required
router.get("/getuser", authenticateRequest, (req, res) => {
  User.findById(req.user.id, (error, user) => {
    if (error) res.status(500).send({ success: false, error });
    res.status(200).send(user);
  }).select("-password");
});

module.exports = router;



/* 
{"name":"umair",
"email":"omairfic922@gmail.com",
"city":"lesbec",
"type":"employer",
"password":"aliyan"
}


*/