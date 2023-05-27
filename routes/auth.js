require("dotenv").config();
const express = require("express");
const User = require("../schemas/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const authenticateRequest = require("../middlewares/authRequest");
const sendMail = require("../middlewares/mailsender");
const verify = require("../schemas/verification");
const router = express.Router();


router.post('/sendmail', sendMail, async (req, res) => {

  const { email, pincode, expiry } = req.body; 

  verify.create({ email, pin: pincode })
    .then(() => {
      res.status(200).json({ success: true, data: { pincode: pincode.toString(), expiry } });
    })
    .catch(err => {
      console.error(err);
      res.status(500).json({ success: false, error: 'Server error' });
    })
});

router.post(
  "/changepassword",
  [
    body("email").exists().isEmail(),
    body("password", "must be min 5 chars").isLength({ min: 5 }),
    body("type").exists(),
    body("pin").exists(),
  ],
  async (req, res) => {
    const { password, email, pin, type } = req.body;

    //express-validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {

      const findmatching = await User.findOne({ email, type });
      if (!findmatching) return res.status(400).json({ success: false, error: 'No matching email found' });


      const isVerified = await verify.findOne({ email, pin });
      if (!isVerified) return res.status(400).json({ success: false, error: 'Invalid pincode' });


      //removing the pincode from the verification collection
      const removeRecord = await verify.deleteOne({ email, pin });
      if (!removeRecord) return res.status(500).json({ success: false, error: 'Server error' });


      // Checking for a duplicate email
      const changePass = await User.findOne({ email });
      if (!changePass) return res.status(500).json({ success: false, error: 'Server error' });


      bcrypt.genSalt(10, function (err, salt) {
        bcrypt.hash(password, salt, async function (err, hashedPass) {

          if (err) return res.status(500).json({ success: false, error: 'Server error' });

          const filter = { email, type };
          const update = { password: hashedPass };

          const doc = await User.findOneAndUpdate(filter, update, { new: true });
          if (!doc) return res.status(500).json({ success: false, error: 'Server error' });
          res.status(200).json({ success: true, data: doc });

        })

      });

    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, error: 'Server error' });
    }

  })

router.post(
  "/updateuser",
  [
    body("name").exists(),
    body("contact").exists(),
    body("city").exists(),
    body("profession").exists(),
    body("experience").exists(),
    body("imageCollectionUrl").exists(),
    body("id").exists(),
  ],
  async (req, res) => {
    const {
      name,
      contact,
      city,
      profession,
      experience,
      imageCollectionUrl,
      id } = req.body;

    //express-validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    const filter = { _id: id };
    const update = {
      name,
      contact,
      city,
      profession,
      experience,
      imageCollectionUrl,
    };

    const user = await User.findOneAndUpdate(filter, update, { new: true });
    if (!user) return res.status(500).json({ success: false, error: 'Server error' });

    const data = {
      id: user._id,
      name: user.name,
      email: user.email,
      contact: user.contact,
      city: user.city,
      imageUrl: user.imageUrl,
      type: user.type,
      profession: user.profession,
      experience: user.experience,
      imageCollectionUrl: user.imageCollectionUrl,
    }


    res.status(200).json({ success: true, data });

  })



//Registering a user POST /api/auth/register :No login required
router.post(
  "/register",
  [
    body("email").isEmail(),
    body("password", "must be min 5 chars").isLength({ min: 5 }),
    body("name").exists(),
    body("city").exists(),
    body("type").exists(),
    body("pin").exists(),
    body("contact").exists(),
  ],
  async (req, res) => {
    const { name, email, password, city, type, contact, profession, imageUrl, experience, pin, imageCollectionUrl } = req.body;

    //express-validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }


    const isVerified = await verify.findOne({ email, pin });
    if (!isVerified) {
      return res.status(400).json({ success: false, error: 'Invalid pincode' });
    }

    //removing the pincode from the verification collection
    const removeRecord = await verify.deleteOne({ email, pin });
    if (!removeRecord) {
      return res.status(500).json({ success: false, error: 'Server error' });
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
              imageCollectionUrl,
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
                    imageCollectionUrl: user.imageCollectionUrl,
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
              user: {
                id: user._id,
                name: user.name,
                email: user.email,
                city: user.city,
                type: user.type,
                profession: user.profession,
                experience: user.experience,
                imageUrl: user.imageUrl,
                contact: user.contact,
                imageCollectionUrl: user.imageCollectionUrl,

              },
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

