const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const { generateDateAfterTwoMinutes, generatePinCode } = require('../utils/helpers')


const validateRequestBody = [
    body('email').exists().isEmail().withMessage('Invalid email address'),
    (req, res, next) => {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, error: errors.array() });
        }

        const { email } = req.body;
        const pincode = generatePinCode();
        const expiry = generateDateAfterTwoMinutes();


        // Create a Nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail', // e.g., 'Gmail'
            auth: {
                user: 'authenticationappp@gmail.com',
                pass: 'xfutqblbqpxyucnn'
            }
        });

        // Set up the email data
        const mailOptions = {
            from: 'authenticationappp@gmail.com',
            to: email,
            subject: "PINCODE",
            text: `Your Pincode is ${pincode} please verify it.\nNote: This pincode will expire in 2 minutes`
        };

        // Send the email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                res.status(500).json({ success: false, error: 'Server error' });
            } else {
                console.log('Email sent:', info);
                req.body.pincode = pincode;
                req.body.expiry = expiry;
                next();

            }
        });

    }
];


module.exports = validateRequestBody;