const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('../models/User'); // Create User model

require('dotenv').config();

// Create JWT Token
const createJWTToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Send Verification Email
const sendVerificationEmail = (email) => {
  const transporter = nodemailer.createTransport({
    // ... (your email service configuration)
    service:"gmail",
    auth:{
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASS,
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: 'Account Verification',
    html: `<p>Click <a href="http://localhost:3000/api/auth/verify/${email}">here</a> to verify your account.</p>`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

// Send Reset Password Email
const sendResetPasswordEmail = (email, resetToken) => {
  const transporter = nodemailer.createTransport({
    // ... (your email service configuration)
    service:"gmail",
    auth:{
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASS,
    }
  });

  const mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: email,
    subject: 'Reset Password',
    html: `<p>Click <a href="http://localhost:3000/api/auth/reset-password/${resetToken}">here</a> to reset your password.</p>`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user in the database
    const newUser = new User({
      email,
      password: hashedPassword,
      isVerified: false,
    });
    await newUser.save();

    // Send verification email
    sendVerificationEmail(newUser.email);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if password matches
    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create and send JWT token
    const token = createJWTToken(user._id);
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Set reset token and expiry in the user document
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000; // Token expires in 1 hour
    await user.save();

    // Send reset password email
    sendResetPasswordEmail(user.email, resetToken);

    res.status(200).json({ message: 'Password reset email sent' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    res.render('reset-password', { token });
  });
  
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    console.log(password);
    // Find the user by reset token and check expiry
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user's password and reset token
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    //res.status(200).json({ message: 'Password reset successful' });
    res.render('password-reset-success'); 
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Handle email verification
router.get('/verify/:email', async (req, res) => {
    try {
      const { email } = req.params;
  
      // Find the user by email and mark as verified
      const user = await User.findOneAndUpdate(
        { email },
        { $set: { isVerified: true } },
        { new: true }
      );
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
  
      res.redirect('http://localhost:3000/api/auth/verified'); // Redirect to a verified page
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // Handle verified page
router.get('/verified', (req, res) => {
    res.send('Your account has been successfully verified.');
  });

module.exports = router;
