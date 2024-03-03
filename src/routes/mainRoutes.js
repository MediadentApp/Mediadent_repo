const express = require('express');
const authController = require('../controllers/authController');

const router = express.Router();

router.route('/')
  .get(authController.protect, (req, res) => {
    res.send('hello world');
  });

module.exports = router;
