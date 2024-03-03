const express = require('express');
const mainRoutes = require('./mainRoutes');
const userRoutes = require('./userRoutes');

const router = express.Router();

router.use('/', mainRoutes);
router.use('/api/v1/users', userRoutes);

module.exports = router;
