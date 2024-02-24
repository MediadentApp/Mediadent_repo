const express = require('express');
const router = express.Router()

const mainRoutes = require('./mainRoutes')

router.use('/', mainRoutes)

module.exports = router