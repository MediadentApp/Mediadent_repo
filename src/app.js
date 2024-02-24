const express = require('express');
const app = express();
const routes = require('./routes')
const bodyParserMiddleware = require('./middlewares/bodyParserMiddleware');

// Middleware
app.use(bodyParserMiddleware.jsonParser);
app.use(bodyParserMiddleware.urlencodedParser);

// Routes
app.use('/', routes);

module.exports = app
