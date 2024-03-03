const express = require('express');
const middlewares = require('./middlewares');
const routes = require('./routes');
const globalErrorHandler = require('./controllers/errorController');
const AppError = require('./utils/appError');

const app = express();

// Middleware
app.use(middlewares);

// Routes
app.use('/', routes);
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
