const morgan = require('morgan');
const express = require('express');

const middleware = express();

if (process.env.NODE_ENV === 'development') {
  middleware.use(morgan('dev'));
}

middleware.use(express.json());
// middleware.use(express.urlencoded({ extended: true }));

middleware.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

module.exports = middleware;
