const express = require('express');
const bodyParser = require('body-parser');

const jsonParser = express.json();
const urlencodedParser = express.urlencoded({ extended: true });

module.exports = {
  jsonParser,
  urlencodedParser
};
