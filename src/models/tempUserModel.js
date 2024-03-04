const mongoose = require('mongoose');
const validator = require('validator');
const config = require('../config/config');

const tempUserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'] // From the Validator Module
  },
  otp: Number,
  otpSendAt: Date,
  otpExpiration: Date,
  emailVerified: Boolean
});

tempUserSchema.methods.checkOtpTime = function () {
  const { otpSendAt } = this;
  const sendOptAfterMilliseconds = config.otp.sendOtpAfter * 60 * 1000;
  const otpSendAtWithDelay = new Date(otpSendAt.getTime() + sendOptAfterMilliseconds);
  return !(otpSendAtWithDelay < new Date());
};

tempUserSchema.methods.checkOtp = function (otp) {
  return this.otp === otp;
};

tempUserSchema.methods.checkOtpExpiration = function () {
  return this.otpExpiration < new Date();
};

const TempUser = mongoose.model('TempUser', tempUserSchema);

module.exports = TempUser;
