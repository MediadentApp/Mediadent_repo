const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const TempUser = require('../models/tempUserModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');
const util = require('../utils/util');
const config = require('../config/config');

const signToken = id => (
  jwt.sign(
    { id: id },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  ));

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.emailReg = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const tempUserDb = await TempUser.findOne({ email: email });

  if (tempUserDb && tempUserDb.otpSendAt) {
    if (await tempUserDb.checkOtpTime()) {
      return next(new AppError(`If you have already sent an OTP, please wait for ${config.otp.sendOtpAfter} minutes before requesting another one.`));
    }
  }

  await TempUser.findOneAndDelete({ email: email });

  // Generate OTP and set expiration time
  const otp = util.generateOTP();
  const otpSendAt = new Date(Date.now());
  const otpExpiration = new Date(Date.now() + config.otp.otpExpiration * 60 * 1000);

  const tempUser = await TempUser.create({
    email,
    otp,
    otpSendAt,
    otpExpiration
  });
  await tempUser.save();

  // Send OTP to user's email
  const emailMessage = `Your OTP for email verification is: ${otp}, The otp will expire in ${config.otp.otpExpiration}`;
  try {
    await sendEmail({
      email: email,
      subject: 'Email Verification OTP',
      message: emailMessage
    });

    res.status(200).json({
      status: 'success',
      message: 'OTP sent to your email for verification',
      data: {
        email
      }
    });
    // next();
  } catch (err) {
    TempUser.findOneAndDelete({ email: email });

    return next(new AppError('There was an error sending the email', 500));
  }
});

exports.emailVerify = catchAsync(async (req, res, next) => {
  const { otp, email } = req.body;
  const tempUser = await TempUser.findOne({ email });
  if (!tempUser) return next(new AppError('Register your email first', 401));
  if (!tempUser.checkOtp(otp)) return next(new AppError('The otp does not match', 401));
  if (tempUser.checkOtpExpiration()) return next(new AppError('The otp has expired', 401));

  tempUser.emailVerified = true;
  await tempUser.save({ validateBeforeSave: false });

  res.status(200).json({
    status: 'success',
    message: 'Email is verified',
    data: {
      email
    }
  });
});

exports.signup = catchAsync(async (req, res, next) => {
  const {
    firstName, lastName, email, password, passwordConfirm, passwordChangedAt
  } = req.body;

  const tempUser = await TempUser.findOne({ email });
  if (!tempUser || !tempUser.emailVerified) return next(new AppError('Register your email first', 401));

  const newUser = await User.create({
    firstName: firstName,
    lastName: lastName,
    email: tempUser.email,
    password: password,
    passwordConfirm: passwordConfirm,
    passwordChangedAt: passwordChangedAt
  });

  // Creating jwt token
  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) return next(new AppError('Please Provide email and password', 400));

  const user = await User.findOne({ email }).select('+password'); // + indicates that the password select is false(in model) so include password in return

  // Checks if user's password is correct
  if (!user || !await user.correctPassword(password, user.password)) return next(new AppError('Incorrect email or password', 403));

  // Creating jwt token
  createSendToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting the token and checking if it's there
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return next(new AppError('You are not logged in'), 401);

  // 2)Verifying token
  // The jwt.verify uses callback,
  //  which is a async func that will run after the verification is done,
  // Instead we promisify ts
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3)Check if the user still exists
  const freshUser = await User.findById(decoded.id);
  if (!freshUser) return next(new AppError('The user belonging to this token no longer exists', 401));

  // 4)Check if user changed password after the token was issued
  if (freshUser.changedPasswordAfter(decoded.iat)) return next(new AppError('User recently changed the password! Please log in again', 401));

  // Grant access to the protected Route
  req.user = freshUser;
  next();
});

// A restrict function for roles, it will run after protect middleware
// authController.restrict('admin','mod')
// A wrapper func that will return the middleware func
exports.restrict = (...roles) => (req, res, next) => {
  // roles is an array now, rest parameter syntax
  if (!roles.include(req.user.role)) return next(new AppError('You do not have permission to perform this action', 403));
  next();
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  if (!req.body.email) return next(new AppError('Please provide your email address to receive Password reset mail', 400));

  // 1)Get user based on the POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) return next(new AppError('There is no user with that email address', 404));

  // 2)Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  //To save encrypted passwordResetToken and ExpirationOfToken in db

  // 3)Send it to user's email
  const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetpassword/${resetToken}`;

  const message = `Click the link below to reset your password\n${resetURL}`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset Token, valid for 10min',
      message
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email', 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  if (!req.body?.password || !req.body?.passwordConfirm) return next(new AppError('Please Provide your new password'));

  // 1) Get user based on the token
  // Hashing the encrypted token back to token
  const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() } // Mongodb formats and compares automatically
  });

  // 2) If the token is not expired and the user exist, set the new password
  if (!user) return next(new AppError('Token is invalid or Expired', 400));

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save(); // save the above to db

  // 3) Update changedPasswordAt property of the user
  // This will happen automatically in userModel

  // 4) Log the user in, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // ! Add validation to check if required parameters are there
  const { currentPassword, updatedPassword, updatedPasswordConfirm } = req.body;

  // 1) Get user from the collection
  const user = await User.findById(req.user.id).select('+password');

  // 2) Check if POSTed current password is correct
  if (!await user.correctPassword(currentPassword, user.password)) return next(new AppError('The Provided Password is incorrect', 401));

  // 3) If so, update the password
  console.log('thisran');
  user.password = updatedPassword;
  user.passwordConfirm = updatedPasswordConfirm;
  await user.save();

  // 4) Log the user in, send JWT
  createSendToken(user, 200, res);
});
