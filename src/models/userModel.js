const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please tell us your First Name!']
  },
  lastName: {
    type: String,
    required: [true, 'Please tell us your Last Name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'] // From the Validator Module
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minLength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // This will only work on CREATE & SAVE, and not on func like findOneAndUpdate, etc
      // Because mongoose doesn't keep the current obj in memory
      // So use SAVE on updating the password
      validator: function (value) {
        return value === this.password; //Should return either true or false
      },
      message: 'Passwords do not match'
    }
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date
});

// This will run between getting the data from client and saving it to DB
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  this.password = await bcrypt.hash(this.password, 10);
  this.passwordConfirm = undefined;
  next();
});

// To check if password is changed, if yes set passwordChangedAt
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next(); //isNew from mongoose

  this.passwordChangedAt = Date.now() - 1000;
  // Subtracting 1sec because sometimes saving to db takes longer than issuing token

  next();
});

// This is Instance Method
// This method will be available on all document in the collection
// This is a method to check user's password (ex. on login)
userSchema.methods.correctPassword = async function (candidatePassword, userPasswordInDB) {
  return await bcrypt.compare(candidatePassword, userPasswordInDB);
};

userSchema.methods.changedPasswordAfter = function (JwtTimestamp) {
  if (this.passwordChangedAt) {
    // Getting timestamp in seconds
    const passwordChangeTimeStamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    // console.log(this.passwordChangedAt, JwtTimestamp);
    return JwtTimestamp < passwordChangeTimeStamp;
  }

  // False means NOT CHANGED
  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  // It is like a password to reset password
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; //10mins
  // Your need to call save() after calling createPasswordResetToken() to save token and expiration
  // console.log({ resetToken }, this.passwordResetToken, this.passwordResetExpires);

  // Sending unencrypted reset token
  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
