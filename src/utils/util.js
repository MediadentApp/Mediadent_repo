exports.generateOTP = () => {
  // Generate a random 5-digit number
  const otp = Math.floor(10000 + Math.random() * 90000);
  // Generate a random number between 10000 and 99999
  return otp.toString(); // Convert the number to a string
};
