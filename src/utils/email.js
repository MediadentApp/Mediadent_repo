const nodemailer = require('nodemailer');

const sendEmail = async options => {
  // 1) Create a transporter
  // const transporterGmail = nodemailer.createTransport({
  //   service: 'Gmail',
  //   auth: {
  //     user: process.env.GMAIL_USERNAME,
  //     pass: process.env.GMAIL_PASSWORD
  //   }
  //   // Activate 'less secure app' option in your gmail
  // });

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: process.env.MAILTRAP_PORT,
    auth: {
      user: process.env.MAILTRAP_USERNAME,
      pass: process.env.MAILTRAP_PASSWORD
    }
  });

  // 2) Define the email options
  const mailOptions = {
    from: 'Mediadent <mediadentprod@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message
    // html:
  };

  // 3) Send the email
  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
