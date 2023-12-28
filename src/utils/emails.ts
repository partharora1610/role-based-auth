import nodemailer from "nodemailer";

const sendEmail = async (email: string, url: string) => {
  // create transporter
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: 2525,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  // mail options
  const mailOptions = {
    from: "Parth Arora <test@partharora.com>",
    to: email,
    subject: "Password reset token",
    text: `Click on the link to reset your password: ${url}`,
  };

  // send email
  await transporter.sendMail(mailOptions);
};

export default sendEmail;
