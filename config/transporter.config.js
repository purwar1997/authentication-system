import nodemailer from 'nodemailer';
import config from './config.js';

let transporter = nodemailer.createTransport({
  host: config.SMTP_HOST,
  port: 2525,
  secure: false,
  auth: {
    user: config.SMTP_USERNAME,
    pass: config.SMTP_PASSWORD,
  },
});

export default transporter;
