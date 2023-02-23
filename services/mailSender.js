import transporter from '../config/transporter.config.js';
import config from '../config/config.js';

const mailSender = async options => {
  return await transporter.sendMail({
    from: config.SMTP_SENDER_EMAIL,
    to: options.email,
    subject: options.subject,
    text: options.text,
  });
};

export default mailSender;
