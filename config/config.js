import dotenv from 'dotenv';
dotenv.config();

const config = {
  PORT: process.env.PORT || 4000,
  MONGODB_URL: process.env.MONGODB_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRY: process.env.JWT_EXPIRY,
  EMAIL_API_KEY: process.env.EMAIL_API_KEY,
  PHONE_API_KEY: process.env.PHONE_API_KEY,
  SMTP_HOST: process.env.SMTP_HOST,
  SMTP_USERNAME: process.env.SMTP_USERNAME,
  SMTP_PASSWORD: process.env.SMTP_PASSWORD,
  SMTP_SENDER_EMAIL: process.env.SMTP_SENDER_EMAIL,
};

export default config;
