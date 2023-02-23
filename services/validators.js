import axios from 'axios';
import config from '../config/config.js';

export const validateEmail = async email => {
  const res = await axios.get(
    `https://emailvalidation.abstractapi.com/v1/?api_key=${config.EMAIL_API_KEY}&email=${email}`
  );

  const isValid =
    res.data.is_valid_format.value &&
    res.data.is_free_email.value &&
    (res.data.deliverability === 'DELIVERABLE' || res.data.deliverability === 'UNKNOWN');

  return isValid;
};

export const validatePhoneNo = async phoneNo => {
  const res = await axios.get(
    `https://phonevalidation.abstractapi.com/v1/?api_key=${config.PHONE_API_KEY}&phone=${
      '91' + phoneNo
    }`
  );

  const isValid = res.data.valid;
  return isValid;
};
