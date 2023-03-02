import crypto from 'crypto';
import User from '../models/user.js';
import asyncHandler from '../services/asyncHandler.js';
import CustomError from '../utils/CustomError.js';
import { validateEmail, validatePhoneNo } from '../services/validators.js';
import mailSender from '../services/mailSender.js';
import regexp from '../utils/regex.js';
import cookieOptions from '../utils/cookieOptions.js';

/**
 * @SIGNUP
 * @request_type POST
 * @route http://localhost:4000/api/v1/auth/signup
 * @description Controller that allows user to signup
 * @parameters firstname, lastname, email, phoneNo, password, confirmPassword
 * @returns User object
 */

export const signup = asyncHandler(async (req, res) => {
  const { firstname, lastname, email, phoneNo, password, confirmPassword } = req.body;

  if (!(firstname && lastname && email && phoneNo && password && confirmPassword)) {
    throw new CustomError('Please enter all the details', 401);
  }

  let isEmailValid, isPhoneNoValid;

  try {
    isEmailValid = await validateEmail(email);
  } catch (err) {
    throw new CustomError(err.response.data.error.message || 'Failure verifying email', 500);
  }

  if (!isEmailValid) {
    throw new CustomError('Please enter a valid email', 401);
  }

  try {
    isPhoneNoValid = await validatePhoneNo(phoneNo);
  } catch (err) {
    throw new CustomError(err.response.data.error.message || 'Failure verifying phone no.', 500);
  }

  if (!isPhoneNoValid) {
    throw new CustomError('Please enter a valid phone no.', 401);
  }

  if (password !== confirmPassword) {
    throw new CustomError("Password and confirmed password don't match with each other", 401);
  }

  let user = await User.findOne({ email: email.trim().toLowerCase() });

  if (user) {
    throw new CustomError('User already exists', 401);
  }

  user = await User.create({ firstname, lastname, email, phoneNo, password });
  user.password = undefined;

  res.status(201).json({
    success: true,
    message: 'User successfully signed up',
    user,
  });
});

/**
 * @LOGIN
 * @request_type POST
 * @route http://localhost:4000/api/v1/auth/login
 * @description Controller that allows user to login via email or phone no.
 * @parameters login, password
 * @returns Response object
 */

export const login = asyncHandler(async (req, res) => {
  let { login, password } = req.body;

  if (!login) {
    throw new CustomError('Email or phone no. is required', 401);
  }

  if (!password) {
    throw new CustomError('Password is required', 401);
  }

  login = login.trim().toLowerCase();

  let regex = new RegExp(regexp.email);
  let isLoginValid = regex.test(login);

  if (!isLoginValid) {
    regex = new RegExp(regexp.phoneNo);
    isLoginValid = regex.test(login);
  }

  if (!isLoginValid) {
    throw new CustomError('Please enter valid email or phone no.', 401);
  }

  let user = await User.findOne({ email: login }).select('+password');

  if (!user) {
    user = await User.findOne({ phoneNo: login }).select('+password');
  }

  if (!user) {
    throw new CustomError('User not registered', 404);
  }

  const passwordMatched = await user.comparePassword(password);

  if (!passwordMatched) {
    throw new CustomError('Incorrect password', 401);
  }

  const token = user.generateJWTtoken();

  res.status(200).cookie('token', token, cookieOptions);

  res.status(200).json({
    success: true,
    message: 'User successfully logged in',
  });
});

/**
 * @LOGOUT
 * @request_type GET
 * @route http://localhost:4000/api/v1/auth/logout
 * @description Controller that allows user to logout
 * @parameters none
 * @returns Response object
 */

export const logout = asyncHandler(async (_req, res) => {
  res.status(200).cookie('token', null, cookieOptions);

  res.status(200).json({
    success: true,
    message: 'User successfully logged out',
  });
});

/**
 * @FORGOT_PASSWORD
 * @request_type PUT
 * @route http://localhost:4000/api/v1/auth/password/forgot
 * @description Controller which sends reset password email to the user
 * @parameters email
 * @returns Response object
 */

export const forgotPassword = asyncHandler(async (req, res) => {
  let { email } = req.body;

  if (!email) {
    throw new CustomError('Please enter your email', 401);
  }

  email = email.trim().toLowerCase();

  const regex = new RegExp(regexp.email);
  const isEmailValid = regex.test(email);

  if (!isEmailValid) {
    throw new CustomError('Please enter a valid email', 401);
  }

  let user = await User.findOne({ email });

  if (!user) {
    throw new CustomError('Email not registered', 404);
  }

  const resetPasswordToken = user.generateForgotPasswordToken();
  await user.save({ validateBeforeSave: true });

  const resetPasswordLink = `${req.protocol}://${req.hostname}/api/v1/auth/password/reset/${resetPasswordToken}`;

  try {
    await mailSender({
      email,
      subject: 'Reset password email',
      text: `Click on this link to reset your password: ${resetPasswordLink}`,
    });
  } catch (err) {
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save({ validateBeforeSave: true });

    throw new CustomError(err.message || 'Failure sending mail', 500);
  }

  res.status(200).json({
    success: true,
    message: 'Reset password email successfully sent to the user',
  });
});

/**
 * @RESET_PASSWORD
 * @request_type PUT
 * @route http://localhost:4000/api/v1/auth/password/reset/:resetPasswordToken
 * @description Controller that allows user to reset his password
 * @parameters password, confirmPassword
 * @returns Response object
 */

export const resetPassword = asyncHandler(async (req, res) => {
  const { resetPasswordToken } = req.params;
  const { password, confirmPassword } = req.body;

  if (!password) {
    throw new CustomError('Please enter a new password', 401);
  }

  if (!confirmPassword) {
    throw new CustomError('Please confirm your password', 401);
  }

  if (password !== confirmPassword) {
    throw new CustomError("Password and confirmed password don't match with each other", 401);
  }

  const encryptedToken = crypto.createHash('sha256').update(resetPasswordToken).digest('hex');

  const user = await User.findOne({
    forgotPasswordToken: encryptedToken,
    forgotPasswordExpiry: { $gt: new Date() },
  });

  if (!user) {
    throw new CustomError('Token invalid or expired', 401);
  }

  user.password = password;
  user.forgotPasswordToken = undefined;
  user.forgotPasswordExpiry = undefined;
  await user.save();

  res.status(201).json({
    success: true,
    message: 'Password reset success',
  });
});

/**
 * @GET_PROFILE
 * @request_type GET
 * @route http://localhost:4000/api/v1/auth/profile
 * @description Controller that allows user to fetch his profile
 * @parameters none
 * @returns User object
 */

export const getProfile = asyncHandler(async (_req, res) => {
  const { user } = res;

  res.status(200).json({
    success: true,
    message: 'Profile successfully fetched',
    user,
  });
});

/**
 * @CHANGE_PASSWORD
 * @request_type PUT
 * @route http://localhost:4000/api/v1/auth/password/change
 * @description Controller that allows user to change his password
 * @parameters currentPassword, newPassword
 * @returns Response object
 */

export const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword) {
    throw new CustomError('Please enter your current password', 401);
  }

  if (!newPassword) {
    throw new CustomError('Please enter a new password', 401);
  }

  let user = await User.findById(res.user._id).select('+password');

  const passwordMatched = await user.comparePassword(currentPassword);

  if (!passwordMatched) {
    throw new CustomError('Incorrect password', 401);
  }

  user.password = newPassword;
  await user.save();

  res.status(201).json({
    success: true,
    message: 'Password successfully changed',
  });
});

/**
 * @DELETE_PROFILE
 * @request_type DELETE
 * @route http://localhost:4000/api/v1/auth/profile/delete
 * @description Controller that allows user to delete his profile
 * @parameters password
 * @returns Response object
 */

export const deleteProfile = asyncHandler(async (req, res) => {
  const { password } = req.body;

  if (!password) {
    throw new CustomError('Please enter your password', 401);
  }

  const user = await User.findById(res.user._id).select('+password');
  const passwordMatched = await user.comparePassword(password);

  if (!passwordMatched) {
    throw new CustomError('Incorrect password', 401);
  }

  await user.remove();

  res.status(200).cookie('token', null, cookieOptions);

  res.status(200).json({
    success: true,
    message: 'Profile successfully deleted',
  });
});
