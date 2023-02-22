import User from '../models/user';
import asyncHandler from '../services/asyncHandler';
import CustomError from '../utils/CustomError';
import { validateEmail, validatePhoneNo } from '../services/validators';
import mailSender from '../services/mailSender';

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
    throw new CustomError('Failure verifying email', 500);
  }

  if (!isEmailValid) {
    throw new CustomError('Please enter a valid email', 401);
  }

  try {
    isPhoneNoValid = await validatePhoneNo(phoneNo);
  } catch (err) {
    throw new CustomError('Failure verifying phone no.', 500);
  }

  if (!isPhoneNoValid) {
    throw new CustomError('Please enter a valid phone no.', 401);
  }

  if (password !== confirmPassword) {
    throw new CustomError("Password and confirmed password don't match", 401);
  }

  let user = await User.findOne({ email: email.toLowerCase() });

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
 * @request_type GET
 * @route http://localhost:4000/api/v1/auth/login
 * @description Controller that allows user to login via email or phone no.
 * @parameters login, password
 * @returns Response object
 */

export const login = asyncHandler(async (req, res) => {
  const { login, password } = req.body;

  if (!(login && password)) {
    throw new CustomError('Please enter all the details', 401);
  }

  let isEmailValid, isPhoneNoValid;

  try {
    isEmailValid = await validateEmail(login);
  } catch (err) {
    throw new CustomError('Failure verifying email', 500);
  }

  try {
    isPhoneNoValid = await validatePhoneNo(login);
  } catch (err) {
    throw new CustomError('Failure verifying phone no.', 500);
  }

  if (!(isEmailValid || isPhoneNoValid)) {
    throw new CustomError('Please enter valid email or phone no.', 401);
  }

  let user;

  if (isEmailValid) {
    user = await User.findOne({ email: login.toLowerCase() }).select('+password');
  }

  if (isPhoneNoValid) {
    user = await User.findOne({ phoneNo: login }).select('+password');
  }

  if (!user) {
    throw new CustomError('User not registered', 401);
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
 * @route https://localhost:4000/api/v1/auth/logout
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
