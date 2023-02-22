import User from '../models/user';
import asyncHandler from '../services/asyncHandler';
import CustomError from '../utils/CustomError';

/**
 * @SIGNUP
 * @request_type POST
 * @route http://localhost:4000/api/v1/auth/signup
 * @description Controller that allows user to signup
 * @parameters firstname, lastname, email, phoneNo, password, confirmPassword
 * @returns User object
 */

export const signup = asyncHandler(async (req, res) => {});
