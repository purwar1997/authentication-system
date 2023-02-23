import JWT from 'jsonwebtoken';
import User from '../models/user.js';
import asyncHandler from '../services/asyncHandler.js';
import CustomError from '../utils/CustomError.js';
import config from '../config/config.js';

const auth = asyncHandler(async (req, res, next) => {
  let token;

  if (
    req.cookies.token ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer'))
  ) {
    token = req.cookies.token || req.headers.authorization.split(' ')[1];

    let decodedToken;

    try {
      decodedToken = JWT.verify(token, config.JWT_SECRET);
    } catch (err) {
      throw new CustomError('Token invalid or expired', 500);
    }

    const user = await User.findById(decodedToken.userId);

    if (!user) {
      throw new CustomError('User not found', 404);
    }

    res.user = user;
    return next();
  }
});

export default auth;
