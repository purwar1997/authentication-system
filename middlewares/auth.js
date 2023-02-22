import JWT from 'jsonwebtoken';
import User from '../models/user';
import asyncHandler from '../services/asyncHandler';
import CustomError from '../utils/CustomError';
import config from '../config/config';

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
