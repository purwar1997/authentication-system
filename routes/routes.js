import express from 'express';

import {
  signup,
  login,
  logout,
  forgotPassword,
  resetPassword,
  changePassword,
  getProfile,
  deleteProfile,
} from '../controllers/auth.controllers.js';

import auth from '../middlewares/auth.js';

const router = express.Router();

router.post('/api/v1/auth/signup', signup);
router.get('/api/v1/auth/login', login);
router.get('/api/v1/auth/logout', logout);
router.put('/api/v1/auth/password/forgot', forgotPassword);
router.put('/api/v1/auth/password/reset', resetPassword);
router.put('/api/v1/auth/password/change', auth, changePassword);
router.get('/api/v1/auth/profile', auth, getProfile);
router.delete('/api/v1/auth/profile/delete', auth, deleteProfile);

export default router;
