import express from 'express';
import {
  loginHandler,
  logoutHandler,
  refreshAccessTokenHandler,
  registerHandler,
  sendOtpHandler,
  confirmOtpHandler,
  forgetPasswordHandler,
  verifyOTPHandler,
  resetPasswordHandler,
  getRolesHandler
} from '../controllers/auth.controller';
import { deserializeUser } from '../middleware/deserializeUser';
import { requireUser } from '../middleware/requireUser';
import { validate } from '../middleware/validate';
import { createUserSchema, loginUserSchema } from '../schema/user.schema';

const router = express.Router();

// Register user route
router.post('/register', validate(createUserSchema), registerHandler);

// Login user route
router.post('/login', validate(loginUserSchema), loginHandler);

// Send registration OTP
router.post('/sendotp', sendOtpHandler);

// Verify registration OTP
router.post('/confirmotp', confirmOtpHandler);

// Get forget password OTP on email
router.post('/forgetpassword', forgetPasswordHandler);

// Verify forget password OTP
router.post('/verifyotp', verifyOTPHandler);

// Reset password
router.post('/resetpassword', resetPasswordHandler);

// Get roles
router.get('/roles', getRolesHandler);

// Refresh access token route
router.get('/refresh', refreshAccessTokenHandler);

router.use(deserializeUser, requireUser);

// Logout User
router.get('/logout', logoutHandler);

export default router;
