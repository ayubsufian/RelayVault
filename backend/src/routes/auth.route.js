import { Router } from 'express';
import {
  loginUser,
  registerUser,
  logoutUser,
  refreshAccessToken,
  logoutAllSessions,
  getCurrentUser,
  forgotPassword,
  resetPassword,
  changePassword,
  verifyEmail,
  resendVerificationEmail,
  googleLogin,
  googleCallback,
  googleLinkStart,
  googleLinkCallback,
  startMfaSetupWithGoogle,
  startMfaSetupWithPassword,
  confirmMfaSetup,
  regenerateRecoveryCodes,
  verifyMfa,
  startMfaReplacement,
  confirmMfaReplacement,
  disableMfa,
  startGoogleMfaReauth,
  completeGoogleMfaReauth,
} from '../controllers/auth.controller.js';
import requireAuth from '../middleware/auth.middleware.js';
import requireRecentAuth from '../middleware/recent-auth.middleware.js';
import requireMfaReauth from '../middleware/mfa-reauth.middleware.js';
import {
  authLimiter,
  mfaLimiter,
  recoveryLimiter,
} from '../middleware/rate-limit.middleware.js';

const router = Router();

// Account registration and login
router.post('/register', authLimiter, registerUser);
router.post('/login', authLimiter, loginUser);

// Session lifecycle
router.post('/refresh', authLimiter, refreshAccessToken);
router.post('/logout', logoutUser);
router.post('/logout-all', requireAuth, logoutAllSessions);
router.get('/me', requireAuth, getCurrentUser);

// Password and email verification
router.post('/forgot-password', recoveryLimiter, forgotPassword);
router.post('/reset-password', recoveryLimiter, resetPassword);
router.patch('/change-password', requireAuth, changePassword);
router.get('/verify-email', verifyEmail);
router.post('/resend-verification', recoveryLimiter, resendVerificationEmail);

// Google OAuth
router.get('/google', googleLogin);
router.get('/google/callback', googleCallback);
router.get('/google/link', requireAuth, googleLinkStart);
router.get('/google/link/callback', googleLinkCallback);

// MFA setup and lifecycle
router.post(
  '/mfa/setup/password',
  requireAuth,
  requireRecentAuth,
  startMfaSetupWithPassword,
);
router.post(
  '/mfa/setup/google',
  requireAuth,
  requireRecentAuth,
  requireMfaReauth,
  startMfaSetupWithGoogle,
);
router.post('/mfa/confirm', requireAuth, requireRecentAuth, confirmMfaSetup);
router.post('/mfa/verify', mfaLimiter, verifyMfa);
router.post(
  '/mfa/replace/start',
  requireAuth,
  requireRecentAuth,
  startMfaReplacement,
);
router.post(
  '/mfa/replace/confirm',
  requireAuth,
  requireRecentAuth,
  confirmMfaReplacement,
);
router.post('/mfa/disable', requireAuth, requireRecentAuth, disableMfa);
router.post(
  '/mfa/recovery-codes/regenerate',
  requireAuth,
  requireRecentAuth,
  regenerateRecoveryCodes,
);

// Google MFA reauthentication
router.get('/google/mfa-reauth', requireAuth, startGoogleMfaReauth);
router.get('/google/mfa-reauth/callback', completeGoogleMfaReauth);

export default router;
