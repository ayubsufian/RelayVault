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

const router = Router();

// Registration and login
router.route('/register').post(registerUser);
router.route('/login').post(loginUser);

// Token and session management
router.route('/refresh').post(refreshAccessToken);
router.route('/logout').post(logoutUser);
router.route('/logout-all').post(requireAuth, logoutAllSessions);
router.route('/me').get(requireAuth, getCurrentUser);

// Password management
router.route('/forgot-password').post(forgotPassword);
router.route('/reset-password').post(resetPassword);
router.route('/change-password').patch(requireAuth, changePassword);

// Email verification
router.route('/verify-email').get(verifyEmail);
router.route('/resend-verification').post(resendVerificationEmail);

// Google OAuth
router.route('/google').get(googleLogin);
router.route('/google/callback').get(googleCallback);
router.get('/google/link', requireAuth, googleLinkStart);
router.get('/google/link/callback', googleLinkCallback);

router.post(
  '/mfa/setup/google',
  requireAuth,
  requireRecentAuth,
  requireMfaReauth,
  startMfaSetupWithGoogle,
);
router.post(
  '/mfa/setup/password',
  requireAuth,
  requireRecentAuth,
  startMfaSetupWithPassword,
);
router.post('/mfa/confirm', requireAuth, requireRecentAuth, confirmMfaSetup);
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
router.post('/mfa/verify', verifyMfa);

router.get('/google/mfa-reauth', requireAuth, startGoogleMfaReauth);
router.get('/google/mfa-reauth/callback', completeGoogleMfaReauth);

router.post(
  '/mfa/recovery-codes/regenerate',
  requireAuth,
  requireRecentAuth,
  regenerateRecoveryCodes,
);

export default router;
