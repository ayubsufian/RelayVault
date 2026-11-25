import {
  registerUserService,
  loginUserService,
  refreshAccessTokenService,
  logoutUserService,
  logoutAllSessionsService,
  getCurrentUserService,
  requestPasswordResetService,
  resetPasswordService,
  changePasswordService,
  verifyEmailService,
  resendVerificationEmailService,
  completeGoogleLoginService,
  getGoogleAuthorizationUrlService,
  startGoogleLinkService,
  completeGoogleLinkService,
  startPasswordMfaSetupService,
  startGoogleMfaSetupService,
  confirmMfaSetupService,
  regenerateRecoveryCodesService,
  verifyMfaService,
  verifyRecoveryCodeService,
  startMfaReplacementService,
  confirmMfaReplacementService,
  disableMfaService,
  startGoogleMfaReauthService,
  completeGoogleMfaReauthService,
} from '../services/auth.service.js';
import HttpError from '../utils/http-error.js';
import { MFA_ERROR } from '../utils/mfa-errors.js';

const toPublicUser = (user) => ({
  id: user._id,
  email: user.email,
  username: user.username,
});

const requireBody = (req) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    throw new HttpError('A JSON object body is required', 400);
  }

  return req.body;
};

const requireString = (value, field, { min = 1, max = 500 } = {}) => {
  if (typeof value !== 'string') {
    throw new HttpError(`${field} must be a string`, 400);
  }

  const normalized = value.trim();

  if (normalized.length < min || normalized.length > max) {
    throw new HttpError(`${field} has an invalid length`, 400);
  }

  return normalized;
};

const requireEmail = (value) => {
  const email = requireString(value, 'Email', { max: 254 }).toLowerCase();

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError('Email has an invalid format', 400);
  }

  return email;
};

const requirePassword = (value, field = 'Password') => {
  if (typeof value !== 'string' || value.length < 6 || value.length > 128) {
    throw new HttpError(`${field} has an invalid length`, 400);
  }

  return value;
};

const requireMfaCode = (value, field = 'MFA code') => {
  if (typeof value !== 'string' || !/^\d{6}$/.test(value)) {
    throw new HttpError(`A valid six-digit ${field.toLowerCase()} is required`, 400);
  }

  return value;
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/api/v1/auth',
};

const clearRefreshCookie = (res) =>
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/v1/auth',
  });

const oauthCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 10 * 60 * 1000,
  path: '/api/v1/auth',
};

const mfaReauthCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 5 * 60 * 1000,
  path: '/api/v1/auth/mfa',
};

const googleMfaStateCookieOptions = {
  ...oauthCookieOptions,
  maxAge: 5 * 60 * 1000,
};

const mapGoogleResult = (result, operation = 'authentication') => {
  if (!result) {
    throw new HttpError(`Unable to complete Google ${operation}`, 500);
  }
  if (result.invalidRequest || result.invalid) {
    throw new HttpError(`Invalid Google ${operation} request`, 400);
  }
  if (result.invalidState) {
    throw new HttpError('Invalid OAuth state', 400);
  }
  if (result.invalidGoogleRequest) {
    throw new HttpError(`Google ${operation} request failed`, 400);
  }
  if (result.invalidGoogleToken) {
    throw new HttpError('Google did not return a valid ID token', 401);
  }
  if (result.unverifiedGoogleEmail) {
    throw new HttpError('Google account email is not verified', 401);
  }
  if (result.emailConflict) {
    throw new HttpError('An account with this email already exists', 409);
  }
  if (result.alreadyLinked) {
    throw new HttpError('This Google account is already linked', 409);
  }
  return result;
};

const mapGoogleMfaReauthError = (result) => {
  if (!result) {
    throw new HttpError('Unable to complete Google reauthentication', 500);
  }
  if (result.error === MFA_ERROR.EXPIRED) {
    throw new HttpError('Google authentication was not recent enough', 401);
  }
  if (result.error === MFA_ERROR.INVALID) {
    throw new HttpError('Invalid Google reauthentication request', 400);
  }
  if (!result.success || !result.reauthToken) {
    throw new HttpError('Unable to complete Google reauthentication', 500);
  }
  return result;
};

const registerUser = async (req, res) => {
  const body = requireBody(req);
  const username = requireString(body.username, 'Username', { max: 30 }).toLowerCase();
  const email = requireEmail(body.email);
  const password = requirePassword(body.password);

  const user = await registerUserService(username, email, password);
  if (!user) {
    throw new HttpError('User already exists', 409);
  }

  return res.status(201).json({
    message: 'User registered',
    user: { id: user._id, email: user.email, username: user.username },
  });
};

const loginUser = async (req, res) => {
  const body = requireBody(req);
  const email = requireEmail(body.email);
  const password = requirePassword(body.password);

  const result = await loginUserService(email, password);
  if (!result) {
    throw new HttpError('Invalid credentials', 401);
  }

  if (result.unverified) {
    throw new HttpError('Please verify your email first', 403);
  }

  if (result.mfaRequired) {
    return res.status(200).json({
      message: 'MFA verification required',
      mfaRequired: true,
      challenge: result.mfaChallenge,
    });
  }

  return res
    .status(200)
    .cookie('refreshToken', result.refreshToken, refreshCookieOptions)
    .json({
      message: 'User logged in',
      user: {
        id: result.user._id,
        email: result.user.email,
        username: result.user.username,
      },
      accessToken: result.accessToken,
    });
};

const logoutUser = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new HttpError('Refresh token is required', 400);
  }

  await logoutUserService(refreshToken);

  return clearRefreshCookie(res)
    .status(200)
    .json({
      message: 'Logout successful',
    });
};

const refreshAccessToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new HttpError('Refresh token is required', 401);
  }

  const result = await refreshAccessTokenService(refreshToken);

  if (!result) {
    throw new HttpError('Invalid, expired, or reused refresh token', 401);
  }

  return res
    .status(200)
    .cookie('refreshToken', result.refreshToken, refreshCookieOptions)
    .json({
      accessToken: result.accessToken,
    });
};

const logoutAllSessions = async (req, res) => {
  await logoutAllSessionsService(req.userId);

  return clearRefreshCookie(res)
    .status(200)
    .json({
      message: 'Logged out from all devices',
    });
};

const getCurrentUser = async (req, res) => {
  const user = await getCurrentUserService(req.userId);

  if (!user) {
    throw new HttpError('User not found', 404);
  }

  return res.status(200).json({
    user,
  });
};

const forgotPassword = async (req, res) => {
  const body = requireBody(req);
  const email = requireEmail(body.email);

  await requestPasswordResetService(email);

  // Do not reveal whether the email exists.
  return res.status(200).json({
    message: 'If the account exists, a reset link has been sent',
  });
};

const resetPassword = async (req, res) => {
  const body = requireBody(req);
  const token = requireString(body.token, 'Token', { max: 256 });
  const newPassword = requirePassword(body.newPassword, 'New password');

  const success = await resetPasswordService(token, newPassword);

  if (!success) {
    throw new HttpError('Invalid or expired reset token', 400);
  }

  return res.status(200).json({
    message: 'Password reset successfully',
  });
};

const changePassword = async (req, res) => {
  const body = requireBody(req);
  const currentPassword = requirePassword(body.currentPassword, 'Current password');
  const newPassword = requirePassword(body.newPassword, 'New password');

  const success = await changePasswordService(
    req.userId,
    currentPassword,
    newPassword,
  );

  if (!success) {
    throw new HttpError('Current password is incorrect', 401);
  }

  return res.status(200).json({
    message: 'Password changed successfully',
  });
};

const verifyEmail = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    throw new HttpError('Verification token is required', 400);
  }

  const verified = await verifyEmailService(token);

  if (!verified) {
    throw new HttpError('Invalid or expired verification token', 400);
  }

  return res.status(200).json({
    message: 'Email verified successfully',
  });
};

const resendVerificationEmail = async (req, res) => {
  const body = requireBody(req);
  const email = requireEmail(body.email);

  await resendVerificationEmailService(email);

  return res.status(200).json({
    message:
      'If the account exists and is unverified, a verification email has been sent',
  });
};

const googleLogin = (req, res) => {
  const { url, state, verifier } = getGoogleAuthorizationUrlService();

  return res
    .cookie('googleState', state, oauthCookieOptions)
    .cookie('googleVerifier', verifier, oauthCookieOptions)
    .redirect(url);
};

const googleCallback = async (req, res) => {
  const { code, state } = req.query;

  const clearGoogleCookies = () =>
    res
      .clearCookie('googleState', { path: '/api/v1/auth' })
      .clearCookie('googleVerifier', { path: '/api/v1/auth' });

  try {
    const result = await completeGoogleLoginService({
      code,
      state,
      savedState: req.cookies.googleState,
      verifier: req.cookies.googleVerifier,
    });

    mapGoogleResult(result);

    return res
      .cookie('refreshToken', result.refreshToken, refreshCookieOptions)
      .status(200)
      .json({
        message: 'Google login successful',
        accessToken: result.accessToken,
        user: {
          id: result.user._id,
          email: result.user.email,
          username: result.user.username,
        },
      });
  } finally {
    clearGoogleCookies();
  }
};

const googleLinkStart = async (req, res) => {
  const url = await startGoogleLinkService(req.userId);
  return res.redirect(url);
};

const googleLinkCallback = async (req, res) => {
  const { code, state } = req.query;

  const result = await completeGoogleLinkService(code, state);

  mapGoogleResult(result, 'linking');

  return res.status(200).json({
    message: 'Google account linked successfully',
  });
};

const mapMfaLifecycleError = (result) => {
  if (!result) {
    throw new HttpError('Unable to complete MFA operation', 500);
  }

  if (!result.error) {
    return result;
  }

  switch (result.error) {
    case MFA_ERROR.TOO_MANY_ATTEMPTS:
      throw new HttpError('Too many MFA attempts. Try again later.', 429);

    case MFA_ERROR.RECENT_AUTH_REQUIRED:
      throw new HttpError('Recent authentication is required', 401);

    case MFA_ERROR.PASSWORD_REQUIRED:
      throw new HttpError('Current password is required', 400);

    case MFA_ERROR.NOT_ENABLED:
      throw new HttpError('MFA is not enabled', 409);

    case MFA_ERROR.ALREADY_ENABLED:
      throw new HttpError('MFA is already enabled', 409);

    case MFA_ERROR.INVALID:
    case MFA_ERROR.EXPIRED:
      throw new HttpError('Invalid or expired MFA request', 401);

    default:
      throw new HttpError('Unable to complete MFA operation', 500);
  }
};

const startMfaSetupWithGoogle = async (req, res) => {
  try {
    const serviceResult = await startGoogleMfaSetupService({
      userId: req.userId,
      reauthUserId: req.mfaReauthUserId,
      reauthJti: req.mfaReauthJti,
      reauthTokenHash: req.mfaReauthTokenHash,
    });

    const result = mapMfaLifecycleError(serviceResult);

    return res.status(200).set('Cache-Control', 'no-store').json({
      qrCode: result.qrCode,
    });
  } finally {
    res.clearCookie('mfaReauthToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1/auth/mfa',
    });
  }
};

const startMfaSetupWithPassword = async (req, res) => {
  const body = requireBody(req);
  const currentPassword = requirePassword(body.currentPassword, 'Current password');

  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    throw new HttpError('Current password is required', 400);
  }

  const serviceResult = await startPasswordMfaSetupService({
    userId: req.userId,
    currentPassword,
  });

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    qrCode: result.qrCode,
  });
};

const confirmMfaSetup = async (req, res) => {
  const body = requireBody(req);
  const code = requireMfaCode(body.code);

  const serviceResult = await confirmMfaSetupService(req.userId, code);

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    message: 'MFA enabled successfully',
    recoveryCodes: result.recoveryCodes,
  });
};

const regenerateRecoveryCodes = async (req, res) => {
  const body = requireBody(req);
  const { code, recoveryCode } = body;

  const hasTotpCode = typeof code === 'string' && code.length > 0;
  const hasRecoveryCode =
    typeof recoveryCode === 'string' && recoveryCode.length > 0;

  if (hasTotpCode === hasRecoveryCode) {
    throw new HttpError('Provide exactly one MFA verification method', 400);
  }

  if (hasTotpCode) requireMfaCode(code);

  const serviceResult = await regenerateRecoveryCodesService({
    userId: req.userId,
    code,
    recoveryCode,
  });

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    message: 'Recovery codes regenerated successfully',
    recoveryCodes: result.recoveryCodes,
  });
};

const verifyMfa = async (req, res) => {
  const body = requireBody(req);
  const { challenge, code, recoveryCode } = body;

  if (typeof challenge !== 'string' || challenge.length === 0) {
    throw new HttpError('MFA challenge is required', 400);
  }

  if (challenge.length > 256) {
    throw new HttpError('Invalid MFA challenge', 400);
  }

  const hasTotpCode = typeof code === 'string' && code.length > 0;
  const hasRecoveryCode =
    typeof recoveryCode === 'string' && recoveryCode.length > 0;

  if (hasTotpCode === hasRecoveryCode) {
    throw new HttpError('Provide exactly one MFA verification method', 400);
  }

  if (hasTotpCode) requireMfaCode(code);

  const serviceResult = hasRecoveryCode
    ? await verifyRecoveryCodeService(challenge, recoveryCode)
    : await verifyMfaService(challenge, code);

  const result = mapMfaLifecycleError(serviceResult);

  if (!result.accessToken || !result.refreshToken || !result.user) {
    throw new HttpError('Unable to complete MFA login', 500);
  }

  return res
    .status(200)
    .set('Cache-Control', 'no-store')
    .cookie('refreshToken', result.refreshToken, refreshCookieOptions)
    .json({
      message: 'MFA verification successful',
      accessToken: result.accessToken,
      user: toPublicUser(result.user),
    });
};

const startMfaReplacement = async (req, res) => {
  const body = requireBody(req);
  const { code } = body;

  requireMfaCode(code, 'current MFA code');

  const serviceResult = await startMfaReplacementService(req.userId, code);

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    qrCode: result.qrCode,
    expiresInSeconds: result.expiresInSeconds,
  });
};

const confirmMfaReplacement = async (req, res) => {
  const body = requireBody(req);
  const { code } = body;

  requireMfaCode(code, 'new MFA code');

  const serviceResult = await confirmMfaReplacementService(req.userId, code);

  mapMfaLifecycleError(serviceResult);

  return res.status(200).json({
    message: 'MFA authenticator replaced successfully',
  });
};

const disableMfa = async (req, res) => {
  const body = requireBody(req);
  const { currentPassword, code } = body;

  requireMfaCode(code);

  const serviceResult = await disableMfaService({
    userId: req.userId,
    currentPassword,
    code,
    authMethods: req.authMethods,
  });

  mapMfaLifecycleError(serviceResult);

  return res
    .clearCookie('refreshToken', refreshCookieOptions)
    .status(200)
    .set('Cache-Control', 'no-store')
    .json({
      message: 'MFA disabled successfully',
    });
};

const startGoogleMfaReauth = async (req, res) => {
  const result = await startGoogleMfaReauthService(req.userId);

  if (!result || result.error) {
    throw new HttpError('Google reauthentication is unavailable', 400);
  }

  return res
    .cookie('googleMfaReauthState', result.state, googleMfaStateCookieOptions)
    .redirect(result.url);
};

const completeGoogleMfaReauth = async (req, res) => {
  const { code, state } = req.query;

  try {
    const result = await completeGoogleMfaReauthService({
      code,
      state,
      savedState: req.cookies.googleMfaReauthState,
    });

    mapGoogleMfaReauthError(result);

    return res
      .cookie('mfaReauthToken', result.reauthToken, mfaReauthCookieOptions)
      .status(200)
      .set('Cache-Control', 'no-store')
      .json({
        message: 'Fresh Google authentication completed',
      });
  } finally {
    res.clearCookie('googleMfaReauthState', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/api/v1/auth',
    });
  }
};

export {
  registerUser,
  loginUser,
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
};
