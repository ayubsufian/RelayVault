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

const registerUser = async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !password || !email) {
    throw new HttpError('All fields are important.', 400);
  }

  const user = await registerUserService(username, email, password);
  if (!user) {
    throw new HttpError('User already exists', 409);
  }

  return res.status(201).json({
    message: 'User registered',
    user: { id: user._id, email: user.email, username: user.username },
  });
};

const refreshCookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/api/v1/auth',
};

const loginUser = async (req, res) => {
  const { password, email } = req.body;

  if (!email || !password) {
    throw new HttpError('Email and password are required', 400);
  }

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

  return res
    .status(200)
    .clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1/auth',
    })
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

  return res
    .status(200)
    .clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/api/v1/auth',
    })
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
  const { email } = req.body;

  if (!email) {
    throw new HttpError('Email is required', 400);
  }

  await requestPasswordResetService(email);

  // Do not reveal whether the email exists.
  return res.status(200).json({
    message: 'If the account exists, a reset link has been sent',
  });
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    throw new HttpError('Token and new password are required', 400);
  }

  const success = await resetPasswordService(token, newPassword);

  if (!success) {
    throw new HttpError('Invalid or expired reset token', 400);
  }

  return res.status(200).json({
    message: 'Password reset successfully',
  });
};

const changePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    throw new HttpError('Current and new passwords are required', 400);
  }

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
  const { email } = req.body;

  if (!email) {
    throw new HttpError('Email is required', 400);
  }

  await resendVerificationEmailService(email);

  return res.status(200).json({
    message:
      'If the account exists and is unverified, a verification email has been sent',
  });
};

const googleLogin = (req, res) => {
  const { url, state, verifier } = getGoogleAuthorizationUrlService();

  const options = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
    path: '/api/v1/auth',
  };

  return res
    .cookie('googleState', state, options)
    .cookie('googleVerifier', verifier, options)
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

    if (result.invalidRequest) {
      throw new HttpError('Invalid Google authentication request', 400);
    }

    if (result.invalidState) {
      throw new HttpError('Invalid OAuth state', 400);
    }

    if (result.invalidGoogleRequest) {
      throw new HttpError('Google authentication request failed', 400);
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

  if (result.invalid) {
    throw new HttpError('Invalid or expired linking request', 400);
  }

  if (result.invalidGoogleRequest) {
    throw new HttpError('Google linking request failed', 400);
  }

  if (result.invalidGoogleToken) {
    throw new HttpError('Google did not return a valid ID token', 401);
  }

  if (result.unverifiedGoogleEmail) {
    throw new HttpError('Google account email is not verified', 401);
  }

  if (result.alreadyLinked) {
    throw new HttpError('This Google account is already linked', 409);
  }

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
  const { currentPassword } = req.body;

  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    throw new HttpError('Current password is required', 400);
  }

  const serviceResult = await startPasswordMfaSetupService({
    userId: req.userId,
    currentPassword,
  });

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).json({
    qrCode: result.qrCode,
  });
};

const confirmMfaSetup = async (req, res) => {
  const { code } = req.body;

  const serviceResult = await confirmMfaSetupService(req.userId, code);

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    message: 'MFA enabled successfully',
    recoveryCodes: result.recoveryCodes,
  });
};

const regenerateRecoveryCodes = async (req, res) => {
  const { code, recoveryCode } = req.body;

  const hasTotpCode = typeof code === 'string' && code.length > 0;
  const hasRecoveryCode =
    typeof recoveryCode === 'string' && recoveryCode.length > 0;

  if (hasTotpCode === hasRecoveryCode) {
    throw new HttpError('Provide exactly one MFA verification method', 400);
  }

  if (hasTotpCode && !/^\d{6}$/.test(code)) {
    throw new HttpError('A valid six-digit MFA code is required', 400);
  }

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
  const { challenge, code, recoveryCode } = req.body;

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

  if (hasTotpCode && !/^\d{6}$/.test(code)) {
    throw new HttpError('A valid six-digit MFA code is required', 400);
  }

  const serviceResult = hasRecoveryCode
    ? await verifyRecoveryCodeService(challenge, recoveryCode)
    : await verifyMfaService(challenge, code);

  const result = mapMfaLifecycleError(serviceResult);

  return res
    .status(200)
    .set('Cache-Control', 'no-store')
    .cookie('refreshToken', result.refreshToken, refreshCookieOptions)
    .json({
      message: 'MFA verification successful',
      accessToken: result.accessToken,
      user: result.user,
    });
};

const startMfaReplacement = async (req, res) => {
  const { code } = req.body;

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    throw new HttpError('A valid current MFA code is required', 400);
  }

  const serviceResult = await startMfaReplacementService(req.userId, code);

  const result = mapMfaLifecycleError(serviceResult);

  return res.status(200).set('Cache-Control', 'no-store').json({
    qrCode: result.qrCode,
    expiresInSeconds: result.expiresInSeconds,
  });
};

const confirmMfaReplacement = async (req, res) => {
  const { code } = req.body;

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    throw new HttpError('A valid new MFA code is required', 400);
  }

  const serviceResult = await confirmMfaReplacementService(req.userId, code);

  mapMfaLifecycleError(serviceResult);

  return res.status(200).json({
    message: 'MFA authenticator replaced successfully',
  });
};

const disableMfa = async (req, res) => {
  const { currentPassword, code } = req.body;

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    throw new HttpError('A valid six-digit MFA code is required', 400);
  }

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

  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 5 * 60 * 1000,
    path: '/api/v1/auth',
  };

  return res
    .cookie('googleMfaReauthState', result.state, cookieOptions)
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

    return res
      .cookie('mfaReauthToken', result.reauthToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 5 * 60 * 1000,
        path: '/api/v1/auth/mfa',
      })
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
