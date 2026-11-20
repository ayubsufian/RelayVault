import { User } from '../models/user.model.js';
import { Session } from '../models/session.model.js';
import { PasswordReset } from '../models/password-reset.model.js';
import { EmailVerification } from '../models/email-verification.model.js';
import { OAuthLink } from '../models/oauth-link.model.js';
import { MfaFactor } from '../models/mfa-factor.model.js';
import { MfaChallenge } from '../models/mfa-challenge.model.js';
import { MfaRecoveryCode } from '../models/mfa-recovery-code.model.js';
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
  sendMfaChangedEmail,
} from './email.service.js';
import { env } from '../config/env.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import ServiceError from '../utils/service-error.js';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import { encryptSecret, decryptSecret } from '../utils/mfa-crypto.js';
import { hashToken } from '../utils/token.js';
import { MFA_ERROR } from '../utils/mfa-error.js';
import mongoose from 'mongoose';

const registerUserService = async (username, email, password) => {
  const exists = await findUserByEmailService(email);

  if (exists) {
    return null;
  }

  const user = await User.create({
    username,
    email,
    password,
  });

  await sendVerificationEmailService(user);

  return user;
};

const loginUserService = async (email, password) => {
  const user = await findUserByEmailService(email);

  if (!user) {
    return null;
  }

  const passwordMatches = await user.comparePassword(password);

  if (!passwordMatches) {
    return null;
  }

  if (!user.isEmailVerified) {
    return {
      unverified: true,
    };
  }

  const factor = await MfaFactor.findOne({
    userId: user._id,
    enabledAt: { $ne: null },
  });

  if (factor) {
    const rawChallenge = crypto.randomBytes(32).toString('hex');
    const challengeHash = hashToken(rawChallenge);

    await MfaChallenge.create({
      userId: user._id,
      challengeHash,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    return {
      mfaRequired: true,
      mfaChallenge: rawChallenge,
    };
  }

  return createApplicationTokens(user, ['pwd']);
};

const findUserByEmailService = (email) => {
  return User.findOne({ email: email.toLowerCase() });
};

const refreshAccessTokenService = async (refreshToken) => {
  let payload;

  try {
    payload = jwt.verify(refreshToken, env.refreshTokenSecret);
  } catch {
    return null;
  }

  const tokenHash = hashToken(refreshToken);

  const session = await Session.findOne({ tokenHash, userId: payload.sub });

  if (!session) {
    return null;
  }

  if (session.revokedAt) {
    await Session.updateMany(
      { userId: session.userId, revokedAt: null },
      { revokedAt: new Date() },
    );

    return null;
  }

  if (session.expiresAt <= new Date()) {
    return null;
  }

  const user = await User.findById(session.userId);

  if (!user) {
    return null;
  }

  const accessToken = jwt.sign(
    { sub: user._id.toString() },
    env.accessTokenSecret,
    { expiresIn: '15m' },
  );

  const newRefreshToken = createRefreshToken(user._id);
  const newTokenHash = hashToken(newRefreshToken);

  session.revokedAt = new Date();
  session.replacedByTokenHash = newTokenHash;

  await session.save();

  try {
    await Session.create({
      userId: user._id,
      tokenHash: hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
  } catch (error) {
    throw new ServiceError(
      'Unable to create a session',
      'SESSION_CREATION_FAILED',
      { cause: error },
    );
  }

  return { accessToken, refreshToken: newRefreshToken };
};

const logoutUserService = async (refreshToken) => {
  const tokenHash = hashToken(refreshToken);

  await Session.findOneAndUpdate(
    {
      tokenHash,
      revokedAt: null,
    },
    {
      revokedAt: new Date(),
    },
  );
};

const createRefreshToken = (userId) => {
  return jwt.sign(
    {
      sub: userId.toString(),
      jti: crypto.randomUUID(),
    },
    env.refreshTokenSecret,
    { expiresIn: '7d' },
  );
};

const logoutAllSessionsService = async (userId) => {
  await Session.updateMany(
    {
      userId,
      revokedAt: null,
    },
    {
      revokedAt: new Date(),
    },
  );
};

const getCurrentUserService = (userId) => {
  return User.findById(userId).select('_id username email createdAt updatedAt');
};

const requestPasswordResetService = async (email) => {
  const user = await findUserByEmailService(email);

  if (!user) {
    return null;
  }

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  await PasswordReset.deleteMany({ userId: user._id });

  const resetRequest = await PasswordReset.create({
    userId: user._id,
    tokenHash,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000),
  });

  try {
    const messageId = await sendPasswordResetEmail(user.email, rawToken);
    console.log(`Password reset email sent: ${messageId}`);
  } catch (error) {
    await PasswordReset.deleteOne({
      _id: resetRequest._id,
    });

    throw new ServiceError(
      'Password reset email could not be sent',
      'EMAIL_DELIVERY_FAILED',
      { cause: error },
    );
  }
};

const resetPasswordService = async (rawToken, newPassword) => {
  const resetRequest = await PasswordReset.findOne({
    tokenHash: hashToken(rawToken),
    usedAt: null,
    expiresAt: { $gt: new Date() },
  });

  if (!resetRequest) {
    return false;
  }

  const user = await User.findById(resetRequest.userId);

  if (!user) {
    return false;
  }

  user.password = newPassword;
  await user.save(); // pre-save hook hashes the password

  resetRequest.usedAt = new Date();
  await resetRequest.save();

  await Session.updateMany(
    { userId: user._id, revokedAt: null },
    { revokedAt: new Date() },
  );

  return true;
};

const changePasswordService = async (userId, currentPassword, newPassword) => {
  const user = await User.findById(userId);

  if (!user) {
    return false;
  }

  const matches = await user.comparePassword(currentPassword);

  if (!matches) {
    return false;
  }

  user.password = newPassword;
  await user.save();

  await Session.updateMany(
    { userId, revokedAt: null },
    { revokedAt: new Date() },
  );

  return true;
};

const sendVerificationEmailService = async (user) => {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashToken(rawToken);

  await EmailVerification.deleteMany({
    userId: user._id,
  });

  const verification = await EmailVerification.create({
    userId: user._id,
    tokenHash,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  try {
    const messageId = await sendVerificationEmail(user.email, rawToken);
    console.log(`Verification email sent: ${messageId}`);
  } catch (error) {
    await EmailVerification.deleteOne({
      _id: verification._id,
    });

    throw new ServiceError(
      'Verification email could not be sent',
      'EMAIL_DELIVERY_FAILED',
      { cause: error },
    );
  }
};

const verifyEmailService = async (rawToken) => {
  const verification = await EmailVerification.findOne({
    tokenHash: hashToken(rawToken),
    usedAt: null,
    expiresAt: { $gt: new Date() },
  });

  if (!verification) {
    return false;
  }

  const user = await User.findById(verification.userId);

  if (!user) {
    return false;
  }

  user.isEmailVerified = true;
  await user.save();

  verification.usedAt = new Date();
  await verification.save();

  return true;
};

const resendVerificationEmailService = async (email) => {
  const user = await findUserByEmailService(email);

  // Do not reveal whether the account exists.
  if (!user || user.isEmailVerified) {
    return;
  }

  await sendVerificationEmailService(user);
};

const createPkcePair = () => {
  const verifier = crypto.randomBytes(32).toString('base64url');

  const challenge = crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');

  return { verifier, challenge };
};

const googleClient = new OAuth2Client(
  env.googleClientId,
  env.googleClientSecret,
  env.googleRedirectUri,
);

const getGoogleAuthorizationUrlService = () => {
  const state = crypto.randomBytes(32).toString('base64url');
  const { verifier, challenge } = createPkcePair();

  const url = googleClient.generateAuthUrl({
    access_type: 'online',
    scope: ['openid', 'email', 'profile'],
    include_granted_scopes: true,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });

  return {
    url,
    state,
    verifier,
  };
};

const buildUsernameBase = (googleProfile) => {
  const source = googleProfile.name || googleProfile.email.split('@')[0];

  return (
    source
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '')
      .slice(0, 20) || 'user'
  );
};

const createGoogleUser = async (googleProfile) => {
  const base = buildUsernameBase(googleProfile);
  let lastError;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const suffix = attempt === 0 ? '' : crypto.randomBytes(3).toString('hex');

    const username = `${base}${suffix}`.slice(0, 30);

    try {
      return await User.create({
        googleId: googleProfile.sub,
        email: googleProfile.email.toLowerCase(),
        username,
        isEmailVerified: true,
      });
    } catch (error) {
      const duplicateUsername =
        error.code === 11000 && error.keyPattern?.username;

      if (!duplicateUsername) {
        throw error;
      }
      lastError = error;
    }
  }

  throw new ServiceError(
    'Could not generate a unique username',
    'USERNAME_GENERATION_FAILED',
    { cause: lastError },
  );
};

const completeGoogleLoginService = async ({
  code,
  state,
  savedState,
  verifier,
}) => {
  if (!code || !state || !savedState || !verifier) {
    return { invalidRequest: true };
  }

  if (state !== savedState) {
    return { invalidState: true };
  }

  let tokens;

  try {
    ({ tokens } = await googleClient.getToken({
      code,
      codeVerifier: verifier,
      redirect_uri: env.googleRedirectUri,
    }));
  } catch {
    return { invalidGoogleRequest: true };
  }

  if (!tokens.id_token) {
    return { invalidGoogleToken: true };
  }

  let payload;

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: env.googleClientId,
    });

    payload = ticket.getPayload();
  } catch {
    return { invalidGoogleToken: true };
  }

  if (!payload?.sub || !payload.email || !payload.email_verified) {
    return { unverifiedGoogleEmail: true };
  }

  return loginWithGoogleService(payload);
};

const createApplicationTokens = async (user, authMethods = ['pwd']) => {
  const accessToken = jwt.sign(
    {
      sub: user._id.toString(),
      auth_time: Math.floor(Date.now() / 1000),
      amr: authMethods,
    },
    env.accessTokenSecret,
    { expiresIn: '15m' },
  );

  const refreshToken = createRefreshToken(user._id);

  try {
    await Session.create({
      userId: user._id,
      tokenHash: hashToken(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
  } catch (error) {
    throw new ServiceError(
      'Unable to create a session',
      'SESSION_CREATION_FAILED',
      { cause: error },
    );
  }

  return {
    user,
    accessToken,
    refreshToken,
  };
};

const loginWithGoogleService = async (googleProfile) => {
  let user = await User.findOne({
    googleId: googleProfile.sub,
  });

  if (!user) {
    const existingEmailUser = await findUserByEmailService(googleProfile.email);

    if (existingEmailUser) {
      return {
        emailConflict: true,
      };
    }

    user = await createGoogleUser(googleProfile);
  }

  const tokens = await createApplicationTokens(user, ['google']);

  return {
    emailConflict: false,
    ...tokens,
  };
};

const startGoogleLinkService = async (userId) => {
  const state = crypto.randomBytes(32).toString('base64url');
  const { verifier, challenge } = createPkcePair();

  await OAuthLink.create({
    userId,
    state,
    codeVerifier: verifier,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });

  const url = googleClient.generateAuthUrl({
    access_type: 'online',
    scope: ['openid', 'email', 'profile'],
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'select_account',
  });

  return url;
};

const completeGoogleLinkService = async (code, state) => {
  if (!code || !state) {
    return { invalid: true };
  }

  const transaction = await OAuthLink.findOne({ state });

  if (!transaction || transaction.expiresAt <= new Date()) {
    if (transaction) {
      await OAuthLink.deleteOne({ _id: transaction._id });
    }

    return { invalid: true };
  }

  try {
    let tokens;

    try {
      ({ tokens } = await googleClient.getToken({
        code,
        codeVerifier: transaction.codeVerifier,
        redirect_uri: env.googleRedirectUri,
      }));
    } catch {
      return { invalidGoogleRequest: true };
    }

    if (!tokens.id_token) {
      return { invalidGoogleToken: true };
    }

    let profile;

    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: tokens.id_token,
        audience: env.googleClientId,
      });

      profile = ticket.getPayload();
    } catch {
      return { invalidGoogleToken: true };
    }

    if (!profile?.sub || !profile.email || !profile.email_verified) {
      return { unverifiedGoogleEmail: true };
    }

    const linkedUser = await User.findOne({
      googleId: profile.sub,
    });

    if (
      linkedUser &&
      linkedUser._id.toString() !== transaction.userId.toString()
    ) {
      return { alreadyLinked: true };
    }

    const user = await User.findById(transaction.userId);

    if (!user) {
      return { invalid: true };
    }

    if (user.googleId && user.googleId !== profile.sub) {
      return { alreadyLinked: true };
    }

    user.googleId = profile.sub;
    user.isEmailVerified = true;
    await user.save();

    return { success: true };
  } finally {
    await OAuthLink.deleteOne({ _id: transaction._id });
  }
};

const isValidTotpCode = (code) => {
  return typeof code === 'string' && /^\d{6}$/.test(code);
};

const normalizeRecoveryCode = (code) => {
  if (typeof code !== 'string') {
    return null;
  }

  const normalized = code.replace(/[\s-]/g, '').toUpperCase();

  return /^[A-F0-9]{16}$/.test(normalized) ? normalized : null;
};

const createPendingTotpFactor = async (userId, email) => {
  if (!userId || !mongoose.isObjectIdOrHexString(userId)) {
    return { error: MFA_ERROR.INVALID };
  }

  const existingFactor = await MfaFactor.findOne({
    userId,
  });

  if (existingFactor?.enabledAt) {
    return { error: MFA_ERROR.ALREADY_ENABLED };
  }

  const secret = authenticator.generateSecret();

  const otpauthUrl = authenticator.keyuri(email, 'RelayVault', secret);

  const qrCode = await QRCode.toDataURL(otpauthUrl);

  try {
    await MfaFactor.findOneAndUpdate(
      { userId, enabledAt: null },
      {
        $set: {
          type: 'totp',
          secretEncrypted: encryptSecret(secret),
          pendingCreatedAt: new Date(),
        },
        $setOnInsert: {
          userId,
        },
      },
      {
        upsert: true,
        new: true,
        runValidators: true,
      },
    );

    return {
      qrCode,
      expiresInSeconds: 10 * 60,
    };
  } catch (error) {
    if (error.code === 11000 && error.keyPattern?.userId) {
      return { error: MFA_ERROR.ALREADY_ENABLED };
    }

    throw error;
  }
};

const RECOVERY_CODE_COUNT = 10;

const generateRecoveryCode = () => {
  return crypto.randomBytes(8).toString('hex').toUpperCase();
};

const createRecoveryCodesService = async (userId) => {
  const rawCodes = Array.from(
    { length: RECOVERY_CODE_COUNT },
    generateRecoveryCode,
  );

  await MfaRecoveryCode.deleteMany({ userId });

  await MfaRecoveryCode.insertMany(
    rawCodes.map((code) => ({
      userId,
      codeHash: hashToken(code),
    })),
  );

  return rawCodes;
};

const consumeRecoveryCodeService = async (userId, rawCode) => {
  const normalizedCode = normalizeRecoveryCode(rawCode);

  if (!normalizedCode) {
    return null;
  }

  return MfaRecoveryCode.findOneAndUpdate(
    {
      userId,
      codeHash: hashToken(normalizedCode),
      usedAt: null,
    },
    {
      $set: {
        usedAt: new Date(),
      },
    },
    {
      new: true,
    },
  );
};

const verifyRecoveryCodeService = async (rawChallenge, recoveryCode) => {
  const challenge = await MfaChallenge.findOne({
    challengeHash: hashToken(rawChallenge),
  });

  if (!challenge || challenge.usedAt) {
    return { error: MFA_ERROR.INVALID };
  }

  if (challenge.expiresAt <= new Date()) {
    return { error: MFA_ERROR.EXPIRED };
  }

  if (challenge.attempts >= 5) {
    return { error: MFA_ERROR.TOO_MANY_ATTEMPTS };
  }

  await MfaChallenge.updateOne(
    { _id: challenge._id },
    { $inc: { attempts: 1 } },
  );

  const consumedCode = await consumeRecoveryCodeService(
    challenge.userId,
    recoveryCode,
  );

  if (!consumedCode) {
    return { error: MFA_ERROR.INVALID };
  }

  const claimedChallenge = await MfaChallenge.findOneAndUpdate(
    {
      _id: challenge._id,
      usedAt: null,
    },
    {
      $set: {
        usedAt: new Date(),
      },
    },
    { new: true },
  );

  if (!claimedChallenge) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(challenge.userId);

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  return {
    success: true,
    ...(await createApplicationTokens(user, ['pwd', 'recovery'])),
  };
};

const regenerateRecoveryCodesService = async ({
  userId,
  code,
  recoveryCode,
}) => {
  if (!userId || !mongoose.isObjectIdOrHexString(userId)) {
    return { error: MFA_ERROR.INVALID };
  }

  if ((code && recoveryCode) || (!code && !recoveryCode)) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId).select('email');

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  const factor = await MfaFactor.findOne({
    userId,
    enabledAt: { $ne: null },
  });

  if (!factor) {
    return { error: MFA_ERROR.NOT_ENABLED };
  }

  if (code) {
    const result = await verifyCurrentTotpService(userId, code);

    if (result.error) {
      return result;
    }

    if (!result.success) {
      return { error: MFA_ERROR.INVALID };
    }
  } else {
    const consumed = await consumeRecoveryCodeService(userId, recoveryCode);

    if (!consumed) {
      return { error: MFA_ERROR.INVALID };
    }
  }

  const recoveryCodes = await createRecoveryCodesService(userId);

  await Session.updateMany(
    {
      userId,
      revokedAt: null,
    },
    {
      $set: {
        revokedAt: new Date(),
      },
    },
  );

  sendMfaChangedEmail(user.email, 'recovery-codes-regenerated').catch(
    (error) => {
      console.error('Recovery-code notification failed', {
        userId: userId.toString(),
        error,
      });
    },
  );

  return {
    success: true,
    recoveryCodes,
  };
};

const consumeMfaReauthGrantService = async ({ userId, jti, tokenHash }) => {
  if (!userId || !jti || !tokenHash) {
    return false;
  }

  const grant = await MfaReauthGrant.findOneAndUpdate(
    {
      userId,
      jti,
      tokenHash,
      usedAt: null,
      expiresAt: { $gt: new Date() },
    },
    {
      $set: { usedAt: new Date() },
    },
    {
      new: true,
      runValidators: true,
    },
  ).select('_id');

  return Boolean(grant);
};

const startPasswordMfaSetupService = async ({ userId, currentPassword }) => {
  if (!userId || !mongoose.isObjectIdOrHexString(userId)) {
    return { error: MFA_ERROR.INVALID };
  }

  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    return { error: MFA_ERROR.PASSWORD_REQUIRED };
  }

  const user = await User.findById(userId);

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  if (!user.password) {
    return { error: MFA_ERROR.PASSWORD_REQUIRED };
  }

  const passwordMatches = await user.comparePassword(currentPassword);

  if (!passwordMatches) {
    return { error: MFA_ERROR.INVALID };
  }

  return createPendingTotpFactor(user._id, user.email);
};

const startGoogleMfaSetupService = async ({
  userId,
  reauthUserId,
  reauthJti,
  reauthTokenHash,
}) => {
  if (
    !userId ||
    !mongoose.isObjectIdOrHexString(userId) ||
    !reauthUserId ||
    reauthUserId !== userId.toString() ||
    !reauthJti ||
    !reauthTokenHash
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId);

  if (!user || !user.googleId) {
    return { error: MFA_ERROR.INVALID };
  }

  const grant = await consumeMfaReauthGrantService({
    userId,
    jti: reauthJti,
    tokenHash: reauthTokenHash,
  });

  if (!grant) {
    return { error: MFA_ERROR.INVALID };
  }

  return createPendingTotpFactor(user._id, user.email);
};

const confirmMfaSetupService = async (userId, code) => {
  if (
    !userId ||
    !mongoose.isObjectIdOrHexString(userId) ||
    typeof code !== 'string' ||
    !/^\d{6}$/.test(code)
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId).select('email');

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  const factor = await MfaFactor.findOne({
    userId,
    enabledAt: null,
    pendingCreatedAt: {
      $gt: new Date(Date.now() - 10 * 60 * 1000),
    },
  });

  if (!factor) {
    return { error: MFA_ERROR.EXPIRED };
  }

  const secret = decryptSecret(factor.secretEncrypted);
  const isValid = authenticator.verify({
    token: code,
    secret,
  });

  if (!isValid) {
    return { error: MFA_ERROR.INVALID };
  }

  const enabledFactor = await MfaFactor.findOneAndUpdate(
    {
      _id: factor._id,
      userId,
      enabledAt: null,
      pendingCreatedAt: factor.pendingCreatedAt,
    },
    {
      $set: {
        enabledAt: new Date(),
        pendingCreatedAt: null,
        lastUsedStep: null,
      },
    },
    {
      new: true,
      runValidators: true,
    },
  );

  if (!enabledFactor) {
    return { error: MFA_ERROR.INVALID };
  }

  const recoveryCodes = await createRecoveryCodesService(userId);

  await Session.updateMany(
    {
      userId,
      revokedAt: null,
    },
    {
      $set: {
        revokedAt: new Date(),
      },
    },
  );

  sendMfaChangedEmail(user.email, 'enabled').catch((error) => {
    console.error('MFA notification failed', {
      userId: user._id.toString(),
      action: 'enabled',
      error: error.message,
    });
  });

  return {
    success: true,
    recoveryCodes,
  };
};

const verifyCurrentTotpService = async (userId, code) => {
  const factor = await MfaFactor.findOne({
    userId,
    enabledAt: { $ne: null },
  });

  if (!factor) {
    return { error: MFA_ERROR.NOT_ENABLED };
  }

  const secret = decryptSecret(factor.secretEncrypted);
  const currentStep = Math.floor(Date.now() / 30000);

  const valid = authenticator.verify({
    token: code,
    secret,
  });

  if (!valid) {
    return { error: MFA_ERROR.INVALID };
  }

  const claimedFactor = await MfaFactor.findOneAndUpdate(
    {
      _id: factor._id,
      userId,
      enabledAt: { $ne: null },
      lastUsedStep: { $ne: currentStep },
    },
    {
      $set: {
        lastUsedStep: currentStep,
      },
    },
    {
      new: true,
      runValidators: true,
    },
  );

  if (!claimedFactor) {
    return { error: MFA_ERROR.INVALID };
  }

  return { success: true };
};

const verifyMfaService = async (rawChallenge, code) => {
  if (!isValidTotpCode(code)) {
    return { error: MFA_ERROR.INVALID };
  }

  const challenge = await MfaChallenge.findOne({
    challengeHash: hashToken(rawChallenge),
  });

  if (!challenge || challenge.usedAt) {
    return { error: MFA_ERROR.INVALID };
  }

  if (challenge.expiresAt <= new Date()) {
    return { error: MFA_ERROR.EXPIRED };
  }

  if (challenge.attempts >= 5) {
    return { error: MFA_ERROR.TOO_MANY_ATTEMPTS };
  }

  await MfaChallenge.updateOne(
    { _id: challenge._id },
    { $inc: { attempts: 1 } },
  );

  const factor = await MfaFactor.findOne({
    userId: challenge.userId,
    enabledAt: { $ne: null },
  });

  if (!factor) {
    return { error: MFA_ERROR.INVALID };
  }

  const valid = authenticator.verify({
    token: code,
    secret: decryptSecret(factor.secretEncrypted),
  });

  if (!valid) {
    return { error: MFA_ERROR.INVALID };
  }

  const currentStep = Math.floor(Date.now() / 30000);

  const claimedFactor = await MfaFactor.findOneAndUpdate(
    {
      _id: factor._id,
      lastUsedStep: { $ne: currentStep },
    },
    {
      $set: { lastUsedStep: currentStep },
    },
    {
      new: true,
    },
  );

  if (!claimedFactor) {
    return { error: MFA_ERROR.INVALID };
  }

  const claimedChallenge = await MfaChallenge.findOneAndUpdate(
    {
      _id: challenge._id,
      usedAt: null,
    },
    {
      $set: {
        usedAt: new Date(),
      },
    },
    { new: true },
  );

  if (!claimedChallenge) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(challenge.userId);

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  return {
    success: true,
    ...(await createApplicationTokens(user, ['pwd', 'totp'])),
  };
};

const startMfaReplacementService = async (userId, code) => {
  if (
    !userId ||
    !mongoose.isObjectIdOrHexString(userId) ||
    typeof code !== 'string' ||
    !/^\d{6}$/.test(code)
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const currentFactorResult = await verifyCurrentTotpService(userId, code);

  if (currentFactorResult.error) {
    return currentFactorResult;
  }

  const secret = authenticator.generateSecret();
  const otpauthUrl = authenticator.keyuri(
    `user-${userId}`,
    'RelayVault',
    secret,
  );
  const qrCode = await QRCode.toDataURL(otpauthUrl);

  const factor = await MfaFactor.findOneAndUpdate(
    {
      userId,
      enabledAt: { $ne: null },
    },
    {
      $set: {
        pendingSecretEncrypted: encryptSecret(secret),
        pendingCreatedAt: new Date(),
      },
    },
    {
      new: true,
      runValidators: true,
    },
  );

  if (!factor) {
    return { error: MFA_ERROR.NOT_ENABLED };
  }

  return {
    success: true,
    qrCode,
    expiresInSeconds: 10 * 60,
  };
};

const confirmMfaReplacementService = async (userId, code) => {
  if (
    !userId ||
    !mongoose.isObjectIdOrHexString(userId) ||
    typeof code !== 'string' ||
    !/^\d{6}$/.test(code)
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId).select('email');

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  const factor = await MfaFactor.findOne({
    userId,
    enabledAt: { $ne: null },
    pendingSecretEncrypted: { $ne: null },
    pendingCreatedAt: {
      $gt: new Date(Date.now() - 10 * 60 * 1000),
    },
  });

  if (!factor) {
    return { error: MFA_ERROR.EXPIRED };
  }

  const pendingSecret = decryptSecret(factor.pendingSecretEncrypted);

  const valid = authenticator.verify({
    token: code,
    secret: pendingSecret,
  });

  if (!valid) {
    return { error: MFA_ERROR.INVALID };
  }

  const updatedFactor = await MfaFactor.findOneAndUpdate(
    {
      _id: factor._id,
      userId,
      enabledAt: { $ne: null },
      pendingSecretEncrypted: factor.pendingSecretEncrypted,
      pendingCreatedAt: factor.pendingCreatedAt,
    },
    {
      $set: {
        secretEncrypted: factor.pendingSecretEncrypted,
        pendingSecretEncrypted: null,
        pendingCreatedAt: null,
        lastUsedStep: null,
      },
    },
    {
      new: true,
      runValidators: true,
    },
  );

  if (!updatedFactor) {
    return { error: MFA_ERROR.INVALID };
  }

  await Session.updateMany(
    {
      userId,
      revokedAt: null,
    },
    {
      $set: {
        revokedAt: new Date(),
      },
    },
  );

  sendMfaChangedEmail(user.email, 'replaced').catch((error) => {
    console.error('MFA replacement notification failed', {
      userId: userId.toString(),
      error,
    });
  });

  return { success: true };
};

const disableMfaService = async ({
  userId,
  currentPassword,
  code,
  authMethods = [],
}) => {
  if (
    !userId ||
    !mongoose.isObjectIdOrHexString(userId) ||
    typeof code !== 'string' ||
    !/^\d{6}$/.test(code)
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId).select('email password');

  if (!user) {
    return { error: MFA_ERROR.INVALID };
  }

  const factor = await MfaFactor.findOne({
    userId,
    enabledAt: { $ne: null },
  });

  if (!factor) {
    return { error: MFA_ERROR.NOT_ENABLED };
  }

  const hasPasswordAuth = authMethods.includes('pwd');
  const hasGoogleAuth = authMethods.includes('google');

  if (hasPasswordAuth) {
    if (
      typeof currentPassword !== 'string' ||
      currentPassword.length === 0 ||
      !user.password
    ) {
      return { error: MFA_ERROR.PASSWORD_REQUIRED };
    }

    const passwordMatches = await user.comparePassword(currentPassword);

    if (!passwordMatches) {
      return { error: MFA_ERROR.INVALID };
    }
  } else if (!hasGoogleAuth) {
    return { error: MFA_ERROR.INVALID };
  }

  const secret = decryptSecret(factor.secretEncrypted);
  const currentStep = Math.floor(Date.now() / 30000);

  const codeValid = authenticator.verify({
    token: code,
    secret,
  });

  if (!codeValid) {
    return { error: MFA_ERROR.INVALID };
  }

  const claimedFactor = await MfaFactor.findOneAndUpdate(
    {
      _id: factor._id,
      userId,
      enabledAt: { $ne: null },
      lastUsedStep: { $ne: currentStep },
    },
    {
      $set: { lastUsedStep: currentStep },
    },
    {
      new: true,
      runValidators: true,
    },
  );

  if (!claimedFactor) {
    return { error: MFA_ERROR.INVALID };
  }

  await MfaFactor.deleteOne({
    _id: factor._id,
    userId,
  });

  await MfaRecoveryCode.deleteMany({ userId });

  await Session.updateMany(
    { userId, revokedAt: null },
    {
      $set: {
        revokedAt: new Date(),
      },
    },
  );

  sendMfaChangedEmail(user.email, 'disabled').catch((error) => {
    console.error('MFA disable notification failed', {
      userId: userId.toString(),
      error,
    });
  });

  return { success: true };
};

const startGoogleMfaReauthService = async (userId) => {
  if (!userId || !mongoose.isObjectIdOrHexString(userId)) {
    return { error: MFA_ERROR.INVALID };
  }

  const user = await User.findById(userId);

  if (!user || !user.googleId) {
    return { error: MFA_ERROR.INVALID };
  }

  const state = crypto.randomBytes(32).toString('base64url');
  const { verifier, challenge } = createPkcePair();

  await OAuthLink.create({
    userId,
    state,
    codeVerifier: verifier,
    purpose: 'mfa-reauth',
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  });

  const url = googleClient.generateAuthUrl({
    access_type: 'online',
    scope: ['openid', 'email', 'profile'],
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'login',
  });

  return { success: true, url, state };
};

const completeGoogleMfaReauthService = async ({ code, state, savedState }) => {
  if (
    typeof code !== 'string' ||
    code.length === 0 ||
    typeof state !== 'string' ||
    state.length === 0 ||
    typeof savedState !== 'string' ||
    savedState.length === 0 ||
    state !== savedState
  ) {
    return { error: MFA_ERROR.INVALID };
  }

  const now = new Date();

  const transaction = await OAuthLink.findOneAndUpdate(
    {
      state,
      purpose: 'mfa-reauth',
      claimedAt: null,
      expiresAt: { $gt: now },
    },
    {
      $set: {
        claimedAt: now,
      },
    },
    {
      new: true,
    },
  );

  if (!transaction) {
    return { error: MFA_ERROR.INVALID };
  }

  try {
    let tokens;

    try {
      ({ tokens } = await googleClient.getToken({
        code,
        codeVerifier: transaction.codeVerifier,
        redirect_uri: env.googleMfaReauthRedirectUri,
      }));
    } catch {
      return { error: MFA_ERROR.INVALID };
    }

    if (!tokens.id_token) {
      return { error: MFA_ERROR.INVALID };
    }

    let payload;

    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: tokens.id_token,
        audience: env.googleClientId,
      });

      payload = ticket.getPayload();
    } catch {
      return { error: MFA_ERROR.INVALID };
    }

    if (
      !payload?.sub ||
      typeof payload.email !== 'string' ||
      payload.email.length === 0 ||
      payload.email_verified !== true
    ) {
      return { error: MFA_ERROR.INVALID };
    }

    if (
      typeof payload.auth_time !== 'number' ||
      !Number.isFinite(payload.auth_time)
    ) {
      return { error: MFA_ERROR.INVALID };
    }

    const googleAuthAge = Math.floor(Date.now() / 1000) - payload.auth_time;

    if (googleAuthAge < 0 || googleAuthAge > 5 * 60) {
      return { error: MFA_ERROR.EXPIRED };
    }

    const user = await User.findById(transaction.userId);

    if (!user || user.googleId !== payload.sub) {
      return { error: MFA_ERROR.INVALID };
    }

    const jti = crypto.randomUUID();

    const reauthToken = jwt.sign(
      {
        sub: user._id.toString(),
        purpose: 'mfa-reauth',
        jti,
        auth_time: payload.auth_time,
      },
      env.mfaReauthSecret,
      { expiresIn: '5m' },
    );

    await MfaReauthGrant.create({
      userId: user._id,
      jti,
      tokenHash: hashToken(reauthToken),
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    });

    return {
      success: true,
      reauthToken,
    };
  } finally {
    await OAuthLink.deleteOne({
      _id: transaction._id,
    });
  }
};

export {
  registerUserService,
  loginUserService,
  refreshAccessTokenService,
  logoutUserService,
  logoutAllSessionsService,
  getCurrentUserService,
  requestPasswordResetService,
  resetPasswordService,
  changePasswordService,
  sendVerificationEmailService,
  verifyEmailService,
  resendVerificationEmailService,
  getGoogleAuthorizationUrlService,
  completeGoogleLoginService,
  loginWithGoogleService,
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
};
