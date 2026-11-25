import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import HttpError from '../utils/http-error.js';
import { MfaReauthGrant } from '../models/mfa-reauth-grant.model.js';
import { hashToken } from '../utils/token.js';

const requireMfaReauth = async (req, res, next) => {
  const token = req.cookies.mfaReauthToken;

  if (!token) {
    throw new HttpError('Fresh Google authentication is required', 401);
  }

  if (typeof req.userId !== 'string' || req.userId.length === 0) {
    throw new HttpError('Authentication is required', 401);
  }

  try {
    const payload = jwt.verify(token, env.mfaReauthSecret, {
      algorithms: ['HS256'],
    });
    const now = Math.floor(Date.now() / 1000);

    if (
      payload.purpose !== 'mfa-reauth' ||
      payload.sub !== req.userId ||
      typeof payload.sub !== 'string' ||
      payload.sub.length === 0 ||
      typeof payload.jti !== 'string' ||
      payload.jti.length === 0 ||
      typeof payload.auth_time !== 'number' ||
      !Number.isFinite(payload.auth_time) ||
      payload.auth_time > now ||
      now - payload.auth_time > 5 * 60
    ) {
      throw new Error('Invalid MFA reauthentication grant');
    }

    const tokenHash = hashToken(token);

    // The service atomically consumes this one-time grant after validation.
    const grant = await MfaReauthGrant.findOne({
      userId: req.userId,
      jti: payload.jti,
      tokenHash,
      usedAt: null,
      expiresAt: { $gt: new Date() },
    });

    if (!grant) {
      throw new Error('Expired or already-used grant');
    }

    req.mfaReauthUserId = payload.sub;
    req.mfaReauthJti = payload.jti;
    req.mfaReauthTokenHash = tokenHash;
    next();
  } catch {
    throw new HttpError('Fresh Google authentication is required', 401);
  }
};

export default requireMfaReauth;
