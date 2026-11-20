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

  try {
    const payload = jwt.verify(token, env.mfaReauthSecret);

    if (
      payload.purpose !== 'mfa-reauth' ||
      payload.sub !== req.userId ||
      !payload.jti
    ) {
      throw new Error('Invalid MFA reauthentication grant');
    }

    const grant = await MfaReauthGrant.findOne({
      userId: req.userId,
      jti: payload.jti,
      tokenHash: hashToken(token),
      usedAt: null,
      expiresAt: { $gt: new Date() },
    });

    if (!grant) {
      throw new Error('Expired or already-used grant');
    }

    req.mfaReauthUserId = payload.sub;
    req.mfaReauthJti = payload.jti;
    req.mfaReauthTokenHash = hashToken(token);
    next();
  } catch {
    throw new HttpError('Fresh Google authentication is required', 401);
  }
};

export default requireMfaReauth;
