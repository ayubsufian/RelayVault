import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import HttpError from '../utils/http-error.js';

const requireAuth = (req, res, next) => {
  const authorization = req.headers.authorization;

  if (typeof authorization !== 'string') {
    throw new HttpError('Access token is required', 401);
  }

  const parts = authorization.trim().split(/\s+/);

  if (parts.length !== 2 || parts[0] !== 'Bearer' || !parts[1]) {
    throw new HttpError('Access token is required', 401);
  }

  try {
    const payload = jwt.verify(parts[1], env.accessTokenSecret, {
      algorithms: ['HS256'],
    });
    const now = Math.floor(Date.now() / 1000);

    if (
      typeof payload.sub !== 'string' ||
      payload.sub.length === 0 ||
      typeof payload.auth_time !== 'number' ||
      !Number.isFinite(payload.auth_time) ||
      payload.auth_time > now ||
      !Array.isArray(payload.amr) ||
      payload.amr.some((method) => typeof method !== 'string')
    ) {
      throw new Error('Invalid access-token claims');
    }

    req.userId = payload.sub;
    req.authTime = payload.auth_time;
    req.authMethods = payload.amr;
    next();
  } catch {
    throw new HttpError('Invalid or expired access token', 401);
  }
};

export default requireAuth;
