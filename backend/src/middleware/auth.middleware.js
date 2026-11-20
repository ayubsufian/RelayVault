import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

const requireAuth = (req, res, next) => {
  const authorization = req.headers.authorization;

  if (!authorization?.startsWith('Bearer ')) {
    return res.status(401).json({
      message: 'Access token is required',
    });
  }

  const accessToken = authorization.split(' ')[1];

  try {
    const payload = jwt.verify(accessToken, env.accessTokenSecret);

    req.userId = payload.sub;
    req.authTime = payload.auth_time;
    req.authMethods = payload.amr || [];
    next();
  } catch {
    return res.status(401).json({
      message: 'Invalid or expired access token',
    });
  }
};

export default requireAuth;
