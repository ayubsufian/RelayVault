import HttpError from '../utils/http-error.js';

const MAX_RECENT_AUTH_AGE_SECONDS = 10 * 60;

const requireRecentAuth = (req, res, next) => {
  const authTime = req.authTime;
  const now = Math.floor(Date.now() / 1000);

  if (
    typeof authTime !== 'number' ||
    !Number.isFinite(authTime) ||
    authTime > now ||
    now - authTime > MAX_RECENT_AUTH_AGE_SECONDS
  ) {
    throw new HttpError('Recent authentication is required', 401);
  }

  next();
};

export default requireRecentAuth;
