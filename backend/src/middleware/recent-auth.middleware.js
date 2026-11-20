import HttpError from '../utils/http-error.js';

const requireRecentAuth = (req, res, next) => {
  const maxAge = 10 * 60;
  const now = Math.floor(Date.now() / 1000);

  if (!req.authTime || now - req.authTime > maxAge) {
    throw new HttpError('Recent authentication is required', 401);
  }

  next();
};

export default requireRecentAuth;
