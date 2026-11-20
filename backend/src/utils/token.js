import crypto from 'crypto';

const hashToken = (token) => {
  if (typeof token !== 'string' || token.length === 0) {
    throw new TypeError('Token must be a non-empty string');
  }

  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
};

export { hashToken };
