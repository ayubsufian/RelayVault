import crypto from 'crypto';
import { env } from '../config/env.js';

const getRequestMetadata = (req) => ({
  ipHash: req.ip
    ? crypto
        .createHmac('sha256', env.accessTokenSecret)
        .update(req.ip, 'utf8')
        .digest('hex')
    : null,
  userAgent: req.get('user-agent')?.slice(0, 500) || null,
});

export default getRequestMetadata;
