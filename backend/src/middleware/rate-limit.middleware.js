import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import redisClient from '../config/redis.js';

const createRateLimiter = ({ windowMs, limit, message, includeUser = false }) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => {
      const routeKey = req.route?.path || req.baseUrl || 'unknown-route';
      const userKey = includeUser && req.userId ? `:${req.userId}` : '';
      const ipKey = req.ip ? ipKeyGenerator(req.ip) : 'unknown';
      return `${ipKey}:${routeKey}${userKey}`;
    },
    store: new RedisStore({
      sendCommand: (...command) => redisClient.sendCommand(command),
    }),
    handler: (req, res) => {
      res.status(429).json({ message });
    },
  });

const globalApiLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  message: 'Too many requests. Try again later.',
});

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: 'Too many authentication attempts. Try again later.',
});

const mfaLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: 'Too many MFA attempts. Try again later.',
});

const recoveryLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: 'Too many recovery attempts. Try again later.',
});

const handoffLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: 'Too many handoff attempts. Try again later.',
  includeUser: true,
});

export {
  globalApiLimiter,
  authLimiter,
  mfaLimiter,
  recoveryLimiter,
  handoffLimiter,
};
