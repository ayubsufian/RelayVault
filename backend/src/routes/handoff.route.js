import { Router } from 'express';
import {
  createHandoff,
  getHandoffs,
  getHandoff,
  updateHandoff,
  revokeHandoff,
  shareHandoff,
  redeemHandoff,
} from '../controllers/handoff.controller.js';
import requireAuth from '../middleware/auth.middleware.js';
import requireRecentAuth from '../middleware/recent-auth.middleware.js';
import { handoffLimiter } from '../middleware/rate-limit.middleware.js';

const router = Router();

router.post('/', requireAuth, createHandoff);
router.get('/', requireAuth, getHandoffs);
router.post('/redeem/:token', handoffLimiter, redeemHandoff);
router.get('/:id', requireAuth, getHandoff);
router.patch('/:id', requireAuth, requireRecentAuth, updateHandoff);
router.post('/:id/share', requireAuth, requireRecentAuth, handoffLimiter, shareHandoff);
router.post('/:id/revoke', requireAuth, requireRecentAuth, revokeHandoff);

export default router;
