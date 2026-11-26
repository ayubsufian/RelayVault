import crypto from 'crypto';
import mongoose from 'mongoose';
import { Handoff } from '../models/handoff.model.js';
import { HandoffToken } from '../models/handoff-token.model.js';
import { HandoffEvent } from '../models/handoff-event.model.js';
import { enqueueHandoffEmail } from './email-outbox.service.js';
import { EmailOutbox } from '../models/email-outbox.model.js';
import { encryptHandoff, decryptHandoff } from '../utils/secret-crypto.js';
import { hashToken } from '../utils/token.js';
import { env } from '../config/env.js';
import ServiceError from '../utils/service-error.js';

const MAX_TITLE_LENGTH = 120;
const MAX_INSTRUCTIONS_LENGTH = 20_000;
const MAX_HANDOFF_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;

const isValidId = (value) => mongoose.isObjectIdOrHexString(value);
const normalizeText = (value) =>
  typeof value === 'string' ? value.trim() : '';
const normalizeEmail = (value) => normalizeText(value).toLowerCase();
const isValidEmail = (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

const assertOwnerId = (ownerId) => {
  if (!isValidId(ownerId))
    throw new ServiceError('Invalid owner ID', 'HANDOFF_INVALID_ID');
};

const assertHandoffId = (handoffId) => {
  if (!isValidId(handoffId))
    throw new ServiceError('Invalid handoff ID', 'HANDOFF_INVALID_ID');
};

const parseFutureExpiry = (value) => {
  const expiresAt = new Date(value);
  const now = Date.now();

  if (
    Number.isNaN(expiresAt.getTime()) ||
    expiresAt.getTime() <= now ||
    expiresAt.getTime() > now + MAX_HANDOFF_LIFETIME_MS
  ) {
    throw new ServiceError(
      'Expiration must be a future date within 30 days',
      'HANDOFF_VALIDATION_FAILED',
    );
  }

  return expiresAt;
};

const getEffectiveStatus = (handoff) => {
  if (handoff.status === 'revoked') return 'revoked';
  if (handoff.viewedAt) return 'viewed';
  if (handoff.expiresAt <= new Date()) return 'expired';
  return handoff.status;
};

const toOwnerResponse = (handoff) => ({
  id: handoff._id,
  title: handoff.title,
  recipientEmail: handoff.recipientEmail,
  expiresAt: handoff.expiresAt,
  status: getEffectiveStatus(handoff),
  viewedAt: handoff.viewedAt,
  sharedAt: handoff.sharedAt,
  revokedAt: handoff.revokedAt,
  createdAt: handoff.createdAt,
  updatedAt: handoff.updatedAt,
});

const addEvent = async (handoffId, type, metadata = {}, dbSession = null) => {
  const event = {
    handoffId,
    type,
    ipHash: metadata.ipHash || null,
    userAgent: metadata.userAgent || null,
  };

  if (dbSession) {
    const [createdEvent] = await HandoffEvent.create([event], {
      session: dbSession,
    });
    return createdEvent;
  } else {
    return HandoffEvent.create(event);
  }
};

const createRawHandoffToken = () =>
  crypto.randomBytes(32).toString('base64url');

const createHandoffService = async ({
  ownerId,
  title,
  instructions,
  recipientEmail,
  expiresAt,
}) => {
  assertOwnerId(ownerId);
  const normalizedTitle = normalizeText(title);
  const normalizedInstructions = normalizeText(instructions);
  const normalizedEmail = normalizeEmail(recipientEmail);

  if (!normalizedTitle || normalizedTitle.length > MAX_TITLE_LENGTH) {
    throw new ServiceError(
      'Title must be between 1 and 120 characters',
      'HANDOFF_VALIDATION_FAILED',
    );
  }
  if (
    !normalizedInstructions ||
    normalizedInstructions.length > MAX_INSTRUCTIONS_LENGTH
  ) {
    throw new ServiceError(
      'Instructions must be between 1 and 20,000 characters',
      'HANDOFF_VALIDATION_FAILED',
    );
  }
  if (!isValidEmail(normalizedEmail)) {
    throw new ServiceError(
      'A valid recipient email is required',
      'HANDOFF_VALIDATION_FAILED',
    );
  }

  const dbSession = await mongoose.startSession();
  let handoff;

  try {
    await dbSession.withTransaction(async () => {
      [handoff] = await Handoff.create(
        [{
          ownerId,
          title: normalizedTitle,
          instructionsEncrypted: encryptHandoff(normalizedInstructions),
          recipientEmail: normalizedEmail,
          expiresAt: parseFutureExpiry(expiresAt),
          status: 'draft',
        }],
        { session: dbSession },
      );

      await addEvent(handoff._id, 'created', {}, dbSession);
    });
  } finally {
    await dbSession.endSession();
  }

  return toOwnerResponse(handoff);
};

const getHandoffsService = async (ownerId) => {
  assertOwnerId(ownerId);
  const handoffs = await Handoff.find({ ownerId })
    .sort({ createdAt: -1 })
    .lean();
  return handoffs.map(toOwnerResponse);
};

const getHandoffService = async (ownerId, handoffId) => {
  assertOwnerId(ownerId);
  assertHandoffId(handoffId);
  const handoff = await Handoff.findOne({ _id: handoffId, ownerId }).lean();
  if (!handoff)
    throw new ServiceError('Handoff not found', 'HANDOFF_NOT_FOUND');
  return toOwnerResponse(handoff);
};

const getHandoffDeliveryStatusService = async (ownerId, handoffId) => {
  assertOwnerId(ownerId);
  assertHandoffId(handoffId);

  const handoff = await Handoff.exists({ _id: handoffId, ownerId });
  if (!handoff) {
    throw new ServiceError('Handoff not found', 'HANDOFF_NOT_FOUND');
  }

  const job = await EmailOutbox.findOne({ aggregateId: handoffId })
    .sort({ createdAt: -1 })
    .select('status attempts nextAttemptAt sentAt completedAt lastError providerMessageId')
    .lean();

  return job || { status: 'not-shared' };
};

const updateHandoffService = async (ownerId, handoffId, updates) => {
  assertOwnerId(ownerId);
  assertHandoffId(handoffId);
  const handoff = await Handoff.findOne({ _id: handoffId, ownerId });

  if (!handoff)
    throw new ServiceError('Handoff not found', 'HANDOFF_NOT_FOUND');
  if (handoff.status !== 'draft' || handoff.viewedAt) {
    throw new ServiceError(
      'Only draft handoffs can be edited',
      'HANDOFF_EDIT_CONFLICT',
    );
  }

  const updateData = {};

  if (updates.title !== undefined) {
    const title = normalizeText(updates.title);
    if (!title || title.length > MAX_TITLE_LENGTH) {
      throw new ServiceError(
        'Title must be between 1 and 120 characters',
        'HANDOFF_VALIDATION_FAILED',
      );
    }
    updateData.title = title;
  }
  if (updates.instructions !== undefined) {
    const instructions = normalizeText(updates.instructions);
    if (!instructions || instructions.length > MAX_INSTRUCTIONS_LENGTH) {
      throw new ServiceError(
        'Instructions must be between 1 and 20,000 characters',
        'HANDOFF_VALIDATION_FAILED',
      );
    }
    updateData.instructionsEncrypted = encryptHandoff(instructions);
  }
  if (updates.recipientEmail !== undefined) {
    const email = normalizeEmail(updates.recipientEmail);
    if (!isValidEmail(email)) {
      throw new ServiceError(
        'A valid recipient email is required',
        'HANDOFF_VALIDATION_FAILED',
      );
    }
    updateData.recipientEmail = email;
  }
  if (updates.expiresAt !== undefined)
    updateData.expiresAt = parseFutureExpiry(updates.expiresAt);
  if (Object.keys(updateData).length === 0) {
    throw new ServiceError(
      'No editable fields were provided',
      'HANDOFF_VALIDATION_FAILED',
    );
  }

  const updated = await Handoff.findOneAndUpdate(
    { _id: handoffId, ownerId, viewedAt: null, status: { $ne: 'revoked' } },
    { $set: updateData },
    { new: true, runValidators: true },
  ).lean();

  if (!updated)
    throw new ServiceError(
      'Handoff can no longer be edited',
      'HANDOFF_EDIT_CONFLICT',
    );
  return toOwnerResponse(updated);
};

const shareHandoffService = async (ownerId, handoffId, metadata = {}) => {
  assertOwnerId(ownerId);
  assertHandoffId(handoffId);
  const handoff = await Handoff.findOne({ _id: handoffId, ownerId });

  if (!handoff)
    throw new ServiceError('Handoff not found', 'HANDOFF_NOT_FOUND');
  if (!['draft', 'active'].includes(handoff.status) || handoff.viewedAt) {
    throw new ServiceError(
      'This handoff cannot be shared',
      'HANDOFF_SHARE_CONFLICT',
    );
  }
  if (handoff.expiresAt <= new Date()) {
    await Handoff.updateOne(
      { _id: handoff._id },
      { $set: { status: 'expired' } },
    );
    throw new ServiceError('This handoff has expired', 'HANDOFF_EXPIRED');
  }

  const rawToken = createRawHandoffToken();
  const tokenHash = hashToken(rawToken);

  const dbSession = await mongoose.startSession();
  let sharedHandoff;

  try {
    await dbSession.withTransaction(async () => {
      await HandoffToken.deleteOne({ handoffId: handoff._id }, { session: dbSession });
      await HandoffToken.create(
        [{ handoffId: handoff._id, tokenHash, expiresAt: handoff.expiresAt }],
        { session: dbSession },
      );

      await enqueueHandoffEmail({
        handoffId: handoff._id,
        recipientEmail: handoff.recipientEmail,
        title: handoff.title,
        redemptionUrl: `${env.clientUrl}/redeem/${encodeURIComponent(rawToken)}`,
        expiresAt: handoff.expiresAt,
        idempotencyKey: `${handoff._id}:${tokenHash}`,
        dbSession,
      });

      sharedHandoff = await Handoff.findOneAndUpdate(
        {
          _id: handoff._id,
          ownerId,
          viewedAt: null,
          status: { $in: ['draft', 'active'] },
          expiresAt: { $gt: new Date() },
        },
        { $set: { status: 'active', sharedAt: new Date() } },
        { new: true, session: dbSession },
      );

      if (!sharedHandoff) {
        throw new ServiceError('Handoff could not be shared', 'HANDOFF_SHARE_FAILED');
      }

      await addEvent(
        handoff._id,
        'shared',
        metadata,
        dbSession,
      );
    });
  } finally {
    await dbSession.endSession();
  }

  return toOwnerResponse(sharedHandoff);
};

const revokeHandoffService = async (ownerId, handoffId, metadata = {}) => {
  assertOwnerId(ownerId);
  assertHandoffId(handoffId);
  const dbSession = await mongoose.startSession();
  let updated;

  try {
    await dbSession.withTransaction(async () => {
      updated = await Handoff.findOneAndUpdate(
        { _id: handoffId, ownerId, status: { $ne: 'revoked' } },
        { $set: { status: 'revoked', revokedAt: new Date() } },
        { new: true, session: dbSession },
      );

      if (!updated) {
        throw new ServiceError(
          'Handoff not found or already revoked',
          'HANDOFF_NOT_FOUND',
        );
      }

      await HandoffToken.updateOne(
        { handoffId, usedAt: null, revokedAt: null },
        { $set: { revokedAt: new Date() } },
        { session: dbSession },
      );
      await addEvent(handoffId, 'revoked', metadata, dbSession);
    });
  } finally {
    await dbSession.endSession();
  }

  return toOwnerResponse(updated);
};

const redeemHandoffService = async (rawToken, metadata = {}) => {
  if (typeof rawToken !== 'string' || rawToken.length < 40) {
    throw new ServiceError(
      'Invalid or unavailable handoff',
      'HANDOFF_UNAVAILABLE',
    );
  }

  const dbSession = await mongoose.startSession();
  let handoff;
  let instructions;

  try {
    await dbSession.withTransaction(async () => {
      const token = await HandoffToken.findOneAndUpdate(
        {
          tokenHash: hashToken(rawToken),
          usedAt: null,
          revokedAt: null,
          expiresAt: { $gt: new Date() },
        },
        { $set: { usedAt: new Date() } },
        { new: true, session: dbSession },
      );

      if (!token) {
        throw new ServiceError('Invalid or unavailable handoff', 'HANDOFF_UNAVAILABLE');
      }

      handoff = await Handoff.findOneAndUpdate(
        {
          _id: token.handoffId,
          viewedAt: null,
          status: { $in: ['draft', 'active'] },
          expiresAt: { $gt: new Date() },
        },
        { $set: { viewedAt: new Date(), status: 'viewed' } },
        { new: true, session: dbSession },
      );

      if (!handoff) {
        throw new ServiceError('Invalid or unavailable handoff', 'HANDOFF_UNAVAILABLE');
      }

      try {
        instructions = decryptHandoff(handoff.instructionsEncrypted);
      } catch {
        throw new ServiceError(
          'Handoff could not be opened',
          'HANDOFF_DECRYPTION_FAILED',
        );
      }

      await addEvent(handoff._id, 'viewed', metadata, dbSession);
    });
  } finally {
    await dbSession.endSession();
  }

  return {
    title: handoff.title,
    instructions,
    expiresAt: handoff.expiresAt,
    viewedAt: handoff.viewedAt,
  };
};

export {
  createHandoffService,
  getHandoffsService,
  getHandoffService,
  getHandoffDeliveryStatusService,
  updateHandoffService,
  shareHandoffService,
  revokeHandoffService,
  redeemHandoffService,
};
