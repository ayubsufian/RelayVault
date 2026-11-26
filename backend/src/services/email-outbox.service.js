import { EmailOutbox } from '../models/email-outbox.model.js';
import {
  sendHandoffEmail,
  sendPasswordResetEmail,
  sendVerificationEmail,
  sendMfaChangedEmail,
} from './email.service.js';
import { decryptHandoff, encryptHandoff } from '../utils/secret-crypto.js';
import crypto from 'crypto';

const MAX_ATTEMPTS = 4;
const LOCK_TIMEOUT_MS = 5 * 60 * 1000;

const enqueueEmail = async ({
  type,
  aggregateId,
  recipientEmail,
  payload,
  idempotencyKey,
  dbSession,
}) => {
  const job = {
    type,
    aggregateId,
    idempotencyKey,
    providerIdempotencyKey: crypto.randomUUID(),
    recipientEmail,
    payloadEncrypted: encryptHandoff(JSON.stringify(payload)),
    status: 'pending',
    attempts: 0,
    nextAttemptAt: new Date(),
  };

  const [created] = dbSession
    ? await EmailOutbox.create([job], { session: dbSession })
    : await EmailOutbox.create([job]);

  return created;
};

const enqueueHandoffEmail = (options) =>
  enqueueEmail({
    ...options,
    type: 'handoff-shared',
    payload: {
      title: options.title,
      redemptionUrl: options.redemptionUrl,
      expiresAt: options.expiresAt,
    },
  });

const enqueueHandoffEmails = async ({ recipientEmails, ...options }) =>
  Promise.all(recipientEmails.map((recipientEmail, recipientIndex) =>
    enqueueHandoffEmail({
      ...options,
      recipientEmail,
      recipientIndex,
      idempotencyKey: `${options.idempotencyKey}:${recipientIndex}`,
    }),
  ));

const enqueuePasswordResetEmail = (options) =>
  enqueueEmail({
    ...options,
    type: 'password-reset',
    payload: { rawToken: options.rawToken },
  });

const enqueueVerificationEmail = (options) =>
  enqueueEmail({
    ...options,
    type: 'email-verification',
    payload: { rawToken: options.rawToken },
  });

const enqueueMfaChangedEmail = (options) =>
  enqueueEmail({
    ...options,
    type: 'mfa-changed',
    payload: { action: options.action },
  });

const calculateNextAttempt = (attempts) => {
  const delayMs = Math.min(60 * 60 * 1000, 2 ** attempts * 60 * 1000);
  return new Date(Date.now() + delayMs);
};

const claimNextEmailJob = async () => {
  const now = new Date();
  const staleLock = new Date(Date.now() - LOCK_TIMEOUT_MS);

  return EmailOutbox.findOneAndUpdate(
    {
      $or: [
        { status: 'pending', nextAttemptAt: { $lte: now } },
        { status: 'processing', lockedAt: { $lte: staleLock } },
      ],
      attempts: { $lt: MAX_ATTEMPTS },
    },
    {
      $set: { status: 'processing', lockedAt: now },
      $inc: { attempts: 1 },
    },
    { new: true, sort: { nextAttemptAt: 1 } },
  );
};

const processNextEmailJob = async () => {
  const job = await claimNextEmailJob();

  if (!job) return false;

  try {
    const payload = JSON.parse(decryptHandoff(job.payloadEncrypted));

    const emailPayload = {
      ...payload,
      idempotencyKey: job.providerIdempotencyKey,
    };

    let providerMessageId;

    switch (job.type) {
      case 'handoff-shared':
        providerMessageId = await sendHandoffEmail(job.recipientEmail, emailPayload);
        break;
      case 'password-reset':
        providerMessageId = await sendPasswordResetEmail(
          job.recipientEmail,
          payload.rawToken,
          emailPayload,
        );
        break;
      case 'email-verification':
        providerMessageId = await sendVerificationEmail(
          job.recipientEmail,
          payload.rawToken,
          emailPayload,
        );
        break;
      case 'mfa-changed':
        providerMessageId = await sendMfaChangedEmail(
          job.recipientEmail,
          payload.action,
          emailPayload,
        );
        break;
      default:
        throw new TypeError(`Unsupported email outbox type: ${job.type}`);
    }

    await EmailOutbox.updateOne(
      { _id: job._id, status: 'processing' },
      {
        $set: {
          status: 'sent',
          sentAt: new Date(),
          completedAt: new Date(),
          lockedAt: null,
          lastError: null,
          providerMessageId,
        },
      },
    );
  } catch (error) {
    const exhausted = job.attempts >= MAX_ATTEMPTS;

    await EmailOutbox.updateOne(
      { _id: job._id, status: 'processing' },
      {
        $set: {
          status: exhausted ? 'failed' : 'pending',
          nextAttemptAt: exhausted ? job.nextAttemptAt : calculateNextAttempt(job.attempts),
          lockedAt: null,
          lastError: error.message.slice(0, 2_000),
          ...(exhausted ? { completedAt: new Date() } : {}),
        },
      },
    );
  }

  return true;
};

const startEmailOutboxWorker = ({ intervalMs = 5_000 } = {}) => {
  const timer = setInterval(() => {
    processNextEmailJob().catch((error) => {
      console.error('Email outbox worker failed', error);
    });
  }, intervalMs);

  timer.unref?.();
  return timer;
};

export {
  enqueueHandoffEmail,
  enqueueHandoffEmails,
  enqueuePasswordResetEmail,
  enqueueVerificationEmail,
  enqueueMfaChangedEmail,
  processNextEmailJob,
  startEmailOutboxWorker,
};
