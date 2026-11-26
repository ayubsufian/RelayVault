import mongoose, { Schema } from 'mongoose';

const emailOutboxSchema = new Schema(
  {
    type: {
      type: String,
      enum: [
        'handoff-shared',
        'password-reset',
        'email-verification',
        'mfa-changed',
      ],
      required: true,
    },
    aggregateId: {
      type: Schema.Types.ObjectId,
      ref: 'Handoff',
      required: true,
      index: true,
    },
    idempotencyKey: {
      type: String,
      required: true,
      unique: true,
    },
    providerIdempotencyKey: {
      type: String,
      required: true,
      unique: true,
    },
    recipientEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    payloadEncrypted: {
      type: String,
      required: true,
    },
    status: {
      type: String,
      enum: ['pending', 'processing', 'sent', 'failed'],
      default: 'pending',
      index: true,
    },
    attempts: {
      type: Number,
      default: 0,
      min: 0,
    },
    nextAttemptAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    lockedAt: {
      type: Date,
      default: null,
    },
    sentAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    providerMessageId: {
      type: String,
      default: null,
    },
    lastError: {
      type: String,
      maxlength: 2_000,
      default: null,
    },
  },
  { timestamps: true },
);

emailOutboxSchema.index({ status: 1, nextAttemptAt: 1 });
emailOutboxSchema.index(
  { completedAt: 1 },
  { expireAfterSeconds: 30 * 24 * 60 * 60 },
);

export const EmailOutbox = mongoose.model('EmailOutbox', emailOutboxSchema);
