import mongoose, { Schema } from 'mongoose';

const mfaReauthGrantSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    jti: {
      type: String,
      required: true,
      unique: true,
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    usedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

mfaReauthGrantSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const MfaReauthGrant = mongoose.model(
  'MfaReauthGrant',
  mfaReauthGrantSchema,
);
