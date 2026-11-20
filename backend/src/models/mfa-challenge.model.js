import mongoose, { Schema } from 'mongoose';

const mfaChallengeSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    challengeHash: {
      type: String,
      required: true,
      unique: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    attempts: {
      type: Number,
      default: 0,
    },
    usedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

mfaChallengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const MfaChallenge = mongoose.model('MfaChallenge', mfaChallengeSchema);
