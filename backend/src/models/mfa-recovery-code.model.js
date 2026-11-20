import mongoose, { Schema } from 'mongoose';

const mfaRecoveryCodeSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    codeHash: {
      type: String,
      required: true,
    },
    usedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

mfaRecoveryCodeSchema.index({ userId: 1, codeHash: 1 }, { unique: true });

export const MfaRecoveryCode = mongoose.model(
  'MfaRecoveryCode',
  mfaRecoveryCodeSchema,
);
