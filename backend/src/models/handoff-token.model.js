import mongoose, { Schema } from 'mongoose';

const handoffTokenSchema = new Schema(
  {
    handoffId: {
      type: Schema.Types.ObjectId,
      ref: 'Handoff',
      required: true,
      unique: true,
      index: true,
    },
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    usedAt: {
      type: Date,
      default: null,
    },
    revokedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

handoffTokenSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 },
);

export const HandoffToken = mongoose.model('HandoffToken', handoffTokenSchema);
