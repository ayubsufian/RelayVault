import mongoose, { Schema } from 'mongoose';

const handoffEventSchema = new Schema(
  {
    handoffId: {
      type: Schema.Types.ObjectId,
      ref: 'Handoff',
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ['created', 'shared', 'viewed', 'revoked', 'expired'],
      required: true,
    },
    ipHash: {
      type: String,
      default: null,
    },
    userAgent: {
      type: String,
      maxlength: 500,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

handoffEventSchema.index({ handoffId: 1, createdAt: -1 });

export const HandoffEvent = mongoose.model('HandoffEvent', handoffEventSchema);
