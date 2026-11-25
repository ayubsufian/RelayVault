import mongoose, { Schema } from 'mongoose';

const handoffSchema = new Schema(
  {
    ownerId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      minLength: 1,
      maxLength: 120,
    },
    instructionsEncrypted: {
      type: String,
      required: true,
    },
    recipientEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      maxlength: 254,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['draft', 'active', 'viewed', 'revoked', 'expired'],
      default: 'draft',
      index: true,
    },
    viewedAt: {
      type: Date,
      default: null,
    },
    sharedAt: {
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

handoffSchema.index({ ownerId: 1, createdAt: -1 });

export const Handoff = mongoose.model('Handoff', handoffSchema);
