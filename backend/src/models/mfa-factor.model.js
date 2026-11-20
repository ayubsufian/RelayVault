import mongoose, { Schema } from 'mongoose';

const mfaFactorSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      unique: true,
      index: true,
    },
    type: {
      type: String,
      enum: ['totp'],
      required: true,
    },
    secretEncrypted: {
      type: String,
      required: true,
    },
    enabledAt: {
      type: Date,
      default: null,
    },
    lastUsedStep: {
      type: Number,
      default: null,
    },
    pendingSecretEncrypted: {
      type: String,
      default: null,
    },
    pendingCreatedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true },
);

export const MfaFactor = mongoose.model('MfaFactor', mfaFactorSchema);
