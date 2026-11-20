import mongoose, { Schema } from 'mongoose';

const oauthLinkSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  state: {
    type: String,
    required: true,
    unique: true,
  },
  codeVerifier: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  purpose: {
    type: String,
    enum: ['account-link', 'mfa-reauth'],
    required: true,
  },
  claimedAt: {
    type: Date,
    default: null,
  },
});

oauthLinkSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const OAuthLink = mongoose.model('OAuthLink', oauthLinkSchema);
